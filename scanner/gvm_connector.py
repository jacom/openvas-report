from datetime import datetime, timezone

from django.db import connections

from .models import ScanReport


# GVM scan_run_status values
GVM_STATUS_MAP = {
    1: 'Done',
    2: 'New',
    3: 'Requested',
    4: 'Running',
    10: 'Delete Requested',
    11: 'Stop Requested',
    12: 'Stopped',
}


def _dictfetchall(cursor):
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _epoch_to_datetime(epoch):
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _parse_severity(cvss_score):
    if cvss_score >= 9.0:
        return 'Critical'
    if cvss_score >= 7.0:
        return 'High'
    if cvss_score >= 4.0:
        return 'Medium'
    if cvss_score >= 0.1:
        return 'Low'
    return 'Info'


def list_gvm_reports():
    """List available reports from GVM database with metadata."""
    imported_ids = set(
        ScanReport.objects.filter(gvm_report_id__isnull=False)
        .values_list('gvm_report_id', flat=True)
    )

    with connections['gvmd'].cursor() as cursor:
        cursor.execute("""
            SELECT
                r.id,
                t.name AS task_name,
                r.scan_run_status,
                r.start_time,
                r.end_time,
                (SELECT COUNT(*) FROM results res WHERE res.report = r.id) AS result_count,
                (SELECT COUNT(DISTINCT rh.host) FROM report_hosts rh WHERE rh.report = r.id) AS host_count
            FROM reports r
            JOIN tasks t ON r.task = t.id
            ORDER BY r.start_time DESC
        """)
        rows = _dictfetchall(cursor)

    reports = []
    for row in rows:
        reports.append({
            'id': row['id'],
            'task_name': row['task_name'],
            'status': GVM_STATUS_MAP.get(row['scan_run_status'], 'Unknown'),
            'start_time': _epoch_to_datetime(row['start_time']),
            'end_time': _epoch_to_datetime(row['end_time']),
            'result_count': row['result_count'],
            'host_count': row['host_count'],
            'already_imported': row['id'] in imported_ids,
        })

    return reports


def check_already_imported(gvm_report_id):
    """Check if a GVM report has already been imported."""
    return ScanReport.objects.filter(gvm_report_id=gvm_report_id).exists()


def fetch_gvm_report(report_id):
    """
    Fetch a full report from GVM database and return data in the same
    format as parse_gvm_xml() for compatibility with _create_report_from_data().
    """
    with connections['gvmd'].cursor() as cursor:
        # 1. Report metadata
        cursor.execute("""
            SELECT r.id, r.start_time, r.end_time, t.name AS task_name
            FROM reports r
            JOIN tasks t ON r.task = t.id
            WHERE r.id = %s
        """, [report_id])
        report_row = _dictfetchall(cursor)
        if not report_row:
            raise ValueError(f"GVM report {report_id} not found")
        report_meta = report_row[0]

        # 2. Results with NVT info
        cursor.execute("""
            SELECT
                res.id AS result_id,
                res.host,
                res.hostname,
                res.port,
                res.nvt AS nvt_oid,
                res.severity AS result_severity,
                res.description,
                n.name AS nvt_name,
                n.summary AS nvt_summary,
                n.family,
                n.cvss_base,
                n.solution,
                n.cve
            FROM results res
            LEFT JOIN nvts n ON res.nvt = n.oid
            WHERE res.report = %s
            ORDER BY res.id
        """, [report_id])
        results = _dictfetchall(cursor)

        # 3. Collect unique NVT OIDs for vt_refs lookup
        nvt_oids = list({r['nvt_oid'] for r in results if r['nvt_oid']})

        # 4. Fetch vt_refs (CVEs and other references)
        cve_map = {}  # oid -> [cve_ids]
        ref_map = {}  # oid -> {type: [ref_ids]}
        if nvt_oids:
            cursor.execute("""
                SELECT vt_oid, type, ref_id
                FROM vt_refs
                WHERE vt_oid = ANY(%s)
            """, [nvt_oids])
            for ref_row in _dictfetchall(cursor):
                oid = ref_row['vt_oid']
                if ref_row['type'] == 'cve':
                    cve_map.setdefault(oid, []).append(ref_row['ref_id'])
                else:
                    ref_map.setdefault(oid, {}).setdefault(
                        ref_row['type'], []
                    ).append(ref_row['ref_id'])

        # 5. Fetch OS info per host (human-readable, exclude CPE format)
        cursor.execute("""
            SELECT rh.host, rhd.value AS os_name
            FROM report_hosts rh
            JOIN report_host_details rhd ON rhd.report_host = rh.id
            WHERE rh.report = %s
              AND rhd.name = 'OS'
              AND rhd.value NOT LIKE 'cpe:/%%'
            GROUP BY rh.host, rhd.value
        """, [report_id])
        host_os_map = {row['host']: row['os_name'] for row in _dictfetchall(cursor)}

    # Build output matching parse_gvm_xml format
    hosts_seen = set()
    vulnerabilities = []

    for r in results:
        host_ip = r['host'] or ''
        if host_ip:
            hosts_seen.add(host_ip)

        # Parse port/protocol
        port = ''
        protocol = 'tcp'
        port_str = r['port'] or ''
        if '/' in port_str:
            parts = port_str.split('/')
            port = parts[0]
            protocol = parts[1] if len(parts) > 1 else 'tcp'
        elif port_str:
            port = port_str

        # CVSS score
        try:
            cvss_score = float(r['cvss_base']) if r['cvss_base'] else 0.0
        except (ValueError, TypeError):
            cvss_score = 0.0
        # Use result severity if available and cvss_base is missing
        if cvss_score == 0.0 and r['result_severity'] is not None:
            cvss_score = max(float(r['result_severity']), 0.0)

        severity = _parse_severity(cvss_score)

        nvt_oid = r['nvt_oid'] or ''

        # CVE list: prefer vt_refs, fallback to nvts.cve field
        cve_list = cve_map.get(nvt_oid, [])
        if not cve_list and r['cve'] and r['cve'] != 'NOCVE':
            cve_list = [c.strip() for c in r['cve'].split(',') if c.strip()]

        references = ref_map.get(nvt_oid, {})

        description = r['nvt_summary'] or r['description'] or ''
        solution = r['solution'] or ''

        vulnerabilities.append({
            'name': r['nvt_name'] or 'Unknown',
            'oid': nvt_oid,
            'cvss_score': cvss_score,
            'severity': severity,
            'description': description,
            'solution': solution,
            'family': r['family'] or '',
            'cve_list': cve_list,
            'references': references,
            'host': {
                'ip': host_ip,
                'hostname': r['hostname'] or '',
                'os_name': host_os_map.get(host_ip, ''),
                'port': port,
                'protocol': protocol,
                'result_detail': r['description'] or '',
            }
        })

    return {
        'report_name': report_meta['task_name'],
        'scan_date': _epoch_to_datetime(report_meta['start_time']),
        'scanner_version': '',
        'hosts': list(hosts_seen),
        'vulnerabilities': vulnerabilities,
    }
