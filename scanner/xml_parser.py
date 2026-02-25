from lxml import etree
from datetime import datetime, timezone


def _get_text(element, tag, default=''):
    """Get text content of a child element."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _parse_severity(threat_text, cvss_score):
    """Map GVM threat text or CVSS score to severity level."""
    threat_text = (threat_text or '').lower()
    if threat_text == 'critical' or cvss_score >= 9.0:
        return 'Critical'
    if threat_text == 'high' or cvss_score >= 7.0:
        return 'High'
    if threat_text == 'medium' or cvss_score >= 4.0:
        return 'Medium'
    if threat_text == 'low' or cvss_score >= 0.1:
        return 'Low'
    return 'Info'


def _parse_datetime(date_str):
    """Try to parse various GVM date formats."""
    if not date_str:
        return None
    for fmt in [
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%a %b %d %H:%M:%S %Y',
        '%Y-%m-%d %H:%M:%S',
    ]:
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def parse_gvm_xml(xml_content):
    """
    Parse GVM/OpenVAS XML report and return structured data.

    Args:
        xml_content: bytes or string of XML content

    Returns:
        dict with keys: report_name, scan_date, scanner_version,
                       hosts, vulnerabilities
    """
    if isinstance(xml_content, str):
        xml_content = xml_content.encode('utf-8')

    root = etree.fromstring(xml_content)

    # Handle both <report> as root and <report><report> nested structure
    report_elem = root
    if root.tag == 'report':
        inner = root.find('report')
        if inner is not None:
            report_elem = inner

    # Report metadata
    report_name = _get_text(root, 'name') or _get_text(report_elem, 'name') or 'Unnamed Scan'

    scan_start = (
        _get_text(report_elem, 'scan_start')
        or _get_text(report_elem, 'creation_time')
        or _get_text(root, 'creation_time')
    )
    scan_date = _parse_datetime(scan_start)

    scanner_version = _get_text(report_elem, 'scanner/version')

    # Parse results
    results_elem = report_elem.find('results')
    if results_elem is None:
        results_elem = report_elem

    result_elements = results_elem.findall('result')

    hosts_seen = set()
    vulnerabilities = []

    for result in result_elements:
        host_elem = result.find('host')
        host_ip = ''
        hostname = ''
        if host_elem is not None:
            host_ip = (host_elem.text or '').strip()
            hostname_elem = host_elem.find('hostname')
            if hostname_elem is not None:
                hostname = (hostname_elem.text or '').strip()

        if host_ip:
            hosts_seen.add(host_ip)

        port_str = _get_text(result, 'port', '')
        port = ''
        protocol = 'tcp'
        if port_str and '/' in port_str:
            parts = port_str.split('/')
            port = parts[0]
            protocol = parts[1] if len(parts) > 1 else 'tcp'
        elif port_str:
            port = port_str

        # NVT info
        nvt = result.find('nvt')
        nvt_name = ''
        oid = ''
        cvss_score = 0.0
        family = ''
        cve_list = []
        references = {}
        solution = ''
        description_from_nvt = ''

        if nvt is not None:
            oid = nvt.get('oid', '')
            nvt_name = _get_text(nvt, 'name', '')
            family = _get_text(nvt, 'family', '')

            cvss_text = _get_text(nvt, 'cvss_base', '')
            if not cvss_text:
                severities = nvt.find('severities')
                if severities is not None:
                    score_elem = severities.find('.//score')
                    if score_elem is not None and score_elem.text:
                        cvss_text = score_elem.text
            try:
                cvss_score = float(cvss_text)
            except (ValueError, TypeError):
                cvss_score = 0.0

            # CVEs
            cve_refs = nvt.find('refs')
            if cve_refs is not None:
                for ref in cve_refs.findall('ref'):
                    ref_type = ref.get('type', '')
                    ref_id = ref.get('id', '')
                    if ref_type == 'cve' and ref_id:
                        cve_list.append(ref_id)
                    elif ref_id:
                        references.setdefault(ref_type, []).append(ref_id)
            else:
                cve_text = _get_text(nvt, 'cve', '')
                if cve_text and cve_text != 'NOCVE':
                    cve_list = [c.strip() for c in cve_text.split(',') if c.strip()]

            solution = _get_text(nvt, 'solution', '')
            description_from_nvt = _get_text(nvt, 'description', '')

        if not nvt_name:
            nvt_name = _get_text(result, 'name', 'Unknown')

        threat = _get_text(result, 'threat', '')
        severity = _parse_severity(threat, cvss_score)
        description = _get_text(result, 'description', '') or description_from_nvt
        if not solution:
            solution = _get_text(result, 'solution', '')

        result_detail = _get_text(result, 'description', '')

        vulnerabilities.append({
            'name': nvt_name,
            'oid': oid,
            'cvss_score': cvss_score,
            'severity': severity,
            'description': description,
            'solution': solution,
            'family': family,
            'cve_list': cve_list,
            'references': references,
            'host': {
                'ip': host_ip,
                'hostname': hostname,
                'port': port,
                'protocol': protocol,
                'result_detail': result_detail,
            }
        })

    return {
        'report_name': report_name,
        'scan_date': scan_date,
        'scanner_version': scanner_version,
        'hosts': list(hosts_seen),
        'vulnerabilities': vulnerabilities,
    }
