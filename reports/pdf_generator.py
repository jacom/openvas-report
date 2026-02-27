import base64
from io import BytesIO
from django.http import HttpResponse
from django.template.loader import render_to_string

from scanner.models import Vulnerability, AffectedHost, OrganizationProfile, AIAnalysis
from scanner.thai_advisory import get_thai_advisory


def _generate_severity_chart_base64(report):
    """Generate severity pie chart as base64 PNG for embedding in PDF."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    labels = ['Critical', 'High', 'Medium', 'Low', 'Info']
    sizes = [report.critical_count, report.high_count, report.medium_count,
             report.low_count, report.info_count]
    colors = ['#dc3545', '#fd7e14', '#ffc107', '#0dcaf0', '#6c757d']

    # Filter out zero values
    filtered = [(l, s, c) for l, s, c in zip(labels, sizes, colors) if s > 0]
    if not filtered:
        return ''
    labels, sizes, colors = zip(*filtered)

    fig, ax = plt.subplots(1, 1, figsize=(5, 4))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct='%1.0f%%',
        startangle=90, pctdistance=0.85
    )
    for t in autotexts:
        t.set_fontsize(9)
    ax.set_title('Severity Distribution', fontsize=12, fontweight='bold')

    buf = BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight', transparent=True)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def generate_pdf(report):
    """Generate professional PDF report using WeasyPrint."""
    vulns = Vulnerability.objects.filter(report=report).prefetch_related('affected_hosts')

    critical_vulns = vulns.filter(severity='Critical')
    high_vulns = vulns.filter(severity='High')
    medium_vulns = vulns.filter(severity='Medium')

    # Build host summary: IP → {os_name, ports, worst_severity, cves}
    SEVERITY_ORDER = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1}
    host_rows = AffectedHost.objects.filter(
        vulnerability__report=report
    ).select_related('vulnerability').values(
        'ip', 'os_name', 'port', 'vulnerability__severity', 'vulnerability__cve_list'
    )
    host_map = {}
    for h in host_rows:
        ip = h['ip']
        if ip not in host_map:
            host_map[ip] = {
                'ip': ip,
                'os_name': h['os_name'] or '',
                'ports': set(),
                'worst_severity': 'Info',
                'cves': set(),
            }
        if h['os_name'] and not host_map[ip]['os_name']:
            host_map[ip]['os_name'] = h['os_name']
        if h['port']:
            host_map[ip]['ports'].add(h['port'])
        sev = h['vulnerability__severity']
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(host_map[ip]['worst_severity'], 0):
            host_map[ip]['worst_severity'] = sev
        for cve in (h['vulnerability__cve_list'] or []):
            host_map[ip]['cves'].add(cve)

    hosts_summary = sorted(
        host_map.values(),
        key=lambda x: (-SEVERITY_ORDER.get(x['worst_severity'], 0), x['ip'])
    )
    for h in hosts_summary:
        h['ports'] = sorted(h['ports'])
        h['cves'] = sorted(h['cves'])

    import ipaddress
    _nets = set()
    for h in hosts_summary:
        if h.get('ip'):
            try:
                _nets.add(ipaddress.ip_interface(f"{h['ip']}/24").network)
            except ValueError:
                pass
    scan_networks = ', '.join(sorted(str(n) for n in _nets))

    chart_b64 = _generate_severity_chart_base64(report)

    # Attach Thai advisories to Critical/High vulns
    critical_high_vulns = list(vulns.filter(severity__in=['Critical', 'High']))
    for v in critical_high_vulns:
        v.thai = get_thai_advisory(v.name, v.severity)

    # Collect vulnerabilities that have AI analysis
    ai_analyses = AIAnalysis.objects.filter(
        vulnerability__report=report
    ).select_related('vulnerability').order_by('-vulnerability__cvss_score')

    # Organization profile + logo as base64
    org = OrganizationProfile.load()
    org_logo_b64 = ''
    if org.logo:
        try:
            with open(org.logo.path, 'rb') as f:
                logo_data = f.read()
            import mimetypes
            mime = mimetypes.guess_type(org.logo.path)[0] or 'image/png'
            org_logo_b64 = f'data:{mime};base64,{base64.b64encode(logo_data).decode("utf-8")}'
        except FileNotFoundError:
            pass

    # Document number: prefix + Buddhist year + sequential
    import datetime
    now = datetime.datetime.now()
    thai_year = now.year + 543
    doc_number = f'{org.document_number_prefix}{thai_year}-001'

    context = {
        'report': report,
        'vulnerabilities': vulns,
        'critical_vulns': critical_vulns,
        'high_vulns': high_vulns,
        'medium_vulns': medium_vulns,
        'critical_high_vulns_thai': critical_high_vulns,
        'hosts_summary': hosts_summary,
        'scan_networks': scan_networks,
        'chart_image': chart_b64,
        'org': org,
        'org_logo_b64': org_logo_b64,
        'doc_number': doc_number,
        'ai_analyses': ai_analyses,
    }

    html_string = render_to_string('reports/pdf_template.html', context)
    from weasyprint import HTML
    from django.conf import settings
    base_url = f'file://{settings.BASE_DIR}/'
    pdf_file = HTML(string=html_string, base_url=base_url).write_pdf()

    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="openvas_report_{report.id}.pdf"'
    return response
