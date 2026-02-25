import csv
from django.http import HttpResponse
from scanner.models import Vulnerability


def generate_csv(report):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="openvas_report_{report.id}.csv"'
    response.write('\ufeff')  # UTF-8 BOM for Excel compatibility

    writer = csv.writer(response)
    writer.writerow([
        'Severity', 'CVSS', 'Vulnerability', 'Family',
        'Host IP', 'Hostname', 'Port', 'Protocol',
        'CVEs', 'Description', 'Solution',
    ])

    vulns = Vulnerability.objects.filter(report=report).prefetch_related('affected_hosts')
    for vuln in vulns:
        for host in vuln.affected_hosts.all():
            writer.writerow([
                vuln.severity,
                vuln.cvss_score,
                vuln.name,
                vuln.family,
                host.ip,
                host.hostname,
                host.port,
                host.protocol,
                ', '.join(vuln.cve_list),
                vuln.description[:500],
                vuln.solution[:500],
            ])

    return response
