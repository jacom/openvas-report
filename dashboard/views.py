from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from scanner.models import ScanReport, Vulnerability, AffectedHost, OrganizationProfile, ChatGPTSettings
from scanner.thai_advisory import get_thai_advisory
from scanner.views import _create_report_from_data
from scanner.gvm_connector import list_gvm_reports, fetch_gvm_report, check_already_imported


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard-index')
    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', 'dashboard-index')
            # If next is a URL path, use redirect directly; if it's a name, use redirect
            if next_url.startswith('/'):
                return redirect(next_url)
            return redirect('dashboard-index')
        else:
            error = 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'
    return render(request, 'dashboard/login.html', {'error': error})


def logout_view(request):
    logout(request)
    return redirect('dashboard-login')


@login_required
def index(request):
    reports = ScanReport.objects.all()
    return render(request, 'dashboard/index.html', {'reports': reports})


@login_required
def report_detail(request, pk):
    report = get_object_or_404(ScanReport, pk=pk)
    severity_filter = request.GET.get('severity', '')
    search_query = request.GET.get('q', '')

    vulns = report.vulnerabilities.all()
    if severity_filter:
        vulns = vulns.filter(severity__iexact=severity_filter)
    if search_query:
        vulns = vulns.filter(
            Q(name__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(cve_list__contains=[search_query.upper()])
        )

    # Attach Thai advisories to Critical/High vulns
    for v in vulns:
        if v.severity in ('Critical', 'High'):
            v.thai = get_thai_advisory(v.name, v.severity)
        else:
            v.thai = None

    # Build host summary: IP → {hostname, ports, worst_severity, cves}
    SEVERITY_ORDER = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1}
    host_rows = AffectedHost.objects.filter(
        vulnerability__report=report
    ).select_related('vulnerability').values(
        'ip', 'hostname', 'os_name', 'port', 'vulnerability__severity', 'vulnerability__cve_list'
    )
    host_map = {}
    for h in host_rows:
        ip = h['ip']
        if ip not in host_map:
            host_map[ip] = {
                'ip': ip,
                'hostname': h['hostname'] or '',
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

    return render(request, 'dashboard/report_detail.html', {
        'report': report,
        'vulnerabilities': vulns,
        'severity_filter': severity_filter,
        'search_query': search_query,
        'hosts_summary': hosts_summary,
    })


@login_required
def delete_report(request, pk):
    report = get_object_or_404(ScanReport, pk=pk)
    if request.method == 'POST':
        name = report.name
        report.delete()
        messages.success(request, f'ลบรายงาน "{name}" เรียบร้อยแล้ว')
        return redirect('dashboard-index')
    return render(request, 'dashboard/confirm_delete.html', {'report': report})


@login_required
def host_detail(request, pk, ip):
    report = get_object_or_404(ScanReport, pk=pk)
    affected = AffectedHost.objects.filter(
        vulnerability__report=report,
        ip=ip,
    ).select_related('vulnerability').order_by('-vulnerability__cvss_score')

    hostname = ''
    if affected.exists():
        hostname = affected[0].hostname

    return render(request, 'dashboard/host_detail.html', {
        'report': report,
        'ip': ip,
        'hostname': hostname,
        'affected_hosts': affected,
    })


@login_required
def organization_profile(request):
    org = OrganizationProfile.load()
    gpt = ChatGPTSettings.load()
    if request.method == 'POST':
        org.name_th = request.POST.get('name_th', '')
        org.name_en = request.POST.get('name_en', '')
        org.address = request.POST.get('address', '')
        org.phone = request.POST.get('phone', '')
        org.email = request.POST.get('email', '')
        org.preparer_name = request.POST.get('preparer_name', '')
        org.preparer_title = request.POST.get('preparer_title', '')
        org.approver_name = request.POST.get('approver_name', '')
        org.approver_title = request.POST.get('approver_title', '')
        org.document_number_prefix = request.POST.get('document_number_prefix', 'VA-RPT-')
        if request.FILES.get('logo'):
            org.logo = request.FILES['logo']
        if request.POST.get('clear_logo') == '1':
            org.logo = ''
        org.save()

        # Save ChatGPT settings
        new_api_key = request.POST.get('chatgpt_api_key', '').strip()
        # Only update if user provided a new key (not the masked placeholder)
        if new_api_key and not new_api_key.startswith('sk-...'):
            gpt.api_key = new_api_key
        gpt.model = request.POST.get('chatgpt_model', 'gpt-4.1')
        try:
            gpt.max_tokens = int(request.POST.get('chatgpt_max_tokens', 400))
        except ValueError:
            gpt.max_tokens = 400
        try:
            gpt.temperature = float(request.POST.get('chatgpt_temperature', 0.0))
        except ValueError:
            gpt.temperature = 0.0
        gpt.prompt_prefix = request.POST.get('chatgpt_prompt_prefix', 'อธิบาย').strip()
        gpt.prompt_suffix = request.POST.get('chatgpt_prompt_suffix', 'และวิธีแก้ไขแบบเป็นขั้นตอน').strip()
        gpt.save()

        messages.success(request, 'บันทึกข้อมูลเรียบร้อยแล้ว')
        return redirect('dashboard-organization')
    return render(request, 'dashboard/organization.html', {'org': org, 'gpt': gpt})


@login_required
def system_update(request):
    from pathlib import Path
    from django.conf import settings as django_settings
    version_file = Path(django_settings.BASE_DIR) / 'VERSION'
    current_version = version_file.read_text().strip() if version_file.exists() else '0.0.0'
    github_repo = getattr(django_settings, 'GITHUB_REPO', '')
    return render(request, 'dashboard/system.html', {
        'current_version': current_version,
        'github_repo': github_repo,
    })


@login_required
def sync_gvm(request):
    if request.method == 'POST':
        report_ids = request.POST.getlist('report_ids')
        if not report_ids:
            messages.error(request, 'กรุณาเลือก report อย่างน้อย 1 รายการ')
            return redirect('dashboard-sync-gvm')

        success_count = 0
        last_report = None
        for rid in report_ids:
            try:
                rid = int(rid)
                if check_already_imported(rid):
                    messages.warning(request, f'Report #{rid} ถูกนำเข้าแล้ว - ข้าม')
                    continue
                data = fetch_gvm_report(rid)
                report = _create_report_from_data(data, gvm_report_id=rid)
                last_report = report
                messages.success(
                    request,
                    f'Sync สำเร็จ: {report.name} '
                    f'(Critical: {report.critical_count}, High: {report.high_count}, '
                    f'Medium: {report.medium_count}, Low: {report.low_count})'
                )
                success_count += 1
            except Exception as e:
                messages.error(request, f'Report #{rid} ผิดพลาด: {e}')

        if success_count == 1 and last_report:
            return redirect('dashboard-report', pk=last_report.id)
        return redirect('dashboard-index')

    # GET: show list of GVM reports
    try:
        gvm_reports = list_gvm_reports()
        error = None
    except Exception as e:
        gvm_reports = []
        error = str(e)

    return render(request, 'dashboard/sync_gvm.html', {
        'gvm_reports': gvm_reports,
        'error': error,
    })
