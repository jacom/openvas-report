import json
import subprocess
import urllib.request
from pathlib import Path

from django.conf import settings as django_settings
from django.db import transaction
from rest_framework import generics, status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import ScanReport, Vulnerability, AffectedHost, ChatGPTSettings, AIAnalysis
from .serializers import (
    ScanReportSerializer,
    ScanReportDetailSerializer,
    VulnerabilitySerializer,
    VulnerabilityListSerializer,
)
from .xml_parser import parse_gvm_xml
from .gvm_connector import list_gvm_reports, fetch_gvm_report, check_already_imported


@api_view(['POST'])
def import_xml(request):
    """Upload and import a GVM XML report file."""
    xml_file = request.FILES.get('file')
    if not xml_file:
        return Response(
            {'error': 'No file provided. Use multipart form with field "file".'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        xml_content = xml_file.read()
        report = _create_report_from_xml(xml_content)
        return Response(
            ScanReportSerializer(report).data,
            status=status.HTTP_201_CREATED,
        )
    except Exception as e:
        return Response(
            {'error': f'Failed to parse XML: {str(e)}'},
            status=status.HTTP_400_BAD_REQUEST,
        )


def _create_report_from_xml(xml_content):
    """Parse XML content and create database records."""
    data = parse_gvm_xml(xml_content)
    return _create_report_from_data(data)


def _create_report_from_data(data, gvm_report_id=None):
    """Create database records from parsed report data (XML or GVM DB)."""
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for vuln in data['vulnerabilities']:
        severity_counts[vuln['severity']] = severity_counts.get(vuln['severity'], 0) + 1

    with transaction.atomic():
        report = ScanReport.objects.create(
            name=data['report_name'],
            scan_date=data['scan_date'],
            scanner_version=data['scanner_version'] or '',
            host_count=len(data['hosts']),
            critical_count=severity_counts['Critical'],
            high_count=severity_counts['High'],
            medium_count=severity_counts['Medium'],
            low_count=severity_counts['Low'],
            info_count=severity_counts['Info'],
            gvm_report_id=gvm_report_id,
        )

        for vuln_data in data['vulnerabilities']:
            host_info = vuln_data.pop('host')
            vuln = Vulnerability.objects.create(report=report, **vuln_data)
            if host_info.get('ip'):
                AffectedHost.objects.create(vulnerability=vuln, **host_info)

    return report


class ReportListView(generics.ListAPIView):
    queryset = ScanReport.objects.all()
    serializer_class = ScanReportSerializer


class ReportDetailView(generics.RetrieveAPIView):
    queryset = ScanReport.objects.all()
    serializer_class = ScanReportDetailSerializer


class ReportVulnsView(generics.ListAPIView):
    serializer_class = VulnerabilityListSerializer

    def get_queryset(self):
        report_id = self.kwargs['pk']
        severity = self.request.query_params.get('severity')
        qs = Vulnerability.objects.filter(report_id=report_id)
        if severity:
            qs = qs.filter(severity__iexact=severity)
        return qs


@api_view(['GET'])
def report_stats(request, pk):
    """Return JSON stats for charts."""
    try:
        report = ScanReport.objects.get(pk=pk)
    except ScanReport.DoesNotExist:
        return Response({'error': 'Report not found'}, status=404)

    severity_dist = {
        'Critical': report.critical_count,
        'High': report.high_count,
        'Medium': report.medium_count,
        'Low': report.low_count,
        'Info': report.info_count,
    }

    top_vulns = Vulnerability.objects.filter(
        report=report, severity__in=['Critical', 'High']
    ).order_by('-cvss_score')[:10]

    top_vulns_data = [
        {
            'name': v.name[:60],
            'cvss_score': v.cvss_score,
            'severity': v.severity,
            'host_count': v.affected_hosts.count(),
        }
        for v in top_vulns
    ]

    # Host severity matrix
    from django.db.models import Count, Q
    hosts = AffectedHost.objects.filter(
        vulnerability__report=report
    ).values('ip').annotate(
        critical=Count('id', filter=Q(vulnerability__severity='Critical')),
        high=Count('id', filter=Q(vulnerability__severity='High')),
        medium=Count('id', filter=Q(vulnerability__severity='Medium')),
        low=Count('id', filter=Q(vulnerability__severity='Low')),
        info=Count('id', filter=Q(vulnerability__severity='Info')),
        total=Count('id'),
    ).order_by('-critical', '-high', '-total')[:20]

    return Response({
        'severity_distribution': severity_dist,
        'top_vulnerabilities': top_vulns_data,
        'host_severity_matrix': list(hosts),
    })


@api_view(['GET'])
def gvm_report_list(request):
    """List available reports from GVM database."""
    try:
        reports = list_gvm_reports()
        return Response(reports)
    except Exception as e:
        return Response(
            {'error': f'Failed to connect to GVM database: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(['POST'])
def chatgpt_explain_cve(request):
    """Send CVE(s) to ChatGPT API for vulnerability explanation and remediation steps.
    Saves result to AIAnalysis model if vulnerability_id is provided.
    """
    if not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

    cves = request.data.get('cves', [])
    vuln_name = request.data.get('vuln_name', '')
    vulnerability_id = request.data.get('vulnerability_id')

    if not cves and not vuln_name:
        return Response({'error': 'กรุณาระบุ CVE หรือชื่อช่องโหว่'}, status=status.HTTP_400_BAD_REQUEST)

    gpt_settings = ChatGPTSettings.load()
    if not gpt_settings.api_key:
        return Response(
            {'error': 'ยังไม่ได้ตั้งค่า ChatGPT API Key กรุณาตั้งค่าในหน้า Settings'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    prefix = (gpt_settings.prompt_prefix or 'อธิบาย').strip()
    suffix = (gpt_settings.prompt_suffix or 'และวิธีแก้ไขแบบเป็นขั้นตอน').strip()
    if cves:
        cve_str = ', '.join(cves)
        content = f"{prefix} {cve_str} {suffix}"
    else:
        content = f"{prefix} {vuln_name} {suffix}"

    try:
        from openai import OpenAI
        client = OpenAI(api_key=gpt_settings.api_key)

        model_name = gpt_settings.model.lower()
        # o-series (o1, o3, o4) and gpt-4.1+, gpt-4.5 use max_completion_tokens
        # o-series also does not support temperature parameter
        uses_completion_tokens = any(
            model_name.startswith(p) for p in ('o1', 'o3', 'o4', 'gpt-4.1', 'gpt-4.5', 'gpt-5')
        )
        is_o_series = any(model_name.startswith(p) for p in ('o1', 'o3', 'o4'))

        create_kwargs = {
            'model': gpt_settings.model,
            'messages': [
                {"role": "system", "content": "You are a knowledgeable and concise cybersecurity expert."},
                {"role": "user", "content": content},
            ],
        }
        if uses_completion_tokens:
            # gpt-5.x and o-series use reasoning tokens that count toward max_completion_tokens
            # require at least 4000 tokens so reasoning doesn't consume the entire budget
            token_budget = max(gpt_settings.max_tokens, 4000)
            create_kwargs['max_completion_tokens'] = token_budget
        else:
            create_kwargs['max_tokens'] = gpt_settings.max_tokens
        if not is_o_series:
            create_kwargs['temperature'] = gpt_settings.temperature

        response = client.chat.completions.create(**create_kwargs)
        answer = response.choices[0].message.content
        print(f"[AI DEBUG] model={gpt_settings.model} finish_reason={response.choices[0].finish_reason} answer_type={type(answer)} answer_len={len(answer) if answer else 0} answer_preview={repr((answer or '')[:200])}")

        # Save result to database if vulnerability_id is provided
        if vulnerability_id:
            try:
                vuln = Vulnerability.objects.get(pk=vulnerability_id)
                AIAnalysis.objects.update_or_create(
                    vulnerability=vuln,
                    defaults={'query': content, 'answer': answer},
                )
            except Vulnerability.DoesNotExist:
                pass

        return Response({'answer': answer, 'query': content})
    except Exception as e:
        return Response(
            {'error': f'ChatGPT API Error: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(['POST'])
def sync_from_gvm(request):
    """Import a report from GVM database by report ID."""
    report_id = request.data.get('report_id')
    if not report_id:
        return Response(
            {'error': 'report_id is required'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        report_id = int(report_id)
    except (ValueError, TypeError):
        return Response(
            {'error': 'report_id must be an integer'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if check_already_imported(report_id):
        return Response(
            {'error': 'This report has already been imported'},
            status=status.HTTP_409_CONFLICT,
        )

    try:
        data = fetch_gvm_report(report_id)
        report = _create_report_from_data(data, gvm_report_id=report_id)
        return Response(
            ScanReportSerializer(report).data,
            status=status.HTTP_201_CREATED,
        )
    except ValueError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_404_NOT_FOUND,
        )
    except Exception as e:
        return Response(
            {'error': f'Failed to sync report: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(['GET'])
def system_version(request):
    """Return current app version and check GitHub for latest release."""
    version_file = Path(django_settings.BASE_DIR) / 'VERSION'
    current = version_file.read_text().strip() if version_file.exists() else '0.0.0'

    github_repo = getattr(django_settings, 'GITHUB_REPO', '')
    latest = None
    update_available = False
    release_url = ''
    changelog = ''
    error = None

    if github_repo and not github_repo.startswith('OWNER/'):
        try:
            api_url = f'https://api.github.com/repos/{github_repo}/releases/latest'
            req = urllib.request.Request(
                api_url,
                headers={'User-Agent': 'openvas-report-updater', 'Accept': 'application/vnd.github+json'},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            latest = data.get('tag_name', '').lstrip('v')
            release_url = data.get('html_url', '')
            changelog = data.get('body', '')[:500]
            update_available = bool(latest) and latest != current
        except urllib.error.HTTPError as e:
            if e.code == 404:
                error = f'ยังไม่มี Release บน GitHub — ไปสร้างที่ https://github.com/{github_repo}/releases/new'
            else:
                error = f'GitHub API Error {e.code}: {e.reason}'
        except Exception as e:
            error = str(e)

    return Response({
        'current': current,
        'latest': latest,
        'update_available': update_available,
        'release_url': release_url,
        'changelog': changelog,
        'github_repo': github_repo,
        'error': error,
    })


@api_view(['POST'])
def system_run_update(request):
    """Run update.sh script. Superuser only."""
    if not request.user.is_authenticated or not request.user.is_superuser:
        return Response({'error': 'Superuser access required'}, status=status.HTTP_403_FORBIDDEN)

    script = Path(django_settings.BASE_DIR) / 'scripts' / 'update.sh'
    if not script.exists():
        return Response({'error': f'update.sh not found at {script}'}, status=status.HTTP_404_NOT_FOUND)

    try:
        result = subprocess.run(
            ['bash', str(script)],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(django_settings.BASE_DIR),
        )
        return Response({
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'success': result.returncode == 0,
        })
    except subprocess.TimeoutExpired:
        return Response({'error': 'Update timed out (5 min)'}, status=status.HTTP_408_REQUEST_TIMEOUT)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
