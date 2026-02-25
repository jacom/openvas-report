from rest_framework import serializers
from .models import ScanReport, Vulnerability, AffectedHost


class AffectedHostSerializer(serializers.ModelSerializer):
    class Meta:
        model = AffectedHost
        fields = ['id', 'ip', 'hostname', 'port', 'protocol', 'result_detail']


class VulnerabilitySerializer(serializers.ModelSerializer):
    affected_hosts = AffectedHostSerializer(many=True, read_only=True)
    host_count = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'name', 'oid', 'cvss_score', 'severity',
            'description', 'solution', 'family',
            'cve_list', 'references', 'affected_hosts', 'host_count',
        ]

    def get_host_count(self, obj):
        return obj.affected_hosts.count()


class VulnerabilityListSerializer(serializers.ModelSerializer):
    host_count = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'name', 'oid', 'cvss_score', 'severity',
            'family', 'cve_list', 'host_count',
        ]

    def get_host_count(self, obj):
        return obj.affected_hosts.count()


class ScanReportSerializer(serializers.ModelSerializer):
    total_vulns = serializers.ReadOnlyField()

    class Meta:
        model = ScanReport
        fields = [
            'id', 'name', 'scan_date', 'import_date',
            'scanner_version', 'host_count',
            'critical_count', 'high_count', 'medium_count',
            'low_count', 'info_count', 'total_vulns',
        ]


class ScanReportDetailSerializer(ScanReportSerializer):
    top_vulnerabilities = serializers.SerializerMethodField()

    class Meta(ScanReportSerializer.Meta):
        fields = ScanReportSerializer.Meta.fields + ['top_vulnerabilities']

    def get_top_vulnerabilities(self, obj):
        top_vulns = obj.vulnerabilities.filter(
            severity__in=['Critical', 'High']
        ).order_by('-cvss_score')[:10]
        return VulnerabilityListSerializer(top_vulns, many=True).data
