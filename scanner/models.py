import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField


class ScanReport(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=500)
    scan_date = models.DateTimeField(null=True, blank=True)
    import_date = models.DateTimeField(auto_now_add=True)
    scanner_version = models.CharField(max_length=100, blank=True, default='')
    host_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    gvm_report_id = models.IntegerField(null=True, blank=True, unique=True)

    class Meta:
        ordering = ['-scan_date', '-import_date']

    def __str__(self):
        return f"{self.name} ({self.scan_date})"

    @property
    def total_vulns(self):
        return self.critical_count + self.high_count + self.medium_count + self.low_count + self.info_count


class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('Info', 'Info'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(ScanReport, on_delete=models.CASCADE, related_name='vulnerabilities')
    name = models.CharField(max_length=1000)
    oid = models.CharField(max_length=200, blank=True, default='')
    cvss_score = models.FloatField(default=0.0)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='Info')
    description = models.TextField(blank=True, default='')
    solution = models.TextField(blank=True, default='')
    family = models.CharField(max_length=500, blank=True, default='')
    cve_list = ArrayField(models.CharField(max_length=50), blank=True, default=list)
    references = models.JSONField(blank=True, default=dict)

    class Meta:
        ordering = ['-cvss_score', 'name']
        verbose_name_plural = 'vulnerabilities'

    def __str__(self):
        return f"[{self.severity}] {self.name} (CVSS: {self.cvss_score})"


class OrganizationProfile(models.Model):
    """Singleton model for organization info displayed on PDF reports."""
    name_th = models.CharField('ชื่อหน่วยงาน (ไทย)', max_length=300)
    name_en = models.CharField('ชื่อหน่วยงาน (อังกฤษ)', max_length=300, blank=True, default='')
    logo = models.ImageField('โลโก้', upload_to='org/', blank=True)
    address = models.TextField('ที่อยู่', blank=True, default='')
    phone = models.CharField('เบอร์โทร', max_length=50, blank=True, default='')
    email = models.EmailField('อีเมล', blank=True, default='')
    preparer_name = models.CharField('ชื่อผู้จัดทำรายงาน', max_length=200, blank=True, default='')
    preparer_title = models.CharField('ตำแหน่งผู้จัดทำ', max_length=200, blank=True, default='')
    approver_name = models.CharField('ชื่อผู้บริหาร', max_length=200, blank=True, default='')
    approver_title = models.CharField('ตำแหน่งผู้บริหาร', max_length=200, blank=True, default='')
    document_number_prefix = models.CharField('Prefix เลขที่เอกสาร', max_length=50, blank=True, default='VA-RPT-')

    class Meta:
        verbose_name = 'Organization Profile'
        verbose_name_plural = 'Organization Profile'

    def __str__(self):
        return self.name_th or 'Organization Profile'

    def save(self, *args, **kwargs):
        # Ensure singleton: always use pk=1
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        obj, _ = cls.objects.get_or_create(pk=1, defaults={'name_th': ''})
        return obj


class AIAnalysis(models.Model):
    """Stores ChatGPT AI analysis result for a vulnerability."""
    vulnerability = models.OneToOneField(
        'Vulnerability', on_delete=models.CASCADE, related_name='ai_analysis'
    )
    query = models.TextField()
    answer = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'AI Analysis'
        verbose_name_plural = 'AI Analyses'

    def __str__(self):
        return f"AI Analysis for {self.vulnerability.name[:60]}"


class ChatGPTSettings(models.Model):
    """Singleton model for ChatGPT API configuration."""
    api_key = models.CharField('API Key', max_length=500, blank=True, default='')
    model = models.CharField('Model', max_length=50, default='gpt-4.1')
    max_tokens = models.IntegerField('Max Tokens', default=400)
    temperature = models.FloatField('Temperature', default=0.0)
    prompt_prefix = models.CharField('Prompt Prefix', max_length=500, blank=True, default='อธิบาย')
    prompt_suffix = models.CharField('Prompt Suffix', max_length=500, blank=True, default='และวิธีแก้ไขแบบเป็นขั้นตอน')

    class Meta:
        verbose_name = 'ChatGPT Settings'
        verbose_name_plural = 'ChatGPT Settings'

    def __str__(self):
        return 'ChatGPT Settings'

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        obj, _ = cls.objects.get_or_create(pk=1, defaults={})
        return obj


class AffectedHost(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='affected_hosts')
    ip = models.GenericIPAddressField()
    hostname = models.CharField(max_length=500, blank=True, default='')
    port = models.CharField(max_length=50, blank=True, default='')
    protocol = models.CharField(max_length=20, blank=True, default='tcp')
    result_detail = models.TextField(blank=True, default='')

    class Meta:
        ordering = ['ip', 'port']

    def __str__(self):
        return f"{self.ip}:{self.port} - {self.vulnerability.name}"
