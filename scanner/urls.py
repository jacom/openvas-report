from django.urls import path
from . import views

urlpatterns = [
    path('import/', views.import_xml, name='api-import'),
    path('reports/', views.ReportListView.as_view(), name='api-report-list'),
    path('reports/<uuid:pk>/', views.ReportDetailView.as_view(), name='api-report-detail'),
    path('reports/<uuid:pk>/vulns/', views.ReportVulnsView.as_view(), name='api-report-vulns'),
    path('stats/<uuid:pk>/', views.report_stats, name='api-report-stats'),
    path('gvm/reports/', views.gvm_report_list, name='api-gvm-reports'),
    path('gvm/sync/', views.sync_from_gvm, name='api-gvm-sync'),
    path('chatgpt/explain/', views.chatgpt_explain_cve, name='api-chatgpt-explain'),
    path('system/version/', views.system_version, name='api-system-version'),
    path('system/update/', views.system_run_update, name='api-system-update'),
]
