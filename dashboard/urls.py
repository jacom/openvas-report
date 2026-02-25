from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='dashboard-login'),
    path('logout/', views.logout_view, name='dashboard-logout'),
    path('', views.index, name='dashboard-index'),
    path('report/<uuid:pk>/', views.report_detail, name='dashboard-report'),
    path('report/<uuid:pk>/host/<str:ip>/', views.host_detail, name='dashboard-host'),
    path('report/<uuid:pk>/delete/', views.delete_report, name='dashboard-delete'),
    path('organization/', views.organization_profile, name='dashboard-organization'),
    path('sync/', views.sync_gvm, name='dashboard-sync-gvm'),
    path('system/', views.system_update, name='dashboard-system'),
]
