from django.urls import path
from . import views

urlpatterns = [
    path('<uuid:pk>/pdf/', views.export_pdf, name='report-pdf'),
    path('<uuid:pk>/csv/', views.export_csv, name='report-csv'),
    path('<uuid:pk>/excel/', views.export_excel, name='report-excel'),
]
