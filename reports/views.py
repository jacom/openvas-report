from django.shortcuts import get_object_or_404
from scanner.models import ScanReport
from .pdf_generator import generate_pdf
from .csv_exporter import generate_csv
from .excel_exporter import generate_excel


def export_pdf(request, pk):
    report = get_object_or_404(ScanReport, pk=pk)
    return generate_pdf(report)


def export_csv(request, pk):
    report = get_object_or_404(ScanReport, pk=pk)
    return generate_csv(report)


def export_excel(request, pk):
    report = get_object_or_404(ScanReport, pk=pk)
    return generate_excel(report)
