from django.core.management.base import BaseCommand, CommandError
from scanner.xml_parser import parse_gvm_xml
from scanner.views import _create_report_from_xml


class Command(BaseCommand):
    help = 'Import a GVM/OpenVAS XML report file into the database'

    def add_arguments(self, parser):
        parser.add_argument('xml_file', type=str, help='Path to the GVM XML report file')

    def handle(self, *args, **options):
        xml_path = options['xml_file']

        try:
            with open(xml_path, 'rb') as f:
                xml_content = f.read()
        except FileNotFoundError:
            raise CommandError(f'File not found: {xml_path}')
        except IOError as e:
            raise CommandError(f'Error reading file: {e}')

        self.stdout.write(f'Parsing {xml_path}...')

        try:
            report = _create_report_from_xml(xml_content)
        except Exception as e:
            raise CommandError(f'Failed to import: {e}')

        self.stdout.write(self.style.SUCCESS(
            f'Successfully imported report: {report.name}\n'
            f'  ID: {report.id}\n'
            f'  Scan date: {report.scan_date}\n'
            f'  Hosts: {report.host_count}\n'
            f'  Critical: {report.critical_count}, High: {report.high_count}, '
            f'Medium: {report.medium_count}, Low: {report.low_count}, Info: {report.info_count}'
        ))
