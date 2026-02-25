from django import template
from django.utils import timezone as tz

register = template.Library()

THAI_MONTHS = [
    'มกราคม', 'กุมภาพันธ์', 'มีนาคม', 'เมษายน',
    'พฤษภาคม', 'มิถุนายน', 'กรกฎาคม', 'สิงหาคม',
    'กันยายน', 'ตุลาคม', 'พฤศจิกายน', 'ธันวาคม',
]

THAI_MONTHS_SHORT = [
    'ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.',
    'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.',
    'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.',
]


def _format_thai(dt, fmt):
    """Format a datetime to Thai Buddhist Era string.

    Supported tokens:
        d  - day of month (zero-padded)
        j  - day of month (no padding)
        F  - full Thai month name
        M  - short Thai month name
        Y  - Buddhist Era year (พ.ศ.)
        H  - hour (24h, zero-padded)
        i  - minute (zero-padded)
    """
    if dt is None:
        return ''
    dt = tz.localtime(dt)
    be_year = dt.year + 543
    result = fmt
    result = result.replace('d', f'{dt.day:02d}')
    result = result.replace('j', str(dt.day))
    result = result.replace('F', THAI_MONTHS[dt.month - 1])
    result = result.replace('M', THAI_MONTHS_SHORT[dt.month - 1])
    result = result.replace('Y', str(be_year))
    result = result.replace('H', f'{dt.hour:02d}')
    result = result.replace('i', f'{dt.minute:02d}')
    return result


@register.filter(name='thaidate')
def thaidate(value, fmt='j F Y'):
    """Template filter: {{ date_value|thaidate:"j M Y H:i" }}"""
    return _format_thai(value, fmt)


@register.simple_tag(name='thainow')
def thainow(fmt='j F Y'):
    """Template tag: {% thainow "j F Y" %}"""
    return _format_thai(tz.now(), fmt)
