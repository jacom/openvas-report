"""
Thai advisory mapping for common vulnerability types.
Maps vulnerability name patterns to Thai descriptions and remediation advice.
"""

ADVISORIES = [
    {
        'pattern': 'log4j',
        'title': 'ช่องโหว่ Log4Shell (การรันโค้ดจากระยะไกล)',
        'description': (
            'พบช่องโหว่ร้ายแรงใน Apache Log4j ซึ่งเป็นไลบรารีที่ใช้บันทึก log '
            'ผู้โจมตีสามารถส่งคำสั่งพิเศษผ่าน JNDI lookup เพื่อรันโค้ดอันตราย '
            'บนเซิร์ฟเวอร์ได้โดยไม่ต้องยืนยันตัวตน ส่งผลให้ผู้โจมตีสามารถ '
            'เข้าควบคุมระบบได้อย่างสมบูรณ์'
        ),
        'remediation': (
            '1. อัปเดต Apache Log4j เป็นเวอร์ชัน 2.17.0 ขึ้นไปโดยเร่งด่วน\n'
            '2. หากยังอัปเดตไม่ได้ ให้ตั้งค่า log4j2.formatMsgNoLookups=true\n'
            '3. บล็อก outbound LDAP/RMI traffic ที่ firewall\n'
            '4. ตรวจสอบ log เพื่อหาร่องรอยการโจมตีที่อาจเกิดขึ้นแล้ว\n'
            '5. สแกนระบบเพื่อหาไลบรารี Log4j ทุกเวอร์ชันที่ใช้อยู่'
        ),
        'impact': 'วิกฤต — ผู้โจมตีสามารถเข้าควบคุมเซิร์ฟเวอร์ได้อย่างสมบูรณ์',
        'urgency': 'ดำเนินการแก้ไขทันที (ภายใน 24 ชั่วโมง)',
    },
    {
        'pattern': 'sql injection',
        'title': 'ช่องโหว่ SQL Injection (การแทรกคำสั่ง SQL)',
        'description': (
            'พบช่องโหว่ SQL Injection ซึ่งผู้โจมตีสามารถแทรกคำสั่ง SQL '
            'เข้าไปในช่องกรอกข้อมูล ทำให้สามารถเข้าถึงข้อมูลในฐานข้อมูล '
            'ได้โดยไม่ได้รับอนุญาต รวมถึงอาจแก้ไข ลบข้อมูล หรือ '
            'เข้าสู่ระบบโดยไม่ต้องใช้รหัสผ่าน'
        ),
        'remediation': (
            '1. ใช้ Parameterized Query (Prepared Statement) แทนการต่อ string SQL\n'
            '2. ใช้ ORM framework ในการเข้าถึงฐานข้อมูล\n'
            '3. ตรวจสอบและกรอง input ทุกช่องที่รับข้อมูลจากผู้ใช้\n'
            '4. จำกัดสิทธิ์ของ database user ให้น้อยที่สุดเท่าที่จำเป็น\n'
            '5. เปิดใช้ Web Application Firewall (WAF) เพื่อช่วยป้องกัน'
        ),
        'impact': 'วิกฤต — อาจถูกขโมยข้อมูลสำคัญหรือเข้าควบคุมฐานข้อมูลทั้งหมด',
        'urgency': 'ดำเนินการแก้ไขทันที (ภายใน 24 ชั่วโมง)',
    },
    {
        'pattern': 'openssl',
        'title': 'ช่องโหว่ OpenSSL (การเข้ารหัสไม่ปลอดภัย)',
        'description': (
            'พบช่องโหว่ใน OpenSSL ซึ่งเป็นไลบรารีเข้ารหัสข้อมูล '
            'ผู้โจมตีที่อยู่ในเครือข่ายเดียวกันสามารถดักจับและถอดรหัส '
            'ข้อมูลที่ส่งผ่านการเชื่อมต่อ SSL/TLS ได้ (Man-in-the-Middle) '
            'รวมถึงรหัสผ่าน ข้อมูลส่วนบุคคล และข้อมูลสำคัญอื่นๆ'
        ),
        'remediation': (
            '1. อัปเดต OpenSSL เป็นเวอร์ชันล่าสุดที่ได้รับการแก้ไขแล้ว\n'
            '2. รีสตาร์ทบริการที่ใช้ OpenSSL หลังอัปเดต\n'
            '3. พิจารณาออก SSL Certificate ใหม่หากใช้เวอร์ชันที่มีช่องโหว่มานาน\n'
            '4. ตรวจสอบว่า TLS 1.2 ขึ้นไปเท่านั้นที่เปิดใช้งาน\n'
            '5. ปิดการใช้งาน cipher suite ที่ไม่ปลอดภัย'
        ),
        'impact': 'สูง — ข้อมูลที่เข้ารหัสอาจถูกดักจับและถอดรหัสได้',
        'urgency': 'ดำเนินการแก้ไขภายใน 7 วัน',
    },
    {
        'pattern': 'openssh',
        'title': 'ช่องโหว่ OpenSSH (การเข้าถึงระยะไกลไม่ปลอดภัย)',
        'description': (
            'พบว่าเวอร์ชันของ OpenSSH ที่ติดตั้งอยู่มีช่องโหว่ด้านความปลอดภัย '
            'ผู้โจมตีอาจใช้ช่องโหว่นี้ในการรันโค้ดอันตราย หรือยกระดับสิทธิ์ '
            'บนเครื่องเซิร์ฟเวอร์ที่เปิดบริการ SSH'
        ),
        'remediation': (
            '1. อัปเดต OpenSSH เป็นเวอร์ชันล่าสุด\n'
            '2. จำกัดการเข้าถึง SSH เฉพาะ IP ที่อนุญาตผ่าน firewall\n'
            '3. ปิดการ login ด้วย root โดยตรง (PermitRootLogin no)\n'
            '4. ใช้ SSH key authentication แทนรหัสผ่าน\n'
            '5. เปิดใช้ fail2ban เพื่อป้องกันการ brute force'
        ),
        'impact': 'สูง — ผู้โจมตีอาจเข้าถึงเครื่องเซิร์ฟเวอร์ผ่าน SSH ได้',
        'urgency': 'ดำเนินการแก้ไขภายใน 7 วัน',
    },
    {
        'pattern': 'wordpress',
        'title': 'ช่องโหว่ WordPress (ระบบจัดการเว็บไซต์)',
        'description': (
            'พบช่องโหว่ Cross-Site Scripting (XSS) ใน WordPress '
            'ผู้โจมตีสามารถแทรกโค้ด JavaScript อันตรายเข้าไปในเว็บไซต์ '
            'เมื่อผู้ใช้หรือผู้ดูแลระบบเข้าชมหน้าที่ถูกแทรกโค้ด '
            'อาจถูกขโมย session, cookie หรือข้อมูลส่วนบุคคล'
        ),
        'remediation': (
            '1. อัปเดต WordPress core เป็นเวอร์ชันล่าสุด\n'
            '2. อัปเดต plugin และ theme ทั้งหมดให้เป็นปัจจุบัน\n'
            '3. ลบ plugin และ theme ที่ไม่ได้ใช้งาน\n'
            '4. ติดตั้ง security plugin เช่น Wordfence หรือ Sucuri\n'
            '5. เปิดใช้ Content-Security-Policy header'
        ),
        'impact': 'สูง — ผู้โจมตีอาจขโมยข้อมูลผู้ดูแลระบบหรือเปลี่ยนแปลงเนื้อหาเว็บ',
        'urgency': 'ดำเนินการแก้ไขภายใน 7 วัน',
    },
    {
        'pattern': 'xss',
        'title': 'ช่องโหว่ Cross-Site Scripting (XSS)',
        'description': (
            'พบช่องโหว่ XSS ซึ่งผู้โจมตีสามารถแทรกโค้ด JavaScript อันตราย '
            'เข้าไปในหน้าเว็บ เมื่อผู้ใช้คนอื่นเปิดหน้าเว็บดังกล่าว โค้ดอันตราย '
            'จะทำงานในเบราว์เซอร์ของผู้ใช้ ทำให้ถูกขโมย cookie, session '
            'หรือข้อมูลส่วนบุคคลได้'
        ),
        'remediation': (
            '1. กรองและ encode output ทุกจุดที่แสดงข้อมูลจากผู้ใช้\n'
            '2. ใช้ Content-Security-Policy (CSP) header\n'
            '3. เปิดใช้ HttpOnly flag สำหรับ cookie สำคัญ\n'
            '4. ใช้ framework ที่มี auto-escaping เช่น React, Angular\n'
            '5. ทดสอบด้วย automated XSS scanner เป็นประจำ'
        ),
        'impact': 'สูง — ผู้โจมตีอาจขโมย session ของผู้ดูแลระบบ',
        'urgency': 'ดำเนินการแก้ไขภายใน 7 วัน',
    },
    {
        'pattern': 'remote code execution',
        'title': 'ช่องโหว่ Remote Code Execution (RCE)',
        'description': (
            'พบช่องโหว่ที่ทำให้ผู้โจมตีสามารถรันคำสั่งหรือโค้ดอันตราย '
            'บนเซิร์ฟเวอร์ได้จากระยะไกล โดยไม่จำเป็นต้องมีสิทธิ์เข้าถึงระบบ '
            'ถือเป็นช่องโหว่ระดับวิกฤตที่ต้องแก้ไขโดยเร่งด่วน'
        ),
        'remediation': (
            '1. อัปเดตซอฟต์แวร์ที่มีช่องโหว่เป็นเวอร์ชันล่าสุดทันที\n'
            '2. จำกัดการเข้าถึงบริการที่มีช่องโหว่จากภายนอก\n'
            '3. ตรวจสอบ log เพื่อหาร่องรอยการโจมตี\n'
            '4. พิจารณาใช้ IDS/IPS เพื่อตรวจจับการโจมตี\n'
            '5. ทำ vulnerability scan ซ้ำหลังแก้ไขเพื่อยืนยันผล'
        ),
        'impact': 'วิกฤต — ผู้โจมตีสามารถเข้าควบคุมเซิร์ฟเวอร์ได้อย่างสมบูรณ์',
        'urgency': 'ดำเนินการแก้ไขทันที (ภายใน 24 ชั่วโมง)',
    },
    {
        'pattern': 'weak cipher',
        'title': 'การใช้ Cipher Suite ที่ไม่ปลอดภัย',
        'description': (
            'เซิร์ฟเวอร์รองรับ cipher suite ที่ล้าสมัยและไม่ปลอดภัย '
            'เช่น RC4, DES หรือ 3DES ซึ่งสามารถถูกถอดรหัสได้ '
            'ด้วยเทคนิคการโจมตีสมัยใหม่'
        ),
        'remediation': (
            '1. ปิดการใช้งาน cipher suite ที่ไม่ปลอดภัย (RC4, DES, 3DES, NULL)\n'
            '2. เปิดใช้เฉพาะ TLS 1.2 และ TLS 1.3\n'
            '3. ใช้ cipher suite ที่รองรับ Forward Secrecy (ECDHE)\n'
            '4. ทดสอบการตั้งค่าด้วย SSL Labs (ssllabs.com)\n'
            '5. ตั้ง cipher order ให้เซิร์ฟเวอร์เลือก cipher ที่แข็งแรงที่สุด'
        ),
        'impact': 'ปานกลาง — ข้อมูลที่เข้ารหัสอาจถูกถอดรหัสได้ในบางกรณี',
        'urgency': 'ดำเนินการแก้ไขภายใน 30 วัน',
    },
    {
        'pattern': 'snmp.*community',
        'title': 'การใช้ SNMP Community String ค่าเริ่มต้น',
        'description': (
            'อุปกรณ์เครือข่ายใช้ SNMP community string เป็นค่าเริ่มต้น (public) '
            'ผู้โจมตีสามารถอ่านข้อมูลการตั้งค่าอุปกรณ์ ข้อมูลเครือข่าย '
            'และข้อมูลระบบได้โดยไม่ต้องยืนยันตัวตน'
        ),
        'remediation': (
            '1. เปลี่ยน community string เป็นค่าที่คาดเดาได้ยาก\n'
            '2. จำกัดการเข้าถึง SNMP เฉพาะ IP ของระบบจัดการเครือข่าย\n'
            '3. พิจารณาใช้ SNMPv3 ที่มีการยืนยันตัวตนและเข้ารหัส\n'
            '4. ปิด SNMP หากไม่จำเป็นต้องใช้งาน\n'
            '5. ใช้ ACL บน firewall เพื่อบล็อก SNMP จากภายนอก'
        ),
        'impact': 'ปานกลาง — ผู้โจมตีอาจเข้าถึงข้อมูลการตั้งค่าอุปกรณ์เครือข่าย',
        'urgency': 'ดำเนินการแก้ไขภายใน 14 วัน',
    },
    {
        'pattern': 'security header',
        'title': 'ขาด HTTP Security Headers ที่สำคัญ',
        'description': (
            'เว็บเซิร์ฟเวอร์ไม่ได้ตั้งค่า HTTP security headers ที่สำคัญ '
            'เช่น X-Frame-Options, Content-Security-Policy และ '
            'Strict-Transport-Security ทำให้ผู้ใช้มีความเสี่ยงต่อการโจมตี '
            'แบบ clickjacking และ MIME-type confusion'
        ),
        'remediation': (
            '1. เพิ่ม X-Frame-Options: DENY หรือ SAMEORIGIN\n'
            '2. เพิ่ม X-Content-Type-Options: nosniff\n'
            '3. เพิ่ม Content-Security-Policy ที่เหมาะสม\n'
            '4. เพิ่ม Strict-Transport-Security สำหรับ HTTPS\n'
            '5. เพิ่ม Referrer-Policy: strict-origin-when-cross-origin'
        ),
        'impact': 'ปานกลาง — ผู้ใช้อาจถูกโจมตีแบบ clickjacking',
        'urgency': 'ดำเนินการแก้ไขภายใน 30 วัน',
    },
]

# Generic fallback for unmatched vulnerabilities
_GENERIC_CRITICAL = {
    'title': 'ช่องโหว่ระดับวิกฤต',
    'description': (
        'พบช่องโหว่ระดับวิกฤตที่ผู้โจมตีอาจใช้ในการเข้าควบคุมระบบ '
        'ขโมยข้อมูล หรือทำให้ระบบหยุดทำงานได้'
    ),
    'remediation': (
        '1. อัปเดตซอฟต์แวร์ที่มีช่องโหว่เป็นเวอร์ชันล่าสุด\n'
        '2. ตรวจสอบและจำกัดการเข้าถึงบริการจากภายนอก\n'
        '3. ตรวจสอบ log เพื่อหาร่องรอยการโจมตี\n'
        '4. ทำ vulnerability scan ซ้ำหลังแก้ไข'
    ),
    'impact': 'วิกฤต — ระบบมีความเสี่ยงสูงต่อการถูกโจมตี',
    'urgency': 'ดำเนินการแก้ไขทันที (ภายใน 24 ชั่วโมง)',
}

_GENERIC_HIGH = {
    'title': 'ช่องโหว่ระดับสูง',
    'description': (
        'พบช่องโหว่ระดับสูงที่ผู้โจมตีอาจใช้ในการเข้าถึงข้อมูล '
        'หรือระบบโดยไม่ได้รับอนุญาต'
    ),
    'remediation': (
        '1. อัปเดตซอฟต์แวร์ที่มีช่องโหว่เป็นเวอร์ชันล่าสุด\n'
        '2. จำกัดการเข้าถึงบริการที่ได้รับผลกระทบ\n'
        '3. เปิดใช้งานระบบตรวจจับการบุกรุก (IDS/IPS)\n'
        '4. ทำ vulnerability scan ซ้ำหลังแก้ไข'
    ),
    'impact': 'สูง — ระบบมีความเสี่ยงต่อการถูกโจมตี',
    'urgency': 'ดำเนินการแก้ไขภายใน 7 วัน',
}


def get_thai_advisory(vuln_name, severity):
    """
    Get Thai advisory for a vulnerability based on name pattern matching.

    Returns dict with: title, description, remediation, impact, urgency
    """
    import re
    name_lower = vuln_name.lower()

    for adv in ADVISORIES:
        if re.search(adv['pattern'], name_lower):
            return {
                'title': adv['title'],
                'description': adv['description'],
                'remediation': adv['remediation'],
                'impact': adv['impact'],
                'urgency': adv['urgency'],
            }

    # Fallback by severity
    if severity == 'Critical':
        return _GENERIC_CRITICAL.copy()
    return _GENERIC_HIGH.copy()
