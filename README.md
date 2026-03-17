# OpenVAS Report

ระบบจัดการและวิเคราะห์รายงานผลการตรวจสอบช่องโหว่จาก GVM/OpenVAS
พร้อมระบบส่งออก PDF/Excel/CSV และ AI Analysis ด้วย ChatGPT

![Version](https://img.shields.io/badge/version-1.0.4-blue)
![Python](https://img.shields.io/badge/python-3.12-green)
![Django](https://img.shields.io/badge/django-5.1-green)

---

## สารบัญ

- [ฟีเจอร์หลัก](#ฟีเจอร์หลัก)
- [วิธีติดตั้ง](#วิธีติดตั้ง)
  - [แบบ ISO (แนะนำ)](#1-ติดตั้งจาก-iso)
  - [แบบ Docker](#2-ติดตั้งด้วย-docker)
- [การใช้งาน](#การใช้งาน)
  - [นำเข้ารายงาน](#นำเข้ารายงาน)
  - [ดูรายงาน](#ดูรายงาน)
  - [ส่งออก PDF](#ส่งออก-pdf)
  - [AI Analysis](#ai-analysis)
  - [ตั้งค่าองค์กร](#ตั้งค่าองค์กร)
- [การอัปเดต](#การอัปเดต)
- [การตั้งค่าขั้นสูง](#การตั้งค่าขั้นสูง)

---

## ฟีเจอร์หลัก

| ฟีเจอร์ | รายละเอียด |
|---------|-----------|
| 📊 Dashboard | สรุปภาพรวมช่องโหว่ Critical/High/Medium/Low/Info พร้อมกราฟ |
| 📋 รายงานละเอียด | แสดง vulnerability แต่ละรายการพร้อม affected hosts, CVE, CVSS |
| 🖥️ Host Summary | สรุปต่อ IP: OS, port ที่เปิด, ระดับความเสี่ยง, CVE |
| 📄 PDF Export | PDF ภาษาไทย พร้อม cover page, executive summary, host summary |
| 📊 Excel/CSV | ส่งออกข้อมูลสำหรับวิเคราะห์ต่อ |
| 🤖 AI Analysis | วิเคราะห์ช่องโหว่ด้วย ChatGPT พร้อมคำแนะนำแก้ไข |
| 🔄 Online Update | อัปเดตระบบผ่านหน้าเว็บหรือ command line |

---

## วิธีติดตั้ง

### 1. ติดตั้งจาก ISO

> แนะนำสำหรับ production — ติดตั้ง OpenVAS + openvas-report พร้อมใช้งานในครั้งเดียว

**ดาวน์โหลด ISO** จาก [Releases](https://github.com/jacom/openvas-report/releases) แล้ว boot ติดตั้งตามปกติ

หลังติดตั้งเสร็จ เข้าใช้งานที่:
- **OpenVAS (GSA):** `http://<IP>:9392`
- **openvas-report:** `http://<IP>:8600`

> **Login เริ่มต้น:** `admin` / `admin`
> กรุณาเปลี่ยนรหัสผ่านหลัง login ครั้งแรก

---

### 2. ติดตั้งด้วย Docker

> สำหรับเครื่องที่มี Docker หรือต้องการทดสอบ

**ความต้องการของระบบ:**
- Ubuntu 22.04 / Debian 12
- RAM 8 GB ขึ้นไป (OpenVAS ต้องการ)
- Disk 20 GB ขึ้นไป

**ติดตั้งด้วยคำสั่งเดียว:**

```bash
curl -fsSL https://raw.githubusercontent.com/jacom/openvas-report/main/docker/setup.sh | sudo bash
```

หรือดาวน์โหลด script แล้วรัน:

```bash
wget https://raw.githubusercontent.com/jacom/openvas-report/main/docker/setup.sh
sudo bash setup.sh
```

**หลังติดตั้งเสร็จ:**
- **OpenVAS (GSA):** `http://<IP>:9392`
- **openvas-report:** `http://<IP>:8600`

**คำสั่งจัดการ Docker:**

```bash
# Start
docker compose -f /opt/openvas-docker/greenbone-compose.yml \
               -f /opt/openvas-docker/openvas-report/docker/docker-compose.yml up -d

# Stop
docker compose -f /opt/openvas-docker/greenbone-compose.yml \
               -f /opt/openvas-docker/openvas-report/docker/docker-compose.yml down

# ดู logs
docker compose -f /opt/openvas-docker/greenbone-compose.yml \
               -f /opt/openvas-docker/openvas-report/docker/docker-compose.yml logs -f openvas-report
```

---

## การใช้งาน

### นำเข้ารายงาน

มี 2 วิธี:

**วิธีที่ 1 — นำเข้าจาก GVM โดยตรง (แนะนำ)**

1. เปิดหน้า **Dashboard** → กดปุ่ม **Import from GVM**
2. เลือกรายงานที่ต้องการจาก dropdown
3. กด **Import** รอสักครู่

**วิธีที่ 2 — อัปโหลดไฟล์ XML**

1. Export รายงานจาก OpenVAS เป็นไฟล์ `.xml`
2. เปิดหน้า **Dashboard** → กดปุ่ม **Upload XML**
3. เลือกไฟล์ → กด **Upload**

---

### ดูรายงาน

**หน้า Dashboard:**
- แสดงรายการรายงานทั้งหมดพร้อมสรุป severity
- คลิกที่รายงานเพื่อดูรายละเอียด

**หน้า Report Detail:**

| ส่วน | รายละเอียด |
|------|-----------|
| Host Summary | สรุปต่อ IP — OS, Port, Risk Level, CVE |
| Filter | กรองตาม severity หรือค้นหาชื่อ vulnerability |
| Vulnerability List | รายการช่องโหว่ทั้งหมด พร้อม affected hosts |
| 🤖 ปุ่ม AI | วิเคราะห์ช่องโหว่นั้นด้วย ChatGPT |

---

### ส่งออก PDF

1. เปิดหน้า Report Detail
2. กดปุ่ม **Export PDF** (มุมขวาบน)
3. รอสักครู่ ไฟล์จะดาวน์โหลดอัตโนมัติ

**โครงสร้าง PDF:**

```
หน้าปก          — ชื่อรายงาน, Network (เช่น 192.168.1.0/24), วันที่, ผู้จัดทำ
Executive Summary — สรุปผู้บริหาร ภาษาไทย
Risk Summary      — ตารางสรุป + กราฟ severity
Top Findings      — ช่องโหว่ Critical & High
Thai Advisory     — คำแนะนำแก้ไข ภาษาไทย
Detailed Findings — รายละเอียดทุก vulnerability
AI Analysis       — ผลวิเคราะห์จาก ChatGPT (ถ้ามี)
Appendix          — Host Summary (IP, OS, Ports, Risk, CVE)
```

**ตั้งค่า PDF:**
ไปที่ **Settings → Organization** เพื่อใส่:
- โลโก้องค์กร, ชื่อภาษาไทย/อังกฤษ
- ชื่อผู้จัดทำ / ผู้รับรองรายงาน
- Prefix เลขที่เอกสาร

---

### AI Analysis

> ต้องมี OpenAI API Key

**ตั้งค่าครั้งแรก:**
1. ไปที่ **Settings → Organization** → เลื่อนลงไปส่วน **ChatGPT Settings**
2. ใส่ **API Key** จาก [platform.openai.com](https://platform.openai.com)
3. เลือก Model (แนะนำ `gpt-4o-mini` สำหรับความคุ้มค่า)
4. กด **Save**

**วิเคราะห์ช่องโหว่:**
1. ในหน้า Report Detail ให้คลิกปุ่ม 🤖 ที่ vulnerability ที่ต้องการ
2. รอผลวิเคราะห์ (5-15 วินาที)
3. ผลจะแสดงทันทีและบันทึกไว้ในระบบ
4. ครั้งต่อไปที่เปิดหน้านี้ จะแสดงผลเดิมโดยไม่เรียก API ซ้ำ
5. ผลวิเคราะห์จะปรากฏใน PDF section **AI Analysis** ด้วย

> **ปุ่มสีเหลือง** = วิเคราะห์แล้ว (มีผลบันทึก)
> **ปุ่มขาว** = ยังไม่ได้วิเคราะห์

---

### ตั้งค่าองค์กร

ไปที่ **Settings → Organization Profile**

| ฟิลด์ | คำอธิบาย |
|-------|---------|
| Organization Name (TH) | ชื่อองค์กรภาษาไทย — แสดงบนหน้าปก PDF |
| Organization Name (EN) | ชื่อภาษาอังกฤษ |
| Logo | โลโก้องค์กร (PNG/JPG) |
| Document Number Prefix | prefix เลขที่เอกสาร เช่น `IT-VA-` |
| Preparer Name/Title | ชื่อ-ตำแหน่งผู้จัดทำรายงาน |
| Approver Name/Title | ชื่อ-ตำแหน่งผู้รับรองรายงาน |

---

## การอัปเดต

### อัปเดตผ่านหน้าเว็บ

1. ไปที่ **Settings → System**
2. ถ้ามีเวอร์ชันใหม่จะแสดงแจ้งเตือน
3. กดปุ่ม **Update**

### อัปเดตด้วย Command Line

```bash
# ISO installation
/opt/openvas-report/scripts/update.sh

# ถ้า GITHUB_REPO ยังไม่ได้ตั้งค่าใน .env
GITHUB_REPO=jacom/openvas-report /opt/openvas-report/scripts/update.sh
```

---

## การตั้งค่าขั้นสูง

### ไฟล์ .env

```bash
# Application
DJANGO_SECRET_KEY=<random-secret>
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=192.168.1.100,localhost
DJANGO_CSRF_TRUSTED_ORIGINS=http://192.168.1.100:8600

# openvas-report Database
DB_NAME=openvas_report
DB_USER=openvas_report
DB_PASSWORD=<password>
DB_HOST=localhost

# GVM Database (สำหรับ import โดยตรง + OS detection)
GVM_DB_NAME=gvmd
GVM_DB_USER=gvmd
GVM_DB_PASSWORD=<gvm-db-password>
GVM_DB_HOST=localhost

# GitHub (สำหรับ online update)
GITHUB_REPO=jacom/openvas-report
```

---

## License

MIT License — © 2024 jacom
