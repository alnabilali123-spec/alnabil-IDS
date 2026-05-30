# ============================================================
# 📦 AEGIS-ADS v11.0 - قائمة المكتبات والأدوات المطلوبة
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  📦 AEGIS-ADS v11.0 - المتطلبات والتثبيت" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# إنشاء ملف requirements.txt للتثبيت السهل
@'
# ============================================================
# AEGIS-ADS v11.0 - Requirements File
# ============================================================
# استخدام الأمر: pip install -r requirements.txt

# Core Web Framework
fastapi==0.115.0
uvicorn[standard]==0.30.0
python-multipart==0.0.9

# AI & Machine Learning
scikit-learn==1.6.0
xgboost==2.1.4
numpy==1.26.0
scipy==1.13.0
joblib==1.4.0

# Deep Learning (Optional - for safetensors models)
safetensors==0.4.0

# Network Capture & Analysis
pyshark==0.6
scapy==2.5.0
tshark  # Requires Wireshark installation separately

# Windows Firewall & Kernel Filtering
pydivert==2.1.0  # WinDivert Python bindings

# PDF Generation
reportlab==4.2.0

# Email & SMTP
secure-smtplib==0.1.1

# System Monitoring
psutil==6.0.0

# Authentication & Security
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
bcrypt==4.1.0

# Data Processing
pandas==2.2.0

# Additional Utilities
requests==2.32.0
websockets==12.0
aiofiles==23.2.1
'@ | Out-File -FilePath "requirements.txt" -Encoding UTF8 -Force

Write-Host "[1/3] ✅ تم إنشاء ملف requirements.txt" -ForegroundColor Green

# 2️⃣ إنشاء ملف متطلبات النظام (System Requirements)
Write-Host "[2/3] إنشاء متطلبات النظام..." -ForegroundColor Yellow

@'
# ============================================================
# AEGIS-ADS v11.0 - System Requirements
# ============================================================

## 1. نظام التشغيل
- Windows 10/11 (64-bit) - يوصى به
- Windows Server 2019/2022
- (يدعم Linux جزئياً مع تعديلات على جدار الحماية)

## 2. متطلبات Python
- Python 3.11 أو 3.12 أو 3.13
- pip (أحدث إصدار)

## 3. الأدوات الخارجية المطلوبة
- Wireshark / TShark (لتحليل الحزم)
  تحميل: https://www.wireshark.org/download.html
  يجب تفعيل خيار "Install Tshark" أثناء التثبيت

- WinDivert (للحظر على مستوى Kernel)
  يتم تثبيته تلقائياً عبر pydivert
  أو تحميل من: https://reqrypt.org/windivert.html

- Npcap (لتشغيل WinDivert)
  تحميل: https://npcap.com
  يجب التثبيت مع خيار "WinPcap API-compatible Mode"

## 4. متطلبات الذاكرة والمعالج
- RAM: 4GB كحد أدنى، 8GB يوصى بها (لـ Deep Learning)
- المعالج: ثنائي النواة أو أفضل
- مساحة التخزين: 2GB كحد أدنى

## 5. المنافذ المطلوبة
- 9999 (FastAPI server)
- 80/443 (اختياري للالتقاط)

## 6. صلاحيات المسؤول
- مطلوب للتشغيل الكامل (WinDivert + Windows Firewall)
- مطلوب لالتقاط حزم الشبكة (Tshark)

# ============================================================
# خطوات التثبيت السريع
# ============================================================

# 1. تثبيت Python من الموقع الرسمي
# 2. تثبيت Wireshark مع Tshark
# 3. تثبيت Npcap
# 4. تثبيت المكتبات:
pip install -r requirements.txt

# 5. تشغيل النظام (كمسؤول):
uvicorn main:app --host 0.0.0.0 --port 9999

# 6. فتح المتصفح على:
http://localhost:9999
# بيانات الدخول: admin / 2005
'@ | Out-File -FilePath "SYSTEM_REQUIREMENTS.md" -Encoding UTF8 -Force

Write-Host "      ✅ تم إنشاء ملف SYSTEM_REQUIREMENTS.md" -ForegroundColor Green

# 3️⃣ إنشاء ملف تثبيت تلقائي (install.bat)
Write-Host "[3/3] إنشاء ملف تثبيت تلقائي..." -ForegroundColor Yellow

@'
@echo off
title AEGIS-ADS v11.0 - Installation Wizard
color 0A

echo ============================================================
echo    🛡️ AEGIS-ADS v11.0 - Installation Wizard
echo ============================================================
echo.

echo [1/4] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed!
    echo Please install Python 3.11+ from https://python.org
    pause
    exit /b 1
)
echo ✅ Python found!

echo.
echo [2/4] Installing required packages...
pip install --upgrade pip
pip install fastapi uvicorn[standard] python-multipart
pip install scikit-learn==1.6.0 xgboost numpy scipy joblib
pip install pyshark scapy
pip install pydivert
pip install reportlab
pip install psutil
pip install python-jose[cryptography] passlib[bcrypt] bcrypt
pip install pandas requests websockets aiofiles

echo.
echo [3/4] Checking external tools...
where tshark >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️ Tshark not found!
    echo Please install Wireshark from https://wireshark.org
    echo Make sure to select "Install Tshark" during installation
)

echo.
echo [4/4] Creating threshold file...
python -c "import joblib; joblib.dump(0.75, 'models/threshold.pkl')" 2>nul
if exist "models\threshold.pkl" (
    echo ✅ Threshold file created
) else (
    echo ⚠️ Could not create threshold file
)

echo.
echo ============================================================
echo   ✅ Installation Complete!
echo ============================================================
echo.
echo 🚀 To run AEGIS-ADS:
echo    run_aegis_admin.ps1
echo.
echo 🌐 http://localhost:9999 | admin/2005
echo.
pause
'@ | Out-File -FilePath "install.bat" -Encoding ASCII -Force

Write-Host "      ✅ تم إنشاء install.bat" -ForegroundColor Green

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  📦 قائمة المكتبات والأدوات" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

# عرض القائمة بشكل منظم
Write-Host "📋 المكتبات الأساسية:" -ForegroundColor Yellow
Write-Host ""
Write-Host "┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│  المكتبة              │  الإصدار    │  الغرض                         │" -ForegroundColor Cyan
Write-Host "├─────────────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "│  fastapi              │  0.115.0    │  إطار عمل API                  │" -ForegroundColor White
Write-Host "│  uvicorn              │  0.30.0     │  تشغيل السيرفر                 │" -ForegroundColor White
Write-Host "│  scikit-learn         │  1.6.0      │  Random Forest, Scalers        │" -ForegroundColor White
Write-Host "│  xgboost              │  2.1.4      │  XGBoost Classifier            │" -ForegroundColor White
Write-Host "│  numpy                │  1.26.0     │  المعالجات الرقمية             │" -ForegroundColor White
Write-Host "│  scipy                │  1.13.0     │  العمليات العلمية              │" -ForegroundColor White
Write-Host "│  joblib               │  1.4.0      │  حفظ/تحميل الموديلات           │" -ForegroundColor White
Write-Host "│  pyshark              │  0.6        │  تحليل حزم الشبكة              │" -ForegroundColor White
Write-Host "│  scapy                │  2.5.0      │  معالجة الحزم                  │" -ForegroundColor White
Write-Host "│  pydivert             │  2.1.0      │  WinDivert (حظر Kernel)        │" -ForegroundColor White
Write-Host "│  reportlab            │  4.2.0      │  إنشاء تقارير PDF              │" -ForegroundColor White
Write-Host "│  psutil               │  6.0.0      │  مراقبة النظام                 │" -ForegroundColor White
Write-Host "│  python-jose          │  3.3.0      │  التوثيق (JWT)                 │" -ForegroundColor White
Write-Host "│  bcrypt               │  4.1.0      │  تشفير كلمات المرور            │" -ForegroundColor White
Write-Host "│  pandas               │  2.2.0      │  معالجة البيانات               │" -ForegroundColor White
Write-Host "│  requests             │  2.32.0     │  طلبات HTTP                    │" -ForegroundColor White
Write-Host "│  websockets           │  12.0       │  WebSocket                     │" -ForegroundColor White
Write-Host "└─────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

Write-Host ""
Write-Host "🛠️ الأدوات الخارجية:" -ForegroundColor Yellow
Write-Host ""
Write-Host "┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│  الأداة        │  الغرض                              │  رابط التحميل │" -ForegroundColor Cyan
Write-Host "├─────────────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "│  Wireshark     │  تحليل حزم الشبكة                   │ wireshark.org │" -ForegroundColor White
Write-Host "│  Tshark        │  سطر أوامر لتحليل الحزم             │ (مع Wireshark)│" -ForegroundColor White
Write-Host "│  WinDivert     │  حزم Kernel IPS                     │ reqrypt.org   │" -ForegroundColor White
Write-Host "│  Npcap         │  تشغيل WinDivert (Windows)          │ npcap.com     │" -ForegroundColor White
Write-Host "└─────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

Write-Host ""
Write-Host "📁 الملفات التي تم إنشاؤها:" -ForegroundColor Yellow
Write-Host "   ✅ requirements.txt - لتثبيت جميع المكتبات دفعة واحدة" -ForegroundColor Green
Write-Host "   ✅ SYSTEM_REQUIREMENTS.md - متطلبات النظام بالتفصيل" -ForegroundColor Green
Write-Host "   ✅ install.bat - سكربت تثبيت تلقائي (شغل كمسؤول)" -ForegroundColor Green
Write-Host ""

Write-Host "🚀 للتثبيت على جهاز الدكتور:" -ForegroundColor Cyan
Write-Host "   1. نسخ مجلد المشروع كاملاً" -ForegroundColor White
Write-Host "   2. تشغيل install.bat كمسؤول" -ForegroundColor White
Write-Host "   3. تشغيل run_aegis_admin.ps1 كمسؤول" -ForegroundColor White
Write-Host "   4. فتح http://localhost:9999" -ForegroundColor White
Write-Host ""

Write-Host "📧 بيانات الدخول:" -ForegroundColor Yellow
Write-Host "   👤 Username: admin" -ForegroundColor Cyan
Write-Host "   🔑 Password: 2005" -ForegroundColor Cyan
Write-Host ""