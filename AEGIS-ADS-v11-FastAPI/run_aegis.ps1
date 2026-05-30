# run_aegis.ps1 - سكربت التشغيل الآمن والمستقر
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  🛡️ AEGIS-ADS v11.0 - التشغيل الآمن" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

cd C:\Users\ComputerWorld\PycharmProjects\AEGIS-ADS-v11-FastAPI

# إيقاف العمليات القديمة
Write-Host "⏹️  إيقاف العمليات القديمة..." -ForegroundColor Yellow
Get-Process -Name python -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name tshark -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "📊 Telemetry System: ACTIVE" -ForegroundColor Green
Write-Host "🎯 Tiered Inference: RF(65%) → XGB(85%) → DL" -ForegroundColor Green
Write-Host "🔄 Queue Worker: READY" -ForegroundColor Green
Write-Host ""
Write-Host "🖥️  افتح المتصفح: http://localhost:9999" -ForegroundColor Cyan
Write-Host "🔐 الدخول: admin / 2005" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  اضغط Ctrl+C للإيقاف" -ForegroundColor Yellow
Write-Host ""

# تشغيل بدون --reload للاستقرار
uvicorn main:app --host 0.0.0.0 --port 9999 --workers 1
