# run_as_admin.ps1
Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -Command `"cd 'C:\Users\ComputerWorld\PycharmProjects\AEGIS-ADS-v11-FastAPI'; uvicorn main:app --host 0.0.0.0 --port 9999 --workers 1`""
