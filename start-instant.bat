@echo off
echo =========================================================
echo   Starting ASOP (Autonomous Security Operations Platform)
echo   Live Dashboard: http://localhost:8000
echo   Swagger API:    http://localhost:8000/docs
echo =========================================================
cd /d "%~dp0backend"
python -m pip install -q fastapi uvicorn sqlalchemy pydantic httpx python-dotenv
start "" http://localhost:8000
python -m uvicorn main:app --host 127.0.0.1 --port 8000
