@echo off
chcp 65001
title Network Traffic Analyzer

echo.
echo 🌐 Запуск Network Traffic Analyzer...
echo.
echo ⚠️  ВАЖНО: Приложение запускается с правами администратора
echo     для доступа к сетевому трафику!
echo.
echo 📢 После запуска откроется браузер с приложением
echo 📍 Адрес: http://localhost:8501
echo.
echo 🕐 Запуск через 3 секунды...
timeout /t 3 /nobreak >nul

:: Запуск Streamlit
streamlit run app.py