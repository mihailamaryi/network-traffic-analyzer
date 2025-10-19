@echo off
chcp 65001
title Network Traffic Analyzer - Installer

echo.
echo ════════════════════════════════════════════
echo    🌐 NETWORK TRAFFIC ANALYZER
echo ════════════════════════════════════════════
echo.
echo Этот установщик настроит приложение для
echo мониторинга сетевого трафика в реальном времени
echo.

:: Проверка Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python не установлен!
    echo.
    echo Установите Python с https://python.org
    echo Затем запустите этот установщик снова.
    echo.
    pause
    exit /b 1
)

echo.
echo ✅ Python обнаружен
echo 📦 Устанавливаем зависимости...

:: Установка пакетов
pip install --upgrade pip
pip install streamlit pandas plotly scapy

echo.
echo ✅ Зависимости установлены!
echo.

:: Создаем файл с инструкцией
echo Инструкция по запуску: > инструкция.txt
echo. >> инструкция.txt
echo 1. Установите Npcap с https://npcap.com/#download >> инструкция.txt
echo 2. Запустите start_app.bat как АДМИНИСТРАТОР >> инструкция.txt
echo 3. Приложение откроется в браузере >> инструкция.txt

echo.
echo ════════════════════════════════════════════
echo           🎉 УСТАНОВКА ЗАВЕРШЕНА!
echo ════════════════════════════════════════════
echo.
echo ЧТО ДЕЛАТЬ ДАЛЕЕ:
echo.
echo 1. 🛡️  Установите Npcap (для захвата пакетов)
echo    Скачайте: https://npcap.com/#download
echo.
echo 2. ⚡ Запустите приложение как АДМИНИСТРАТОР:
echo    - Правой кнопкой на start_app.bat
echo    - "Запуск от имени администратора"
echo.
echo 3. 🌐 Откроется браузер с приложением
echo.
echo 📖 Полная инструкция в файле инструкция.txt
echo.
pause