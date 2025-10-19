@echo off
chcp 65001
title Network Traffic Analyzer - Admin Mode

echo.
echo 🌐 Network Traffic Analyzer - Запуск с правами администратора
echo.

:: ВАЖНО: Переходим в папку где лежит bat файл
cd /d "%~dp0"

echo 📍 Рабочая папка: %CD%
echo.

:: Проверяем что app.py существует в этой папке
if not exist "app.py" (
    echo ❌ ОШИБКА: app.py не найден в текущей папке!
    echo Папка: %CD%
    echo.
    echo Убедитесь что:
    echo 1. Все файлы находятся в одной папке
    echo 2. app.py находится в той же папке что и start_app.bat
    echo.
    dir *.py
    echo.
    pause
    exit /b 1
)

echo ✅ app.py найден
echo 📦 Запускаем Streamlit сервер...
echo 🌐 Приложение откроется по адресу: http://localhost:8501
echo.
echo ⚠️  НЕ ЗАКРЫВАЙТЕ это окно пока работаете с приложением!
echo.

timeout /t 3 /nobreak >nul

:: Запускаем Streamlit
streamlit run app.py --server.port=8501 --server.address=localhost

echo.
echo Приложение остановлено. Нажмите любую клавишу...
pause