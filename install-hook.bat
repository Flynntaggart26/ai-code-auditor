@echo off
REM Tek tikla pre-commit kurulumu (Windows). Cift tikla calistir.
cd /d "%~dp0"
set HOOKDIR=.git\hooks
if not exist ".git" (
  echo [hata] .git bulunamadi. Once: git init
  pause
  exit /b 1
)
if not exist "%HOOKDIR%" mkdir "%HOOKDIR%"
copy /Y pre-commit-hook.py "%HOOKDIR%\pre-commit.py" >nul
> "%HOOKDIR%\pre-commit.bat" echo @echo off
>> "%HOOKDIR%\pre-commit.bat" echo python "%%~dp0pre-commit.py" %%*
>> "%HOOKDIR%\pre-commit.bat" echo exit /b %%ERRORLEVEL%%
echo [ok] pre-commit kuruldu.
echo Kaldirma: del .git\hooks\pre-commit.py .git\hooks\pre-commit.bat
pause
