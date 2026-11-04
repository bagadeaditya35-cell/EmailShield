@echo off
setlocal
REM ============================================================================
REM  EmailShield Windows build. Run in Command Prompt from this folder:  build_windows.bat
REM  Produces: dist\EmailShield\EmailShield.exe (folder build), dist_portable\EmailShield-Portable.zip,
REM            and dist_installer\EmailShield-Setup.exe + SHA256SUMS.txt if Inno Setup 6 is installed.
REM  Recommended: Python 3.12 (py -3.12). Internet needed once to download packages.
REM ============================================================================
set PY=python
py -3.12 --version >nul 2>&1 && set PY=py -3.12
echo Using: & %PY% --version

if not exist venv_build (%PY% -m venv venv_build || goto fail)
call venv_build\Scripts\activate || goto fail
python -m pip install --upgrade pip || goto fail
pip install -r requirements.txt -r requirements-desktop.txt || goto fail

echo === 1/6 tests (build stops if any fail) ===
python scripts\generate_samples.py && python evaluation\build_dataset.py
python -m pytest -q || goto fail

echo === 2/6 icon + version resource ===
python packaging\make_icon.py || goto fail
python packaging\make_version_file.py || goto fail
for /f %%v in ('python -c "import emailshield;print(emailshield.__version__)"') do set VER=%%v

echo === 3/6 PyInstaller ===
pyinstaller --noconfirm --clean packaging\emailshield.spec || goto fail

echo === 4/6 smoke test of the BUILT exe (starts server, analyzes one email, stops) ===
if exist dist\selftest.json del dist\selftest.json
start "" /wait dist\EmailShield\EmailShield.exe --selftest --out "%CD%\dist\selftest.json"
if errorlevel 1 (echo SELFTEST FAILED & type dist\selftest.json & goto fail)
type dist\selftest.json & echo.

echo === 4b/6 smoke test of the engine/window split (background engine start, status, stop) ===
start "" dist\EmailShield\EmailShield.exe --background
timeout /t 10 /nobreak >nul
start "" /wait dist\EmailShield\EmailShield.exe --status
if errorlevel 1 (echo ENGINE DID NOT START & goto fail)
start "" /wait dist\EmailShield\EmailShield.exe --stop
timeout /t 3 /nobreak >nul
start "" /wait dist\EmailShield\EmailShield.exe --status
if not errorlevel 3 (echo ENGINE DID NOT STOP & goto fail)
echo engine start/stop OK

echo === 5/6 portable zip ===
if exist dist_portable rmdir /s /q dist_portable
mkdir dist_portable\EmailShield-Portable
xcopy /e /i /q dist\EmailShield dist_portable\EmailShield-Portable >nul
echo portable> dist_portable\EmailShield-Portable\portable.flag
copy packaging\Create-Shortcut.ps1 dist_portable\EmailShield-Portable >nul
powershell -NoProfile -Command "Compress-Archive -Force -Path dist_portable\EmailShield-Portable -DestinationPath dist_portable\EmailShield-Portable-%VER%.zip" || goto fail

echo === 6/6 installer (needs Inno Setup 6) ===
set ISCC=
where iscc >nul 2>&1 && set ISCC=iscc
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set ISCC="%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if "%ISCC%"=="" (echo Inno Setup not found - skipping installer. Install from https://jrsoftware.org/isinfo.php and run build_windows.bat again. & goto record)
%ISCC% /DAppVersion=%VER% packaging\emailshield.iss || goto fail
copy /y dist_installer\EmailShield-Setup-%VER%.exe dist_installer\EmailShield-Setup.exe >nul

:record
echo === build record: exact package versions + checksums ===
pip freeze > dist\build-requirements.lock.txt
python --version > dist\build-info.txt & echo Windows build on %COMPUTERNAME% >> dist\build-info.txt
if exist dist_installer\EmailShield-Setup-%VER%.exe (
  powershell -NoProfile -Command "Get-FileHash dist_installer\EmailShield-Setup-%VER%.exe -Algorithm SHA256 | ForEach-Object { $_.Hash.ToLower() + '  ' + (Split-Path $_.Path -Leaf) }" > dist_installer\SHA256SUMS.txt
  type dist_installer\SHA256SUMS.txt
)
powershell -NoProfile -Command "Get-FileHash dist_portable\EmailShield-Portable-%VER%.zip -Algorithm SHA256 | ForEach-Object { $_.Hash.ToLower() + '  ' + (Split-Path $_.Path -Leaf) }" >> dist_installer\SHA256SUMS.txt 2>nul

echo.
echo DONE. Test the results on a machine WITHOUT Python before sharing them.
exit /b 0
:fail
echo.
echo BUILD FAILED - read the messages above, fix, and run again.
exit /b 1
