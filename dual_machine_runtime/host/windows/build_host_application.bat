@echo off
setlocal EnableExtensions

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo ERROR: Visual Studio Installer was not found.
  exit /b 1
)
for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath`) do set "VSROOT=%%I"
if not defined VSROOT (
  echo ERROR: Visual Studio C++ build tools were not found.
  exit /b 1
)
call "%VSROOT%\Common7\Tools\VsDevCmd.bat" -no_logo -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1

for %%I in ("%~dp0..\..") do set "RUNTIME_ROOT=%%~fI"
for %%I in ("%RUNTIME_ROOT%\..") do set "REPOSITORY_ROOT=%%~fI"
set "BUILD_DIR=%RUNTIME_ROOT%\out_ninja_host_release"
rem Keep the disposable test tree short. CMake's Ninja generator embeds the
rem absolute path of Android benchmark sources in object paths, and the full
rem repository path can exceed MSVC's legacy path limit.
set "TEST_BUILD_DIR=%RUNTIME_ROOT%\out\cmake-host-tests-clean"
set "CMAKE_EXE=%REPOSITORY_ROOT%\.android-sdk\cmake\3.22.1\bin\cmake.exe"
set "CTEST_EXE=%REPOSITORY_ROOT%\.android-sdk\cmake\3.22.1\bin\ctest.exe"
set "NINJA_EXE=%REPOSITORY_ROOT%\.android-sdk\cmake\3.22.1\bin\ninja.exe"
set "HOST_VERSION_FILE=%RUNTIME_ROOT%\release_version.txt"
set "HOST_VERIFY_SCRIPT=%RUNTIME_ROOT%\host\windows\verify_host_release_artifact.ps1"
set "VSLANG=1033"

if not exist "%CMAKE_EXE%" (
  echo ERROR: Bundled CMake was not found at "%CMAKE_EXE%".
  exit /b 1
)
if not exist "%NINJA_EXE%" (
  echo ERROR: Bundled Ninja was not found at "%NINJA_EXE%".
  exit /b 1
)
if not exist "%CTEST_EXE%" (
  echo ERROR: Bundled CTest was not found at "%CTEST_EXE%".
  exit /b 1
)
if not exist "%HOST_VERSION_FILE%" (
  echo ERROR: Dual-machine release version was not found at "%HOST_VERSION_FILE%".
  exit /b 1
)
if not exist "%HOST_VERIFY_SCRIPT%" (
  echo ERROR: Host release verifier was not found at "%HOST_VERIFY_SCRIPT%".
  exit /b 1
)
if not defined VFDUAL_HOST_OUTPUT set "VFDUAL_HOST_OUTPUT=%RUNTIME_ROOT%\out\VFHost.exe"
for %%I in ("%VFDUAL_HOST_OUTPUT%") do set "HOST_OUTPUT_PDB=%%~dpnI.pdb"
set "HOST_EVIDENCE_DIR=%BUILD_DIR%\private_release_evidence"
rem Remove only obsolete public verification sidecars from earlier builds. The
rem new verifier writes evidence out-of-band under HOST_EVIDENCE_DIR.
if exist "%VFDUAL_HOST_OUTPUT%.verify.json" del /F /Q "%VFDUAL_HOST_OUTPUT%.verify.json"
if exist "%VFDUAL_HOST_OUTPUT%.sha256" del /F /Q "%VFDUAL_HOST_OUTPUT%.sha256"
if exist "%HOST_OUTPUT_PDB%" del /F /Q "%HOST_OUTPUT_PDB%"
if exist "%VFDUAL_HOST_OUTPUT%.verify.json" exit /b 1
if exist "%VFDUAL_HOST_OUTPUT%.sha256" exit /b 1
if exist "%HOST_OUTPUT_PDB%" exit /b 1
if /I not "%VFDUAL_REQUIRE_AUTHENTICODE%"=="1" (
  echo ERROR: Production Host builds require VFDUAL_REQUIRE_AUTHENTICODE=1.
  exit /b 1
)
if not defined VFDUAL_HOST_SIGN_SCRIPT (
  echo ERROR: Set VFDUAL_HOST_SIGN_SCRIPT to a reviewed PowerShell signer outside the repository.
  exit /b 1
)
if not exist "%VFDUAL_HOST_SIGN_SCRIPT%" (
  echo ERROR: Host signing script was not found at "%VFDUAL_HOST_SIGN_SCRIPT%".
  exit /b 1
)
for %%I in ("%VFDUAL_HOST_SIGN_SCRIPT%") do set "HOST_SIGN_SCRIPT_ABS=%%~fI"
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$repo = [IO.Path]::GetFullPath($env:REPOSITORY_ROOT).TrimEnd('\') + '';" ^
  "$signer = [IO.Path]::GetFullPath($env:HOST_SIGN_SCRIPT_ABS);" ^
  "if ($signer.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) { exit 1 }"
if errorlevel 1 (
  echo ERROR: VFDUAL_HOST_SIGN_SCRIPT must be stored outside the repository workspace.
  exit /b 1
)
if not defined VFDUAL_HOST_SIGNER_CERT_SHA256 (
  echo ERROR: Set VFDUAL_HOST_SIGNER_CERT_SHA256 to the reviewed signer certificate SHA-256.
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$value = $env:VFDUAL_HOST_SIGNER_CERT_SHA256; if ($value -notmatch '^[0-9A-Fa-f]{64}$') { exit 1 }"
if errorlevel 1 (
  echo ERROR: VFDUAL_HOST_SIGNER_CERT_SHA256 must be exactly 64 hexadecimal characters.
  exit /b 1
)
if not defined VFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64 (
  echo ERROR: VFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64 is required and must contain 1-3 public PEM files encoded as Base64.
  exit /b 1
)

rem OUTPUT_NAME does not remove binaries emitted by the former product name.
rem Delete only the two formal-build legacy artifacts so a successful build
rem cannot leave two apparently distributable Host executables behind.
if exist "%BUILD_DIR%\VisionForgeHost.exe" del /F /Q "%BUILD_DIR%\VisionForgeHost.exe"
if exist "%BUILD_DIR%\VisionForgeHost.exe" (
  echo ERROR: Failed to remove legacy Host EXE "%BUILD_DIR%\VisionForgeHost.exe".
  exit /b 1
)
if exist "%RUNTIME_ROOT%\out\VisionForgeHost.exe" del /F /Q "%RUNTIME_ROOT%\out\VisionForgeHost.exe"
if exist "%RUNTIME_ROOT%\out\VisionForgeHost.exe" (
  echo ERROR: Failed to remove legacy Host EXE "%RUNTIME_ROOT%\out\VisionForgeHost.exe".
  exit /b 1
)

"%CMAKE_EXE%" -S "%RUNTIME_ROOT%" -B "%BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_MAKE_PROGRAM="%NINJA_EXE%" -DVFDUAL_ENABLE_PRIVATE_HOST_SYMBOLS=OFF -DVFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY=ON -DVFDUAL_ENFORCE_HOST_RELEASE_SECURITY_INPUTS=ON "-DVFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64=%VFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64%"
if errorlevel 1 exit /b 1
"%CMAKE_EXE%" --build "%BUILD_DIR%" --target verify_host_release_security_inputs
if errorlevel 1 exit /b 1
rem A formal one-EXE build must not reuse objects compiled against an older
rem class layout. Ninja dependency output can be localized on Windows, so a
rem header-only layout change is not always enough to invalidate every object.
"%CMAKE_EXE%" --build "%BUILD_DIR%" --target VisionForgeHost --clean-first
if errorlevel 1 exit /b 1

rem Never extend the formal Host build tree with test targets. A fresh test
rem tree prevents stale objects from a localized MSVC /showIncludes database
rem from being linked with objects compiled against the current headers.
echo Preparing clean Host test build: %TEST_BUILD_DIR%
"%CMAKE_EXE%" -E remove_directory "%TEST_BUILD_DIR%"
if errorlevel 1 exit /b 1
if exist "%TEST_BUILD_DIR%" (
  echo ERROR: Failed to remove stale Host test build "%TEST_BUILD_DIR%".
  exit /b 1
)
"%CMAKE_EXE%" -S "%RUNTIME_ROOT%" -B "%TEST_BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_MAKE_PROGRAM="%NINJA_EXE%" -DVFDUAL_ENABLE_PRIVATE_HOST_SYMBOLS=OFF "-DVFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64=%VFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64%"
if errorlevel 1 exit /b 1
"%CMAKE_EXE%" --build "%TEST_BUILD_DIR%" --target vfdual_test_build
if errorlevel 1 exit /b 1
"%CTEST_EXE%" --test-dir "%TEST_BUILD_DIR%" --output-on-failure --no-tests=error
if errorlevel 1 exit /b 1

for %%I in ("%VFDUAL_HOST_OUTPUT%") do if not exist "%%~dpI" mkdir "%%~dpI"
copy /Y "%BUILD_DIR%\VFHost.exe" "%VFDUAL_HOST_OUTPUT%" >nul
if errorlevel 1 (
  echo ERROR: Failed to copy Host EXE to "%VFDUAL_HOST_OUTPUT%".
  powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
    "$target = [IO.Path]::GetFullPath($env:VFDUAL_HOST_OUTPUT);" ^
    "Get-Process | Where-Object { $_.Path -and [string]::Equals($_.Path, $target, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { Write-Host ('Running target process: pid=' + $_.Id + ' name=' + $_.ProcessName) }"
  echo Close the running Host or set VFDUAL_HOST_OUTPUT to an unused path, then rerun.
  exit /b 1
)

powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$product = Get-Item -LiteralPath '%VFDUAL_HOST_OUTPUT%';" ^
  "if ($product.Length -le 0) { Write-Error 'Signed Host artifact is empty'; exit 1 };" ^
  "$productHash = (Get-FileHash -LiteralPath $product.FullName -Algorithm SHA256).Hash;" ^
  "Write-Host ('Signed product SHA256: ' + $productHash)"
if errorlevel 1 exit /b 1

if exist "%HOST_EVIDENCE_DIR%" "%CMAKE_EXE%" -E remove_directory "%HOST_EVIDENCE_DIR%"
if errorlevel 1 exit /b 1
mkdir "%HOST_EVIDENCE_DIR%"
if errorlevel 1 exit /b 1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%HOST_VERIFY_SCRIPT%" ^
  -ExePath "%VFDUAL_HOST_OUTPUT%" ^
  -VersionFile "%HOST_VERSION_FILE%" ^
  -ReportDirectory "%HOST_EVIDENCE_DIR%" ^
  -ExpectedSignerCertificateSha256 "%VFDUAL_HOST_SIGNER_CERT_SHA256%" ^
  -RequireAuthenticode ^
  -RequireTimestamp
if errorlevel 1 exit /b 1

echo Built signed product EXE: %VFDUAL_HOST_OUTPUT%
echo Private verification evidence: %HOST_EVIDENCE_DIR%
echo Clean Host test build: %TEST_BUILD_DIR%
exit /b 0
