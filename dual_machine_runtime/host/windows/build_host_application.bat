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
set "TEST_BUILD_DIR=C:\vfdual-host-tests-clean"
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

"%CMAKE_EXE%" -S "%RUNTIME_ROOT%" -B "%BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_MAKE_PROGRAM="%NINJA_EXE%" -DVFDUAL_ENABLE_PRIVATE_HOST_SYMBOLS=ON
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
"%CMAKE_EXE%" -S "%RUNTIME_ROOT%" -B "%TEST_BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_MAKE_PROGRAM="%NINJA_EXE%" -DVFDUAL_ENABLE_PRIVATE_HOST_SYMBOLS=OFF
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
  "Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop;" ^
  "$sourceHash = (Get-FileHash -LiteralPath '%BUILD_DIR%\VFHost.exe' -Algorithm SHA256).Hash;" ^
  "$productHash = (Get-FileHash -LiteralPath '%VFDUAL_HOST_OUTPUT%' -Algorithm SHA256).Hash;" ^
  "if ($sourceHash -ne $productHash) { Write-Error ('Product copy verification failed: source=' + $sourceHash + ' product=' + $productHash); exit 1 };" ^
  "Write-Host ('Verified product SHA256: ' + $productHash)"
if errorlevel 1 exit /b 1

set "HOST_AUTHENTICODE_ARGUMENT="
if /I "%VFDUAL_REQUIRE_AUTHENTICODE%"=="1" set "HOST_AUTHENTICODE_ARGUMENT=-RequireAuthenticode"
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%HOST_VERIFY_SCRIPT%" ^
  -ExePath "%VFDUAL_HOST_OUTPUT%" ^
  -VersionFile "%HOST_VERSION_FILE%" ^
  -PrivateSymbolsDirectory "%BUILD_DIR%\private_symbols" ^
  %HOST_AUTHENTICODE_ARGUMENT%
if errorlevel 1 exit /b 1

echo Built product EXE: %VFDUAL_HOST_OUTPUT%
echo Host verification: %VFDUAL_HOST_OUTPUT%.verify.json
echo Private symbols: %BUILD_DIR%\private_symbols
echo Clean Host test build: %TEST_BUILD_DIR%
exit /b 0
