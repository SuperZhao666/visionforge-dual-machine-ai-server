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
call "%VSROOT%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1

set "ROOT=%~dp0..\.."
set "OUT=%ROOT%\out"
if not exist "%OUT%" mkdir "%OUT%"
if not defined VFDUAL_DATASET_EVALUATOR_OUTPUT set "VFDUAL_DATASET_EVALUATOR_OUTPUT=%OUT%\VisionForgeDatasetEvaluate.exe"
pushd "%ROOT%"
cl /nologo /utf-8 /std:c++20 /EHsc /O2 /Ishared\include host\windows\src\dataset_detection_evaluator.cpp /link /OUT:"%VFDUAL_DATASET_EVALUATOR_OUTPUT%"
if errorlevel 1 goto :failure
popd
echo Built: %VFDUAL_DATASET_EVALUATOR_OUTPUT%
exit /b 0

:failure
popd
exit /b 1
