@echo off
REM Lanzador de GLAMDRING para cmd.
REM
REM POR QUE EXISTE: la forma "oficial" era
REM     powershell -ExecutionPolicy Bypass -File tools\run.ps1
REM que falla de dos maneras muy faciles de encontrarse:
REM   - desde otra carpeta, porque la ruta es relativa
REM   - copiando comandos de PowerShell en una ventana de cmd
REM
REM Esto se puede ejecutar desde cualquier sitio y con doble clic.
REM
REM Uso:
REM     run.bat
REM     run.bat 8003        (otro puerto)

setlocal
set "RAIZ=%~dp0"
set "PUERTO=%~1"
if "%PUERTO%"=="" set "PUERTO=8000"

powershell -ExecutionPolicy Bypass -File "%RAIZ%tools\run.ps1" -Port %PUERTO%
set "CODIGO=%ERRORLEVEL%"

REM Con doble clic la ventana se cerraria antes de poder leer el error.
if not "%CODIGO%"=="0" (
    echo.
    echo Ha fallado el arranque. Codigo: %CODIGO%
    echo.
    pause
)
endlocal
