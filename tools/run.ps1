# Arranca GLAMDRING, cerrando antes cualquier otro que estuviera corriendo.
#
# Siempre en el MISMO puerto (8000 salvo que se diga otro). Ir cambiando de
# puerto para esquivar uno ocupado es como se acaba con seis servidores vivos
# sirviendo cuatro versiones distintas del codigo, mirando una vieja y creyendo
# que los cambios no han hecho nada.
#
# USO:
#   powershell -ExecutionPolicy Bypass -File tools\run.ps1
#   powershell -ExecutionPolicy Bypass -File tools\run.ps1 -Port 8080
#   powershell -ExecutionPolicy Bypass -File tools\run.ps1 -Reload

param(
    [int]    $Port   = 8000,
    # Recarga al guardar. Levanta un proceso mas (el vigilante), asi que se pide
    # a proposito y no viene puesto.
    [switch] $Reload
)

$ErrorActionPreference = 'Stop'
$raiz = Split-Path -Parent $PSScriptRoot
Set-Location $raiz

$python = Join-Path $raiz '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    Write-Host "No hay entorno virtual en .venv\. Crealo con:" -ForegroundColor Red
    Write-Host "  python -m venv .venv" -ForegroundColor Yellow
    Write-Host "  .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt" -ForegroundColor Yellow
    exit 1
}

Write-Host "Cerrando lo que hubiera..." -ForegroundColor Cyan
& powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'stop_servers.ps1')

# Si el puerto sigue ocupado por algo que no es nuestro, mejor avisar que pelear.
$ocupa = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($ocupa) {
    $duenyo = $ocupa[0].OwningProcess
    # Buscar el primer puerto libre a partir del pedido, para no dejar al que
    # ejecuta esto buscandolo a mano. Es el momento en que mas estorba tener que
    # ponerse a investigar.
    $libre = $null
    foreach ($p in ($Port + 1)..($Port + 20)) {
        if (-not (Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)) {
            $libre = $p; break
        }
    }

    Write-Host ""
    Write-Host "El puerto $Port sigue ocupado por el PID $duenyo." -ForegroundColor Red
    Write-Host ""
    Write-Host "Para liberarlo, en PowerShell COMO ADMINISTRADOR:" -ForegroundColor Yellow
    Write-Host "    Stop-Process -Id $duenyo -Force" -ForegroundColor White
    if ($libre) {
        Write-Host ""
        Write-Host "O para seguir ahora mismo en otro puerto:" -ForegroundColor Yellow
        Write-Host "    powershell -ExecutionPolicy Bypass -File tools\run.ps1 -Port $libre" -ForegroundColor White
    }
    exit 1
}

Write-Host ""
Write-Host "GLAMDRING en http://127.0.0.1:$Port" -ForegroundColor Green
Write-Host "Ctrl+C para parar." -ForegroundColor DarkGray
Write-Host ""

$args = @('-m', 'uvicorn', 'glamdring.main:app', '--host', '127.0.0.1', '--port', "$Port")
if ($Reload) { $args += @('--reload', '--reload-dir', 'glamdring') }
& $python @args
