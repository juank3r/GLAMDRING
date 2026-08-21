# Cierra los GLAMDRING que se hayan quedado corriendo.
#
# POR QUE HACE FALTA: al levantar uvicorn desde una terminal que luego se cierra
# (o desde un agente), el proceso queda vivo y el puerto ocupado. Al cabo de un
# rato hay cinco o seis puertos sirviendo versiones distintas del codigo y es
# facil estar mirando una vieja creyendo que los cambios no han hecho nada.
#
# Busca por linea de comandos, no solo por puerto: asi caza tambien el proceso
# padre del recargador (--reload levanta dos), que no escucha en ningun puerto
# pero vuelve a levantar al hijo si se mata solo al hijo.
#
# USO (desde TU terminal, no desde un agente: hace falta tu permiso):
#   powershell -ExecutionPolicy Bypass -File tools\stop_servers.ps1
#   powershell -ExecutionPolicy Bypass -File tools\stop_servers.ps1 -Keep 8000
#   powershell -ExecutionPolicy Bypass -File tools\stop_servers.ps1 -WhatIf

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Puerto que NO se toca, normalmente el que se esta usando ahora mismo.
    # Solo respeta al proceso que escucha en ese puerto; los demas caen igual.
    [int] $Keep = 0
)

# Quien escucha en cada puerto, para poder informar y para respetar -Keep.
$porPuerto = @{}
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    if (-not $porPuerto.ContainsKey([int]$_.OwningProcess)) {
        $porPuerto[[int]$_.OwningProcess] = @()
    }
    $porPuerto[[int]$_.OwningProcess] += $_.LocalPort
}

$protegido = $null
if ($Keep -gt 0) {
    $protegido = ($porPuerto.GetEnumerator() | Where-Object { $_.Value -contains $Keep } | Select-Object -First 1).Key
}

# Todo proceso de Python que este sirviendo ESTE proyecto.
$objetivos = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'uvicorn' -and $_.CommandLine -match 'glamdring' }

if (-not $objetivos) {
    Write-Host "No hay ningun GLAMDRING corriendo." -ForegroundColor Green
    exit 0
}

Write-Host ("Encontrados {0} procesos de GLAMDRING." -f ($objetivos | Measure-Object).Count)
Write-Host ""

$cerrados = 0
$fallidos = 0
foreach ($p in $objetivos) {
    $procId = [int]$p.ProcessId
    $puertos = if ($porPuerto.ContainsKey($procId)) { $porPuerto[$procId] -join ', ' } else { '(sin puerto)' }

    if ($protegido -and $procId -eq $protegido) {
        Write-Host ("  PID {0,-6} puerto {1,-14} SE RESPETA (-Keep {2})" -f $procId, $puertos, $Keep) -ForegroundColor Cyan
        continue
    }

    if ($PSCmdlet.ShouldProcess("PID $procId (puerto $puertos)", "detener")) {
        try {
            Stop-Process -Id $procId -Force -ErrorAction Stop
            Write-Host ("  PID {0,-6} puerto {1,-14} cerrado" -f $procId, $puertos) -ForegroundColor Green
            $cerrados++
        } catch {
            Write-Host ("  PID {0,-6} puerto {1,-14} NO se deja: {2}" -f $procId, $puertos, $_.Exception.Message) -ForegroundColor Red
            $fallidos++
        }
    }
}

Start-Sleep -Milliseconds 800
Write-Host ""
Write-Host ("Cerrados: {0}. Fallidos: {1}." -f $cerrados, $fallidos)

$quedan = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -ge 8000 -and $_.LocalPort -le 8100 }
if ($quedan) {
    Write-Host ""
    Write-Host "Siguen ocupados estos puertos:" -ForegroundColor Yellow
    $quedan | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort | Format-Table -AutoSize
    if ($fallidos -gt 0) {
        Write-Host "Si alguno da 'Acceso denegado', abre PowerShell como administrador." -ForegroundColor Yellow
    }
} else {
    Write-Host "Todos los puertos libres." -ForegroundColor Green
}
