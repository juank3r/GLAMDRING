# Cierra los GLAMDRING que se hayan quedado escuchando.
#
# Levantar el servidor desde un agente o desde una terminal que luego se cierra
# deja el proceso vivo y el puerto ocupado. Al cabo de un rato hay cuatro o cinco
# puertos sirviendo versiones distintas del codigo, y es facil estar mirando una
# vieja sin darse cuenta: parece que los cambios no han hecho nada.
#
# Uso:
#   powershell -ExecutionPolicy Bypass -File tools\stop_servers.ps1
#   powershell -ExecutionPolicy Bypass -File tools\stop_servers.ps1 -Keep 8030
#   powershell -ExecutionPolicy Bypass -File tools\stop_servers.ps1 -WhatIf

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Puertos donde buscar.
    [int[]] $Ports = @(8000..8040),
    # Puerto que NO se toca, normalmente el que se esta usando ahora mismo.
    [int]   $Keep = 0
)

$listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $Ports -contains $_.LocalPort -and $_.LocalPort -ne $Keep }

if (-not $listeners) {
    Write-Host "No hay ningun servidor escuchando en esos puertos." -ForegroundColor Green
    exit 0
}

$vistos = @{}
foreach ($l in $listeners) {
    $procId = $l.OwningProcess
    if ($vistos.ContainsKey($procId)) { continue }
    $vistos[$procId] = $true

    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $proc) { continue }

    # Solo se tocan procesos de Python: en estos puertos puede haber cosas de
    # otra gente, y matar a ciegas por numero de puerto es como se tira algo que
    # importa.
    if ($proc.ProcessName -notin @('python', 'pythonw')) {
        Write-Host ("Puerto {0}: {1} (PID {2}) no es Python, se deja." -f $l.LocalPort, $proc.ProcessName, $procId) -ForegroundColor Yellow
        continue
    }

    if ($PSCmdlet.ShouldProcess("PID $procId (puerto $($l.LocalPort))", "detener")) {
        try {
            Stop-Process -Id $procId -Force -ErrorAction Stop
            Write-Host ("Puerto {0}: cerrado (PID {1})." -f $l.LocalPort, $procId) -ForegroundColor Green
        } catch {
            # Pasa cuando lo lanzo un proceso con otro contexto de seguridad.
            # Desde una terminal propia del usuario normalmente si se deja.
            Write-Host ("Puerto {0}: no se deja cerrar (PID {1}). {2}" -f $l.LocalPort, $procId, $_.Exception.Message) -ForegroundColor Red
        }
    }
}

Write-Host ""
$quedan = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $Ports -contains $_.LocalPort }
if ($quedan) {
    Write-Host "Siguen escuchando:" -ForegroundColor Yellow
    $quedan | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort | Format-Table -AutoSize
} else {
    Write-Host "Todos los puertos libres." -ForegroundColor Green
}
