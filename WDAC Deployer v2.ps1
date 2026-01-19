<#
.SYNOPSIS
  Convert and deploy a WDAC / App Control XML policy to the local machine.

.DESCRIPTION
  - Converts XML -> binary with ConvertFrom-CIPolicy
  - Deploys binary to CodeIntegrity CIPolicies\Active\<PolicyId>.cip (recommended)
  - If requested, can deploy as single policy C:\Windows\System32\CodeIntegrity\SiPolicy.p7b
  - Tries to activate new policy via CiTool (if available) or shows commands to refresh/apply.

  Требуется запуск от администратора.
#>

param(
    [string]$XmlPath = 'C:\WDAC\WDACCustomPolicy.xml',
    [switch]$DeployAsSinglePolicy
)

function Require-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
    if (-not $isAdmin) {
        Write-Error "Скрипт должен быть запущен с правами администратора."
        exit 1
    }
}

Require-Admin

if (-not (Test-Path -Path $XmlPath)) {
    Write-Error "XML-файл не найден: $XmlPath"
    exit 1
}

Write-Output "Чтение XML-политики: $XmlPath"
try {
    [xml]$xmlDoc = Get-Content -Path $XmlPath -ErrorAction Stop
} catch {
    Write-Error "Не удалось прочитать XML: $_"
    exit 1
}

# Попробуем извлечь PolicyId из XML (если есть)
$policyId = $null
try {
    $policyId = $xmlDoc.SiPolicy.PolicyId
} catch { $policyId = $null }

if (-not $policyId) {
    Write-Warning "Не удалось извлечь PolicyId из XML. Политика всё равно будет конвертирована, но имя файла будет случайным."
}

# Подготовка путей
if ($DeployAsSinglePolicy) {
    $destBinary = Join-Path $env:windir 'System32\CodeIntegrity\SiPolicy.p7b'
} else {
    $activeFolder = Join-Path $env:windir 'System32\CodeIntegrity\CIPolicies\Active'
    if (-not (Test-Path -Path $activeFolder)) {
        New-Item -Path $activeFolder -ItemType Directory -Force | Out-Null
    }
    if ($policyId) {
        $cleanId = ($policyId -replace '[{}]','')
        $destBinary = Join-Path $activeFolder ($cleanId + '.cip')
    } else {
        # случайное имя если нет PolicyId
        $rnd = [guid]::NewGuid().ToString()
        $destBinary = Join-Path $activeFolder ($rnd + '.cip')
    }
}

$tempBin = Join-Path $env:TEMP ("WDAC_policy_" + ([guid]::NewGuid().ToString()) + ".cip")

# Конвертация XML -> бинарник
Write-Output "Конвертация XML -> бинарный полис (временный файл: $tempBin)..."
try {
    ConvertFrom-CIPolicy -XmlFilePath $XmlPath -BinaryFilePath $tempBin -ErrorAction Stop
} catch {
    Write-Error "ConvertFrom-CIPolicy failed: $($_.Exception.Message)"
    Write-Error "Full exception:"
    Write-Error $_.Exception.ToString()
    if ($_.Exception.InnerException) {
        Write-Error "Inner exception:"
        Write-Error $_.Exception.InnerException.ToString()
    }
    exit 1
}


# Копирование в целевую директорию
Write-Output "Копирование бинарного файла в: $destBinary"
try {
    Copy-Item -Path $tempBin -Destination $destBinary -Force -ErrorAction Stop
} catch {
    Write-Error "Не удалось скопировать бинарный файл: $_"
    Remove-Item -Path $tempBin -ErrorAction SilentlyContinue
    exit 1
}

# Удаляем временный файл
Remove-Item -Path $tempBin -ErrorAction SilentlyContinue

Write-Output "Политика успешно сконвертирована и записана: $destBinary"

# Попытка активировать политику немедленно (если возможно)
$ciToolPath = Join-Path $env:windir 'System32\CiTool.exe'
if (Test-Path $ciToolPath) {
    Write-Output "Найден CiTool ($ciToolPath) — запускаю обновление политики..."
    try {
        & cmd.exe /c "echo.|`"$ciToolPath`" --update-policy `"$destBinary`""
        Write-Output "Запуск CiTool (non-interactive) через cmd: $cmd"
        Write-Output "CiTool выполнен. Проверьте события/логи для подтверждения активации."
    } catch {
        Write-Warning "Запуск CiTool завершился с ошибкой: $_"
    }
} else {
    # Если нет CiTool, можно использовать RefreshPolicy.exe (если у вас есть инструмент) или метод WMI для старых систем
    Write-Warning "CiTool не обнаружен. Чтобы активировать политику без перезагрузки, используйте RefreshPolicy.exe (из Microsoft) или инструмент обновления политики."
    Write-Output "Если хотите активировать single policy (SiPolicy.p7b) через WMI, можно выполнить (требует прав администратора):"
    Write-Output "Invoke-CimMethod -Namespace root\\Microsoft\\Windows\\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = '$destBinary'}"
    Write-Output "Если активация невозможна сейчас — перезагрузка системы применит новую политику."
}
sleep 1

Write-Output "Готово."
sleep 2
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 1 | Select-Object TimeCreated, Id, LevelDisplayName, Message
