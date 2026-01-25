function Save--MyPC {

    $path = "C:\Windows\System32\CodeIntegrity\CIPolicies\Active"

    Get-ChildItem $path -File | Where-Object {
        $_.CreationTime.Year -gt 2026
    } | ForEach-Object {
        Write-Host "Удаляю:" $_.FullName
        Remove-Item $_.FullName -Force
    }

# Перезагрузка политик WDAC
    if (Get-Command citool -ErrorAction SilentlyContinue) {
        citool --refresh
    } else {
        Write-Warning "citool не найден"
    }

    Write-Host "Готово."

}
function Prepare--NamesForWDACPolicy {
    <#
    .SYNOPSIS
      Создаёт WDAC XML на базе AllowAll_EnableHVCI и добавляет deny-правила.

    .PARAMETER DenyNames
      Массив имён/масок/путей. Примеры:
        "test.exe"                      -> запрет по имени (в любых папках)
        "*.bat"                         -> запрет по маске (в любых папках)
        "C:\Temp\evil.exe"              -> запрет по конкретному пути
        "*\subdir\bad.exe"              -> явная маска пути

    .PARAMETER DenyDevelopers
      Массив фрагментов имени издателя (SignerCertificate.Subject). Функция попытается найти подписанный файл
      в системных папках и создать FilePublisher -Deny правило на его основе.

    .PARAMETER Audit
      Булево (по умолчанию $true). Если $true — включается Audit Mode (Option 3).
    #>

    [CmdletBinding()]
    param(
        [string[]] $DenyNames = @(),
        [bool] $Audit = $true
    )

    # --- Импорт и проверки ---
    try {
        Import-Module ConfigCI -ErrorAction Stop
    } catch {
        Write-Error "Не удалось импортировать модуль ConfigCI: $($_.Exception.Message). Убедитесь, что модуль доступен и вы запускаете PowerShell на Windows с необходимым функционалом."
        return $null
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "Рекомендуется запускать эту функцию от имени администратора."
    }

    $osDrive = $env:SystemDrive.TrimEnd('\')
    $examplePath = Join-Path $osDrive "Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll_EnableHVCI.xml"
    if (-not (Test-Path $examplePath)) {
        Write-Error "Шаблон AllowAll_EnableHVCI.xml не найден по пути: $examplePath. Укажите другой шаблон или положите примерный файл в систему."
        return $null
    }

    $outDir = "C:\WDAC"
    if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
    $outXml = Join-Path $outDir "WDACCustomPolicy.xml"
    $outCip = Join-Path $outDir "WDACCustomPolicy.cip"

    $AllRules = @()

    # Стандартные папки для поиска подписанных образцов (системные, чтобы избежать UserWritable)
    $searchFolders = @(
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)",
        "$env:WinDir\System32",
        "$env:WinDir\SysWOW64"
    ) | Where-Object { $_ -and (Test-Path $_) } | Get-Unique

    # --- Обработка DenyNames ---
    foreach ($entry in $DenyNames) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }

        try {
            # 1) Простое имя без слэшей и без масок -> создаём pattern "*\name"
            if ($entry -notmatch '[\\:]' -and $entry -notmatch '[\*\?]') {
                $pattern = "*\$entry"
                Write-Verbose "Создаю deny FilePathRule (по имени) -> $pattern"
                $r = New-CIPolicyRule -FilePathRule $pattern -Deny
                $AllRules += $r
                continue
            }

            # 2) Если есть маска, но нет пути, например "*.exe" -> делаем "*\*.exe"
            if ($entry -match '[\*\?]' -and $entry -notmatch '[\\:]') {
                $pattern = "*\$entry"
                Write-Verbose "Создаю deny FilePathRule (по маске) -> $pattern"
                $r = New-CIPolicyRule -FilePathRule $pattern -Deny
                $AllRules += $r
                continue
            }

            # 3) Если указан путь (с буквой диска или с обратными слэшами) -> используем как есть
            #    (можно применять конкретный путь или маску с путём)
            if ($entry -match '[\\:]') {
                # Нормализуем: если путь содержит wildcard — оставляем, иначе используем точный путь
                $pattern = $entry
                # Если передан абсолютный путь к файлу, но вы хотите «по имени во всех папках», используйте на входе только имя.
                Write-Verbose "Создаю deny FilePathRule (по пути) -> $pattern"
                $r = New-CIPolicyRule -FilePathRule $pattern -Deny
                $AllRules += $r
                continue
            }

            # fallback — попытка создать как FilePathRule
            Write-Verbose "Попытка создать FilePathRule для '$entry' как есть"
            $r = New-CIPolicyRule -FilePathRule $entry -Deny
            $AllRules += $r

        } catch {
            Write-Warning "Не удалось создать правило для '$entry': $($_.Exception.Message)"
        }
    }

    if ($AllRules.Count -eq 0) {
        Write-Warning "Не создано дополнительных deny-правил (DenyNames/DenyDevelopers пусты или не удалось создать правила). Политика AllowAll скопирована в $outXml."
        return @{ Xml = $outXml; Cip = $null }
    }

    # --- Merge правил в XML ---
    try {
        Merge-CIPolicy -PolicyPaths $outXml -Rules $AllRules -OutputFilePath $outXml -ErrorAction Stop
    } catch {
        Write-Error "Ошибка Merge-CIPolicy: $($_.Exception.Message)"; return $null
    }

    # --- Обновить метаданные политики ---
    try {
        $policyName = "WDAC_Custom_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Set-CIPolicyIdInfo -FilePath $outXml -PolicyName $policyName -ResetPolicyID
    } catch {
        Write-Warning "Set-CIPolicyIdInfo завершился с предупреждением: $($_.Exception.Message)"
    }

    # --- Установить/удалить Audit Mode (Option 3) ---
    try {
        if ($Audit) {
            Set-RuleOption -FilePath $outXml -Option 3
            Write-Verbose "Audit Mode включён (Option 3)."
        } else {
            Set-RuleOption -FilePath $outXml -Option 3 -Delete
            Write-Verbose "Audit Mode отключён (Option 3 удалён)."
        }
    } catch {
        Write-Warning "Set-RuleOption: $($_.Exception.Message)"
    }

    # --- Конвертация в бинарный .cip (если нужно) ---
    try {
        ConvertFrom-CIPolicy -XmlFilePath $outXml -BinaryFilePath $outCip -ErrorAction Stop
    } catch {
        Write-Warning "ConvertFrom-CIPolicy завершился с ошибкой: $($_.Exception.Message). XML сохранён: $outXml"
        $outCip = $null
    }

    Write-Host "Готово. Политика: $outXml" -ForegroundColor Green
    if ($outCip) { Write-Host "Binary: $outCip" -ForegroundColor Green }

    # Небольшая проверка: показать, что в XML есть наши маски (по ключевым словам)
    try {
        Select-String -Path $outXml -Pattern ($DenyNames + $DenyDevelopers) -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 10
    } catch { }

    Set-HVCIOptions -FilePath "C:\WDAC\WDACCustomPolicy.xml" -Strict

    return @{ Xml = $outXml; Cip = $outCip }
}

function Prepare--DriverDevsForWDACPolicy {
    <#
    .SYNOPSIS
        Обновлённая версия: поддерживает создание правила Deny по SampleFile без системного сканирования (флаг -DenyFromSample).

    .DESCRIPTION
        Поддерживает три сценария:
          - Добавление Update signer из SampleFile (если указан).
          - Быстрое создание правила Deny уровня Publisher только на основе SampleFile (-DenyFromSample) без вызова Get-SystemDriver.
          - Классический режим: поиск драйверов по массиву -DenyDevelopers (запускает Get-SystemDriver и может занять время).

    .PARAMETER DenyDevelopers
        Массив строк: имена или части имён издателей. Если указан — включается режим со сканированием.

    .PARAMETER Audit
        $true (по умолчанию) — оставить политику в Audit mode (Option 3 установлен). $false — удалить опцию Audit.

    .PARAMETER SampleFile
        Путь к подписанному файлу; используется для извлечения сертификата и/или для создания правила Deny без сканирования.

    .PARAMETER DenyFromSample
        Switch. Если указан — создаёт правило Deny по издателю из SampleFile без сканирования.

    .PARAMETER PolicyPath
        Путь к XML-файлу политики (по умолчанию C:\WDAC\WDACCustomPolicy.xml).

    .PARAMETER DryRun
        Если указан — показывается, какие действия были бы выполнены, без изменения файлов.

    .NOTES
        Требует модуля ConfigCI и запуска с повышенными правами (администратор).
    #>

    [CmdletBinding()]
    param(
        [string[]]$DenyDevelopers = @(),
        [bool]$Audit = $true,
        [string]$SampleFile,
        [switch]$DenyFromSample = $true,
        [string]$PolicyPath = 'C:\WDAC\WDACCustomPolicy.xml',
        [switch]$DryRun
    )

    begin {
        if (-not (Get-Command -Name Add-SignerRule -ErrorAction SilentlyContinue)) {
            try { Import-Module ConfigCI -ErrorAction Stop }
            catch { throw "Модуль ConfigCI недоступен или не может быть загружен: $($_.Exception.Message)" }
        }

        if (-not $DryRun -and -not (Test-Path -Path $PolicyPath)) {
            throw "Файл политики не найден: $PolicyPath"
        }

        $tempFiles = @()
        $addedRules = @()
        $log = @()
    }

    process {
        try {
            # 1) Если задан SampleFile — извлечь сертификат и (опционально) добавить как Update signer
            if ($SampleFile) {
                if (-not (Test-Path -Path $SampleFile)) { throw "SampleFile не найден: $SampleFile" }

                $sig = Get-AuthenticodeSignature -FilePath $SampleFile -ErrorAction Stop
                if (-not $sig.SignerCertificate) { throw "В файле $SampleFile не обнаружено подписи (SignerCertificate)" }

                $tmpCer = Join-Path -Path $env:TEMP -ChildPath ([guid]::NewGuid().ToString() + '.cer')
                $bytes = $sig.SignerCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                [System.IO.File]::WriteAllBytes($tmpCer, $bytes)
                $tempFiles += $tmpCer
                $log += "Экспортирован сертификат из $SampleFile во временный файл $tmpCer"

                if ($DryRun) { $log += "[DRY-RUN] Add-SignerRule -CertificatePath $tmpCer -Update (пропущено)" }
                else { Add-SignerRule -FilePath $PolicyPath -CertificatePath $tmpCer -Update -User -Kernel -ErrorAction Stop; $log += "Добавлен Update signer из $SampleFile" }
            }

            # 2) Быстрый режим: создать правило Deny уровня Publisher на основе самого SampleFile без сканирования
            if ($DenyFromSample) {
                if (-not $SampleFile) { throw "Для -DenyFromSample необходимо указать -SampleFile" }

                $log += "Генерация правила Deny (Publisher) на основе $SampleFile (без сканирования)"
                $rule = New-CIPolicyRule -DriverFilePath $SampleFile -Level Publisher -Deny -ErrorAction Stop

                if ($DryRun) { $log += "[DRY-RUN] Создано правило Deny (пропущено встраивание)" }
                else { $addedRules += $rule; $log += "Создано правило Deny (Publisher) для издателя из $SampleFile" }
            }

            # 3) Стандартный режим: поиск драйверов по -DenyDevelopers (включает Get-SystemDriver — сканирование)
            if (($DenyDevelopers -and $DenyDevelopers.Count -gt 0) -and -not $DenyFromSample) {
                $log += "Запуск Get-SystemDriver — возможно длительное сканирование"
                $drivers = Get-SystemDriver -ErrorAction Stop

                foreach ($dev in $DenyDevelopers) {
                    if ([string]::IsNullOrWhiteSpace($dev)) { continue }

                    $matches = @()
                    foreach ($d in $drivers) {
                        $found = $false
                        if ($d.Signers -and $d.Signers.Count -gt 0) {
                            foreach ($s in $d.Signers) {
                                $cands = @()
                                if ($s.PSObject.Properties.Name -contains 'Subject') { $cands += $s.Subject }
                                if ($s.PSObject.Properties.Name -contains 'Name')    { $cands += $s.Name }
                                if ($s.PSObject.Properties.Name -contains 'Issuer')  { $cands += $s.Issuer }

                                foreach ($cs in $cands) { if ($cs -and ($cs -like "*$dev*")) { $found = $true; break } }
                                if ($found) { break }
                            }
                        }
                        if ($found) { $matches += $d }
                    }

                    if ($matches.Count -eq 0) { $log += "Не найдено драйверов для издателя '$dev'"; continue }

                    $log += "Найдено $($matches.Count) файлов для издателя '$dev' — создание правил Deny"
                    $rules = New-CIPolicyRule -DriverFiles $matches -Level Publisher -Deny -ErrorAction Stop
                    if ($rules) { $addedRules += $rules; $log += "Добавлены правила Deny для '$dev'" }
                }
            }

            # 4) Если есть правила — встраиваем их в политику
            if ($addedRules.Count -gt 0) {
                $tempOut = Join-Path -Path $env:TEMP -ChildPath ([guid]::NewGuid().ToString() + '_WDAC.xml')

                if ($DryRun) { $log += "[DRY-RUN] Merge-CIPolicy -Rules ... (пропущено)" }
                else {
                    Merge-CIPolicy -PolicyPaths $PolicyPath -Rules $addedRules -OutputFilePath $tempOut -ErrorAction Stop
                    $backup = "$PolicyPath.bak.$((Get-Date).ToString('yyyyMMddHHmmss'))"
                    Copy-Item -Path $PolicyPath -Destination $backup -Force
                    Move-Item -Path $tempOut -Destination $PolicyPath -Force
                    $log += "Политика обновлена: $PolicyPath (backup: $backup)"
                }
            }
            else { $log += "Новых правил для встраивания нет" }

            # 5) Установка/удаление Audit (Option 3)
            if ($Audit) {
                if ($DryRun) { $log += "[DRY-RUN] Set-RuleOption -Option 3 (пропущено)" }
                else { Set-RuleOption -FilePath $PolicyPath -Option 3 -ErrorAction Stop; $log += "Установлен Audit mode (Option 3)" }
            }
            else {
                if ($DryRun) { $log += "[DRY-RUN] Set-RuleOption -Option 3 -Delete (пропущено)" }
                else { Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete -ErrorAction Stop; $log += "Удалён Audit mode (Option 3)" }
            }

            Set-HVCIOptions -FilePath "C:\WDAC\WDACCustomPolicy.xml" -Strict

            return [pscustomobject]@{
                PolicyPath = $PolicyPath
                AddedRulesCount = $addedRules.Count
                AuditMode = $Audit
                SampleFile = if ($SampleFile) { $SampleFile } else { $null }
                ActionsLog = $log
                DryRun = $DryRun
            }
        }
        catch { throw "Ошибка: $($_.Exception.Message)" }
        finally { foreach ($f in $tempFiles) { if (Test-Path $f) { Remove-Item -Path $f -Force -ErrorAction SilentlyContinue } } }
    }
}

# Примеры:
# Prepare-DriverDevsWDACPolicy -SampleFile 'C:\temp\BadSys.sys' -DenyFromSample
# Prepare-DriverDevsWDACPolicy -DenyDevelopers @('BadVendor')
# Prepare-DriverDevsWDACPolicy -SampleFile 'C:\temp\BadSys.sys' -DenyFromSample -DryRun

function Disable--Audit { Set-RuleOption -FilePath 'C:\WDAC\WDACCustomPolicy.xml' -Option 3 -Delete -ErrorAction Stop }
function Constrain--Scripts--DANGEROUS { param($Confirm); if ($Confirm = "USE-SAVE--MYPC-TO-REVERSE!") { Set-RuleOption -FilePath 'C:\WDAC\WDACCustomPolicy.xml' -Option 11 -Delete -ErrorAction Stop } }

function Initialize--WDACPolicy {

    param(
        [string[]] $DenyNames = @(),
        [string[]] $DenyDevelopers = @(),
        [bool] $Audit = $true
    )

    # Требуются права администратора
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Скрипт должен быть запущен с правами администратора."
    exit 1
}

$activePath = 'C:\Windows\System32\CodeIntegrity\CIPolicies\Active'

if (-not (Test-Path $activePath)) {
    Write-Error "Каталог не найден: $activePath"
    exit 1
}

# Всё, что создано ПОСЛЕ 31.12.2025 23:59:59
$cutoffDate = Get-Date '2026-01-01'

Write-Output "Поиск WDAC policies, созданных начиная с $cutoffDate"
Write-Output "Каталог: $activePath"
Write-Output ""

$policiesToRemove = Get-ChildItem `
    -Path $activePath `
    -Filter '*.cip' `
    -File `
    -ErrorAction Stop |
    Where-Object { $_.CreationTime -ge $cutoffDate }

if (-not $policiesToRemove) {
    Write-Output "Политик для удаления не найдено."
    # --- Импорт и проверки ---
    try {
        Import-Module ConfigCI -ErrorAction Stop
    } catch {
        Write-Error "Не удалось импортировать модуль ConfigCI: $($_.Exception.Message). Убедитесь, что модуль доступен и вы запускаете PowerShell на Windows с необходимым функционалом."
        return $null
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "Рекомендуется запускать эту функцию от имени администратора."
    }

    $osDrive = $env:SystemDrive.TrimEnd('\')
    $examplePath = Join-Path $osDrive "Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll_EnableHVCI.xml"
    if (-not (Test-Path $examplePath)) {
        Write-Error "Шаблон AllowAll_EnableHVCI.xml не найден по пути: $examplePath. Укажите другой шаблон или положите примерный файл в систему."
        return $null
    }

    $outDir = "C:\WDAC"
    if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
    $outXml = Join-Path $outDir "WDACCustomPolicy.xml"
    $outCip = Join-Path $outDir "WDACCustomPolicy.cip"

    Copy-Item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll_EnableHVCI.xml" -Destination "C:\WDAC\WDACCustomPolicy.xml" -Force
    return
}

Write-Output "Найдены политики для удаления:"
$policiesToRemove |
    Select-Object Name, CreationTime, FullName |
    Format-Table -AutoSize

Write-Output ""
Write-Output "Удаление..."

foreach ($policy in $policiesToRemove) {
    try {
        Remove-Item -Path $policy.FullName -Force -ErrorAction Stop
        Write-Output ("Удалено: {0}" -f $policy.Name)
    } catch {
        Write-Warning ("Не удалось удалить {0}: {1}" -f $policy.Name, $_.Exception.Message)
    }
}
# --- Импорт и проверки ---
    try {
        Import-Module ConfigCI -ErrorAction Stop
    } catch {
        Write-Error "Не удалось импортировать модуль ConfigCI: $($_.Exception.Message). Убедитесь, что модуль доступен и вы запускаете PowerShell на Windows с необходимым функционалом."
        return $null
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "Рекомендуется запускать эту функцию от имени администратора."
    }

    $osDrive = $env:SystemDrive.TrimEnd('\')
    $examplePath = Join-Path $osDrive "Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll_EnableHVCI.xml"
    if (-not (Test-Path $examplePath)) {
        Write-Error "Шаблон AllowAll_EnableHVCI.xml не найден по пути: $examplePath. Укажите другой шаблон или положите примерный файл в систему."
        return $null
    }

    $outDir = "C:\WDAC"
    if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
    $outXml = Join-Path $outDir "WDACCustomPolicy.xml"
    $outCip = Join-Path $outDir "WDACCustomPolicy.cip"

    Copy-Item -Path $examplePath -Destination $outXml -Force
Write-Output ""
Write-Output "Готово."

    }




function Prepare--DevsForWDACPolicy {
    <#
    .SYNOPSIS
    Добавляет DENY signer-правила в WDAC XML и управляет режимом Audit.

    .DESCRIPTION
    ... (описание прежнее, сокращено для компактности)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$DenyDevelopers,

        [Parameter(Mandatory=$false)]
        [bool]$Audit = $true,

        [Parameter(Mandatory=$false)]
        [string]$SampleFile,

        [Parameter(Mandatory=$false)]
        [string]$PolicyPath = 'C:\WDAC\WDACCustomPolicy.xml'
    )

    begin {
        $result = [System.Collections.ArrayList]::new()

        if (-not (Test-Path -Path $PolicyPath)) {
            Throw ("Policy file '{0}' не найден. Создайте или укажите существующий XML WDAC политики." -f $PolicyPath)
        }

        try {
            Import-Module -Name ConfigCI -ErrorAction Stop
        } catch {
            Throw ("Не удалось импортировать модуль ConfigCI. Убедитесь, что вы запустили PowerShell с правами администратора и модуль доступен. Оригинальная ошибка: {0}" -f $_.Exception.Message)
        }

        try {
            $policyText = Get-Content -Path $PolicyPath -Raw -ErrorAction Stop
        } catch {
            Throw ("Не удалось прочитать '{0}': {1}" -f $PolicyPath, $_.Exception.Message)
        }
    }

    process {
        try {
            if ($Audit) {
                Write-Verbose "Ensuring Audit Mode (option 3) is present in policy."
                Set-RuleOption -FilePath $PolicyPath -Option 3 -ErrorAction Stop
                $result.Add([pscustomobject]@{Action='SetAudit';Status='Added/Ensured'}) | Out-Null
            } else {
                Write-Verbose "Removing Audit Mode (option 3) from policy."
                Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete -ErrorAction Stop
                $result.Add([pscustomobject]@{Action='SetAudit';Status='DeletedIfPresent'}) | Out-Null
            }
        } catch {
            $result.Add([pscustomobject]@{Action='SetAudit';Status='Failed';Error=$_.Exception.Message}) | Out-Null
            Write-Warning ("Не удалось изменить опцию Audit Mode: {0}" -f $_.Exception.Message)
        }

        foreach ($dev in $DenyDevelopers) {
            $item = [ordered]@{Developer = $dev; FoundCert = $false; CertSource=''; Thumbprint=''; Action='None'; Message=''}
            Write-Verbose ("Processing developer pattern: '{0}'" -f $dev)

            $storePaths = @(
                'Cert:\LocalMachine\My',
                'Cert:\LocalMachine\TrustedPublisher',
                'Cert:\LocalMachine\Root',
                'Cert:\LocalMachine\TrustedPeople',
                'Cert:\CurrentUser\My',
                'Cert:\CurrentUser\TrustedPublisher',
                'Cert:\CurrentUser\TrustedPeople'
            )

            $foundCert = $null
            foreach ($store in $storePaths) {
                try {
                    if (Test-Path $store) {
                        $candidates = Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
                            Where-Object {
                                ($_ -and $_.Subject -and $_.Subject -like "*$dev*") -or
                                ($_ -and $_.Issuer -and $_.Issuer -like "*$dev*")
                            }
                        if ($candidates) {
                            $valid = $candidates | Where-Object { $_.NotAfter -gt (Get-Date) } | Sort-Object NotAfter -Descending
                            if ($valid.Count -gt 0) { $foundCert = $valid[0]; break }
                            else { $foundCert = $candidates[0]; break }
                        }
                    }
                } catch {
                    Write-Verbose ("Ошибка при сканировании {0}: {1}" -f $store, $_.Exception.Message)
                }
            }

            if (-not $foundCert -and $SampleFile) {
                if (-not (Test-Path -Path $SampleFile)) {
                    $item.Message = ("SampleFile '{0}' не найден." -f $SampleFile)
                    Write-Warning $item.Message
                } else {
                    try {
                        $sig = Get-AuthenticodeSignature -FilePath $SampleFile -ErrorAction Stop
                        if ($sig -and $sig.SignerCertificate) {
                            $foundCert = $sig.SignerCertificate
                            $item.CertSource = ("SampleFile: {0}" -f $SampleFile)
                        } else {
                            Write-Verbose ("Подпись отсутствует или сертификат не найден в {0}." -f $SampleFile)
                        }
                    } catch {
                        Write-Verbose ("Get-AuthenticodeSignature не удался для {0}: {1}" -f $SampleFile, $_.Exception.Message)
                    }
                }
            } elseif ($foundCert) {
                $item.CertSource = "CertStore"
            }

            if ($foundCert) {
                $item.FoundCert = $true
                $item.Thumbprint = $foundCert.Thumbprint
                try {
                    $safeName = ($dev -replace '\W','')
                    $tmp = Join-Path -Path $env:TEMP -ChildPath ("wdac_signer_{0}_{1}.cer" -f $safeName, (Get-Random))
                    $bytes = $foundCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    [System.IO.File]::WriteAllBytes($tmp, $bytes)
                    $item.TempCer = $tmp

                    $policyText = Get-Content -Path $PolicyPath -Raw
                    $subjectEsc = [regex]::Escape($foundCert.Subject)
                    $thumbEsc = [regex]::Escape($foundCert.Thumbprint)
                    if ($policyText -match $thumbEsc -or $policyText -match $subjectEsc) {
                        $item.Action = 'Skipped'
                        $item.Message = 'Сертификат или его отпечаток уже присутствует в policy XML. Пропуск добавления.'
                        Remove-Item -Path $tmp -ErrorAction SilentlyContinue
                    } else {
                        try {
                            Add-SignerRule -FilePath $PolicyPath -CertificatePath $tmp -User -Deny -ErrorAction Stop
                            $item.Action = 'Added'
                            $item.Message = "Add-SignerRule выполнен (User, Deny)."
                        } catch {
                            $item.Action = 'Failed'
                            $item.Message = ("Add-SignerRule завершился с ошибкой: {0}" -f $_.Exception.Message)
                        } finally {
                            Remove-Item -Path $tmp -ErrorAction SilentlyContinue
                        }
                    }
                } catch {
                    $item.Action = 'Failed'
                    $item.Message = ("Не удалось экспортировать/записать временный .cer: {0}" -f $_.Exception.Message)
                }
            } else {
                $item.Message = ("Для шаблона '{0}' сертификат не найден ни в хранилищах, ни в SampleFile (если указан)." -f $dev)
                $item.Action = 'NoCert'
                Write-Warning $item.Message
            }

            $result.Add((New-Object PSObject -Property $item)) | Out-Null
        }
    }

    end {
    Set-HVCIOptions -FilePath "C:\WDAC\WDACCustomPolicy.xml" -Strict
        return $result
    }
}

function Prepare--DriverNamesForWDACPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$PolicyXmlPath = "C:\WDAC\WDACCustomPolicy.xml",

        [Parameter(Mandatory = $true)]
        [string[]]$PathesToDriversWithNamesToDeny,

        [Parameter(Mandatory = $false)]
        [bool]$Audit = $true
    )

    if (-not (Test-Path $PolicyXmlPath)) {
        throw "Файл политики WDAC не найден: $PolicyXmlPath"
    }

    foreach ($path in $PathesToDriversWithNamesToDeny) {
        if (-not (Test-Path $path)) {
            Write-Warning "Драйвер не найден и будет пропущен: $path"
        }
    }
    $updatedPath = "$PolicyXmlPath.updated.xml"

    # 2. Создание Deny-правил
    $rules = foreach ($driver in $PathesToDriversWithNamesToDeny) {
        if (Test-Path $driver) {
            New-CIPolicyRule `
                -DriverFilePath $driver `
                -Level FileName `
                -Deny
        }
    }

    if (-not $rules) {
        throw "Не создано ни одного правила DENY"
    }

    # 3. Merge правил в политику
    Merge-CIPolicy `
        -PolicyPaths $PolicyXmlPath `
        -Rules $rules `
        -OutputFilePath $updatedPath

    # 4. Замена исходного XML
    Move-Item -Path $updatedPath -Destination $PolicyXmlPath -Force

    # 5.
    Write-Host "DENY-правила для имён драйверов успешно добавлены."
    if ($Audit) {Set-RuleOption -FilePath $PolicyXmlPath -Option 3}
}




function Get--DevName {

    param($Path)
    Get-AuthenticodeSignature $Path | Select-Object -ExpandProperty SignerCertificate | Select-Object -ExpandProperty Subject
}
