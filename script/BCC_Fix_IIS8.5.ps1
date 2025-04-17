# 02.03
foreach ($site in $sites) {
    Write-Log "Starting #2.03 for site: $site"
    $currentValue = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL'

    # Salva il valore precedente in un file
    $backupFile = "C:\Temp\Backup_2.03_$site.txt"
    $currentValue | Out-File -FilePath $backupFile -Force

    if ($currentValue.Value -ne 'True') {
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' -value 'True'
        Write-Log "#2.03 Hardened for site: $site"
    } else {
        Write-Log "#2.03 Already Hardened for site: $site"
    }

    Write-Log "Finished #2.03 for site: $site"
    Write-Log "----------------------------------------"
}

# 02.04
foreach ($site in $sites) {
    Write-Log "Starting #2.04 for site: $site"
    $currentValue = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless'

    # Salva il valore precedente in un file
    $backupFile = "C:\Temp\Backup_2.04_$site.txt"
    $currentValue | Out-File -FilePath $backupFile -Force

    if ($currentValue -ne 'InProc') {
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' -value 'UseCookies'
        Write-Log "#2.04 Hardened for site: $site"
    } else {
        Write-Log "#2.04 Already Hardened for site: $site"
    }

    Write-Log "Finished #2.04 for site: $site"
    Write-Log "----------------------------------------"
}

# 02.05
Write-Log "Starting #2.05"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.web/authentication/forms' -name 'protection'

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_2.05.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue -ne 'All') {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.web/authentication/forms' -name 'protection' -value 'All'
    Write-Log "#2.05 Hardened"
} else {
    Write-Log "#2.05 Already Hardened"
}

Write-Log "Finished #2.05"
Write-Log "----------------------------------------"

# 03.06
Write-Log "Starting #3.06"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.web/sessionState" -name "mode"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_3.06.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue -ne 'StateServer') {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.web/sessionState" -name "mode" -value 'StateServer'
    Write-Log "#3.06 Hardened"
} else {
    Write-Log "#3.06 Already Hardened"
}

Write-Log "Finished #3.06"
Write-Log "----------------------------------------"

# 04.01
Write-Log "Starting #4.01"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_4.01.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne 30000000) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value 30000000
    Write-Log "#4.01 Hardened"
} else {
    Write-Log "#4.01 Already Hardened"
}

Write-Log "Finished #4.01"
Write-Log "----------------------------------------"

# 04.02
Write-Log "Starting #4.02"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_4.02.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne 4096) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value 4096
    Write-Log "#4.02 Hardened"
} else {
    Write-Log "#4.02 Already Hardened"
}

Write-Log "Finished #4.02"
Write-Log "----------------------------------------"

# 04.03
Write-Log "Starting #4.03"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_4.03.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne 2048) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value 2048
    Write-Log "#4.03 Hardened"
} else {
    Write-Log "#4.03 Already Hardened"
}

Write-Log "Finished #4.03"
Write-Log "----------------------------------------"

# 04.04
Write-Log "Starting #4.04"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_4.04.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne $false) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value $false
    Write-Log "#4.04 Hardened"
} else {
    Write-Log "#4.04 Already Hardened"
}

Write-Log "Finished #4.04"
Write-Log "----------------------------------------"

# 04.05
Write-Log "Starting #4.05"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_4.05.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne $false) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value $false
    Write-Log "#4.05 Hardened"
} else {
    Write-Log "#4.05 Already Hardened"
}

Write-Log "Finished #4.05"
Write-Log "----------------------------------------"

# 07.05
Write-Log "Starting #7.05"

# Salva i valori precedenti per TLS 1.1 Server
$backupFileServer = "C:\Temp\Backup_7.05_Server.txt"
$currentValueServerEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -ErrorAction SilentlyContinue
$currentValueServerDisabledByDefault = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

@{
    Enabled = $currentValueServerEnabled.Enabled
    DisabledByDefault = $currentValueServerDisabledByDefault.DisabledByDefault
} | Out-File -FilePath $backupFileServer -Force

# Salva i valori precedenti per TLS 1.1 Client
$backupFileClient = "C:\Temp\Backup_7.05_Client.txt"
$currentValueClientEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -ErrorAction SilentlyContinue
$currentValueClientDisabledByDefault = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

@{
    Enabled = $currentValueClientEnabled.Enabled
    DisabledByDefault = $currentValueClientDisabledByDefault.DisabledByDefault
} | Out-File -FilePath $backupFileClient -Force

# Applica le modifiche per TLS 1.1 Server
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null

# Applica le modifiche per TLS 1.1 Client
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null

Write-Log "Finished #7.05"
Write-Log "----------------------------------------"

# 07.12
Write-Log "Starting #7.12"

# Salva il valore precedente per le funzioni SSL
$backupFile = "C:\Temp\Backup_7.12.txt"
$currentValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -ErrorAction SilentlyContinue
$currentValue.Functions | Out-File -FilePath $backupFile -Force

# Applica le modifiche per le funzioni SSL
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -Value 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256' -PropertyType 'MultiString' -Force | Out-Null

Write-Log "Finished #7.12"
Write-Log "----------------------------------------"

















