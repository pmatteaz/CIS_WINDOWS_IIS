# Funzione per scrivere nel log con timestamp e separatori
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Write-Output $logMessage
    $logMessage | Out-File -FilePath C:\Temp\Hardening.log -Append
}

# Backup della configurazione IIS
Write-Log "Backup della configurazione IIS"
Backup-WebConfiguration -Name "Backup-pre-hardening"
$result = Get-WebConfiguration -Name "Backup-pre-hardening" | Format-Table -AutoSize
Write-Log "Backup presenti $result"


Write-Log "Next # 01.07 Ensure WebDav feature is disabled"

pause

# 01.07 Ensure WebDav feature is disabled
Write-Log "Starting #1.07  Ensure WebDav feature is disabled"
$currentValue = Get-WindowsFeature Web-DAV-Publishing
Write-Log "$currentValue"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_1.07.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Installed -eq $true) {
    Remove-WindowsFeature Web-DAV-Publishing
    Write-Log " #1.07 Hardened"
} else {
    Write-Log " #1.07 Already Hardened"
}

Write-Log "New Value"
$result = Get-WindowsFeature Web-DAV-Publishing

Write-Log "WebDAV Publishing Feature Status: $result"
Write-Log "Finished #1.07"
Write-Log "----------------------------------------"

Write-Log "Next #02.03 Ensure forms authentication require SSL"

pause

Write-Log "Get all site in IIS"

# Get all site in IIS
$sites = Get-IISSite | Where-Object { $_.Bindings.Protocol -ne 'ftp' } | Select-Object -ExpandProperty Name
Write-Log "$sites"

# 02.03
Write-Log "#02.03  Ensure forms authentication require SSL"

foreach ($site in $sites) {
    Write-Log "Starting #2.03 for site: $site"
    $currentValue = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL'

    # Salva il valore precedente in un file
    $backupFile = "C:\Temp\Backup_2.03_$site.txt"
    $currentValue | Out-File -FilePath $backupFile -Force
    Write-Log "Site : $site"
    Write-Log "Current Value : $currentValue"

    if ($currentValue.Value -ne 'True') {
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' -value 'True'
        Write-Log "#2.03 Hardened for site: $site"
    } else {
        Write-Log "#2.03 Already Hardened for site: $site"
    }
    Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' | Format-Table -AutoSize | Out-File -FilePath C:\Temp\Hardening.log -Append

Write-Log "New Value"

$result = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' | Format-Table -AutoSize

    Write-Log "$result"

    Write-Log "Finished #2.03 for site: $site"
    Write-Log "----------------------------------------"

}

Write-Log "Next #2.04 Ensure forms authentication is set to use cookies"

pause

# 02.04
Write-Log " #02.04 Ensure forms authentication is set to use cookies"

foreach ($site in $sites) {
    Write-Log "Starting #2.04 for site: $site"
    # Controlla il valore corrente di cookieless
    $currentValue = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless'
    Write-Log "Site: $site"
    Write-Output "Current Value:  $currentValue"

    # Salva il valore precedente in un file
    $backupFile = "C:\Temp\Backup_2.04_$site.txt"
    $currentValue | Out-File -FilePath $backupFile -Force

    if ($currentValue -ne 'UseCookies') {
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' -value 'UseCookies'
        Write-Log "#2.04 Hardened for site: $site"

    } else {
        Write-Log "#2.04 Already Hardened for site: $site"

    }

    $result = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' | Out-File -FilePath C:\Temp\Hardening.log -Append
    Write-Log "New value : $result"
    Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless'
    Write-Log "Finished #2.04 for site: $site"
    Write-Log "----------------------------------------
}

Write-Log "Next #2.05 Ensure 'cookie protection mode' is configured for forms authentication"

pause

# 02.05
Write-Log "Starting #2.05 Ensure 'cookie protection mode' is configured for forms authentication"

$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter 'system.web/authentication/forms' -name 'protection'

Write-Log "Current Value: $currentValue"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_2.05.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue -ne 'All') {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.web/authentication/forms' -name 'protection' -value 'All'
    Write-Log "#2.05 Hardened"

} else {
    Write-Log "#2.05 Already Hardened"

}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter 'system.web/authentication/forms' -name 'protection' | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "Finished #2.05"

$result = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter 'system.web/authentication/forms' -name 'protection'
Write-Log "New Value $result"
Write-Log "----------------------------------------"

Write-Output "Finished #2.05"
Write-Output "----------------------------------------"
Write-Output "Next #03.06 Ensure httpcookie mode is configured for session state"

pause

# 03.06
Write-Log "Starting #3.06"
Write-Log "#3.06  Ensure httpcookie mode is configured for session state"

foreach ($site in $sites){ 
$currentValue = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter "system.web/sessionState" -name "cookieless"
Write-Output " Current Value: $currentValue"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_3.06.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue -ne 'UseCookies') {
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter "system.web/sessionState" -name "cookieless" -value UseCookies
    Write-Log "#3.06 Hardened"

} else {
    Write-Log "#3.06 Already Hardened"

}

$result = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter "system.web/sessionState" -name "cookieless" | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "New Value: $result"
Write-Log "Finished #3.06 for site: $site"
Write-Log "----------------------------------------"

}

Write-Log "Next #03.12 Ensure Server Header is removed"

pause

# 03.12
Write-Log "Starting #3.12 Ensure Server Header is removed"

$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader'
Write-Log "Current Value: $currentValue"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_3.12.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne $true) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "removeServerHeader" -value $true
    Write-Log "#3.12 Hardened"
    $result = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader' | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
    Write-Log "New Value: $result"
} else {
    Write-Log "#3.12 Already Hardened"

}


Write-Log "Finished #3.12"
Write-Log "----------------------------------------"

Write-Log "Next #04.01 Ensure 'maxAllowedContentLength' is configured"

pause

# 04.01
Write-Log "Starting #4.01 Ensure 'maxAllowedContentLength' is configured"

$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength"

Write-Output "Current Value:  $currentValue"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_4.01.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne 30000000) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value 30000000
    Write-Log "#4.01 Hardened"
    $result = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
    Write-Log "New Value: $result"
} else {
    Write-Log "#4.01 Already Hardened"

}


Write-Log "Finished #4.01"
Write-Log "----------------------------------------"

Write-Log "Next #04.02 Ensure 'maxURL request filter' is configured"

pause

# 04.02
Write-Log "Starting #4.02 Ensure 'maxURL request filter' is configured"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl"

Write-Output "Current Value: $currentValue"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_4.02.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne 4096) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value 4096
    Write-Log "#4.02 Hardened"
    $result = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
    Write-Log "New Value: $result"
    
} else {
    Write-Log "#4.02 Already Hardened"

}


Write-Log "Finished #4.02"
Write-Log "----------------------------------------"

Write-Log "Next #04.03 Ensure MaxQueryString request filter is configured"

pause

# 04.03
Write-Log "Starting #4.03  Ensure MaxQueryString request filter is configured"

$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString"

Write-Log "Current Value: $currentValue"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_4.03.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne 2048) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value 2048
    Write-Log "#4.03 Hardened"
    $result = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
    Write-Log "New Value: $result"

} else {
    Write-Log "#4.03 Already Hardened"

}


Write-Log "Finished #4.03"
Write-Log "----------------------------------------"

Write-Log "Next #04.04 Ensure non-ASCII characters in URLs are not allowed"

pause

# 04.04
Write-Log "Starting #4.04 Ensure non-ASCII characters in URLs are not allowed"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters'

Write-Output "Current Value: $currentValue"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_4.04.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne $false) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value $false
    Write-Log "#4.04 Hardened"
    $result = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters' | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
    Write-Log "New Value: $result"
} else {
    Write-Log "#4.04 Already Hardened"

}


Write-Log "Finished #4.04"
Write-Log "----------------------------------------"

Write-Log "Next 04.05 Ensure Double-Encoded requests will be rejected"

pause

# 04.05
Write-Log "Starting #4.05 Ensure Double-Encoded requests will be rejected"

$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping"

Write-Log "Current Value: $currentValue"

# Salva il valore precedente in un file
$backupFile = "C:\Temp\Backup_4.05.txt"
$currentValue | Out-File -FilePath $backupFile -Force

if ($currentValue.Value -ne $false) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value $false
    Write-Log "#4.05 Hardened"
    $result = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
    Write-Log "New Value: $result"
} else {
    Write-Log "#4.05 Already Hardened"

}


Write-Log "Finished #4.05"
Write-Log "----------------------------------------"

Write-Log "Next #07.05 Ensure TLS 1.1 is Disabled"

pause

# 07.05
Write-Log "Starting #7.05 Ensure TLS 1.1 is Disabled"


# Controllo per TLS 1.1 Server
Write-Log "Controllo per TLS 1.1 Server"

$backupFileServer = "C:\Temp\Backup_7.05_Server.txt"
$currentValueServerEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -ErrorAction SilentlyContinue
$currentValueServerDisabledByDefault = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

Write-Log "currentValueServerEnabled.Enabled: $currentValueServerEnabled.Enabled"
Write-Log "currentValueServerDisabledByDefault.DisabledByDefault: $currentValueServerDisabledByDefault.DisabledByDefault"


# Salva i valori precedenti in un file
@{
    Enabled = $currentValueServerEnabled.Enabled
    DisabledByDefault = $currentValueServerDisabledByDefault.DisabledByDefault
} | Out-File -FilePath $backupFileServer -Force

if ($currentValueServerEnabled.Enabled -ne 0 -or $currentValueServerDisabledByDefault.DisabledByDefault -ne 1) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Log "#7.05 Hardened (Server)"

} else {
    Write-Log "#7.05 Already Hardened (Server)"

}

# Controllo per TLS 1.1 Client

Write-Log " Controllo per TLS 1.1 Client"

$backupFileClient = "C:\Temp\Backup_7.05_Client.txt"
$currentValueClientEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -ErrorAction SilentlyContinue
$currentValueClientDisabledByDefault = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

Write-Output "currentValueClientEnabled.Enabled"
$currentValueClientEnabled.Enabled

Write-Log "currentValueClientDisabledByDefault.DisabledByDefault: $currentValueClientDisabledByDefault.DisabledByDefault"

# Salva i valori precedenti in un file
@{
    Enabled = $currentValueClientEnabled.Enabled
    DisabledByDefault = $currentValueClientDisabledByDefault.DisabledByDefault
} | Out-File -FilePath $backupFileClient -Force

if ($currentValueClientEnabled.Enabled -ne 0 -or $currentValueClientDisabledByDefault.DisabledByDefault -ne 1) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Log "#7.05 Hardened (Client)"

} else {
    Write-Log "#7.05 Already Hardened (Client)"

}

Write-Log "Finished #7.05"
Write-Log "----------------------------------------"

Write-Log "Next #07.12 Ensure TLS Cipher Suite ordering is Configured"

pause


# 07.12
Write-Log "Starting #7.12  Ensure TLS Cipher Suite ordering is Configured"
#
$backupFile = "C:\Temp\Backup_7.12.txt"
$currentValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -ErrorAction SilentlyContinue

# Salva il valore precedente in un file
$currentValue.Functions | Out-File -FilePath $backupFile -Force

if ($null -eq $currentValue.Functions -or $currentValue.Functions -ne 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256') {
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -Value 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256' -PropertyType 'MultiString' -Force | Out-Null
    Write-Log "#7.12 Hardened"
    $result = Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions'
    Write-Log "New Value: $result"
} else {
    Write-Log "#7.12 Already Hardened"

}

# Controllo per TLS 1.0 e 1.1
Write-Log "Finished #7.12"
Write-Log "----------------------------------------"
# 07.12  - Fine 