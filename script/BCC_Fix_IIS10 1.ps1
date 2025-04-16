# Funzione per scrivere nel log con timestamp e separatori
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$timestamp - $Message" | Out-File -FilePath C:\Temp\Hardening.log -Append
}

# 01.07
Write-Log "Starting #1.07"
$currentValue = Get-WindowsFeature Web-DAV-Publishing

if ($currentValue.Installed -eq $true) {
    Remove-WindowsFeature Web-DAV-Publishing
    Write-Log "#1.07 Hardened"
} else {
    Write-Log "#1.07 Already Hardened"
}

Get-WindowsFeature Web-DAV-Publishing | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "Finished #1.07"
Write-Log "----------------------------------------"
pause

# Get all site in IIS
$sites = Get-IISSite | Where-Object { $_.Bindings.Protocol -ne 'ftp' } | Select-Object -ExpandProperty Name

# 02.03
foreach ($site in $sites) {
    Write-Log "Starting #2.03 for site: $site"
    $currentValue = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL'

    if ($currentValue.Value -ne 'True') {
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' -value 'True'
        Write-Log "#2.03 Hardened for site: $site"
    } else {
        Write-Log "#2.03 Already Hardened for site: $site"
    }

    Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' | Format-Table -AutoSize | Out-File -FilePath C:\Temp\Hardening.log -Append
    Write-Log "Finished #2.03 for site: $site"
    Write-Log "----------------------------------------"
}
pause

# 02.04
foreach ($site in $sites) {
    Write-Log "Starting #2.04 for site: $site"
    $currentValue = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless'

    if ($currentValue -ne 'UseCookies') {
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' -value 'UseCookies'
        Write-Log "#2.04 Hardened for site: $site"
    } else {
        Write-Log "#2.04 Already Hardened for site: $site"
    }

    Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' | Out-File -FilePath C:\Temp\Hardening.log -Append
    Write-Log "Finished #2.04 for site: $site"
    Write-Log "----------------------------------------"
}
pause

# 02.05
Write-Log "Starting #2.05"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter 'system.web/authentication/forms' -name 'protection'

if ($currentValue -ne 'All') {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.web/authentication/forms' -name 'protection' -value 'All'
    Write-Log "#2.05 Hardened"
} else {
    Write-Log "#2.05 Already Hardened"
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter 'system.web/authentication/forms' -name 'protection' | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "Finished #2.05"
Write-Log "----------------------------------------"
pause

# 03.06
Write-Log "Starting #3.06"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter "system.web/sessionState" -name "mode"

if ($currentValue -ne 'InProc') {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.web/sessionState" -name "mode" -value StateServer
    Write-Log "#3.06 Hardened"
} else {
    Write-Log "#3.06 Already Hardened"
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter "system.web/sessionState" -name "mode" | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "Finished #3.06"
Write-Log "----------------------------------------"
pause

# 03.12
Write-Log "Starting #3.12"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader'

if ($currentValue.Value -ne $true) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "removeServerHeader" -value $true
    Write-Log "#3.12 Hardened"
} else {
    Write-Log "#3.12 Already Hardened"
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader' | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "Finished #3.12"
Write-Log "----------------------------------------"
pause

# 04.01
Write-Log "Starting #4.01"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength"

if ($currentValue.Value -ne 30000000) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value 30000000
    Write-Log "#4.01 Hardened"
} else {
    Write-Log "#4.01 Already Hardened"
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "Finished #4.01"
Write-Log "----------------------------------------"
pause

# 04.02
Write-Log "Starting #4.02"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl"

if ($currentValue.Value -ne 4096) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value 4096
    Write-Log "#4.02 Hardened"
} else {
    Write-Log "#4.02 Already Hardened"
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "Finished #4.02"
Write-Log "----------------------------------------"
pause

# 04.03
Write-Log "Starting #4.03"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString"

if ($currentValue.Value -ne 2048) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value 2048
    Write-Log "#4.03 Hardened"
} else {
    Write-Log "#4.03 Already Hardened"
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "Finished #4.03"
Write-Log "----------------------------------------"
pause

# 04.04
Write-Log "Starting #4.04"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters'

if ($currentValue.Value -ne $false) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value $false
    Write-Log "#4.04 Hardened"
} else {
    Write-Log "#4.04 Already Hardened"
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters' | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "Finished #4.04"
Write-Log "----------------------------------------"
pause

# 04.05
Write-Log "Starting #4.05"
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping"

if ($currentValue.Value -ne $false) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value $false
    Write-Log "#4.05 Hardened"
} else {
    Write-Log "#4.05 Already Hardened"
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -Append
Write-Log "Finished #4.05"
Write-Log "----------------------------------------"
pause

# 07.05
Write-Log "Starting #7.05"

# Controllo per TLS 1.1 Server
$currentValueServerEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -ErrorAction SilentlyContinue
$currentValueServerDisabledByDefault = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

if ($currentValueServerEnabled.Enabled -ne 0 -or $currentValueServerDisabledByDefault.DisabledByDefault -ne 1) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Log "#7.05 Hardened (Server)"
} else {
    Write-Log "#7.05 Already Hardened (Server)"
}

# Controllo per TLS 1.1 Client
$currentValueClientEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -ErrorAction SilentlyContinue
$currentValueClientDisabledByDefault = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

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
pause

# 07.12
Write-Log "Starting #7.12"
$currentValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -ErrorAction SilentlyContinue

if ($null -eq $currentValue.Functions -or $currentValue.Functions -ne 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256') {
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -Value 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256' -PropertyType 'MultiString' -Force | Out-Null
    Write-Log "#7.12 Hardened"
} else {
    Write-Log "#7.12 Already Hardened"
}

Write-Log "Finished #7.12"
Write-Log "----------------------------------------"
pause