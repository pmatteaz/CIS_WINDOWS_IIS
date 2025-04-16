# 01.07
Write-output "#1.07" | Out-File -FilePath C:\Temp\Hardening.log

$currentValue = Get-WindowsFeature Web-DAV-Publishing

if ($currentValue.Installed -eq $true) {
    Remove-WindowsFeature Web-DAV-Publishing
    Write-output "#1.07 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#1.07 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
}

Get-WindowsFeature Web-DAV-Publishing | Out-File -FilePath C:\Temp\Hardening.log -append
pause

# Get all site in IIS
$sites=Get-IISSite |select name | ForEach-Object {$_.Name}

# 02.03
foreach ($site in $sites) {
    Write-output "#2.03" | Out-File -FilePath C:\Temp\Hardening.log -append
    Write-output $site | Out-File -FilePath C:\Temp\Hardening.log -append

    $currentValue = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL'

    if ($currentValue.Value -ne 'True') {
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' -value 'True'
        Write-output "#2.03 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
    } else {
        Write-output "#2.03 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
    }

    Write-output $site | Out-File -FilePath C:\Temp\Hardening.log -append
    Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' | Format-Table $site,Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
}
pause

# 02.04
foreach ($site in $sites) {
    Write-output "#2.04" | Out-File -FilePath C:\Temp\Hardening.log -append
    Write-output $site | Out-File -FilePath C:\Temp\Hardening.log -append

    $currentValue = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless'

    if ($currentValue.Value -ne 'UseCookies') {
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' -value 'UseCookies'
        Write-output "#2.04 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
    } else {
        Write-output "#2.04 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
    }

    Write-output $site | Out-File -FilePath C:\Temp\Hardening.log -append
    Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' | Out-File -FilePath C:\Temp\Hardening.log -append
}
pause

# 02.05
Write-output "#2.05" | Out-File -FilePath C:\Temp\Hardening.log -append
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter 'system.web/authentication/forms' -name 'protection'

if ($currentValue.Value -ne 'All') {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.web/authentication/forms' -name 'protection' -value 'All'
    Write-output "#2.05 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#2.05 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter 'system.web/authentication/forms' -name 'protection' | Out-File -FilePath C:\Temp\Hardening.log -append
pause

# 03.06
Write-output "#3.06" | Out-File -FilePath C:\Temp\Hardening.log -append
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter "system.web/sessionState" -name "mode"

if ($currentValue.Value -ne 'StateServer') {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.web/sessionState" -name "mode" -value StateServer
    Write-output "#3.06 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#3.06 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter "system.web/sessionState" -name "mode" | Out-File -FilePath C:\Temp\Hardening.log -append
pause

# 03.12
Write-output "#3.12" | Out-File -FilePath C:\Temp\Hardening.log -append
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader'

if ($currentValue.Value -ne $true) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "removeServerHeader" -value $true
    Write-output "#3.12 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#3.12 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader' | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
pause

# 04.01
Write-output "#4.01" | Out-File -FilePath C:\Temp\Hardening.log -append
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength"

if ($currentValue.Value -ne 30000000) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value 30000000
    Write-output "#4.01 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#4.01 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
pause

# 04.02
Write-output "#4.02" | Out-File -FilePath C:\Temp\Hardening.log -append
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl"

if ($currentValue.Value -ne 4096) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value 4096
    Write-output "#4.02 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#4.02 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" | Out-File -FilePath C:\Temp\Hardening.log -append
pause

# 04.03
Write-output "#4.03" | Out-File -FilePath C:\Temp\Hardening.log -append
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString"

if ($currentValue.Value -ne 2048) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value 2048
    Write-output "#4.03 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#4.03 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
pause

# 04.04
Write-output "#4.04" | Out-File -FilePath C:\Temp\Hardening.log -append
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters'

if ($currentValue.Value -ne $false) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value $false
    Write-output "#4.04 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#4.04 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters' | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
pause

# 04.05
Write-output "#4.05" | Out-File -FilePath C:\Temp\Hardening.log -append
$currentValue = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping"

if ($currentValue.Value -ne $false) {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value $false
    Write-output "#4.05 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#4.05 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
}

Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
pause

# 07.05
Write-output "#7.05" | Out-File -FilePath C:\Temp\Hardening.log -append

# Controllo per TLS 1.1 Server
$currentValueServerEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -ErrorAction SilentlyContinue
$currentValueServerDisabledByDefault = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

if ($currentValueServerEnabled.Enabled -ne 0 -or $currentValueServerDisabledByDefault.DisabledByDefault -ne 1) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-output "#7.05 Hardened (Server)" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#7.05 Already Hardened (Server)" | Out-File -FilePath C:\Temp\Hardening.log -append
}

# Controllo per TLS 1.1 Client
$currentValueClientEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -ErrorAction SilentlyContinue
$currentValueClientDisabledByDefault = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

if ($currentValueClientEnabled.Enabled -ne 0 -or $currentValueClientDisabledByDefault.DisabledByDefault -ne 1) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-output "#7.05 Hardened (Client)" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#7.05 Already Hardened (Client)" | Out-File -FilePath C:\Temp\Hardening.log -append
}

pause

# 07.12
Write-output "#7.12" | Out-File -FilePath C:\Temp\Hardening.log -append
$currentValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -ErrorAction SilentlyContinue

if ($null -eq $currentValue.Functions -or $currentValue.Functions -ne 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256') {
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -Value 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256' -PropertyType 'MultiString' -Force | Out-Null
    Write-output "#7.12 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
} else {
    Write-output "#7.12 Already Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
}

pause