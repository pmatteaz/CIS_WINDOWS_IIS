# 01.07
Write-output "#1.07" | Out-File -FilePath C:\Temp\Hardening.log
Get-WindowsFeature Web-DAV-Publishing | Out-File -FilePath C:\Temp\Hardening.log -append
Remove-WindowsFeature Web-DAV-Publishing
Write-output "#1.07 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WindowsFeature Web-DAV-Publishing | Out-File -FilePath C:\Temp\Hardening.log -append
pause

# Get all site in IIS
$sites=Get-IISSite |select name | ForEach-Object {$_.Name}

# 02.03
foreach ($site in $sites) {
	Write-output "#2.03" | Out-File -FilePath C:\Temp\Hardening.log -append
	Write-output $site | Out-File -FilePath C:\Temp\Hardening.log -append
	Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' | Format-Table $site,Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
	Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' -value 'True'
	Write-output "#2.03 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
	Write-output $site | Out-File -FilePath C:\Temp\Hardening.log -append
	Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' | Format-Table $site,Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
			}
pause
# 02.04
foreach ($site in $sites) {
	Write-output "#2.04" | Out-File -FilePath C:\Temp\Hardening.log -append
	Write-output $site | Out-File -FilePath C:\Temp\Hardening.log -append
	Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' | Out-File -FilePath C:\Temp\Hardening.log -append
	Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' -value 'UseCookies'
	Write-output "#2.04 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
	Write-output $site | Out-File -FilePath C:\Temp\Hardening.log -append
	Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' | Out-File -FilePath C:\Temp\Hardening.log -append
			}
pause
# 02.05
Write-output "#2.05" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter 'system.web/authentication/forms' -name 'protection' | Out-File -FilePath C:\Temp\Hardening.log -append
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.web/authentication/forms' -name 'protection' -value All
Write-output "#2.05 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter 'system.web/authentication/forms' -name 'protection' | Out-File -FilePath C:\Temp\Hardening.log -append
pause
# 03.06
Write-output "#3.06" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter "system.web/sessionState" -name "mode" | Out-File -FilePath C:\Temp\Hardening.log -append
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.web/sessionState" -name "mode" -value StateServer
Write-output "#3.06 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter "system.web/sessionState" -name "mode" | Out-File -FilePath C:\Temp\Hardening.log -append
pause
# 03.12
Write-output "#3.12" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath machine/webroot/apphost -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader'| Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "removeServerHeader" -value True
Write-output "#3.12 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath machine/webroot/apphost -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader'| Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
pause
# 04.01
Write-output "#4.01" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value 30000000
Write-output "#4.01 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
pause
# 04.02
Write-output "#4.02" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" | Out-File -FilePath C:\Temp\Hardening.log -append
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value 4096
Write-output "#4.02 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" | Out-File -FilePath C:\Temp\Hardening.log -append
pause
# 04.03
Write-output "#4.03" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value 2048
Write-output "#4.03 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
pause
# 04.04
Write-output "#4.04" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters' | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value False
Write-output "#4.04 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters' | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
pause
# 04.05
Write-output "#4.05" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value False
Write-output "#4.05 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" | Format-Table Name, Value | Out-File -FilePath C:\Temp\Hardening.log -append
pause
# 07.05
Write-output "#7.05" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' | Out-File -FilePath C:\Temp\Hardening.log -append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' | Out-File -FilePath C:\Temp\Hardening.log -append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' | Out-File -FilePath C:\Temp\Hardening.log -append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' | Out-File -FilePath C:\Temp\Hardening.log -append
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
Write-output "#7.05 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' | Out-File -FilePath C:\Temp\Hardening.log -append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' | Out-File -FilePath C:\Temp\Hardening.log -append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' | Out-File -FilePath C:\Temp\Hardening.log -append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' | Out-File -FilePath C:\Temp\Hardening.log -append
pause
# 07.12
Write-output "#7.12" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' | Out-File -FilePath C:\Temp\Hardening.log -append
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256' -PropertyType 'MultiString' -Force | Out-Null
Write-output "#7.12 Hardened" | Out-File -FilePath C:\Temp\Hardening.log -append
Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' | Out-File -FilePath C:\Temp\Hardening.log -append