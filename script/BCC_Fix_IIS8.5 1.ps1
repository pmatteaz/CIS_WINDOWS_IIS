# 02.03
foreach ($site in $sites) {Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' -value 'True'}
# 02.04
foreach ($site in $sites) {Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' -value 'UseCookies'}
# 02.05
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.web/authentication/forms' -name 'protection' -value All
# 03.06
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.web/sessionState" -name "mode" -value StateServer

######################################################################################################################################################################
# 03.11
#######################################################################################################################################################################
#Removing access to the iisWasKey can be done by using an aspnet_regiis.exe command. The syntax is as #follows, and is dependent on the version of .NET being used:

#	%systemroot%\Microsoft.NET\Framework<bitness (if not the 32 bit)>\<framework version>\aspnet_regiis.exe -pr iisWasKey IIS_IUSRS 

#	To remove read access to the IIS_IUSRS security group on a system using .NET Framework v2.0:

#* Open an elevated command prompt
#* Run the following aspnet_regiis.exe command:

#	%systemroot%\Microsoft.NET\Framework\v2.0.50727\aspnet_regiis.exe -pr iisWasKey IIS_IUSRS 
#
#	If running a 64-bit system, also run the following:
#
#	%systemroot%\Microsoft.NET\Framework64\v2.0.50727\aspnet_regiis.exe -pr iisWasKey IIS_IUSRS 
#
#	Note: A unique version of aspnet_regiis.exe is included with each version of the .NET Framework. Since each version of the tool applies only to its associated version of the .NET Framework, be sure to use the appropriate version of the tool.
##########################################################################################################################################################################

# 04.01
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value 30000000
# 04.02
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value 4096
# 04.03
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value 2048
# 04.04
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value False
# 04.05
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value True
# 07.05
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
# 07.12
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256' -PropertyType 'MultiString' -Force | Out-Null

















