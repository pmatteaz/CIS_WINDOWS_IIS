param (
    [string]$ActivityCode
)

# Funzione per scrivere nel log con timestamp
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$timestamp - $Message" | Out-File -FilePath C:\Temp\Rollback_IIS8.5.log -Append
}

# Directory dei file di backup
$backupDir = "C:\Temp"

# Funzione per ripristinare un'attività
function Rollback-Activity {
    param (
        [string]$ActivityCode
    )

    Write-Log "Starting rollback for activity: $ActivityCode"

    switch ($ActivityCode) {
        # Rollback per 02.03
        "2.03" {
            $sites = Get-Website | Where-Object { $_.Bindings.Collection.Protocol -notcontains "ftp" } | Select-Object -ExpandProperty Name
            foreach ($site in $sites) {
                $backupFile = Join-Path $backupDir "Backup_2.03_$site.txt"
                if (Test-Path $backupFile) {
                    $previousValue = Get-Content -Path $backupFile
                    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'requireSSL' -value $previousValue
                    Write-Log "Rolled back #2.03 for site: $site"
                } else {
                    Write-Log "Backup file for #2.03 (site: $site) not found"
                }
            }
        }

        # Rollback per 02.04
        "2.04" {
            $sites = Get-Website | Where-Object { $_.Bindings.Collection.Protocol -notcontains "ftp" } | Select-Object -ExpandProperty Name
            foreach ($site in $sites) {
                $backupFile = Join-Path $backupDir "Backup_2.04_$site.txt"
                if (Test-Path $backupFile) {
                    $previousValue = Get-Content -Path $backupFile
                    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$site" -filter 'system.web/authentication/forms' -name 'cookieless' -value $previousValue
                    Write-Log "Rolled back #2.04 for site: $site"
                } else {
                    Write-Log "Backup file for #2.04 (site: $site) not found"
                }
            }
        }

        # Rollback per 02.05
        "2.05" {
            $backupFile = Join-Path $backupDir "Backup_2.05.txt"
            if (Test-Path $backupFile) {
                $previousValue = Get-Content -Path $backupFile
                Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter 'system.web/authentication/forms' -name 'protection' -value $previousValue
                Write-Log "Rolled back #2.05"
            } else {
                Write-Log "Backup file for #2.05 not found"
            }
        }

        # Rollback per 03.06
        "3.06" {
            $backupFile = Join-Path $backupDir "Backup_3.06.txt"
            if (Test-Path $backupFile) {
                $previousValue = Get-Content -Path $backupFile
                Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter "system.web/sessionState" -name "mode" -value $previousValue
                Write-Log "Rolled back #3.06"
            } else {
                Write-Log "Backup file for #3.06 not found"
            }
        }

        # Rollback per 04.01
        "4.01" {
            $backupFile = Join-Path $backupDir "Backup_4.01.txt"
            if (Test-Path $backupFile) {
                $previousValue = Get-Content -Path $backupFile
                Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value $previousValue
                Write-Log "Rolled back #4.01"
            } else {
                Write-Log "Backup file for #4.01 not found"
            }
        }

        # Rollback per 04.02
        "4.02" {
            $backupFile = Join-Path $backupDir "Backup_4.02.txt"
            if (Test-Path $backupFile) {
                $previousValue = Get-Content -Path $backupFile
                Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value $previousValue
                Write-Log "Rolled back #4.02"
            } else {
                Write-Log "Backup file for #4.02 not found"
            }
        }

        # Rollback per 04.03
        "4.03" {
            $backupFile = Join-Path $backupDir "Backup_4.03.txt"
            if (Test-Path $backupFile) {
                $previousValue = Get-Content -Path $backupFile
                Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value $previousValue
                Write-Log "Rolled back #4.03"
            } else {
                Write-Log "Backup file for #4.03 not found"
            }
        }

        # Rollback per 04.04
        "4.04" {
            $backupFile = Join-Path $backupDir "Backup_4.04.txt"
            if (Test-Path $backupFile) {
                $previousValue = Get-Content -Path $backupFile
                Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value $previousValue
                Write-Log "Rolled back #4.04"
            } else {
                Write-Log "Backup file for #4.04 not found"
            }
        }

        # Rollback per 04.05
        "4.05" {
            $backupFile = Join-Path $backupDir "Backup_4.05.txt"
            if (Test-Path $backupFile) {
                $previousValue = Get-Content -Path $backupFile
                Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value $previousValue
                Write-Log "Rolled back #4.05"
            } else {
                Write-Log "Backup file for #4.05 not found"
            }
        }

        # Rollback per 07.05
        "7.05" {
            $backupFileServer = Join-Path $backupDir "Backup_7.05_Server.txt"
            $backupFileClient = Join-Path $backupDir "Backup_7.05_Client.txt"

            # Ripristino per TLS 1.1 Server
            if (Test-Path $backupFileServer) {
                $previousValues = Get-Content -Path $backupFileServer | ConvertFrom-Csv
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value $previousValues.Enabled
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value $previousValues.DisabledByDefault
                Write-Log "Rolled back #7.05 (Server)"
            } else {
                Write-Log "Backup file for #7.05 (Server) not found"
            }

            # Ripristino per TLS 1.1 Client
            if (Test-Path $backupFileClient) {
                $previousValues = Get-Content -Path $backupFileClient | ConvertFrom-Csv
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value $previousValues.Enabled
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value $previousValues.DisabledByDefault
                Write-Log "Rolled back #7.05 (Client)"
            } else {
                Write-Log "Backup file for #7.05 (Client) not found"
            }
        }

        # Rollback per 07.12
        "7.12" {
            $backupFile = Join-Path $backupDir "Backup_7.12.txt"
            if (Test-Path $backupFile) {
                $previousValue = Get-Content -Path $backupFile
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -Value $previousValue -PropertyType 'MultiString'
                Write-Log "Rolled back #7.12"
            } else {
                Write-Log "Backup file for #7.12 not found"
            }
        }

        default {
            Write-Log "Activity code $ActivityCode not recognized"
        }
    }

    Write-Log "Finished rollback for activity: $ActivityCode"
}

# Esegui il rollback per il codice attività specificato
Rollback-Activity -ActivityCode $ActivityCode