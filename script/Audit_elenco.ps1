# Audit punti CIS IIS per Windows 
# Versione 0.1
# Autore: Piergiorgio Matteazzi    
# Data: 2025-01-02
# Descrizione: Script per l'audit di un server Windows con IIS installato
#              secondo i punti CIS contenuti nel documento elenco_CIS_IIS_2025-01-01.txt
#              Il file di output è un file di testo con estensione .txt contenente
#              i comandi per la remediation dove serve.
#
# Note: 
# - Lo script deve essere eseguito con privilegi di amministratore
# - Lo script deve essere eseguito in una shell PowerShell
#

$content = Get-Content ".\elenco_CIS_IIS10.txt"
$description = ""
$checkCommands = @()
$remediationCommands = @()

foreach ($line in $content) {
    if ($line -match "^#D#") {
        if ($checkCommands.Count -gt 0) {
            Write-Host "`nChecking: $description"
            $hasError = $false
            
            foreach ($cmd in $checkCommands) {
                try {
                    Write-Host "Executing check: $cmd"
                    $result = Invoke-Expression $cmd
                    Write-Host "Result: $result"
                } catch {
                    Write-Host "Error executing check: $_" -ForegroundColor Red
                    $hasError = $true
                }
            }
            
            if ($hasError -and $remediationCommands.Count -gt 0) {
                Write-Host "Applying remediation..." -ForegroundColor Yellow
                foreach ($remedy in $remediationCommands) {
                    try {
                        Write-Host "Executing: $remedy"
                        Invoke-Expression $remedy
                    } catch {
                        Write-Host "Error in remediation: $_" -ForegroundColor Red
                    }
                }
            }
            
            $checkCommands = @()
            $remediationCommands = @()
        }
        $description = $line.Substring(4)
    }
    elseif ($line -match "^#C#") {
        $checkCommands += $line.Substring(4).Trim()
    }
    elseif ($line -match "^#R#") {
        $remediationCommands += $line.Substring(4).Trim()
    }
}

# Process the last set of commands
if ($checkCommands.Count -gt 0) {
    Write-Host "`nChecking: $description"
    $hasError = $false
    
    foreach ($cmd in $checkCommands) {
        try {
            Write-Host "Executing check: $cmd"
            $result = Invoke-Expression $cmd
            Write-Host "Result: $result"
        } catch {
            Write-Host "Error executing check: $_" -ForegroundColor Red
            $hasError = $true
        }
    }
    
    if ($hasError -and $remediationCommands.Count -gt 0) {
        Write-Host "Applying remediation..." -ForegroundColor Yellow
        foreach ($remedy in $remediationCommands) {
            try {
                Write-Host "Executing: $remedy"
                Invoke-Expression $remedy
            } catch {
                Write-Host "Error in remediation: $_" -ForegroundColor Red
            }
        }
    }
}