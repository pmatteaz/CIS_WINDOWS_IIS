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

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true,
               Position=0,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Percorso del file di input contenente i comandi da eseguire")]
    [ValidateNotNullOrEmpty()]
    [string]$InputFile
)

# Variabili
$Data = Get-Date -Format "yyyy-MM-dd"
$OutputFile = "elenco_CIS_IIS_$Data.txt"

# Funzioni
function Write-OutputFile {
    param (
        [string]$Text
    )
    Add-Content -Path $OutputFile -Value $Text
}

# Inizio script
Write-OutputFile "Data: $Data"
Write-OutputFile "Audit punti CIS IIS per Windows"
Write-OutputFile "Versione 0.1"

# Verifica iniziale del file
if (-not $InputFile) {
    Write-Error "Il parametro InputFile è obbligatorio. Specificare il percorso del file."
    exit 1
}

if (-not (Test-Path -Path $InputFile -PathType Leaf)) {
    Write-Error "Il file '$InputFile' non esiste o non è accessibile."
    exit 1
}

function Write-Log {
    param(
        [string]$Point,
        [string]$Status,
        [string]$Details
    )
    $logMessage = "Punto $Point : $Status"
    if ($Details) {
        $logMessage += " - $Details"
    }
    Write-Output $logMessage
}

function Test-CommandResult {
    param (
        [string]$Command,
        $Result
    )
    
    if ($null -eq $Result) {
        return $false
    }
    
    if ($Command -match "Get-ItemProperty") {
        return $null -ne $Result
    }
    
    if ($Command -match "Get-WebConfiguration") {
        return $true
    }
    
    return $true
}

try {
    # Leggi il contenuto del file con gestione errori
    $content = Get-Content -Path $InputFile -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($content)) {
        Write-Error "Il file è vuoto."
        exit 1
    }

    # Dividi il contenuto in sezioni basate su #D#
    $sections = $content -split "#D#" | Where-Object { $_ -match "\S" }

    if ($sections.Count -eq 0) {
        Write-Error "Nessuna sezione valida trovata nel file. Verificare il formato del file."
        exit 1
    }

    foreach ($section in $sections) {
        # Estrai il numero del punto e la descrizione
        if ($section -match "^\s*([0-9.]+)\s+(.+?)(?=#|$)") {
            $pointNumber = $Matches[1].Trim()
            $description = $Matches[2].Trim()
            
            # Estrai i comandi critici e di recovery
            $criticalCommands = [regex]::Matches($section, "(?<=#C#\s*)(.*?)(?=\s*#R#|##F)", [System.Text.RegularExpressions.RegexOptions]::Singleline).Value.Trim() -split "`r`n|`n"
            $recoveryCommands = [regex]::Matches($section, "(?<=#R#\s*)(.*?)(?=\s*##F)", [System.Text.RegularExpressions.RegexOptions]::Singleline).Value.Trim() -split "`r`n|`n"
            
            $criticalFailed = $false
            $recoveryNeeded = $false
            $recoverySuccess = $true
            $errorDetails = @()

            # Esegui i comandi critici
            foreach ($cmd in $criticalCommands) {
                $cmd = $cmd.Trim()
                if ($cmd) {
                    try {
                        Write-Verbose "Esecuzione comando critico: $cmd"
                        $result = Invoke-Expression $cmd -ErrorAction Stop
                        if (-not (Test-CommandResult -Command $cmd -Result $result)) {
                            $criticalFailed = $true
                            $recoveryNeeded = $true
                            $errorDetails += "Controllo fallito: $cmd"
                        }
                    }
                    catch {
                        $criticalFailed = $true
                        $recoveryNeeded = $true
                        $errorDetails += "Errore nell'esecuzione: $cmd - $($_.Exception.Message)"
                    }
                }
            }

            # Se necessario, esegui i comandi di recovery
            if ($recoveryNeeded) {
                foreach ($cmd in $recoveryCommands) {
                    $cmd = $cmd.Trim()
                    if ($cmd) {
                        try {
                            Write-Verbose "Esecuzione comando recovery: $cmd"
                            Invoke-Expression $cmd -ErrorAction Stop
                        }
                        catch {
                            $recoverySuccess = $false
                            $errorDetails += "Recovery fallito: $cmd - $($_.Exception.Message)"
                        }
                    }
                }
            }

            # Genera il report per questo punto
            if (-not $criticalFailed) {
                Write-Log -Point $pointNumber -Status "OK" -Details $description
            }
            elseif ($recoveryNeeded -and $recoverySuccess) {
                Write-Log -Point $pointNumber -Status "Risolto dopo recovery" -Details $description
            }
            else {
                Write-Log -Point $pointNumber -Status "Fallito" -Details ($errorDetails -join "; ")
            }
        }
    }
}
catch {
    Write-Error "Errore durante l'esecuzione dello script: $_"
    exit 1
}