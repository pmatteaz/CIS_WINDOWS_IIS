##.\script.ps1 -InputFile comandi.txt
##
param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile
)

if (-not (Test-Path $InputFile)) {
    Write-Error "File $InputFile non trovato"
    exit 1
}

$outputFile = "risultati_comandi.txt"
"Risultati Esecuzione Comandi" | Out-File $outputFile

$lines = Get-Content $InputFile
$currentGroup = $null
$groupCommands = @()

foreach ($line in $lines) {
    if ($line.StartsWith("#") -and -not $line.EndsWith("##F")) {
        # Nuova intestazione gruppo
        $currentGroup = $line.TrimStart("#").Trim()
        "`n=== GRUPPO: $currentGroup ===" | Add-Content $outputFile
        $groupCommands = @()
    }
    elseif ($line.Trim() -eq "##F") {
        # Fine gruppo, esegui i comandi accumulati
        foreach ($cmd in $groupCommands) {
            "--- Comando: $cmd" | Add-Content $outputFile
            try {
                $output = Invoke-Expression $cmd -ErrorAction Stop
                if ($output) {
                    $output | Out-String | Add-Content $outputFile
                }
                "Status: OK" | Add-Content $outputFile
            }
            catch {
                "ERRORE: $_" | Add-Content $outputFile
                "Status: FALLITO" | Add-Content $outputFile
            }
        }
        $groupCommands = @()
    }
    elseif (-not [string]::IsNullOrWhiteSpace($line) -and $currentGroup) {
        # Aggiungi comando al gruppo corrente
        $groupCommands += $line.Trim()
    }
}

Write-Host "Esecuzione completata. Risultati salvati in: $outputFile"
