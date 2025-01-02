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
Write-OutputFile "Audit punti CIS IIS per Windows"
Write-OutputFile "Versione 0.1"

# Leggi il file di input con i punti CIS come parametro di input
$InputFile = $args[0]
if (-not $InputFile) {
    Write-OutputFile "Errore: specificare il file di input con i punti CIS"
    exit
}
# File di input e composto da 
# #D# numero_punto - descrizione
# #C# comando per l'audit
# #R# comandi per la remediation su più righe
# ##F fine punto
$Lines = Get-Content -Path $InputFile
$Point = 0 # Punto CIS corrente
$Description = "" # Descrizione del punto CIS corrente
$Command = "" # Comando per l'audit del punto CIS corrente
$Remediation = "" # Comandi per la remediation del punto CIS corrente
# Per ogni punto verrà eseguito il comando di audit e se necessario il comando di remediation
# Viene generato in output una riga che segnala per ogni punto CIS come è andato l'audit 
# e se necessario viene eseguito il comando per la remediation con relativo output di come è andato il comando o i comandi
foreach ($Line in $Lines) {
    if ($Line -match "^#D#") {
        $Point = $Line -replace "^#D# ", ""
        Write-OutputFile "Punto CIS $Point"
    } elseif ($Line -match "^#C#") {
        $Command = $Line -replace "^#C# ", ""
        Write-OutputFile "Audit: $Command"
        $Output = Invoke-Expression $Command
        Write-OutputFile $Output
    } elseif ($Line -match "^#R#") {
        $Remediation = $Line -replace "^#R# ", ""
        Write-OutputFile "Remediation: $Remediation"
        $Output = Invoke-Expression $Remediation
        Write-OutputFile $Output
    } elseif ($Line -match "^##F") {
        Write-OutputFile "Fine punto CIS $Point"
    }
}   