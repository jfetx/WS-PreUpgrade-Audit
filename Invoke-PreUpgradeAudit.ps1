#Requires -Version 5.1
<#
.SYNOPSIS
    Audit de cadrage pré-migration Windows Server 2019 -> Windows Server 2025
    (AD DS, RDS, Hyper-V et rôles courants). 100 % LECTURE SEULE.

.DESCRIPTION
    Script unique, à lancer en administrateur sur CHAQUE serveur à migrer
    (hyperviseur Hyper-V, contrôleur(s) de domaine, serveur(s) RDS...).
    Il détecte automatiquement les rôles installés et n'exécute que les
    collecteurs pertinents :

      - Commun      : système, licence, matériel, prérequis WS2025 (SSE4.2/POPCNT,
                      espace disque, UEFI/TPM), stockage, réseau, rôles/fonctionnalités,
                      mises à jour, logiciels/services/tâches/pilotes tiers, sécurité,
                      stratégies appliquées, journaux d'événements, sauvegarde, impression.
      - AD DS       : forêt/domaine, niveaux fonctionnels, schéma, FSMO, DC, SYSVOL
                      (FRS/DFSR), réplication, dcdiag, comptes à risque, groupes à
                      privilèges, OS du parc, LAPS, GPO, DNS, DHCP.
      - RDS         : licences (mode, serveur, CAL, période de grâce), déploiement,
                      collections, RemoteApp, certificats, UPD/FSLogix, profils, Office.
      - Hyper-V     : hôte, vSwitch (LBFO/SET), VM, disques, checkpoints, réplication,
                      compatibilité processeur, vTPM, OS invités (KVP), surallocation.
      - Protocoles hérités (usage RÉEL d'après les journaux) : NTLMv1/NTLM (4624),
                      LDAP non signé (2887/2889), Kerberos RC4/DES (4769).

    Sorties (dans -OutputPath\Audit_<HOTE>_<date>) :
      Rapport_<HOTE>.html  rapport lisible avec synthèse, points d'attention et verdict
      audit.json           données structurées (utilisées par Merge-AuditReports.ps1)
      findings.csv         points d'attention (séparateur ;)
      csv\*.csv            chaque tableau du rapport (séparateur ;, UTF-8)
      raw\*.txt|html       sorties brutes des outils (dcdiag, repadmin, gpresult...)
      audit.log            journal d'exécution
      + archive ZIP de l'ensemble (sauf -NoZip)

    Console : affichage détaillé en temps réel (sections [n/22], sous-étapes, commandes
    externes avec durée et code retour, constats au fil de l'eau) puis récapitulatif des
    erreurs de collecte et des points CRITIQUE/ÉLEVÉ en fin d'exécution.

    Coreinfo (Sysinternals) est téléchargé automatiquement dans le dossier de sortie
    s'il est absent (désactivable : -NoDownload) ; il n'est exécuté que si sa signature
    Authenticode Microsoft est valide.

    Le script ne modifie AUCUN paramètre. Seule exception, uniquement si
    -SetupMediaPath est fourni : lancement du scan de compatibilité officiel
    Microsoft (setup.exe /compat scanonly) qui crée le dossier C:\$WINDOWS.~BT
    sans rien installer.

.PARAMETER OutputPath
    Dossier racine de sortie. Défaut : C:\AuditPreUpgrade

.PARAMETER EventDays
    Profondeur d'analyse des journaux d'événements (jours). Défaut : 14

.PARAMETER StaleDays
    Seuil d'inactivité des comptes AD (jours). Défaut : 90

.PARAMETER SetupMediaPath
    Racine du média Windows Server 2025 monté (ex. D:\). Active le scan de
    compatibilité Microsoft (setup.exe /auto upgrade /compat scanonly).

.PARAMETER SetupImageIndex
    Index d'image du média WS2025 pour le scan (1=Std Core, 2=Std Desktop,
    3=DC Core, 4=DC Desktop). Déduit automatiquement si absent.

.PARAMETER CoreinfoPath
    Chemin vers Coreinfo64.exe (Sysinternals) pour vérifier formellement
    SSE4.2/POPCNT. Ordre de recherche : ce paramètre, puis à côté du script,
    puis téléchargement automatique (sauf -NoDownload).

.PARAMETER NoDownload
    N'essaie pas de télécharger Coreinfo depuis Sysinternals (serveur sans Internet).
    Par défaut, si Coreinfo64.exe est absent, il est téléchargé dans le dossier
    de sortie (tools\), sa signature Microsoft est vérifiée, puis il est exécuté.

.PARAMETER SkipSection
    Sections à ignorer (ex. -SkipSection Events,Software).

.PARAMETER Quick
    Mode rapide : pas de taille des profils, pas de dcdiag DNS, pas de rapport
    GPO HTML complet, journaux réduits.

.PARAMETER NoZip
    Ne pas produire d'archive ZIP.

.EXAMPLE
    PS> Set-ExecutionPolicy -Scope Process Bypass -Force
    PS> .\Invoke-PreUpgradeAudit.ps1

.EXAMPLE
    PS> .\Invoke-PreUpgradeAudit.ps1 -OutputPath E:\Audit -EventDays 30 -SetupMediaPath D:\

.NOTES
    Compatibilité : Windows PowerShell 5.1 (Windows Server 2016/2019/2022/2025).
    Exécution : session PowerShell "Exécuter en tant qu'administrateur"
    (sur un DC : compte membre de Domain Admins pour un inventaire AD complet).
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $env:SystemDrive 'AuditPreUpgrade'),
    [ValidateRange(1, 365)][int]$EventDays = 14,
    [ValidateRange(7, 3650)][int]$StaleDays = 90,
    [string]$SetupMediaPath,
    [ValidateRange(0, 16)][int]$SetupImageIndex = 0,
    [string]$CoreinfoPath,
    [switch]$NoDownload,
    [ValidateSet('System', 'Hardware', 'Storage', 'Network', 'Features', 'Updates', 'Software', 'Security',
        'Policies', 'Events', 'ActiveDirectory', 'GPO', 'DNS', 'DHCP', 'RDS', 'HyperV', 'Guest',
        'OtherRoles', 'Printing', 'Backup', 'LegacyAuth', 'SetupCompat')]
    [string[]]$SkipSection = @(),
    [switch]$Quick,
    [switch]$NoZip
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

#region ===================== Initialisation =====================
$Script:AuditVersion = '1.1.0'
$Script:Start = Get-Date
$Script:HostName = $env:COMPUTERNAME
if (-not $Script:HostName) { $Script:HostName = [System.Net.Dns]::GetHostName() }
$Script:RunFolder = Join-Path $OutputPath ('Audit_{0}_{1}' -f $Script:HostName, $Script:Start.ToString('yyyyMMdd_HHmm'))
$Script:RawFolder = Join-Path $Script:RunFolder 'raw'
$Script:CsvFolder = Join-Path $Script:RunFolder 'csv'
foreach ($d in @($Script:RunFolder, $Script:RawFolder, $Script:CsvFolder)) {
    if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
}
$Script:LogFile = Join-Path $Script:RunFolder 'audit.log'
$Script:Sections = New-Object System.Collections.Generic.List[object]
$Script:Findings = New-Object System.Collections.Generic.List[object]
$Script:Current = $null
$Script:Progress = ''
$Script:ExternalLog = New-Object System.Collections.Generic.List[object]
$Script:Facts = @{}          # faits partagés entre collecteurs (ex. logiciels détectés)
$Script:SeverityOrder = @{ 'Critique' = 0; 'Eleve' = 1; 'Moyen' = 2; 'Faible' = 3; 'Info' = 4 }
$Script:SeverityLabel = @{ 'Critique' = 'CRITIQUE'; 'Eleve' = 'ÉLEVÉ'; 'Moyen' = 'MOYEN'; 'Faible' = 'FAIBLE'; 'Info' = 'INFO' }
#endregion

#region ===================== Fonctions utilitaires =====================
function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERR', 'OK', 'STEP', 'DBG', 'FIND', 'HEAD')][string]$Level = 'INFO', [string]$Color)
    $line = '{0} [{1,-4}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    if (-not $Color) { $Color = @{ INFO = 'Gray'; WARN = 'Yellow'; ERR = 'Red'; OK = 'Green'; STEP = 'DarkGray'; DBG = 'DarkGray'; FIND = 'White'; HEAD = 'Cyan' }[$Level] }
    $color = $Color
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $Script:LogFile -Value $line -Encoding UTF8 } catch { }
}

function Test-Cmd { param([string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function Import-ModuleSafe {
    param([string]$Name)
    if (Get-Module -Name $Name) { return $true }
    if (-not (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)) { return $false }
    try { Import-Module $Name -ErrorAction Stop -WarningAction SilentlyContinue -Verbose:$false | Out-Null; return $true } catch { return $false }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { $i = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop; return $i.$Name } catch { return $null }
}

function Get-RegKeyValues {
    param([string]$Path)
    try { $k = Get-Item -Path $Path -ErrorAction Stop } catch { return $null }
    $h = [ordered]@{}
    foreach ($n in $k.GetValueNames()) {
        $key = if ($n) { $n } else { '(Défaut)' }
        $h[$key] = $k.GetValue($n)
    }
    return $h
}

function Format-Value {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { if ($Value.Year -lt 1900) { return $null }; return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [enum]) { return $Value.ToString() }
    if ($Value -is [timespan]) { return ('{0}j {1:00}h{2:00}' -f $Value.Days, $Value.Hours, $Value.Minutes) }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or
        $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [byte] -or $Value -is [single]) { return $Value }
    if ($Value -is [byte[]]) { return (($Value | ForEach-Object { $_.ToString('X2') }) -join '') }
    if ($Value -is [System.Collections.IDictionary]) {
        return ((@($Value.Keys) | ForEach-Object { '{0}={1}' -f $_, (Format-Value $Value[$_]) }) -join '; ')
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return ((@($Value) | ForEach-Object { Format-Value $_ }) -join '; ')
    }
    return $Value.ToString()
}

function ConvertTo-FlatObject {
    param($InputObject)
    $excluded = '^(PSComputerName|PSShowComputerName|CimClass|CimInstanceProperties|CimSystemProperties|RunspaceId|PSSourceJobInstanceId)$'
    foreach ($o in $InputObject) {
        if ($null -eq $o) { continue }
        if ($o -is [string] -or $o -is [ValueType]) { [pscustomobject]@{ Valeur = (Format-Value $o) }; continue }
        $h = [ordered]@{}
        foreach ($p in $o.PSObject.Properties) {
            if ($p.MemberType -notin @('Property', 'NoteProperty', 'ScriptProperty')) { continue }
            if ($p.Name -match $excluded) { continue }
            $v = $null
            try { $v = $p.Value } catch { $v = '<erreur lecture>' }
            $h[$p.Name] = Format-Value $v
        }
        [pscustomobject]$h
    }
}

function Get-SafeFileName { param([string]$Name) return (($Name -replace '[^\w\-]+', '_').Trim('_')) }

function Add-Table {
    param([string]$Title, $Data, [string]$Note, [switch]$NoCsv)
    if ($null -eq $Script:Current) { return }
    $rows = @(ConvertTo-FlatObject $Data)
    $Script:Current.Items.Add([pscustomobject]@{ Type = 'table'; Title = $Title; Data = $rows; Note = $Note })
    if (-not $NoCsv -and $rows.Count -gt 0) {
        $file = Join-Path $Script:CsvFolder ((Get-SafeFileName ('{0}_{1}' -f $Script:Current.Id, $Title)) + '.csv')
        try { $rows | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 -Delimiter ';' } catch { }
    }
}

function Add-KV {
    param([string]$Title, [System.Collections.IDictionary]$Data, [string]$Note)
    if ($null -eq $Data) { return }
    $rows = foreach ($k in @($Data.Keys)) { [pscustomobject]@{ 'Propriété' = $k; 'Valeur' = (Format-Value $Data[$k]) } }
    if ($null -eq $Script:Current) { return }
    $Script:Current.Items.Add([pscustomobject]@{ Type = 'kv'; Title = $Title; Data = @($rows); Note = $Note })
    $file = Join-Path $Script:CsvFolder ((Get-SafeFileName ('{0}_{1}' -f $Script:Current.Id, $Title)) + '.csv')
    try { @($rows) | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 -Delimiter ';' } catch { }
}

function Add-Raw {
    param([string]$Title, [string]$Text, [string]$FileName, [int]$MaxHtmlChars = 60000)
    if (-not $FileName) { $FileName = (Get-SafeFileName $Title) + '.txt' }
    $path = Join-Path $Script:RawFolder $FileName
    try { Set-Content -Path $path -Value $Text -Encoding UTF8 } catch { }
    if ($null -eq $Script:Current) { return }
    $shown = $Text
    if ($shown -and $shown.Length -gt $MaxHtmlChars) { $shown = $shown.Substring(0, $MaxHtmlChars) + "`r`n[... tronqué, voir raw\$FileName ...]" }
    $Script:Current.Items.Add([pscustomobject]@{ Type = 'raw'; Title = $Title; Data = $shown; Note = "raw\$FileName" })
}

function Add-Note {
    param([string]$Text)
    if ($null -eq $Script:Current) { return }
    $Script:Current.Items.Add([pscustomobject]@{ Type = 'note'; Title = ''; Data = $Text; Note = $null })
}

function Add-Finding {
    param(
        [ValidateSet('Critique', 'Eleve', 'Moyen', 'Faible', 'Info')][string]$Severity,
        [string]$Area, [string]$Title, [string]$Detail, [string]$Recommendation
    )
    $Script:Findings.Add([pscustomobject]@{
            Host           = $Script:HostName
            Severity       = $Severity
            Area           = $Area
            Title          = $Title
            Detail         = $Detail
            Recommendation = $Recommendation
        })
    $fc = @{ Critique = 'Red'; Eleve = 'DarkYellow'; Moyen = 'Yellow'; Faible = 'DarkCyan'; Info = 'DarkGray' }[$Severity]
    Write-Log ('      -> [{0}] {1}' -f $Script:SeverityLabel[$Severity], $Title) 'FIND' $fc
}

function Invoke-External {
    <# Exécute un binaire avec délai maximal, capture stdout+stderr (encodage OEM). #>
    param([string]$FilePath, [string]$Arguments = '', [int]$TimeoutSec = 300)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        try {
            $enc = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
            $psi.StandardOutputEncoding = $enc; $psi.StandardErrorEncoding = $enc
        } catch { }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log ('      exec : {0} {1}' -f $FilePath, $Arguments) 'DBG'
        $p = [System.Diagnostics.Process]::Start($psi)
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            try { $p.Kill() } catch { }
            Write-Log ('      ! {0} {1} : délai de {2} s dépassé, processus arrêté' -f $FilePath, $Arguments, $TimeoutSec) 'WARN'
            $Script:ExternalLog.Add([pscustomobject]@{ Commande = "$FilePath $Arguments"; 'Durée (s)' = $TimeoutSec; Code = 'TIMEOUT' })
            if ($Script:Current) { $Script:Current.Errors.Add("Délai dépassé : $FilePath $Arguments") }
            return "[DÉLAI DÉPASSÉ après $TimeoutSec s : $FilePath $Arguments]`r`n" + $o.Result
        }
        $p.WaitForExit()
        $sw.Stop()
        $lvl = if ($p.ExitCode -ne 0) { 'WARN' } else { 'DBG' }
        Write-Log ('      exec : {0} terminé en {1:N1} s (code {2})' -f (Split-Path $FilePath -Leaf), $sw.Elapsed.TotalSeconds, $p.ExitCode) $lvl
        $Script:ExternalLog.Add([pscustomobject]@{ Commande = "$FilePath $Arguments"; 'Durée (s)' = [math]::Round($sw.Elapsed.TotalSeconds, 1); Code = $p.ExitCode })
        $txt = $o.Result
        if ($e.Result) { $txt += "`r`n[stderr]`r`n" + $e.Result }
        return $txt
    } catch {
        Write-Log ('      ! impossible d''exécuter {0} : {1}' -f $FilePath, $_.Exception.Message) 'WARN'
        if ($Script:Current) { $Script:Current.Errors.Add("Exécution impossible : $FilePath ($($_.Exception.Message))") }
        return "[ERREUR exécution $FilePath $Arguments : $($_.Exception.Message)]"
    }
}

function Invoke-Step {
    <# Exécute une sous-étape : toute erreur est consignée dans la section sans interrompre l'audit. #>
    param([string]$Name, [scriptblock]$Script)
    $ErrorActionPreference = 'Stop'
    Write-Log ('   > {0}' -f $Name) 'STEP'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $null = & $Script
        $sw.Stop()
        if ($sw.Elapsed.TotalSeconds -ge 5) { Write-Log ('   < {0} ({1:N1} s)' -f $Name, $sw.Elapsed.TotalSeconds) 'STEP' }
    }
    catch {
        $msg = '{0} : {1} (ligne {2})' -f $Name, $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber
        if ($Script:Current) { $Script:Current.Errors.Add($msg) }
        Write-Log "   ! ÉCHEC $msg" 'WARN'
    }
}

function Invoke-Collector {
    param([string]$Id, [string]$Title, [scriptblock]$Body, [bool]$When = $true)
    if ($SkipSection -contains $Id) { Write-Log "$($Script:Progress) [$Id] ignorée (-SkipSection)" 'WARN'; return }
    if (-not $When) { Write-Log "$($Script:Progress) [$Id] non applicable (rôle non détecté)" 'DBG'; return }
    $fBefore = $Script:Findings.Count
    $sec = [pscustomobject]@{
        Id          = $Id
        Title       = $Title
        Items       = (New-Object System.Collections.Generic.List[object])
        Errors      = (New-Object System.Collections.Generic.List[string])
        DurationSec = 0
    }
    $Script:Current = $sec
    Write-Host ''
    Write-Log "$($Script:Progress) [$Id] $Title" 'HEAD'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { $null = & $Body }
    catch { $m = '{0} (ligne {1})' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber; $sec.Errors.Add("Erreur collecteur : $m"); Write-Log "   ! $m" 'ERR' }
    $sw.Stop()
    $sec.DurationSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $nf = $Script:Findings.Count - $fBefore
    $lvl = if ($sec.Errors.Count) { 'WARN' } else { 'OK' }
    Write-Log ('   = [{0}] terminé en {1} s : {2} constat(s), {3} erreur(s) de collecte' -f $Id, $sec.DurationSec, $nf, $sec.Errors.Count) $lvl
    $Script:Sections.Add($sec)
    $Script:Current = $null
}

function Get-DirectorySizeGB {
    param([string]$Path)
    try {
        $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        return [math]::Round(($sum / 1GB), 2)
    } catch { return $null }
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-OSLanguageName {
    param($Lcid)
    try { return [System.Globalization.CultureInfo]::GetCultureInfo([int]$Lcid).Name } catch { return "$Lcid" }
}
#endregion

function Get-CoreinfoPath {
    <#
      Retourne le chemin d'un Coreinfo64.exe utilisable :
      1) -CoreinfoPath  2) à côté du script  3) téléchargement Sysinternals (sauf -NoDownload)
      Le binaire téléchargé n'est exécuté que si sa signature Authenticode est valide ET émise pour Microsoft.
    #>
    if ($CoreinfoPath) {
        if (Test-Path $CoreinfoPath) { Write-Log "   Coreinfo fourni : $CoreinfoPath" 'DBG'; return $CoreinfoPath }
        Write-Log "   -CoreinfoPath introuvable : $CoreinfoPath" 'WARN'
    }
    if ($PSScriptRoot) {
        foreach ($c in @((Join-Path $PSScriptRoot 'Coreinfo64.exe'), (Join-Path $PSScriptRoot 'Coreinfo.exe'))) {
            if (Test-Path $c) { Write-Log "   Coreinfo trouvé à côté du script : $c" 'DBG'; return $c }
        }
    }
    if ($NoDownload) { Write-Log '   Coreinfo absent et -NoDownload : vérification SSE4.2/POPCNT par l''API Windows uniquement.' 'WARN'; return $null }

    $dir = Join-Path $Script:RunFolder 'tools'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $exe = Join-Path $dir 'Coreinfo64.exe'
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    $sources = @(
        @{ Url = 'https://download.sysinternals.com/files/Coreinfo.zip'; Zip = $true },
        @{ Url = 'https://live.sysinternals.com/Coreinfo64.exe'; Zip = $false }
    )
    foreach ($s in $sources) {
        try {
            Write-Log "   Téléchargement de Coreinfo : $($s.Url)" 'INFO'
            $target = if ($s.Zip) { Join-Path $dir 'Coreinfo.zip' } else { $exe }
            $iwr = @{ Uri = $s.Url; OutFile = $target; UseBasicParsing = $true; TimeoutSec = 30; ErrorAction = 'Stop' }
            if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('ProxyUseDefaultCredentials')) {
                $proxy = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy([uri]$s.Url)
                if ($proxy -and $proxy.AbsoluteUri -ne $s.Url) { $iwr.Proxy = $proxy.AbsoluteUri; $iwr.ProxyUseDefaultCredentials = $true; Write-Log "   via proxy $($proxy.AbsoluteUri)" 'DBG' }
            }
            Invoke-WebRequest @iwr
            if ($s.Zip) { Expand-Archive -Path $target -DestinationPath $dir -Force -ErrorAction Stop }
            if (Test-Path $exe) { break }
        } catch { Write-Log "   ! Échec du téléchargement ($($s.Url)) : $($_.Exception.Message)" 'WARN' }
    }
    if (-not (Test-Path $exe)) {
        Write-Log '   Coreinfo indisponible (pas d''accès Internet ?). Copier Coreinfo64.exe à côté du script pour une vérification formelle.' 'WARN'
        return $null
    }
    $sig = Get-AuthenticodeSignature -FilePath $exe
    if ($sig.Status -ne 'Valid' -or "$($sig.SignerCertificate.Subject)" -notmatch 'O=Microsoft Corporation') {
        Write-Log ("   ! Signature de Coreinfo64.exe NON valide ({0} / {1}) : fichier supprimé, non exécuté." -f $sig.Status, $sig.SignerCertificate.Subject) 'ERR'
        Remove-Item $exe -Force -ErrorAction SilentlyContinue
        return $null
    }
    Write-Log ("   Coreinfo téléchargé, signature Microsoft valide ({0})" -f $sig.SignerCertificate.Subject) 'OK'
    return $exe
}

#region ===================== Contexte et détection des rôles =====================
function Initialize-Context {
    $Script:CS = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $Script:OS = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $Script:BIOS = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $Script:CV = Get-RegKeyValues 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if (-not $Script:CV) { $Script:CV = [ordered]@{} }

    $Script:Features = @()
    if (Test-Cmd 'Get-WindowsFeature') {
        try { $Script:Features = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed }) } catch { }
    }

    $model = '{0} {1}' -f $Script:CS.Manufacturer, $Script:CS.Model
    $vm = $null
    switch -Regex ($model) {
        'Microsoft Corporation Virtual Machine' { $vm = 'Hyper-V'; break }
        'VMware' { $vm = 'VMware'; break }
        'VirtualBox|innotek' { $vm = 'VirtualBox'; break }
        'QEMU|KVM|Proxmox|Red Hat|oVirt' { $vm = 'KVM/QEMU (Proxmox...)'; break }
        'Xen|Citrix' { $vm = 'Xen'; break }
        'Nutanix' { $vm = 'Nutanix AHV'; break }
        'Amazon EC2' { $vm = 'AWS EC2'; break }
        'Google Compute' { $vm = 'Google Cloud'; break }
    }
    $Script:VMPlatform = $vm

    function Test-Feature([string]$n) { return [bool]($Script:Features | Where-Object { $_.Name -eq $n }) }
    $Script:Roles = [ordered]@{
        IsDC          = ([int]$Script:CS.DomainRole -ge 4)
        IsHyperV      = (Test-Feature 'Hyper-V')
        IsRDSH        = (Test-Feature 'RDS-RD-Server')
        IsRDLicensing = (Test-Feature 'RDS-Licensing')
        IsRDBroker    = (Test-Feature 'RDS-Connection-Broker')
        IsRDWeb       = (Test-Feature 'RDS-Web-Access')
        IsRDGateway   = (Test-Feature 'RDS-Gateway')
        IsDNS         = (Test-Feature 'DNS')
        IsDHCP        = (Test-Feature 'DHCP')
        IsADCS        = (Test-Feature 'ADCS-Cert-Authority')
        IsFileServer  = (Test-Feature 'FS-FileServer')
        IsPrintServer = (Test-Feature 'Print-Server')
        IsIIS         = (Test-Feature 'Web-Server')
        IsWSUS        = (Test-Feature 'UpdateServices')
        IsCluster     = (Test-Feature 'Failover-Clustering')
        IsVM          = [bool]$vm
    }
    $Script:Roles.IsRDS = ($Script:Roles.IsRDSH -or $Script:Roles.IsRDLicensing -or $Script:Roles.IsRDBroker -or $Script:Roles.IsRDWeb -or $Script:Roles.IsRDGateway)
    $Script:RoleLabels = [ordered]@{
        IsDC = 'Contrôleur de domaine'; IsHyperV = 'Hôte Hyper-V'; IsRDSH = 'RDS Hôte de session'; IsRDLicensing = 'RDS Licences'
        IsRDBroker = 'RDS Service Broker'; IsRDWeb = 'RDS Accès Web'; IsRDGateway = 'RDS Passerelle'; IsDNS = 'Serveur DNS'
        IsDHCP = 'Serveur DHCP'; IsADCS = 'Autorité de certification'; IsFileServer = 'Serveur de fichiers'; IsPrintServer = "Serveur d'impression"
        IsIIS = 'IIS'; IsWSUS = 'WSUS'; IsCluster = 'Cluster de basculement'; IsVM = 'Machine virtuelle'
    }
}
#endregion

#region ===================== Collecteurs communs =====================
function Invoke-SystemCollector {
    Invoke-Collector -Id 'System' -Title 'Système, édition et licence' -Body {
        $os = $Script:OS; $cs = $Script:CS; $cv = $Script:CV
        $domainRoles = @{ 0 = 'Station autonome'; 1 = 'Station membre'; 2 = 'Serveur autonome'; 3 = 'Serveur membre'; 4 = 'Contrôleur de domaine (secondaire)'; 5 = 'Contrôleur de domaine (PDC)' }
        $uptime = $null; if ($os -and $os.LastBootUpTime) { $uptime = (Get-Date) - $os.LastBootUpTime }
        $netRel = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' 'Release'
        $netVer = if ($netRel -ge 533320) { '4.8.1' } elseif ($netRel -ge 528040) { '4.8' } elseif ($netRel -ge 461808) { '4.7.2' } elseif ($netRel -ge 461308) { '4.7.1' } elseif ($netRel) { '< 4.7.1' } else { 'inconnu' }
        $osLang = Get-OSLanguageName $os.OSLanguage
        $sysLocale = $null; try { $sysLocale = (Get-WinSystemLocale).Name } catch { }
        $tz = $null; try { $tz = (Get-TimeZone).Id } catch { }
        $who = $null; try { $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { }
        $fqdn = if ($cs.PartOfDomain) { '{0}.{1}' -f $env:COMPUTERNAME, $cs.Domain } else { $env:COMPUTERNAME }
        $Script:Facts.OSLanguage = $osLang

        Add-KV 'Identification et version' ([ordered]@{
                'Nom d''hôte'                    = $env:COMPUTERNAME
                'FQDN'                           = $fqdn
                'Domaine / groupe de travail'    = $cs.Domain
                'Rôle domaine'                   = $domainRoles[[int]$cs.DomainRole]
                'Système'                        = $os.Caption
                'Version'                        = $os.Version
                'Build complet (Build.UBR)'      = ('{0}.{1}' -f $cv.CurrentBuild, $cv.UBR)
                'EditionID'                      = $cv.EditionID
                'Type d''installation'           = $cv.InstallationType
                'Architecture'                   = $os.OSArchitecture
                'Date d''installation'           = $os.InstallDate
                'Dernier démarrage'              = $os.LastBootUpTime
                'Uptime'                         = $uptime
                'Langue de base OS'              = $osLang
                'Langues MUI installées'         = $os.MUILanguages
                'Locale système'                 = $sysLocale
                'Fuseau horaire'                 = $tz
                'Fabricant'                      = $cs.Manufacturer
                'Modèle'                         = $cs.Model
                'N° de série / BIOS'             = ('{0} / {1} {2}' -f $Script:BIOS.SerialNumber, $Script:BIOS.Manufacturer, $Script:BIOS.SMBIOSBIOSVersion)
                'Plateforme virtuelle détectée'  = $(if ($Script:VMPlatform) { $Script:VMPlatform } else { 'Aucune (physique)' })
                'RAM totale (Go)'                = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
                'Windows PowerShell'             = $PSVersionTable.PSVersion.ToString()
                '.NET Framework 4.x'             = ('{0} (Release {1})' -f $netVer, $netRel)
                'Compte d''exécution de l''audit' = $who
                'Administrateur'                 = (Test-IsAdmin)
            })

        $roleRows = foreach ($k in $Script:RoleLabels.Keys) { [pscustomobject]@{ 'Rôle' = $Script:RoleLabels[$k]; 'Détecté' = [bool]$Script:Roles[$k] } }
        Add-Table 'Rôles détectés (pilotent les collecteurs exécutés)' $roleRows -NoCsv

        Invoke-Step 'Licence Windows' {
            $lic = @(Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction Stop)
            $status = @{ 0 = 'Sans licence'; 1 = 'Activé'; 2 = 'Grâce OOB'; 3 = 'Grâce OOT'; 4 = 'Grâce non authentique'; 5 = 'Notification'; 6 = 'Grâce étendue' }
            $rows = foreach ($l in $lic) {
                [pscustomobject]@{
                    Nom = $l.Name; Description = $l.Description; Canal = $l.ProductKeyChannel; 'Clé (partielle)' = $l.PartialProductKey
                    Statut = $status[[int]$l.LicenseStatus]; 'Serveur KMS' = $l.KeyManagementServiceMachine; 'Grâce restante (min)' = $l.GracePeriodRemaining
                }
            }
            Add-Table 'Licence Windows' $rows
            foreach ($l in $lic) {
                if ([int]$l.LicenseStatus -ne 1) { Add-Finding Eleve 'Licence' 'Windows non activé' "Statut : $($status[[int]$l.LicenseStatus])" 'Activer Windows avant toute mise à niveau.' }
                if ($l.ProductKeyChannel -match 'OEM') { Add-Finding Info 'Licence' 'Licence OEM' "Canal : $($l.ProductKeyChannel). Une licence OEM 2019 est liée au matériel et ne couvre pas WS2025." 'Prévoir une licence Windows Server 2025 (OEM/CSP/Volume) avant la migration.' }
            }
        }

        if ($cv.EditionID -match 'Eval') {
            Add-Finding Critique 'Édition' "Édition d'évaluation détectée ($($cv.EditionID))" 'La mise à niveau sur place depuis une édition Evaluation n''est pas supportée.' 'Convertir en édition commerciale (DISM /online /Set-Edition) avant l''upgrade, ou réinstaller.'
        }
        if ($cv.CurrentBuild -and [int]$cv.CurrentBuild -ne 17763) {
            Add-Finding Info 'Système' "Build $($cv.CurrentBuild) (et non 17763 / WS2019)" 'Le script cible WS2019 mais reste applicable.' 'Vérifier le chemin de mise à niveau supporté vers WS2025.'
        }
        Add-Finding Info 'Mise à niveau' 'Contraintes de la mise à niveau sur place 2019 → 2025' ("Langue de base : {0} ; type d'installation : {1} ; édition : {2}." -f $osLang, $cv.InstallationType, $cv.EditionID) "Utiliser un média WS2025 de MÊME langue ($osLang), même édition (Standard→Standard / Datacenter→Datacenter) et même type (Server Core / Expérience de bureau), sinon les applications et paramètres ne sont pas conservés."
        if ($uptime -and $uptime.TotalDays -gt 45) {
            Add-Finding Moyen 'Système' ("Uptime élevé : {0:N0} jours" -f $uptime.TotalDays) 'Un redémarrage n''a pas été testé depuis longtemps (services qui ne redémarrent pas, MAJ en attente).' 'Faire un redémarrage contrôlé AVANT la fenêtre de migration pour valider le retour à l''état nominal.'
        }
        if (-not $cs.PartOfDomain) { Add-Finding Info 'Système' 'Serveur hors domaine (groupe de travail)' "Groupe de travail : $($cs.Workgroup)" 'Normal pour un hyperviseur isolé ; vérifier les comptes locaux utilisés pour la gestion.' }
        if ($netRel -and $netRel -lt 528040) { Add-Finding Faible 'Système' ".NET Framework $netVer" 'WS2025 embarque .NET 4.8.1 ; certaines applications métier peuvent réagir.' 'Vérifier la compatibilité des applications .NET avec 4.8.1.' }
        Add-Finding Info 'Licence' 'Licences Windows Server 2025 à prévoir' 'Licence par cœur (min. 8 cœurs/processeur, 16 cœurs/serveur ; Standard = 2 VM Windows par licence complète de l''hôte) + CAL Windows Server 2025 (utilisateur ou périphérique).' 'Chiffrer licences cœurs + CAL WS2025 (+ CAL RDS 2025 si RDS) dans le cadrage.'

        Invoke-Step 'systeminfo' { Add-Raw 'systeminfo' (Invoke-External 'systeminfo.exe' '' 180) 'systeminfo.txt' }
        Invoke-Step 'whoami' { Add-Raw 'whoami /all (contexte d''exécution)' (Invoke-External 'whoami.exe' '/all' 30) 'whoami_all.txt' }
    }
}

function Invoke-HardwareCollector {
    Invoke-Collector -Id 'Hardware' -Title 'Matériel et prérequis Windows Server 2025' -Body {
        $req = New-Object System.Collections.Generic.List[object]
        function Add-Req($n, $min, $val, $ok) { $req.Add([pscustomobject]@{ 'Prérequis' = $n; 'Attendu' = $min; 'Détecté' = $val; 'Statut' = $ok }) }

        Invoke-Step 'Processeurs' {
            $cpus = @(Get-CimInstance Win32_Processor -ErrorAction Stop)
            Add-Table 'Processeurs' ($cpus | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, SocketDesignation, AddressWidth, VirtualizationFirmwareEnabled, SecondLevelAddressTranslationExtensions, VMMonitorModeExtensions)
            $cores = ($cpus | Measure-Object NumberOfCores -Sum).Sum
            $Script:Facts.PhysicalCores = $cores
            $Script:Facts.Sockets = $cpus.Count
            Add-Req 'Processeur 64 bits ≥ 1,4 GHz' 'x64, 1,4 GHz' ('{0} bits, {1} MHz' -f $cpus[0].AddressWidth, $cpus[0].MaxClockSpeed) $(if ($cpus[0].AddressWidth -eq 64 -and $cpus[0].MaxClockSpeed -ge 1400) { 'OK' } else { 'À VÉRIFIER' })
            if (-not $Script:Roles.IsVM) {
                $lic = [math]::Max(16, [math]::Max($cores, 8 * $cpus.Count))
                Add-Req 'Cœurs à licencier (hôte physique)' 'max(16, cœurs physiques, 8 × CPU)' "$cores cœurs / $($cpus.Count) CPU → $lic cœurs à licencier" 'INFO'
                $slat = $cpus[0].SecondLevelAddressTranslationExtensions
                if ($Script:Roles.IsHyperV) { $slat = $true } # sur un hôte Hyper-V actif, WMI renvoie souvent False alors que SLAT est utilisé
                Add-Req 'SLAT (EPT/NPT)' 'Oui' $slat $(if ($slat) { 'OK' } else { 'À VÉRIFIER' })
            }
        }

        Invoke-Step 'Jeux d''instructions CPU' {
            $res = [ordered]@{}
            try {
                if (-not ('AuditNative.Cpu' -as [type])) {
                    Add-Type -Namespace AuditNative -Name Cpu -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool IsProcessorFeaturePresent(uint ProcessorFeature);' -ErrorAction Stop
                }
                $pf = [ordered]@{ 'SSE2' = 10; 'NX / DEP' = 12; 'SSE3' = 13; 'CMPXCHG16B' = 14; 'SLAT' = 20; 'Virtualisation firmware' = 21; 'SSSE3' = 36; 'SSE4.1' = 37; 'SSE4.2' = 38; 'AVX' = 39; 'AVX2' = 40 }
                $rows = foreach ($k in $pf.Keys) { $v = [AuditNative.Cpu]::IsProcessorFeaturePresent([uint32]$pf[$k]); $res[$k] = $v; [pscustomobject]@{ Instruction = $k; 'Constante PF' = $pf[$k]; 'Présente (API)' = $v } }
                Add-Table 'Instructions CPU (IsProcessorFeaturePresent)' $rows -Note 'Sur WS2019, les constantes ≥ 36 peuvent ne pas être reconnues par le noyau (réponse False par défaut) : un False sur SSSE3/SSE4.x/AVX n''est donc pas forcément une absence réelle. Coreinfo fait foi.'
            } catch {
                Write-Log "   ! API IsProcessorFeaturePresent indisponible : $($_.Exception.Message)" 'WARN'
                $Script:Current.Errors.Add("API IsProcessorFeaturePresent : $($_.Exception.Message)")
            }

            $sse42 = $null; $popcnt = $null; $src = 'API Windows'
            $ci = Get-CoreinfoPath
            if ($ci) {
                $out = Invoke-External $ci '-accepteula -f' 60
                Add-Raw 'Coreinfo -f' $out 'coreinfo.txt'
                if ($out -match '(?m)^SSE4\.2\s+([\*\-])') { $sse42 = ($Matches[1] -eq '*'); $src = 'Coreinfo' }
                if ($out -match '(?m)^POPCNT\s+([\*\-])') { $popcnt = ($Matches[1] -eq '*') }
            } else {
                if ($res['SSE4.2']) { $sse42 = $true }
                elseif ($res['SSE4.1'] -or $res['SSSE3'] -or $res['AVX']) { $sse42 = $false }   # le noyau connaît les constantes récentes et dit non
            }
            $Script:Facts.SSE42 = $sse42
            $label = if ($sse42 -eq $true) { 'OK' } elseif ($sse42 -eq $false) { 'BLOQUANT' } else { 'INDÉTERMINÉ' }
            Add-Req 'SSE4.2 + POPCNT (nouveau prérequis WS2025)' 'Présents' ("SSE4.2={0} ; POPCNT={1} (source : {2})" -f $sse42, $popcnt, $src) $label
            if ($sse42 -eq $false -or $popcnt -eq $false) {
                Add-Finding Critique 'Prérequis CPU' 'SSE4.2 / POPCNT non exposés au système' "Source : $src. WS2025 exige SSE4.2 et POPCNT : l'installation/upgrade échoue ou le système ne démarre pas." $(if ($Script:VMPlatform -eq 'Hyper-V') { 'Sur l''hôte Hyper-V : VM éteinte, Set-VMProcessor -CompatibilityForMigrationEnabled $false, puis revérifier.' } else { 'Vérifier le CPU / le masquage d''instructions (mode compatibilité EVC/migration de l''hyperviseur).' })
            } elseif ($null -eq $sse42) {
                Add-Finding Moyen 'Prérequis CPU' 'Présence de SSE4.2 / POPCNT non confirmée' 'L''API de WS2019 ne permet pas de conclure et Coreinfo n''a pas pu être téléchargé/exécuté (pas d''accès Internet ?). WS2025 exige SSE4.2 et POPCNT (CPU post-2008 en général, mais masquables en VM).' 'Copier Coreinfo64.exe (Sysinternals) à côté du script et relancer, ou exécuter « Coreinfo64.exe -accepteula -f » ; sur VM Hyper-V vérifier que la compatibilité processeur pour la migration est désactivée.'
            }
        }

        Invoke-Step 'Mémoire' {
            $ramGB = [math]::Round($Script:CS.TotalPhysicalMemory / 1GB, 1)
            $core = ($Script:CV.InstallationType -eq 'Server Core')
            $min = if ($core) { 0.5 } else { 2 }
            Add-Req 'Mémoire vive' ("≥ {0} Go ({1})" -f $min, $(if ($core) { 'Core' } else { 'Bureau' })) "$ramGB Go" $(if ($ramGB -ge $min) { 'OK' } else { 'BLOQUANT' })
            if (-not $Script:Roles.IsVM) {
                Add-Table 'Barrettes mémoire' (Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel, DeviceLocator, @{n = 'CapacitéGo'; e = { [math]::Round($_.Capacity / 1GB, 1) } }, Speed, Manufacturer, PartNumber)
            }
        }

        Invoke-Step 'Firmware / Secure Boot' {
            $bcd = Invoke-External 'bcdedit.exe' '/enum {current}' 30
            $uefi = $bcd -match 'winload\.efi'
            $sb = $null
            try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sb = $null }
            $Script:Facts.UEFI = $uefi
            Add-Req 'Firmware UEFI' 'UEFI 2.3.1c (recommandé, requis pour Secure Boot)' $(if ($uefi) { 'UEFI' } else { 'BIOS hérité' }) $(if ($uefi) { 'OK' } else { 'RECOMMANDÉ' })
            Add-Req 'Secure Boot' 'Activé (recommandé)' $(if ($null -eq $sb) { 'Non pris en charge / inconnu' } else { $sb }) $(if ($sb) { 'OK' } else { 'RECOMMANDÉ' })
            Add-Raw 'bcdedit /enum {current}' $bcd 'bcdedit_current.txt'
            if (-not $uefi -and $Script:Roles.IsVM -and $Script:VMPlatform -eq 'Hyper-V') {
                Add-Finding Info 'Matériel' 'VM de génération 1 (BIOS)' 'Supporté par WS2025 mais sans Secure Boot / vTPM / démarrage UEFI.' 'Pour un nouveau serveur (migration side-by-side), créer une VM génération 2.'
            }
        }

        Invoke-Step 'TPM' {
            $tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
            if ($tpm) {
                Add-Table 'TPM' ($tpm | Select-Object IsEnabled_InitialValue, IsActivated_InitialValue, IsOwned_InitialValue, SpecVersion, ManufacturerIdTxt, ManufacturerVersion)
                Add-Req 'TPM 2.0' 'Recommandé (requis pour certaines fonctions de sécurité)' $tpm.SpecVersion $(if ($tpm.SpecVersion -match '^2') { 'OK' } else { 'RECOMMANDÉ' })
            } else { Add-Req 'TPM 2.0' 'Recommandé' 'Absent / non exposé' 'RECOMMANDÉ' }
        }

        Invoke-Step 'VBS / Device Guard' {
            $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
            if ($dg) {
                $vbs = @{ 0 = 'Désactivé'; 1 = 'Activé, non actif'; 2 = 'Actif' }
                Add-KV 'Sécurité basée sur la virtualisation (VBS)' ([ordered]@{
                        'Statut VBS'                 = $vbs[[int]$dg.VirtualizationBasedSecurityStatus]
                        'Services configurés'        = $dg.SecurityServicesConfigured
                        'Services actifs'            = $dg.SecurityServicesRunning
                        'Propriétés de sécurité dispo' = $dg.AvailableSecurityProperties
                    }) -Note 'Services : 1 = Credential Guard, 2 = HVCI (intégrité mémoire).'
            }
        }

        Invoke-Step 'Disque système' {
            $sys = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive) -ErrorAction Stop
            $sizeGB = [math]::Round($sys.Size / 1GB, 1); $freeGB = [math]::Round($sys.FreeSpace / 1GB, 1)
            $Script:Facts.SystemFreeGB = $freeGB
            Add-Req 'Taille du volume système' '≥ 32 Go (≥ 64 Go conseillé)' "$sizeGB Go" $(if ($sizeGB -ge 64) { 'OK' } elseif ($sizeGB -ge 32) { 'LIMITE' } else { 'BLOQUANT' })
            Add-Req 'Espace libre pour l''upgrade' '≥ 30 Go conseillé' "$freeGB Go" $(if ($freeGB -ge 30) { 'OK' } elseif ($freeGB -ge 20) { 'LIMITE' } else { 'BLOQUANT' })
            if ($freeGB -lt 20) { Add-Finding Critique 'Stockage' "Espace libre insuffisant sur $($env:SystemDrive) ($freeGB Go)" 'Une mise à niveau sur place nécessite ~20-30 Go libres (image, Windows.old, rollback).' 'Libérer de l''espace (Dism /Online /Cleanup-Image /StartComponentCleanup, nettoyage profils/logs) ou étendre le disque.' }
            elseif ($freeGB -lt 30) { Add-Finding Moyen 'Stockage' "Espace libre limite sur $($env:SystemDrive) ($freeGB Go)" 'Marge faible pour l''upgrade et Windows.old.' 'Prévoir ≥ 30 Go libres avant l''upgrade.' }
            if ($sizeGB -lt 32) { Add-Finding Critique 'Stockage' "Volume système trop petit ($sizeGB Go)" 'WS2025 requiert 32 Go minimum.' 'Étendre le disque système.' }
        }
        Add-Table 'Synthèse des prérequis Windows Server 2025' $req
    }
}

function Invoke-StorageCollector {
    Invoke-Collector -Id 'Storage' -Title 'Stockage' -Body {
        Invoke-Step 'Disques' {
            $disks = @(Get-Disk -ErrorAction Stop)
            Add-Table 'Disques' ($disks | Select-Object Number, FriendlyName, SerialNumber, BusType, PartitionStyle, @{n = 'TailleGo'; e = { [math]::Round($_.Size / 1GB, 1) } }, HealthStatus, OperationalStatus, IsBoot, IsSystem, IsOffline, IsReadOnly)
            foreach ($d in $disks) {
                if ($d.HealthStatus -and "$($d.HealthStatus)" -ne 'Healthy') { Add-Finding Eleve 'Stockage' "Disque $($d.Number) en état $($d.HealthStatus)" "$($d.FriendlyName) / $($d.OperationalStatus)" 'Corriger l''état du stockage avant toute opération.' }
                if ($d.IsBoot -and "$($d.PartitionStyle)" -eq 'MBR' -and -not $Script:Roles.IsVM) { Add-Finding Info 'Stockage' 'Disque de démarrage MBR (BIOS hérité)' 'Upgrade possible, mais pas de Secure Boot.' 'À considérer en cas de réinstallation (GPT/UEFI).' }
            }
        }
        if (-not $Script:Roles.IsVM) {
            Invoke-Step 'Disques physiques' { Add-Table 'Disques physiques' (Get-PhysicalDisk -ErrorAction Stop | Select-Object DeviceId, FriendlyName, MediaType, BusType, @{n = 'TailleGo'; e = { [math]::Round($_.Size / 1GB, 1) } }, HealthStatus, OperationalStatus, FirmwareVersion, SerialNumber) }
            Invoke-Step 'Storage Spaces' { $p = @(Get-StoragePool -IsPrimordial $false -ErrorAction SilentlyContinue); if ($p.Count) { Add-Table 'Pools de stockage' ($p | Select-Object FriendlyName, HealthStatus, OperationalStatus, @{n = 'TailleGo'; e = { [math]::Round($_.Size / 1GB, 1) } }, @{n = 'AllouéGo'; e = { [math]::Round($_.AllocatedSize / 1GB, 1) } }) } }
        }
        Invoke-Step 'Volumes' {
            $vols = @(Get-Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 'Fixed' -and $_.Size -gt 0 })
            $rows = foreach ($v in $vols) {
                $pct = if ($v.Size) { [math]::Round(100 * $v.SizeRemaining / $v.Size, 1) } else { $null }
                [pscustomobject]@{ Lettre = $v.DriveLetter; Nom = $v.FileSystemLabel; FS = $v.FileSystem; TailleGo = [math]::Round($v.Size / 1GB, 1); LibreGo = [math]::Round($v.SizeRemaining / 1GB, 1); 'Libre %' = $pct; Santé = $v.HealthStatus; Dedup = $v.DedupMode }
                if ($v.DriveLetter -and $v.Size -gt 2GB) {
                    if ($pct -lt 10) { Add-Finding Eleve 'Stockage' "Volume $($v.DriveLetter): presque plein ($pct % libre)" ("{0:N1} Go libres sur {1:N1} Go" -f ($v.SizeRemaining / 1GB), ($v.Size / 1GB)) 'Libérer/étendre avant migration (VHDX dynamiques, logs, profils).' }
                    elseif ($pct -lt 20) { Add-Finding Moyen 'Stockage' "Volume $($v.DriveLetter): peu d'espace libre ($pct %)" '' 'Surveiller ; prévoir de la marge pour snapshots/exports.' }
                }
            }
            Add-Table 'Volumes' $rows
        }
        Invoke-Step 'Partitions' { Add-Table 'Partitions' (Get-Partition -ErrorAction Stop | Select-Object DiskNumber, PartitionNumber, DriveLetter, Type, @{n = 'TailleGo'; e = { [math]::Round($_.Size / 1GB, 2) } }, IsBoot, IsSystem, IsActive, GptType) }
        Invoke-Step 'BitLocker' {
            if (Test-Cmd 'Get-BitLockerVolume') {
                $bl = @(Get-BitLockerVolume -ErrorAction Stop)
                Add-Table 'BitLocker' ($bl | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod, EncryptionPercentage, LockStatus, @{n = 'Protecteurs'; e = { ($_.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', ' } })
                $on = @($bl | Where-Object { "$($_.ProtectionStatus)" -eq 'On' })
                if ($on.Count) { Add-Finding Moyen 'Stockage' ("BitLocker actif sur {0}" -f (($on.MountPoint) -join ', ')) 'L''upgrade suspend normalement BitLocker, mais une demande de clé de récupération reste possible.' 'Sauvegarder les clés de récupération (manage-bde -protectors -get C:) et les vérifier dans AD/coffre avant la migration.' }
            } else { Add-Note 'BitLocker : fonctionnalité non installée.' }
        }
        Invoke-Step 'Fichier d''échange' {
            Add-Table 'Fichier d''échange' (Get-CimInstance Win32_PageFileUsage -ErrorAction Stop | Select-Object Name, AllocatedBaseSize, CurrentUsage, PeakUsage)
        }
        Invoke-Step 'Clichés instantanés (VSS)' { Add-Raw 'vssadmin list shadowstorage' (Invoke-External 'vssadmin.exe' 'list shadowstorage' 60) 'vss_shadowstorage.txt' }
        Invoke-Step 'Déduplication' { if (Test-Cmd 'Get-DedupVolume') { $d = @(Get-DedupVolume -ErrorAction SilentlyContinue); if ($d.Count) { Add-Table 'Déduplication' ($d | Select-Object Volume, Enabled, UsageType, SavingsRate, @{n = 'GainGo'; e = { [math]::Round($_.SavedSpace / 1GB, 1) } }) } } }
    }
}

function Invoke-NetworkCollector {
    Invoke-Collector -Id 'Network' -Title 'Réseau' -Body {
        Invoke-Step 'Cartes réseau' {
            Add-Table 'Cartes réseau' (Get-NetAdapter -ErrorAction Stop | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, VlanID, DriverProvider, DriverVersion, @{n = 'DriverDate'; e = { $_.DriverDate } }, ifIndex)
        }
        Invoke-Step 'Adresses IP' {
            Add-Table 'Adresses IP' (Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.IPAddress -notmatch '^(127\.|::1|fe80)' } | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength, PrefixOrigin, SuffixOrigin, AddressState)
            $dhcp = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { "$($_.PrefixOrigin)" -eq 'Dhcp' })
            if ($dhcp.Count -and ($Script:Roles.IsDC -or $Script:Roles.IsHyperV -or $Script:Roles.IsDNS)) { Add-Finding Eleve 'Réseau' 'Adresse IP en DHCP sur un serveur d''infrastructure' (($dhcp | ForEach-Object { "$($_.InterfaceAlias)=$($_.IPAddress)" }) -join ', ') 'Configurer une adresse IP statique.' }
        }
        Invoke-Step 'Passerelles / routes' { Add-Table 'Routes (hors liens locaux)' (Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -notmatch '^(ff00|fe80|127\.|224\.|255\.)' -and $_.DestinationPrefix -notmatch '/32$|/128$' } | Select-Object InterfaceAlias, DestinationPrefix, NextHop, RouteMetric, Protocol) }
        Invoke-Step 'Client DNS' {
            $dns = @(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { $_.ServerAddresses })
            Add-Table 'Serveurs DNS configurés' ($dns | Select-Object InterfaceAlias, AddressFamily, @{n = 'Serveurs'; e = { $_.ServerAddresses -join ', ' } })
            Add-Table 'Suffixes / enregistrement DNS' (Get-DnsClient -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionSpecificSuffix -or $_.RegisterThisConnectionsAddress } | Select-Object InterfaceAlias, ConnectionSpecificSuffix, RegisterThisConnectionsAddress, UseSuffixWhenRegistering)
            $v4 = @($dns | Where-Object { [int]$_.AddressFamily -eq 2 })
            if ($Script:Roles.IsDC) {
                foreach ($d in $v4) {
                    if ($d.ServerAddresses[0] -match '^127\.') { Add-Finding Faible 'DNS' "DC : DNS principal = boucle locale sur $($d.InterfaceAlias)" 'Microsoft recommande un autre DC en premier et 127.0.0.1 en secondaire (si plusieurs DC).' 'Ajuster l''ordre DNS (après ajout d''un 2e DC).' }
                }
            }
            foreach ($d in $v4) { if (@($d.ServerAddresses | Where-Object { $_ -match '^(8\.8\.|1\.1\.1\.|9\.9\.9\.|208\.67\.)' }).Count -and $Script:CS.PartOfDomain) { Add-Finding Moyen 'DNS' "DNS public configuré sur $($d.InterfaceAlias) (machine du domaine)" ($d.ServerAddresses -join ', ') 'Les membres du domaine ne doivent pointer que vers les DNS AD (les redirecteurs se configurent sur le serveur DNS).' } }
        }
        Invoke-Step 'IPv6' {
            $b = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop)
            Add-Table 'Liaison IPv6' ($b | Select-Object Name, Enabled)
            if ($Script:Roles.IsDC -and @($b | Where-Object { -not $_.Enabled }).Count) { Add-Finding Faible 'Réseau' 'IPv6 désactivé sur une carte d''un DC' 'Microsoft ne recommande pas de désactiver IPv6 (préférer DisabledComponents=0x20 si besoin).' 'Documenter le choix ; ne pas le reproduire sur le nouveau serveur sans raison.' }
        }
        Invoke-Step 'Teaming LBFO' {
            if (Test-Cmd 'Get-NetLbfoTeam') {
                $t = @(Get-NetLbfoTeam -ErrorAction SilentlyContinue)
                if ($t.Count) {
                    Add-Table 'Équipes LBFO' ($t | Select-Object Name, TeamingMode, LoadBalancingAlgorithm, Status, @{n = 'Membres'; e = { $_.Members -join ', ' } })
                    $Script:Facts.LbfoTeams = $t
                    Add-Finding Moyen 'Réseau' 'Teaming LBFO utilisé' (($t.Name) -join ', ') 'LBFO est déprécié ; lié à un vSwitch Hyper-V il n''est plus supporté depuis WS2022 (voir section Hyper-V).' 'Prévoir la migration vers SET (Switch Embedded Teaming) ou un teaming natif adapté.'
                } else { Add-Note 'Aucune équipe LBFO.' }
            }
        }
        Invoke-Step 'Profils réseau' {
            $np = @(Get-NetConnectionProfile -ErrorAction Stop)
            Add-Table 'Profils de connexion' ($np | Select-Object InterfaceAlias, Name, NetworkCategory, IPv4Connectivity)
            if ($Script:CS.PartOfDomain -and @($np | Where-Object { "$($_.NetworkCategory)" -ne 'DomainAuthenticated' }).Count) { Add-Finding Moyen 'Réseau' 'Carte(s) non détectée(s) en profil Domaine' (($np | Where-Object { "$($_.NetworkCategory)" -ne 'DomainAuthenticated' } | ForEach-Object { "$($_.InterfaceAlias)=$($_.NetworkCategory)" }) -join ', ') 'Vérifier NLA (service NlaSvc, DNS) : un mauvais profil applique les mauvaises règles de pare-feu.' }
        }
        Invoke-Step 'Pare-feu' {
            $fw = @(Get-NetFirewallProfile -ErrorAction Stop)
            Add-Table 'Profils pare-feu' ($fw | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName)
            $off = @($fw | Where-Object { -not $_.Enabled -or "$($_.Enabled)" -eq 'False' })
            if ($off.Count) { Add-Finding Moyen 'Sécurité' ("Pare-feu Windows désactivé : {0}" -f (($off.Name) -join ', ')) '' 'Réactiver le pare-feu (règles adaptées) ; à intégrer dans la cible WS2025.' }
            $rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $null -or $_.Group -eq '' })
            Add-Table 'Règles entrantes personnalisées (hors groupes Windows)' ($rules | Select-Object DisplayName, Profile, Action, Direction, @{n = 'Ports'; e = { ($_ | Get-NetFirewallPortFilter).LocalPort -join ',' } }, @{n = 'Protocole'; e = { ($_ | Get-NetFirewallPortFilter).Protocol } }, @{n = 'Sources'; e = { ($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ',' } })
        }
        Invoke-Step 'Ports en écoute' {
            $procs = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
            $tcp = Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalPort -Unique | Select-Object LocalAddress, LocalPort, OwningProcess, @{n = 'Processus'; e = { $procs[[int]$_.OwningProcess] } }
            Add-Table 'Ports TCP en écoute' $tcp
            $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -lt 49152 } | Sort-Object LocalPort -Unique | Select-Object LocalAddress, LocalPort, OwningProcess, @{n = 'Processus'; e = { $procs[[int]$_.OwningProcess] } }
            Add-Table 'Ports UDP (< 49152)' $udp
            $est = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' }
            $g = $est | Group-Object RemoteAddress, LocalPort | Sort-Object Count -Descending | Select-Object -First 100 | ForEach-Object {
                $f = $_.Group[0]; [pscustomobject]@{ 'IP distante' = $f.RemoteAddress; 'Port local' = $f.LocalPort; 'Port distant (ex.)' = $f.RemotePort; Connexions = $_.Count; Processus = $procs[[int]$f.OwningProcess] }
            }
            Add-Table 'Flux établis (cartographie des dépendances, top 100)' $g -Note 'Photographie à l''instant T : utile pour identifier les clients/serveurs dépendants à prévenir avant la coupure.'
        }
        Invoke-Step 'SMB' {
            $srv = Get-SmbServerConfiguration -ErrorAction Stop
            $cli = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
            Add-KV 'Configuration SMB' ([ordered]@{
                    'Serveur SMB1 activé'          = $srv.EnableSMB1Protocol
                    'Serveur SMB2/3 activé'        = $srv.EnableSMB2Protocol
                    'Serveur : signature exigée'   = $srv.RequireSecuritySignature
                    'Serveur : signature activée'  = $srv.EnableSecuritySignature
                    'Serveur : chiffrement exigé'  = $srv.EncryptData
                    'Client : signature exigée'    = $cli.RequireSecuritySignature
                    'Client : signature activée'   = $cli.EnableSecuritySignature
                    'Client : invités non sécurisés' = $cli.EnableInsecureGuestLogons
                })
            if ($srv.EnableSMB1Protocol) { Add-Finding Eleve 'Sécurité' 'SMBv1 activé côté serveur' 'SMB1 n''est pas installé par défaut sous WS2025 ; des clients anciens (copieurs, NAS, applis) peuvent en dépendre.' 'Activer l''audit SMB1 (Set-SmbServerConfiguration -AuditSmb1Access $true), identifier les clients, puis désactiver.' }
            if (-not $cli.RequireSecuritySignature) { Add-Finding Moyen 'Compatibilité' 'Signature SMB : comportement plus strict sous WS2025' 'WS2025 exige par défaut la signature SMB pour les connexions sortantes et durcit les accès invités ; des NAS/copieurs (scan vers dossier) ou partages anciens peuvent échouer.' 'Inventorier NAS/copieurs/partages tiers et tester la signature SMB avant la bascule.' }
            if ($cli.EnableInsecureGuestLogons) { Add-Finding Moyen 'Sécurité' 'Connexions invité SMB non sécurisées autorisées' 'Désactivées par défaut sous WS2025 : les accès invités à des NAS échoueront.' 'Configurer des comptes sur les NAS concernés.' }
            $shares = @(Get-SmbShare -ErrorAction Stop)
            $Script:Facts.Shares = $shares
            Add-Table 'Partages SMB' ($shares | Select-Object Name, Path, Description, ShareType, Special, FolderEnumerationMode, CachingMode, EncryptData, CurrentUsers)
            $acc = foreach ($s in ($shares | Where-Object { -not $_.Special })) { Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | Select-Object Name, AccountName, AccessControlType, AccessRight }
            Add-Table 'Permissions de partage' $acc
            $sess = @(Get-SmbSession -ErrorAction SilentlyContinue)
            Add-Table 'Sessions SMB ouvertes' ($sess | Select-Object ClientComputerName, ClientUserName, NumOpens, Dialect, SecondsExists)
        }
        Invoke-Step 'Proxy / hosts' {
            Add-Raw 'netsh winhttp show proxy' (Invoke-External 'netsh.exe' 'winhttp show proxy' 30) 'winhttp_proxy.txt'
            $h = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
            $lines = @(Get-Content $h -ErrorAction Stop | Where-Object { $_ -match '^\s*[^#\s]' })
            if ($lines.Count) { Add-Table 'Entrées actives du fichier hosts' $lines; Add-Finding Faible 'Réseau' "Fichier hosts personnalisé ($($lines.Count) entrées)" ($lines -join ' | ') 'Reporter/valider ces entrées sur la cible.' }
        }
        Invoke-Step 'ipconfig /all' { Add-Raw 'ipconfig /all' (Invoke-External 'ipconfig.exe' '/all' 30) 'ipconfig_all.txt' }
    }
}

function Invoke-FeaturesCollector {
    Invoke-Collector -Id 'Features' -Title 'Rôles et fonctionnalités Windows' -Body {
        Add-Table 'Rôles, services de rôle et fonctionnalités installés' ($Script:Features | Select-Object Name, DisplayName, FeatureType, Path, Depth)
        # Source : learn.microsoft.com - Features removed or no longer developed starting with Windows Server 2025
        $map = @(
            @{ N = 'Web-Lgcy-Mgmt-Console'; S = 'Eleve'; T = 'Console de gestion IIS 6 (SUPPRIMÉE dans WS2025)'; R = 'Supprimer la dépendance (anciens outils SMTP/métabase) avant upgrade.' }
            @{ N = 'SMTP-Server'; S = 'Eleve'; T = 'Serveur SMTP (SUPPRIMÉ dans WS2025, sans remplacement)'; R = 'Migrer le relais SMTP (relais tiers, hMailServer/Postfix, service cloud) avant upgrade.' }
            @{ N = 'PowerShell-V2'; S = 'Moyen'; T = 'Moteur Windows PowerShell 2.0 (SUPPRIMÉ)'; R = 'Vérifier qu''aucun script/outil ne lance powershell -Version 2.' }
            @{ N = 'FS-SMB1'; S = 'Eleve'; T = 'Support SMB 1.0/CIFS installé'; R = 'Identifier les clients SMB1 et supprimer la fonctionnalité.' }
            @{ N = 'WINS'; S = 'Moyen'; T = 'Serveur WINS (déprécié)'; R = 'Planifier l''abandon de WINS (DNS / GlobalNames zone).' }
            @{ N = 'UpdateServices'; S = 'Moyen'; T = 'WSUS (déprécié, plus de nouvelles fonctionnalités)'; R = 'Fonctionne encore sous WS2025 ; envisager Azure Update Manager / Intune / autre solution à moyen terme.' }
            @{ N = 'WebDAV-Redirector'; S = 'Faible'; T = 'Redirecteur WebDAV (déprécié)'; R = 'Vérifier l''usage.' }
            @{ N = 'DirectAccess-VPN'; S = 'Faible'; T = 'DirectAccess/VPN RRAS'; R = 'DirectAccess est déprécié : vérifier l''usage réel.' }
            @{ N = 'Telnet-Client'; S = 'Faible'; T = 'Client Telnet'; R = 'Réinstallable si nécessaire.' }
            @{ N = 'NLB'; S = 'Faible'; T = 'Équilibrage de charge réseau (NLB)'; R = 'Vérifier la configuration NLB et sa reprise.' }
        )
        foreach ($m in $map) {
            if ($Script:Features | Where-Object { $_.Name -eq $m.N }) { Add-Finding $m.S 'Fonctionnalités' $m.T "Fonctionnalité installée : $($m.N)" $m.R }
        }
        $roleCount = @($Script:Features | Where-Object { "$($_.FeatureType)" -eq 'Role' }).Count
        $combo = @()
        if ($Script:Roles.IsHyperV) { foreach ($k in 'IsDC', 'IsRDSH', 'IsRDBroker', 'IsRDLicensing', 'IsDHCP', 'IsFileServer', 'IsPrintServer') { if ($Script:Roles[$k] -and $k -ne 'IsFileServer') { $combo += $Script:RoleLabels[$k] } } }
        if ($combo.Count) { Add-Finding Eleve 'Architecture' 'Rôles applicatifs installés sur l''hôte Hyper-V' ($combo -join ', ') 'Bonne pratique : l''hôte Hyper-V ne porte QUE Hyper-V. Profiter de la migration pour déplacer ces rôles dans des VM.' }
        if ($Script:Roles.IsDC -and $Script:Roles.IsRDSH) { Add-Finding Eleve 'Architecture' 'Hôte de session RDS installé sur un contrôleur de domaine' 'Configuration non recommandée (sécurité : utilisateurs ouvrant une session sur un DC ; performances ; mise à niveau plus risquée).' 'Séparer : nouveau DC 2025 dédié + serveur RDS 2025 dédié.' }
        Add-Note "$roleCount rôle(s) installé(s)."
    }
}

function Invoke-UpdatesCollector {
    Invoke-Collector -Id 'Updates' -Title 'Mises à jour et état de redémarrage' -Body {
        Invoke-Step 'Correctifs' {
            $hf = @(Get-HotFix -ErrorAction Stop | Sort-Object { try { [datetime]$_.InstalledOn } catch { [datetime]::MinValue } } -Descending)
            Add-Table 'Correctifs installés (Get-HotFix)' ($hf | Select-Object HotFixID, Description, InstalledOn, InstalledBy)
            $last = $hf | Where-Object { $_.InstalledOn } | Select-Object -First 1
            $Script:Facts.LastPatch = $last.InstalledOn
            if ($last -and $last.InstalledOn) {
                $age = ((Get-Date) - [datetime]$last.InstalledOn).Days
                if ($age -gt 60) { Add-Finding Eleve 'Mises à jour' "Dernier correctif installé il y a $age jours ($($last.HotFixID))" 'Le serveur n''est pas à jour.' 'Appliquer la dernière mise à jour cumulative (CU + SSU) avant l''upgrade : prérequis de stabilité et de rollback.' }
                elseif ($age -gt 35) { Add-Finding Moyen 'Mises à jour' "Dernier correctif installé il y a $age jours" '' 'Appliquer la CU du mois avant l''upgrade.' }
            }
        }
        Invoke-Step 'Redémarrage en attente' {
            $pend = [ordered]@{
                'CBS RebootPending'          = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
                'WindowsUpdate RebootRequired' = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
                'PendingFileRenameOperations' = [bool](Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')
                'Renommage ordinateur en attente' = ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName') -ne (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'))
                'Jonction domaine en attente' = (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\JoinDomain')
            }
            Add-KV 'Indicateurs de redémarrage en attente' $pend
            $any = @($pend.Values | Where-Object { $_ }).Count
            if ($any) { Add-Finding Eleve 'Mises à jour' 'Redémarrage en attente' (($pend.Keys | Where-Object { $pend[$_] }) -join ', ') 'Redémarrer et revérifier avant l''upgrade (le setup peut refuser de démarrer).' }
        }
        Invoke-Step 'Source des mises à jour' {
            $wu = Get-RegKeyValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            $au = Get-RegKeyValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            if ($wu) { Add-KV 'Stratégie Windows Update (WSUS...)' $wu } else { Add-Note 'Aucune stratégie WSUS/Windows Update : mises à jour directes depuis Microsoft.' }
            if ($au) { Add-KV 'Stratégie Windows Update (AU)' $au }
            if ($wu -and $wu['WUServer']) { Add-Finding Info 'Mises à jour' "Serveur WSUS : $($wu['WUServer'])" 'Après upgrade, le produit "Windows Server 2025" doit être activé dans la console WSUS.' 'Ajouter la classification/produit WS2025 dans WSUS avant la bascule.' }
        }
        Invoke-Step 'Historique Windows Update' {
            $s = New-Object -ComObject Microsoft.Update.Session
            $sr = $s.CreateUpdateSearcher()
            $n = $sr.GetTotalHistoryCount()
            if ($n -gt 0) {
                $res = @{ 0 = 'Non démarré'; 1 = 'En cours'; 2 = 'Réussi'; 3 = 'Réussi avec erreurs'; 4 = 'Échec'; 5 = 'Annulé' }
                $hist = $sr.QueryHistory(0, [math]::Min($n, 80)) | ForEach-Object { [pscustomobject]@{ Date = $_.Date.ToLocalTime(); Titre = $_.Title; 'Résultat' = $res[[int]$_.ResultCode]; HResult = ('0x{0:X8}' -f $_.HResult) } }
                Add-Table 'Historique Windows Update (80 derniers)' $hist
                $fail = @($hist | Where-Object { $_.'Résultat' -eq 'Échec' -and $_.Date -gt (Get-Date).AddDays(-60) })
                if ($fail.Count) { Add-Finding Moyen 'Mises à jour' "$($fail.Count) échec(s) d'installation de mises à jour sur 60 jours" (($fail | Select-Object -First 5 | ForEach-Object { $_.Titre }) -join ' | ') 'Résoudre les échecs (DISM /RestoreHealth, SFC) : un magasin de composants corrompu fait échouer l''upgrade.' }
            }
        }
        Invoke-Step 'Santé du magasin de composants' {
            $o = Invoke-External 'dism.exe' '/Online /Cleanup-Image /CheckHealth' 180
            Add-Raw 'DISM /CheckHealth' $o 'dism_checkhealth.txt'
            # « No component store corruption detected » / « Aucun endommagement » = cas sain : ne pas matcher corrupt/endommag
            if ($o -match 'is repairable|not repairable|peut .tre r.par|n.est pas r.parable') { Add-Finding Eleve 'Mises à jour' 'Magasin de composants Windows endommagé (DISM CheckHealth)' '' 'Exécuter DISM /Online /Cleanup-Image /RestoreHealth puis sfc /scannow avant l''upgrade.' }
        }
    }
}

function Invoke-SoftwareCollector {
    Invoke-Collector -Id 'Software' -Title 'Logiciels, services, tâches planifiées et pilotes' -Body {
        Invoke-Step 'Logiciels installés' {
            $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
            $apps = foreach ($p in $paths) {
                Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName } |
                    Select-Object @{n = 'Nom'; e = { $_.DisplayName } }, @{n = 'Version'; e = { $_.DisplayVersion } }, @{n = 'Éditeur'; e = { $_.Publisher } }, @{n = 'Installé le'; e = { $_.InstallDate } }, @{n = 'Arch'; e = { if ($p -match 'WOW6432') { 'x86' } else { 'x64' } } }, @{n = 'Emplacement'; e = { $_.InstallLocation } }
            }
            $apps = @($apps | Sort-Object Nom -Unique)
            $Script:Facts.Apps = $apps
            Add-Table 'Logiciels installés' $apps

            $rules = @(
                @{ C = 'Antivirus / EDR'; P = 'Sophos|ESET|Kaspersky|Bitdefender|Trend Micro|Symantec|McAfee|Trellix|SentinelOne|CrowdStrike|Cortex|WithSecure|F-Secure|Avast|AVG|Avira|Panda|Malwarebytes|Webroot|Cylance|Carbon Black|HarfangLab|Stormshield|TEHTRIS|Cybereason|Check Point|Watchguard|Vade'; S = 'Moyen'; R = 'Vérifier la compatibilité WS2025 de la version ; désactiver/désinstaller pendant l''upgrade si l''éditeur le recommande (cause fréquente d''échec/rollback).' }
                @{ C = 'Sauvegarde'; P = 'Veeam|Acronis|Arcserve|Backup Exec|Commvault|Altaro|Nakivo|Datto|Cohesity|Rubrik|Zerto|Atempo|Uranium|Cobian|Iperius|Synology Active Backup|Bacula|Druva|Storagecraft|ShadowProtect'; S = 'Moyen'; R = 'Vérifier le support WS2025 de l''agent (et du serveur de sauvegarde pour un hôte Hyper-V).' }
                @{ C = 'Prise en main / RMM'; P = 'TeamViewer|AnyDesk|ConnectWise|ScreenConnect|N-able|N-central|NinjaOne|NinjaRMM|Datto RMM|Kaseya|Splashtop|Atera|RustDesk|Dameware|LogMeIn|GoTo|Action1|Syncro|Pulseway'; S = 'Faible'; R = 'Vérifier la compatibilité et le maintien de l''accès distant pendant/après l''upgrade (prévoir un accès console de secours).' }
                @{ C = 'SQL Server'; P = '^Microsoft SQL Server \d{4}(?! .*(Native Client|Management Objects|Compact|LocalDB|Setup|Policies|T-SQL|Browser|Writer|Language))|SQL Server \d{4} Database Engine'; S = 'Eleve'; R = 'Vérifier la matrice de support SQL Server sur WS2025 (versions anciennes non supportées) ; sauvegarder toutes les bases.' }
                @{ C = 'Exchange'; P = 'Microsoft Exchange Server'; S = 'Critique'; R = 'La mise à niveau sur place de l''OS d''un serveur Exchange n''est PAS supportée : migration vers un nouveau serveur.' }
                @{ C = 'Citrix / VDI'; P = 'Citrix|Parallels RAS|VMware Horizon|Omnissa'; S = 'Eleve'; R = 'Vérifier le support WS2025 auprès de l''éditeur.' }
                @{ C = 'Virtualisation (outils invités)'; P = 'VMware Tools|QEMU Guest Agent|VirtIO|Citrix VM Tools|XenServer'; S = 'Faible'; R = 'Mettre à jour les outils/pilotes invités avant l''upgrade.' }
                @{ C = 'ERP / métier'; P = 'Sage|EBP|Cegid|Quadra|Divalto|Isagri|Silae|Wavesoft|Ciel|Septeo|Lefebvre|Akuiteo|Navision|Dynamics|Odoo|Hyperplanning|Medistory|Pandat'; S = 'Moyen'; R = 'Obtenir l''attestation de compatibilité WS2025 de l''éditeur (et procédure de réinstallation/licence).' }
                @{ C = 'Bureautique'; P = '^Microsoft (Office|365)|Microsoft 365 Apps|LibreOffice'; S = 'Info'; R = 'Sur RDS : vérifier le support de la version Office sur WS2025 (Microsoft 365 Apps en activation partagée, Office LTSC 2021/2024).' }
                @{ C = 'Java / runtimes'; P = '^Java|JRE|JDK|Adoptium|Zulu|Corretto'; S = 'Faible'; R = 'Inventorier les applis Java dépendantes.' }
                @{ C = 'Synchro identité'; P = 'Azure AD Connect|Microsoft Entra Connect|Entra Connect|AD Connect'; S = 'Eleve'; R = 'Entra Connect : vérifier la version supportée sur WS2025 ; souvent plus simple de réinstaller sur un nouveau serveur (mode staging).' }
            )
            $sens = foreach ($a in $apps) {
                foreach ($r in $rules) {
                    if ($a.Nom -match $r.P -or $a.'Éditeur' -match $r.P) { [pscustomobject]@{ 'Catégorie' = $r.C; Logiciel = $a.Nom; Version = $a.Version; 'Éditeur' = $a.'Éditeur'; 'Point d''attention' = $r.R; Sev = $r.S }; break }
                }
            }
            $sens = @($sens)
            Add-Table 'Logiciels sensibles à valider avec les éditeurs' ($sens | Select-Object 'Catégorie', Logiciel, Version, 'Éditeur', "Point d'attention")
            foreach ($g in ($sens | Group-Object 'Catégorie')) {
                $first = $g.Group[0]
                Add-Finding $first.Sev 'Logiciels' ("{0} : {1}" -f $g.Name, (($g.Group | ForEach-Object { "$($_.Logiciel) $($_.Version)" }) -join ' | ')) '' $first.'Point d''attention'
            }
            $Script:Facts.SensitiveApps = $sens
        }
        Invoke-Step 'Services' {
            $svc = @(Get-CimInstance Win32_Service -ErrorAction Stop)
            $msPath = '\\Windows\\(system32|SysWOW64|servicing|Microsoft\.NET|ADWS|WinSxS)|\\Windows Defender|\\Microsoft\\Windows Defender|svchost\.exe|lsass\.exe|\\Windows\\ImmersiveControlPanel|\\Windows\\PolicyDefinitions'
            $third = @($svc | Where-Object { $_.PathName -and $_.PathName -notmatch $msPath })
            Add-Table 'Services non Microsoft (heuristique chemin)' ($third | Sort-Object DisplayName | Select-Object Name, DisplayName, State, StartMode, StartName, PathName)
            $acct = @($svc | Where-Object { $_.StartName -and $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|AUTORITE NT\\|\.\\?LocalSystem|NT Authority\\)' })
            Add-Table 'Services exécutés avec un compte nominatif / de service' ($acct | Select-Object Name, DisplayName, State, StartMode, StartName)
            if ($acct.Count) { Add-Finding Moyen 'Services' "$($acct.Count) service(s) exécuté(s) avec un compte spécifique" (($acct | ForEach-Object { "$($_.Name) ($($_.StartName))" }) -join ', ') 'Récupérer les mots de passe / documenter ces comptes : nécessaires pour reconfigurer sur la cible (ou passer en gMSA).' }
            $ignore = 'gupdate|edgeupdate|sppsvc|RemoteRegistry|MapsBroker|CDPSvc|tiledatamodelsvc|WbioSrvc|ShellHWDetection|TrustedInstaller|BITS|wuauserv|UsoSvc|DoSvc|sysmain|Sense|WaaSMedicSvc|clr_optimization|NetTcpPortSharing|DPS|InstallService|StateRepository|stisvc|GoogleUpdater|MicrosoftEdgeElevationService|WMPNetworkSvc|camsvc|AGMService|AGSService|ClickToRunSvc'
            $stopped = @($svc | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' -and $_.Name -notmatch $ignore })
            Add-Table 'Services automatiques arrêtés' ($stopped | Select-Object Name, DisplayName, State, StartMode, ExitCode, StartName)
            if ($stopped.Count) { Add-Finding Faible 'Services' "$($stopped.Count) service(s) automatique(s) arrêté(s)" (($stopped.Name | Select-Object -First 15) -join ', ') 'Comprendre pourquoi (état de référence avant upgrade pour comparer après).' }
            $Script:Facts.Services = $svc
        }
        Invoke-Step 'Tâches planifiées' {
            $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
            $rows = foreach ($t in $tasks) {
                $i = $null; try { $i = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch { }
                [pscustomobject]@{
                    Nom = $t.TaskName; Chemin = $t.TaskPath; 'État' = $t.State; Auteur = $t.Author; 'Exécuter en tant que' = $t.Principal.UserId
                    Actions = (($t.Actions | ForEach-Object { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() }) -join ' | ')
                    'Dernière exécution' = $i.LastRunTime; 'Dernier résultat' = $(if ($i) { '0x{0:X}' -f $i.LastTaskResult }); 'Prochaine' = $i.NextRunTime
                }
            }
            $rows = @($rows)
            Add-Table 'Tâches planifiées (hors \Microsoft\)' $rows
            $legacy = @($rows | Where-Object { $_.Actions -match 'wmic|cscript|wscript|\.vbs|powershell(\.exe)?\s.*-v(ersion)?\s*2' })
            if ($legacy.Count) { Add-Finding Moyen 'Compatibilité' "Tâches utilisant WMIC / VBScript / PowerShell 2" (($legacy | ForEach-Object { $_.Nom }) -join ', ') 'WMIC est désactivé par défaut et VBScript devient une fonctionnalité à la demande (dépréciés) sous WS2025 : réécrire en PowerShell ou réactiver la FoD.' }
            $acct = @($rows | Where-Object { $_.'Exécuter en tant que' -and $_.'Exécuter en tant que' -notmatch '^(SYSTEM|Système|LOCAL SERVICE|NETWORK SERVICE|S-1-5-18|S-1-5-19|S-1-5-20|INTERACTIVE|Users|Utilisateurs)$' })
            if ($acct.Count) { Add-Finding Faible 'Tâches planifiées' "$($acct.Count) tâche(s) exécutée(s) avec un compte nommé" (($acct | ForEach-Object { "$($_.Nom) ($($_.'Exécuter en tant que'))" }) -join ', ') 'Documenter les comptes/mots de passe pour recréer les tâches si besoin.' }
        }
        Invoke-Step 'Pilotes tiers' {
            $drv = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop | Where-Object { $_.DriverProviderName -and $_.DriverProviderName -notmatch '^Microsoft' -and $_.DeviceName })
            Add-Table 'Pilotes de périphériques tiers' ($drv | Sort-Object DriverProviderName, DeviceName | Select-Object DeviceName, DeviceClass, DriverProviderName, DriverVersion, @{n = 'DriverDate'; e = { $_.DriverDate } }, InfName, IsSigned)
            $old = @($drv | Where-Object { $_.DriverDate -and $_.DriverDate -lt (Get-Date).AddYears(-6) -and $_.DeviceClass -match 'NET|SCSIADAPTER|HDC|DISPLAY|SYSTEM' })
            if ($old.Count -and -not $Script:Roles.IsVM) { Add-Finding Moyen 'Pilotes' "$($old.Count) pilote(s) critique(s) de plus de 6 ans" (($old | Select-Object -First 10 | ForEach-Object { "$($_.DeviceName) ($($_.DriverVersion))" }) -join ' | ') 'Vérifier sur le site du constructeur (HPE/Dell/Lenovo...) le support WS2025 du serveur et mettre à jour firmware/pilotes (SPP, SUU...) AVANT l''upgrade.' }
            $fl = Invoke-External 'fltmc.exe' 'filters' 30
            Add-Raw 'Filtres de système de fichiers (fltmc)' $fl 'fltmc_filters.txt'
        }
        Invoke-Step 'Démarrage automatique' { Add-Table 'Programmes au démarrage' (Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Select-Object Name, Command, Location, User) }
    }
}

function Invoke-SecurityCollector {
    Invoke-Collector -Id 'Security' -Title 'Sécurité et durcissement' -Body {
        Invoke-Step 'Administrateurs locaux' {
            $m = $null
            try { $m = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | Select-Object Name, ObjectClass, PrincipalSource }
            catch { $m = (Invoke-External 'net.exe' 'localgroup administrators' 30) -split "`r?`n" | Where-Object { $_ -and $_ -notmatch '^(Alias|Nom alias|Comment|Commentaire|Members|Membres|---|The command|La commande)' } }
            Add-Table 'Membres du groupe Administrateurs' $m
        }
        if (-not $Script:Roles.IsDC) {
            Invoke-Step 'Comptes locaux' { Add-Table 'Comptes locaux' (Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, PasswordLastSet, PasswordExpires, LastLogon, PasswordRequired, Description, SID) }
        }
        Invoke-Step 'Microsoft Defender' {
            if (Test-Cmd 'Get-MpComputerStatus') {
                $mp = Get-MpComputerStatus -ErrorAction Stop
                Add-KV 'Microsoft Defender' ([ordered]@{
                        'Service AM actif'        = $mp.AMServiceEnabled; 'Antivirus actif' = $mp.AntivirusEnabled; 'Temps réel' = $mp.RealTimeProtectionEnabled
                        'Mode'                    = $mp.AMRunningMode; 'Version moteur' = $mp.AMEngineVersion; 'Version produit' = $mp.AMProductVersion
                        'Signatures du'           = $mp.AntivirusSignatureLastUpdated; 'Protection falsification' = $mp.IsTamperProtected
                    })
                $pref = Get-MpPreference -ErrorAction SilentlyContinue
                if ($pref) { Add-KV 'Exclusions Defender' ([ordered]@{ 'Chemins' = $pref.ExclusionPath; 'Extensions' = $pref.ExclusionExtension; 'Processus' = $pref.ExclusionProcess }) -Note 'À reporter sur la cible (exclusions AD/Hyper-V/RDS/applicatives).' }
            }
        }
        Invoke-Step 'LSA / NTLM / Kerberos' {
            $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            $lm = Get-RegValue $lsa 'LmCompatibilityLevel'
            $kv = [ordered]@{
                'LmCompatibilityLevel'                 = $(if ($null -eq $lm) { '(non défini = 3)' } else { $lm })
                'NoLMHash'                             = Get-RegValue $lsa 'NoLMHash'
                'RunAsPPL (protection LSA)'            = Get-RegValue $lsa 'RunAsPPL'
                'LsaCfgFlags (Credential Guard)'       = Get-RegValue $lsa 'LsaCfgFlags'
                'RestrictAnonymous'                    = Get-RegValue $lsa 'RestrictAnonymous'
                'RestrictSendingNTLMTraffic'           = Get-RegValue "$lsa\MSV1_0" 'RestrictSendingNTLMTraffic'
                'RestrictReceivingNTLMTraffic'         = Get-RegValue "$lsa\MSV1_0" 'RestrictReceivingNTLMTraffic'
                'AuditReceivingNTLMTraffic'            = Get-RegValue "$lsa\MSV1_0" 'AuditReceivingNTLMTraffic'
                'NtlmMinClientSec'                     = Get-RegValue "$lsa\MSV1_0" 'NtlmMinClientSec'
                'WDigest UseLogonCredential'           = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
                'Kerberos SupportedEncryptionTypes (GPO)' = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes'
                'LDAP client : LDAPClientIntegrity'    = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' 'LDAPClientIntegrity'
                'UAC EnableLUA'                        = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
                'SMB1 (LanmanServer\Parameters)'       = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
            }
            Add-KV 'Paramètres d''authentification' $kv
            if ($null -ne $lm -and [int]$lm -lt 3) { Add-Finding Eleve 'Sécurité' "LmCompatibilityLevel = $lm (LM/NTLMv1 autorisés)" 'NTLMv1 est supprimé à partir de WS2025 : tout client/équipement encore en NTLMv1 cessera de s''authentifier.' 'Auditer NTLM (événements 4624 "Package Name (NTLM only)"), puis passer à 5 (NTLMv2 uniquement).' }
            if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -eq 1) { Add-Finding Eleve 'Sécurité' 'WDigest stocke les mots de passe en clair (UseLogonCredential=1)' '' 'Passer UseLogonCredential à 0.' }
        }
        Invoke-Step 'TLS / Schannel' {
            $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
            $rows = @()
            if (Test-Path $base) {
                foreach ($p in Get-ChildItem $base -ErrorAction SilentlyContinue) {
                    foreach ($side in 'Server', 'Client') {
                        $k = Join-Path $p.PSPath $side
                        if (Test-Path $k) { $rows += [pscustomobject]@{ Protocole = $p.PSChildName; 'Côté' = $side; Enabled = Get-RegValue $k 'Enabled'; DisabledByDefault = Get-RegValue $k 'DisabledByDefault' } }
                    }
                }
            }
            Add-Table 'Protocoles SCHANNEL explicitement configurés' $rows -Note 'Vide = valeurs par défaut de l''OS. WS2025 désactive TLS 1.0/1.1 par défaut.'
            $net = [ordered]@{
                '.NET 4 SchUseStrongCrypto (x64)'   = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto'
                '.NET 4 SchUseStrongCrypto (x86)'   = Get-RegValue 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto'
                '.NET 4 SystemDefaultTlsVersions'   = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' 'SystemDefaultTlsVersions'
            }
            Add-KV 'TLS pour .NET' $net
            Add-Finding Moyen 'Compatibilité' 'TLS 1.0 / 1.1 désactivés par défaut sous WS2025' 'Applications anciennes, SQL Server non patchés, clients RDP anciens, copieurs (SMTP/LDAP), onduleurs, iDRAC/iLO anciens peuvent ne plus se connecter.' 'Inventorier les flux TLS anciens (journaux Schannel 36874/36871, flux établis) et mettre à jour les composants concernés.'
        }
        Invoke-Step 'Bureau à distance (paramètres)' {
            $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            $rdp = "$ts\WinStations\RDP-Tcp"
            $kv = [ordered]@{
                'RDP autorisé (fDenyTSConnections=0)' = ((Get-RegValue $ts 'fDenyTSConnections') -eq 0)
                'Port RDP'                             = Get-RegValue $rdp 'PortNumber'
                'NLA (UserAuthentication)'             = Get-RegValue $rdp 'UserAuthentication'
                'SecurityLayer (0=RDP,1=Nég.,2=TLS)'   = Get-RegValue $rdp 'SecurityLayer'
                'MinEncryptionLevel'                   = Get-RegValue $rdp 'MinEncryptionLevel'
                'Certificat RDP (SHA1)'                = Get-RegValue $rdp 'SSLCertificateSHA1Hash'
            }
            Add-KV 'Configuration RDP (RDP-Tcp)' $kv
            if ($kv['RDP autorisé (fDenyTSConnections=0)'] -and $kv['NLA (UserAuthentication)'] -eq 0) { Add-Finding Eleve 'Sécurité' 'RDP sans authentification au niveau du réseau (NLA)' '' 'Activer NLA (UserAuthentication=1).' }
        }
        Invoke-Step 'LAPS' {
            $legacy = Test-Path (Join-Path $env:ProgramFiles 'LAPS\CSE\AdmPwd.dll')
            $win = Get-RegKeyValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            Add-KV 'LAPS' ([ordered]@{ 'LAPS hérité (AdmPwd.dll) installé' = $legacy; 'Stratégie Windows LAPS' = $(if ($win) { Format-Value $win } else { 'non configurée' }) })
            if ($legacy) { Add-Finding Moyen 'Sécurité' 'LAPS hérité (Microsoft LAPS / AdmPwd) installé' 'Le LAPS hérité n''est plus supporté sur les OS récents (WS2025 intègre Windows LAPS).' 'Planifier la migration vers Windows LAPS (Update-LapsADSchema, GPO Windows LAPS) et désinstaller l''ancien client.' }
        }
        Invoke-Step 'Certificats machine' {
            $certs = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop)
            $rows = foreach ($c in $certs) {
                [pscustomobject]@{ Sujet = $c.Subject; 'Émetteur' = $c.Issuer; 'Expire le' = $c.NotAfter; 'Jours restants' = [int]($c.NotAfter - (Get-Date)).TotalDays; 'Clé privée' = $c.HasPrivateKey; Empreinte = $c.Thumbprint; Usages = (($c.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join ', '); SAN = (($c.DnsNameList | ForEach-Object { $_.Unicode }) -join ', ') }
            }
            Add-Table 'Certificats (LocalMachine\My)' $rows
            $exp = @($rows | Where-Object { $_.'Jours restants' -lt 60 -and $_.'Clé privée' })
            if ($exp.Count) { Add-Finding Moyen 'Certificats' "$($exp.Count) certificat(s) expiré(s) ou expirant sous 60 jours" (($exp | ForEach-Object { "$($_.Sujet) ($($_.'Jours restants') j)" }) -join ' | ') 'Renouveler, et exporter (avec clé privée si autorisé) les certificats à réutiliser sur la cible (RDS, IIS, LDAPS...).' }
        }
        Invoke-Step 'Stratégie d''exécution PowerShell' { Add-Table 'ExecutionPolicy' (Get-ExecutionPolicy -List | Select-Object Scope, ExecutionPolicy) }
        Invoke-Step 'Spouleur d''impression' {
            $sp = Get-Service Spooler -ErrorAction Stop
            if ($Script:Roles.IsDC -and $sp.Status -eq 'Running' -and -not $Script:Roles.IsPrintServer) { Add-Finding Moyen 'Sécurité' 'Spouleur d''impression actif sur un contrôleur de domaine' '' 'Désactiver le spouleur sur les DC (surface d''attaque type PrintNightmare).' }
        }
    }
}

function Invoke-PoliciesCollector {
    Invoke-Collector -Id 'Policies' -Title 'Stratégies appliquées, audit et droits' -Body {
        Invoke-Step 'gpresult' {
            $f = Join-Path $Script:RawFolder 'gpresult_computer.html'
            $null = Invoke-External 'gpresult.exe' "/scope computer /h `"$f`" /f" 180
            Add-Raw 'gpresult /r /scope computer' (Invoke-External 'gpresult.exe' '/r /scope computer' 180) 'gpresult_computer.txt'
            if (Test-Path $f) { Add-Note 'Rapport RSoP HTML complet : raw\gpresult_computer.html' }
        }
        Invoke-Step 'auditpol' { Add-Raw 'Stratégie d''audit (auditpol)' (Invoke-External 'auditpol.exe' '/get /category:*' 60) 'auditpol.txt' }
        Invoke-Step 'secedit' {
            $f = Join-Path $Script:RawFolder 'secedit_export.inf'
            $null = Invoke-External 'secedit.exe' "/export /cfg `"$f`" /areas SECURITYPOLICY USER_RIGHTS" 120
            if (Test-Path $f) { Add-Raw 'Stratégie de sécurité locale effective (secedit /export)' (Get-Content $f -Raw) 'secedit_export.txt' }
        }
    }
}

function Invoke-EventsCollector {
    Invoke-Collector -Id 'Events' -Title "Journaux d'événements ($EventDays derniers jours)" -Body {
        $since = (Get-Date).AddDays(-$EventDays)
        $logs = @('System', 'Application')
        if ($Script:Roles.IsDC) { $logs += 'Directory Service', 'DFS Replication', 'DNS Server' }
        if ($Script:Roles.IsHyperV) { $logs += 'Microsoft-Windows-Hyper-V-VMMS-Admin', 'Microsoft-Windows-Hyper-V-Worker-Admin' }
        if ($Script:Roles.IsRDS) { $logs += 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin', 'Microsoft-Windows-TerminalServices-Licensing/Admin' }
        $max = if ($Quick) { 500 } else { 3000 }
        Invoke-Step 'Configuration des journaux' {
            Add-Table 'Configuration des journaux' (Get-WinEvent -ListLog ($logs + 'Security') -ErrorAction SilentlyContinue | Select-Object LogName, @{n = 'TailleMaxMo'; e = { [math]::Round($_.MaximumSizeInBytes / 1MB) } }, RecordCount, LogMode, IsEnabled)
        }
        $all = @()
        foreach ($l in $logs) {
            Invoke-Step "Journal $l" {
                $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $l; Level = 1, 2; StartTime = $since } -MaxEvents $max -ErrorAction SilentlyContinue)
                $Script:Facts["ev_$l"] = $ev.Count
                $script:tmpEv = $ev
            }
            if ($script:tmpEv) { $all += $script:tmpEv; $script:tmpEv = $null }
        }
        Invoke-Step 'Synthèse erreurs' {
            $sum = $all | Group-Object LogName, ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 80 | ForEach-Object {
                $f = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
                $msg = "$($f.Message)"; if ($msg.Length -gt 250) { $msg = $msg.Substring(0, 250) + '…' }
                [pscustomobject]@{ Journal = $f.LogName; Source = $f.ProviderName; ID = $f.Id; Niveau = $f.LevelDisplayName; Nombre = $_.Count; 'Dernière occurrence' = $f.TimeCreated; 'Message (extrait)' = ($msg -replace '\s+', ' ') }
            }
            Add-Table 'Erreurs et critiques groupées (top 80)' $sum
        }
        Invoke-Step 'Événements clés' {
            $keys = @(
                @{ L = 'System'; P = 'Microsoft-Windows-Kernel-Power'; I = 41; T = 'Arrêts brutaux (Kernel-Power 41)'; S = 'Moyen' }
                @{ L = 'System'; P = 'EventLog'; I = 6008; T = 'Arrêts inattendus (6008)'; S = 'Moyen' }
                @{ L = 'System'; P = $null; I = 7, 11, 15, 51, 129, 153; T = 'Erreurs disque / contrôleur (7,11,15,51,129,153)'; S = 'Eleve' }
                @{ L = 'System'; P = 'Ntfs'; I = 55, 98; T = 'Corruption NTFS (55/98)'; S = 'Eleve' }
                @{ L = 'System'; P = 'Microsoft-Windows-WHEA-Logger'; I = 1, 17, 18, 19, 46, 47; T = 'Erreurs matérielles WHEA'; S = 'Eleve' }
                @{ L = 'System'; P = 'Microsoft-Windows-Time-Service'; I = 129, 134, 36, 50; T = 'Problèmes de synchronisation horaire'; S = 'Moyen' }
                @{ L = 'System'; P = 'Microsoft-Windows-GroupPolicy'; I = 1129, 1053, 1058, 1030, 1055; T = 'Échecs de traitement GPO'; S = 'Moyen' }
                @{ L = 'System'; P = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'; I = 14, 16, 26, 27, 42, 45; T = 'Erreurs KDC (chiffrement Kerberos)'; S = 'Moyen' }
            )
            $rows = foreach ($k in $keys) {
                $fh = @{ LogName = $k.L; Id = $k.I; StartTime = $since }
                if ($k.P) { $fh.ProviderName = $k.P }
                $e = @(Get-WinEvent -FilterHashtable $fh -MaxEvents 500 -ErrorAction SilentlyContinue)
                if ($k.I -contains 7 -and -not $k.P) { $e = @($e | Where-Object { $_.ProviderName -match 'disk|stor|iaStor|LSI|megasas|HpCISSs|SmartArray|stornvme|nvme|percsas|mpt|vhdmp' }) }
                if ($e.Count) { Add-Finding $k.S 'Journaux' ("{0} : {1} occurrence(s) sur {2} j" -f $k.T, $e.Count, $EventDays) ("Dernière : {0}" -f ($e | Select-Object -First 1).TimeCreated) 'Analyser et corriger avant la migration (risque d''échec ou de rollback).' }
                [pscustomobject]@{ 'Contrôle' = $k.T; 'Occurrences' = $e.Count; 'Dernière' = $(if ($e.Count) { ($e | Select-Object -First 1).TimeCreated }) }
            }
            Add-Table 'Événements clés surveillés' $rows
        }
        Invoke-Step 'Échecs d''ouverture de session (4625)' {
            $f = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -MaxEvents $(if ($Quick) { 2000 } else { 20000 }) -ErrorAction SilentlyContinue)
            if ($f.Count) {
                $parsed = foreach ($e in $f) { $x = [xml]$e.ToXml(); $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }; [pscustomobject]@{ IP = $d.IpAddress; Compte = $d.TargetUserName; Type = $d.LogonType } }
                Add-Table 'Échecs 4625 par IP source (top 25)' ($parsed | Group-Object IP | Sort-Object Count -Descending | Select-Object -First 25 | ForEach-Object { [pscustomobject]@{ 'IP source' = $_.Name; 'Échecs' = $_.Count; 'Comptes visés (ex.)' = (($_.Group.Compte | Select-Object -Unique -First 6) -join ', ') } })
                Add-Table 'Échecs 4625 par compte (top 25)' ($parsed | Group-Object Compte | Sort-Object Count -Descending | Select-Object -First 25 | Select-Object @{n = 'Compte'; e = { $_.Name } }, @{n = 'Échecs'; e = { $_.Count } })
                if ($f.Count -gt 500) { Add-Finding Eleve 'Sécurité' "$($f.Count) échecs d'ouverture de session en $EventDays jours" 'Indice d''attaque par force brute (RDP/SMB exposé ?).' 'Vérifier l''exposition Internet (RDP derrière VPN/RD Gateway + MFA), le verrouillage de compte, et les IP sources.' }
            } else { Add-Note 'Aucun 4625 trouvé (ou audit des échecs d''ouverture de session non activé).' }
        }
    }
}
#endregion

#region ===================== Usage réel des protocoles hérités =====================
function Get-EventDataTable {
    <# Convertit les événements en objets (EventData Name -> valeur). #>
    param($Events)
    foreach ($e in $Events) {
        $h = [ordered]@{ Date = $e.TimeCreated }
        try {
            $x = [xml]$e.ToXml()
            foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $h[$n.Name] = $n.'#text' } }
        } catch { }
        [pscustomobject]$h
    }
}

function Invoke-LegacyAuthCollector {
    Invoke-Collector -Id 'LegacyAuth' -Title "Usage réel des protocoles hérités (NTLMv1, NTLM, LDAP non signé, Kerberos RC4/DES)" -Body {
        Add-Note ("Analyse des {0} derniers jours de journaux. Contrairement à la section Sécurité (configuration), cette section montre QUI utilise encore ces protocoles et cassera après le passage à WS2025 / au durcissement." -f $EventDays)
        $sinceMs = [int64]$EventDays * 86400000
        $max = if ($Quick) { 5000 } else { 50000 }

        Invoke-Step 'NTLMv1 (4624)' {
            $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $sinceMs]] and EventData[Data[@Name='LmPackageName']='NTLM V1']]"
            $ev = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents $max -ErrorAction SilentlyContinue)
            if ($ev.Count) {
                $rows = Get-EventDataTable $ev
                Add-Table 'Ouvertures de session NTLMv1 (top sources)' ($rows | Group-Object WorkstationName, IpAddress, TargetUserName | Sort-Object Count -Descending | Select-Object -First 50 | ForEach-Object {
                        $f = $_.Group[0]; [pscustomobject]@{ 'Poste source' = $f.WorkstationName; 'IP source' = $f.IpAddress; Compte = ('{0}\{1}' -f $f.TargetDomainName, $f.TargetUserName); Occurrences = $_.Count; 'Dernière' = ($_.Group | Sort-Object Date -Descending | Select-Object -First 1).Date }
                    })
                Add-Finding Eleve 'Compatibilité' "NTLMv1 encore utilisé ($($ev.Count) ouvertures de session en $EventDays j)" ((($rows | Select-Object -ExpandProperty WorkstationName -Unique) | Select-Object -First 10) -join ', ') 'NTLMv1 est supprimé dans WS2025 : mettre à jour/reconfigurer ces clients (LmCompatibilityLevel ≥ 3 côté client, firmware des équipements) avant la migration.'
            } else { Add-Note 'Aucune ouverture de session NTLMv1 détectée (4624, LmPackageName = NTLM V1) — ou audit des ouvertures de session non activé.' }
        }

        Invoke-Step 'NTLM (toutes versions)' {
            $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $sinceMs]] and EventData[Data[@Name='AuthenticationPackageName']='NTLM'] and EventData[Data[@Name='LogonType']!='5']]"
            $ev = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents $max -ErrorAction SilentlyContinue)
            if ($ev.Count) {
                $rows = Get-EventDataTable $ev
                Add-Table 'Ouvertures de session NTLM (top 30 sources)' ($rows | Group-Object WorkstationName, IpAddress, LmPackageName | Sort-Object Count -Descending | Select-Object -First 30 | ForEach-Object {
                        $f = $_.Group[0]; [pscustomobject]@{ 'Poste source' = $f.WorkstationName; 'IP source' = $f.IpAddress; Version = $f.LmPackageName; 'Comptes (ex.)' = (($_.Group.TargetUserName | Select-Object -Unique -First 5) -join ', '); Occurrences = $_.Count }
                    }) -Note $(if ($ev.Count -ge $max) { "Limité aux $max événements les plus récents." } else { '' })
                Add-Finding Info 'Compatibilité' "NTLM utilisé ($($ev.Count) ouvertures de session réseau en $EventDays j)" 'NTLM (toutes versions) est déprécié par Microsoft ; WS2025 permet de le bloquer progressivement (SMB, etc.).' 'Identifier les flux NTLM (accès par IP, applications anciennes) et privilégier Kerberos (noms DNS, SPN corrects).'
            }
        }

        if ($Script:Roles.IsDC) {
            Invoke-Step 'LDAP non signé (2887/2889)' {
                $s = Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 2887; StartTime = (Get-Date).AddDays(-$EventDays) } -MaxEvents 30 -ErrorAction SilentlyContinue
                if ($s) {
                    $rows = foreach ($e in $s) { [pscustomobject]@{ Date = $e.TimeCreated; 'Binds simples sans SSL/TLS' = $e.Properties[0].Value; 'Binds SASL sans signature' = $e.Properties[1].Value } }
                    Add-Table 'Synthèse quotidienne des binds LDAP non sécurisés (2887)' $rows
                    $tot = ($rows | Measure-Object 'Binds simples sans SSL/TLS' -Sum).Sum + ($rows | Measure-Object 'Binds SASL sans signature' -Sum).Sum
                    if ($tot -gt 0) { Add-Finding Eleve 'Compatibilité' "Binds LDAP non signés / en clair : $tot sur $EventDays j (événement 2887)" 'Des clients (copieurs, NAS, firewall, applications) s''authentifient en LDAP simple ou non signé.' 'Activer le diagnostic (HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics "16 LDAP Interface Events" = 2) pour obtenir les IP clientes (événement 2889), les passer en LDAPS (636) ou LDAP signé, puis exiger la signature.' }
                }
                $d = Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 2889; StartTime = (Get-Date).AddDays(-$EventDays) } -MaxEvents 5000 -ErrorAction SilentlyContinue
                if ($d) {
                    $rows = foreach ($e in $d) { [pscustomobject]@{ IP = ("$($e.Properties[0].Value)" -replace ':\d+$', ''); Compte = $e.Properties[1].Value; Type = $e.Properties[2].Value } }
                    Add-Table 'Clients LDAP non signés (2889, diagnostic activé)' ($rows | Group-Object IP, Compte | Sort-Object Count -Descending | Select-Object -First 50 | ForEach-Object { [pscustomobject]@{ 'IP client' = $_.Group[0].IP; Compte = $_.Group[0].Compte; 'Type de bind (0=SASL non signé,1=simple)' = $_.Group[0].Type; Occurrences = $_.Count } })
                } elseif ($s) { Add-Note 'Pas d''événement 2889 : le diagnostic LDAP n''est pas activé, les IP clientes ne sont pas connues.' }
            }
            Invoke-Step 'Kerberos RC4 / DES (4769)' {
                $xp = "*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= $sinceMs]] and EventData[(Data[@Name='TicketEncryptionType']='0x17' or Data[@Name='TicketEncryptionType']='0x18' or Data[@Name='TicketEncryptionType']='0x1' or Data[@Name='TicketEncryptionType']='0x3')]]"
                $ev = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents $max -ErrorAction SilentlyContinue)
                if ($ev.Count) {
                    $enc = @{ '0x17' = 'RC4'; '0x18' = 'RC4-EXP'; '0x1' = 'DES-CBC-CRC'; '0x3' = 'DES-CBC-MD5' }
                    $rows = Get-EventDataTable $ev
                    Add-Table 'Tickets de service Kerberos en RC4/DES (top 50)' ($rows | Group-Object ServiceName, IpAddress, TicketEncryptionType | Sort-Object Count -Descending | Select-Object -First 50 | ForEach-Object {
                            $f = $_.Group[0]; [pscustomobject]@{ Service = $f.ServiceName; 'Client (IP)' = ("$($f.IpAddress)" -replace '^::ffff:', ''); Compte = $f.TargetUserName; Chiffrement = $enc["$($f.TicketEncryptionType)"]; Occurrences = $_.Count }
                        })
                    $des = @($rows | Where-Object { $_.TicketEncryptionType -in '0x1', '0x3' })
                    Add-Finding $(if ($des.Count) { 'Eleve' } else { 'Moyen' }) 'Compatibilité' "Kerberos RC4/DES encore utilisé ($($ev.Count) tickets en $EventDays j)" ((($rows | Select-Object -ExpandProperty ServiceName -Unique) | Select-Object -First 10) -join ', ') 'Microsoft durcit progressivement Kerberos (RC4 en voie de désactivation par défaut, DES déjà désactivé). Passer les comptes de service concernés en AES (msDS-SupportedEncryptionTypes = 0x18, puis changement de mot de passe) et vérifier les comptes anciens (mot de passe antérieur au niveau fonctionnel 2008).'
                } else { Add-Note 'Aucun ticket Kerberos RC4/DES détecté (4769) — ou audit "Kerberos Service Ticket Operations" non activé.' }
            }
            Invoke-Step 'Audit activé ?' {
                $ap = Invoke-External 'auditpol.exe' '/get /subcategory:{0CCE9240-69AE-11D9-BED3-505054503030},{0CCE9215-69AE-11D9-BED3-505054503030}' 30
                Add-Raw 'auditpol (Kerberos Service Ticket / Logon)' $ap 'auditpol_legacyauth.txt'
            }
        }
    }
}
#endregion

#region ===================== Active Directory / GPO / DNS / DHCP =====================
function Invoke-ADCollector {
    Invoke-Collector -Id 'ActiveDirectory' -Title 'Active Directory (AD DS)' -When $Script:Roles.IsDC -Body {
        if (-not (Import-ModuleSafe 'ActiveDirectory')) { throw 'Module ActiveDirectory indisponible.' }
        $dc = $env:COMPUTERNAME
        $forest = $null; $domain = $null
        Invoke-Step 'Forêt / domaine' {
            $script:forest = Get-ADForest -Server $dc -ErrorAction Stop
            $script:domain = Get-ADDomain -Server $dc -ErrorAction Stop
            $f = $script:forest; $d = $script:domain
            $schema = (Get-ADObject (Get-ADRootDSE -Server $dc).schemaNamingContext -Properties objectVersion -Server $dc).objectVersion
            $schemaMap = @{ 13 = '2000'; 30 = '2003'; 31 = '2003 R2'; 44 = '2008'; 47 = '2008 R2'; 56 = '2012'; 69 = '2012 R2'; 87 = '2016'; 88 = '2019 / 2022'; 91 = '2025' }
            $Script:Facts.SchemaVersion = $schema
            Add-KV 'Forêt et domaine' ([ordered]@{
                    'Forêt'                      = $f.Name
                    'Niveau fonctionnel forêt'   = $f.ForestMode
                    'Domaine (DNS)'              = $d.DNSRoot
                    'Domaine (NetBIOS)'          = $d.NetBIOSName
                    'Niveau fonctionnel domaine' = $d.DomainMode
                    'Version du schéma'          = ('{0} (Windows Server {1})' -f $schema, $schemaMap[[int]$schema])
                    'Maître de schéma'           = $f.SchemaMaster
                    'Maître d''attribution de noms' = $f.DomainNamingMaster
                    'Émulateur PDC'              = $d.PDCEmulator
                    'Maître RID'                 = $d.RIDMaster
                    'Maître d''infrastructure'   = $d.InfrastructureMaster
                    'Domaines de la forêt'       = $f.Domains
                    'Sites'                      = $f.Sites
                    'Catalogues globaux'         = $f.GlobalCatalogs
                    'Suffixes UPN'               = $f.UPNSuffixes
                    'SID du domaine'             = $d.DomainSID
                    'Conteneur ordinateurs par défaut' = $d.ComputersContainer
                    'Conteneur utilisateurs par défaut' = $d.UsersContainer
                })
            $fl = "$($f.ForestMode)"; $dl = "$($d.DomainMode)"
            $okLevel = '2016|2025|Windows2016|Windows2025'
            if ($fl -notmatch $okLevel -or $dl -notmatch $okLevel) {
                Add-Finding Critique 'Active Directory' "Niveaux fonctionnels insuffisants (forêt : $fl / domaine : $dl)" 'Un DC Windows Server 2025 exige des niveaux fonctionnels de domaine ET de forêt ≥ Windows Server 2016.' 'Vérifier qu''aucun DC < 2016 ne subsiste, puis relever le niveau du domaine puis de la forêt à Windows2016Domain/Windows2016Forest (opération quasi irréversible : sauvegarde préalable).'
            }
            Add-Finding Info 'Active Directory' "Schéma actuel : version $schema" 'L''ajout du premier DC 2025 (ou l''upgrade) étend le schéma vers la version 91 (adprep automatique si compte Schema/Enterprise Admins).' 'Sauvegarde état système du DC détenteur du rôle de schéma avant extension ; vérifier la réplication juste avant.'
        }
        $f = $script:forest; $d = $script:domain
        Invoke-Step 'Contrôleurs de domaine' {
            $dcs = @(Get-ADDomainController -Filter * -Server $dc -ErrorAction Stop)
            Add-Table 'Contrôleurs de domaine' ($dcs | Select-Object Name, HostName, IPv4Address, OperatingSystem, OperatingSystemVersion, Site, IsGlobalCatalog, IsReadOnly, @{n = 'Rôles FSMO'; e = { $_.OperationMasterRoles -join ', ' } })
            $Script:Facts.DCCount = $dcs.Count
            if ($dcs.Count -lt 2) { Add-Finding Eleve 'Active Directory' 'Un seul contrôleur de domaine' 'Aucune redondance : toute erreur pendant l''upgrade rend le domaine indisponible (authentification, DNS, GPO).' 'Stratégie recommandée : créer une NOUVELLE VM WS2025, la promouvoir DC/DNS(/GC), valider la réplication, transférer les FSMO, puis rétrograder l''ancien DC (side-by-side) plutôt qu''un upgrade sur place.' }
            else { Add-Finding Info 'Active Directory' "$($dcs.Count) contrôleurs de domaine" (($dcs | ForEach-Object { "$($_.Name) ($($_.OperatingSystem))" }) -join ', ') 'Migrer un DC à la fois, en validant la réplication entre chaque étape.' }
            $old = @($dcs | Where-Object { $_.OperatingSystem -match '2003|2008|2012' })
            if ($old.Count) { Add-Finding Critique 'Active Directory' 'DC anciens (< 2016) présents' (($old.Name) -join ', ') 'Les retirer avant d''introduire un DC 2025 (prérequis niveau fonctionnel 2016).' }
        }
        Invoke-Step 'SYSVOL (FRS / DFSR)' {
            $dn = $d.DistinguishedName
            $gs = $null; $dsv = $null   # Get-ADObject lève une erreur bloquante si l'objet n'existe pas
            try { $gs = Get-ADObject -Identity "CN=DFSR-GlobalSettings,CN=System,$dn" -Properties 'msDFSR-Flags' -Server $dc -ErrorAction Stop } catch { }
            try { $dsv = Get-ADObject -Identity "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$dn" -Server $dc -ErrorAction Stop } catch { }
            $flags = $null; if ($gs) { $flags = $gs.'msDFSR-Flags' }
            $state = if (-not $dsv) { 'FRS (aucun groupe DFSR SYSVOL)' } elseif ($null -eq $flags -or [int]$flags -eq 48) { 'DFSR (migration terminée / natif)' } else { "Migration FRS→DFSR en cours (msDFSR-Flags=$flags)" }
            $Script:Facts.SysvolState = $state
            $sysvol = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SysVol'
            Add-KV 'SYSVOL' ([ordered]@{ 'Réplication SYSVOL' = $state; 'Chemin SYSVOL' = $sysvol; 'Service DFSR' = (Get-Service DFSR -ErrorAction SilentlyContinue).Status; 'Service NtFrs' = (Get-Service NtFrs -ErrorAction SilentlyContinue).Status })
            Add-Raw 'dfsrmig /getglobalstate' (Invoke-External 'dfsrmig.exe' '/getglobalstate' 60) 'dfsrmig_globalstate.txt'
            if ($state -like 'FRS*') { Add-Finding Critique 'Active Directory' 'SYSVOL répliqué par FRS' 'FRS n''est plus supporté (dernier OS : 2016). Impossible d''ajouter/upgrader un DC 2025.' 'Migrer SYSVOL vers DFSR (dfsrmig /setglobalstate 1→2→3) AVANT toute autre opération.' }
            elseif ($state -like 'Migration*') { Add-Finding Critique 'Active Directory' 'Migration FRS → DFSR inachevée' $state 'Terminer la migration (état 3 = Eliminated).' }
            # Scripts de connexion VBS dans SYSVOL/NETLOGON
            $netlogon = Join-Path $sysvol ('{0}\scripts' -f $d.DNSRoot)
            if (-not (Test-Path $netlogon)) { $netlogon = '\\{0}\NETLOGON' -f $env:COMPUTERNAME }
            $scr = @(Get-ChildItem -Path $netlogon -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName, Extension, Length, LastWriteTime)
            Add-Table 'Contenu NETLOGON (scripts de connexion)' $scr
            $vbs = @($scr | Where-Object { $_.Extension -match '\.(vbs|vbe|wsf|js)$' })
            if ($vbs.Count) { Add-Finding Moyen 'Compatibilité' "$($vbs.Count) script(s) VBScript/WSH dans NETLOGON" (($vbs | Select-Object -First 10 | ForEach-Object { Split-Path $_.FullName -Leaf }) -join ', ') 'VBScript est déprécié (fonctionnalité à la demande puis suppression) : planifier la réécriture en PowerShell/GPP.' }
            $pol = Join-Path $sysvol ('{0}\Policies' -f $d.DNSRoot)
            $Script:Facts.SysvolPolicies = $pol
            $size = Get-DirectorySizeGB (Split-Path $sysvol -Parent)
            Add-Note ("Taille approximative du dossier SYSVOL : {0} Go" -f $size)
        }
        Invoke-Step 'Base NTDS' {
            $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            $db = Get-RegValue $p 'DSA Database file'
            $dbSize = $null; if ($db -and (Test-Path $db)) { $dbSize = [math]::Round((Get-Item $db).Length / 1MB, 0) }
            Add-KV 'Base de données AD (NTDS)' ([ordered]@{
                    'ntds.dit'                    = $db
                    'Taille ntds.dit (Mo)'        = $dbSize
                    'Journaux'                    = Get-RegValue $p 'Database log files path'
                    'LDAPServerIntegrity (signature LDAP)' = Get-RegValue $p 'LDAPServerIntegrity'
                    'LdapEnforceChannelBinding'   = Get-RegValue $p 'LdapEnforceChannelBinding'
                    'Strict Replication Consistency' = Get-RegValue $p 'Strict Replication Consistency'
                })
            $li = Get-RegValue $p 'LDAPServerIntegrity'
            if ($null -eq $li -or [int]$li -lt 2) { Add-Finding Moyen 'Compatibilité' 'Signature LDAP non exigée sur ce DC' 'Les DC WS2025 durcissent LDAP (signature/chiffrement par défaut sur les nouveaux déploiements) : applications, copieurs (carnet LDAP), NAS, firewalls en LDAP simple (389) risquent d''échouer.' 'Auditer les binds LDAP non signés (événement 2889 après activation du diagnostic 16 LDAP Interface Events=2) et basculer ces clients en LDAPS/signature.' }
        }
        Invoke-Step 'Réplication' {
            $rs = Invoke-External 'repadmin.exe' '/replsummary' 300
            Add-Raw 'repadmin /replsummary' $rs 'repadmin_replsummary.txt'
            $csv = Invoke-External 'repadmin.exe' '/showrepl * /csv' 300
            Add-Raw 'repadmin /showrepl * /csv' $csv 'repadmin_showrepl.csv'
            try {
                $rows = @($csv -split "`r?`n" | Where-Object { $_ -match ',' } | ConvertFrom-Csv)
                if ($rows.Count -and $rows[0].PSObject.Properties.Name -contains 'Number of Failures') {
                    Add-Table 'Partenaires de réplication' ($rows | Select-Object 'Destination DSA', 'Source DSA', 'Naming Context', 'Number of Failures', 'Last Failure Time', 'Last Success Time', 'Last Failure Status')
                    $bad = @($rows | Where-Object { [int]$_.'Number of Failures' -gt 0 })
                    if ($bad.Count) { Add-Finding Critique 'Active Directory' "Échecs de réplication AD ($($bad.Count) liens)" (($bad | Select-Object -First 5 | ForEach-Object { "$($_.'Source DSA')→$($_.'Destination DSA') : $($_.'Last Failure Status')" }) -join ' | ') 'Corriger la réplication AVANT toute opération (repadmin /showrepl, dcdiag /test:replications).' }
                }
            } catch { }
            Add-Raw 'repadmin /showrepl' (Invoke-External 'repadmin.exe' '/showrepl' 300) 'repadmin_showrepl.txt'
            Add-Raw 'repadmin /queue' (Invoke-External 'repadmin.exe' '/queue' 60) 'repadmin_queue.txt'
        }
        Invoke-Step 'Dernière sauvegarde AD' {
            $nc = @($d.DistinguishedName, (Get-ADRootDSE -Server $dc).configurationNamingContext, (Get-ADRootDSE -Server $dc).schemaNamingContext)
            $rows = foreach ($n in $nc) {
                $m = Get-ADReplicationAttributeMetadata -Object $n -Server $dc -Properties dSASignature -ErrorAction SilentlyContinue | Select-Object -First 1
                [pscustomobject]@{ 'Contexte de nommage' = $n; 'Dernière sauvegarde' = $m.LastOriginatingChangeTime }
            }
            Add-Table 'Dernière sauvegarde état système (dSASignature)' $rows
            $last = ($rows | Where-Object { $_.'Dernière sauvegarde' } | Sort-Object 'Dernière sauvegarde' | Select-Object -First 1).'Dernière sauvegarde'
            if (-not $last -or ((Get-Date) - [datetime]$last).TotalDays -gt 7) { Add-Finding Eleve 'Sauvegarde' 'Pas de sauvegarde AD récente (> 7 j ou jamais)' ("Dernière : {0}" -f $(if ($last) { $last } else { 'jamais' })) 'Réaliser une sauvegarde de l''état système (wbadmin start systemstatebackup / outil tiers compatible AD) et TESTER une restauration avant la migration.' }
        }
        Invoke-Step 'dcdiag' {
            $o = Invoke-External 'dcdiag.exe' '/v /c /skip:DNS /skip:Topology /skip:CutoffServers /skip:OutboundSecureChannels /skip:VerifyEnterpriseReferences' 900
            Add-Raw 'dcdiag /v /c' $o 'dcdiag.txt' -MaxHtmlChars 120000
            $fails = @(([regex]::Matches($o, '(?im)^\s*\.+\s*(\S+)\s+(failed test|a échoué au test|n''a pas réussi le test)\s+(\S+)')) | ForEach-Object { "$($_.Groups[1].Value) : $($_.Groups[3].Value)" })
            Add-Table 'dcdiag : tests en échec' $fails -NoCsv
            if ($fails.Count) { Add-Finding Eleve 'Active Directory' "dcdiag : $($fails.Count) test(s) en échec" (($fails | Select-Object -Unique) -join ', ') 'Analyser raw\dcdiag.txt et corriger (certaines erreurs SystemLog sont bénignes, les autres non).' }
            if (-not $Quick) { Add-Raw 'dcdiag /test:dns /v' (Invoke-External 'dcdiag.exe' '/test:dns /v' 900) 'dcdiag_dns.txt' }
        }
        Invoke-Step 'Service de temps' {
            $c = Invoke-External 'w32tm.exe' '/query /configuration' 30
            $s = Invoke-External 'w32tm.exe' '/query /status' 30
            Add-Raw 'w32tm /query /status' $s 'w32tm_status.txt'
            Add-Raw 'w32tm /query /configuration' $c 'w32tm_configuration.txt'
            $isPdc = ($d.PDCEmulator -like "$env:COMPUTERNAME*")
            if ($isPdc -and ($s -match '(?im)^(Source|Source\s*)\s*:\s*(Local CMOS Clock|Free-running System Clock|VM IC Time Synchronization Provider|Horloge CMOS locale)')) { Add-Finding Moyen 'Active Directory' 'PDC sans source de temps externe fiable' ($Matches[2]) 'Configurer le PDC sur des serveurs NTP externes (w32tm /config /manualpeerlist:"0.fr.pool.ntp.org,0x8 1.fr.pool.ntp.org,0x8" /syncfromflags:manual /reliable:yes /update) et désactiver la synchro horaire Hyper-V côté invité DC.' }
        }
        Invoke-Step 'Sites / sous-réseaux / approbations' {
            Add-Table 'Sites' (Get-ADReplicationSite -Filter * -Server $dc | Select-Object Name, Description)
            Add-Table 'Sous-réseaux' (Get-ADReplicationSubnet -Filter * -Server $dc | Select-Object Name, Site, Location)
            Add-Table 'Liens de sites' (Get-ADReplicationSiteLink -Filter * -Server $dc | Select-Object Name, Cost, ReplicationFrequencyInMinutes, @{n = 'Sites'; e = { $_.SitesIncluded -join '; ' } })
            $t = @(Get-ADTrust -Filter * -Server $dc -ErrorAction SilentlyContinue)
            Add-Table 'Approbations (trusts)' ($t | Select-Object Name, Direction, TrustType, ForestTransitive, SelectiveAuthentication, SIDFilteringQuarantined, UsesAESKeys, UsesRC4Encryption)
            if ($t.Count) { Add-Finding Info 'Active Directory' "$($t.Count) approbation(s) avec d'autres domaines" (($t.Name) -join ', ') 'Vérifier le chiffrement (AES) et le fonctionnement des approbations après introduction des DC 2025.' }
        }
        Invoke-Step 'Fonctionnalités optionnelles / tombstone' {
            $of = Get-ADOptionalFeature -Filter * -Server $dc | Select-Object Name, @{n = 'Activée'; e = { [bool]$_.EnabledScopes } }
            Add-Table 'Fonctionnalités optionnelles AD' $of
            if (-not (($of | Where-Object { $_.Name -like 'Recycle Bin*' }).'Activée')) { Add-Finding Faible 'Active Directory' 'Corbeille AD non activée' '' 'Activer la corbeille AD (Enable-ADOptionalFeature "Recycle Bin Feature") : filet de sécurité en cas de suppression pendant la migration.' }
            $cfg = (Get-ADRootDSE -Server $dc).configurationNamingContext
            $tsl = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$cfg" -Properties tombstoneLifetime -Server $dc).tombstoneLifetime
            Add-Note ("Durée de vie tombstone : {0} jours" -f $(if ($tsl) { $tsl } else { '60 (défaut historique, non défini)' }))
            $exch = $null; try { $exch = Get-ADObject -Filter * -SearchBase "CN=Services,$cfg" -SearchScope OneLevel -Server $dc -ErrorAction Stop | Where-Object { $_.Name -eq 'Microsoft Exchange' } } catch { }
            if ($exch) { Add-Finding Info 'Active Directory' 'Organisation Exchange présente dans la forêt' 'Le schéma/la configuration contient Exchange (sur site ou hybride).' 'Vérifier la compatibilité des serveurs Exchange avec des DC 2025 (versions Exchange supportées).' }
            $cas = @(); try { $cas = @(Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg" -Filter * -Properties dNSHostName -Server $dc -ErrorAction Stop | Where-Object { $_ }) } catch { }
            if ($cas.Count) { Add-Table 'Autorités de certification d''entreprise (AD CS)' ($cas | Select-Object Name, dNSHostName); Add-Finding Info 'PKI' "AD CS présent : $(($cas.dNSHostName) -join ', ')" 'Les certificats des DC (LDAPS, Kerberos) seront à réémettre pour les nouveaux DC.' 'Vérifier les modèles DomainController/Kerberos Authentication et l''auto-enrollment.' }
        }
        Invoke-Step 'Stratégies de mot de passe' {
            Add-Table 'Stratégie de mot de passe par défaut' (Get-ADDefaultDomainPasswordPolicy -Server $dc | Select-Object ComplexityEnabled, MinPasswordLength, PasswordHistoryCount, MaxPasswordAge, MinPasswordAge, LockoutThreshold, LockoutDuration, LockoutObservationWindow, ReversibleEncryptionEnabled)
            Add-Table 'Stratégies affinées (FGPP)' (Get-ADFineGrainedPasswordPolicy -Filter * -Server $dc -ErrorAction SilentlyContinue | Select-Object Name, Precedence, MinPasswordLength, MaxPasswordAge, LockoutThreshold, @{n = 'AppliquéeÀ'; e = { $_.AppliesTo -join '; ' } })
        }
        Invoke-Step 'Groupes à privilèges' {
            $groups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners', 'Protected Users', 'Remote Desktop Users', 'Hyper-V Administrators'
            $sidMap = @{ 'Domain Admins' = "$($d.DomainSID)-512"; 'Enterprise Admins' = "$($script:domain.DomainSID)-519"; 'Schema Admins' = "$($d.DomainSID)-518"; 'Administrators' = 'S-1-5-32-544'; 'Account Operators' = 'S-1-5-32-548'; 'Backup Operators' = 'S-1-5-32-551'; 'Server Operators' = 'S-1-5-32-549'; 'Print Operators' = 'S-1-5-32-550'; 'Group Policy Creator Owners' = "$($d.DomainSID)-520"; 'Protected Users' = "$($d.DomainSID)-525"; 'Remote Desktop Users' = 'S-1-5-32-555'; 'Hyper-V Administrators' = 'S-1-5-32-578' }
            $rows = foreach ($g in $groups) {
                $id = if ($sidMap[$g]) { $sidMap[$g] } else { $g }
                try {
                    $grp = Get-ADGroup -Identity $id -Server $dc -ErrorAction Stop
                    $mem = @(Get-ADGroupMember -Identity $grp -Recursive -Server $dc -ErrorAction Stop)
                    foreach ($m in $mem) { [pscustomobject]@{ Groupe = $grp.Name; Membre = $m.SamAccountName; Nom = $m.Name; Type = $m.objectClass } }
                    if (-not $mem.Count) { [pscustomobject]@{ Groupe = $grp.Name; Membre = '(vide)'; Nom = ''; Type = '' } }
                } catch { }
            }
            Add-Table 'Membres des groupes à privilèges (récursif)' $rows
            $daName = $null; $saName = $null
            try { $daName = (Get-ADGroup -Identity "$($d.DomainSID)-512" -Server $dc -ErrorAction Stop).Name; $saName = (Get-ADGroup -Identity "$($d.DomainSID)-518" -Server $dc -ErrorAction Stop).Name } catch { }
            $da = @($rows | Where-Object { $_.Groupe -eq $daName -and $_.Type -eq 'user' })
            if ($da.Count -gt 5) { Add-Finding Moyen 'Sécurité' "$($da.Count) comptes membres de Domain Admins" (($da.Membre) -join ', ') 'Réduire les comptes à privilèges ; utiliser des comptes d''administration dédiés.' }
            $sa = @($rows | Where-Object { $_.Groupe -eq $saName -and $_.Membre -ne '(vide)' })
            if ($sa.Count) { Add-Finding Info 'Active Directory' "Membres de Schema Admins : $(($sa.Membre) -join ', ')" 'Nécessaire uniquement pendant l''extension de schéma.' 'Vider Schema Admins après la migration.' }
        }
        Invoke-Step 'Comptes utilisateurs' {
            $limit = (Get-Date).AddDays(-$StaleDays)
            $users = @(Get-ADUser -Filter * -Server $dc -Properties Enabled, LastLogonTimestamp, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, AllowReversiblePasswordEncryption, UseDESKeyOnly, ServicePrincipalName, adminCount, 'msDS-SupportedEncryptionTypes', WhenCreated, Description)
            $en = @($users | Where-Object { $_.Enabled })
            $stale = @($en | Where-Object { -not $_.LastLogonTimestamp -or [datetime]::FromFileTime($_.LastLogonTimestamp) -lt $limit })
            $kerb = @($en | Where-Object { $_.ServicePrincipalName -and $_.SamAccountName -ne 'krbtgt' })
            Add-KV 'Statistiques comptes utilisateurs' ([ordered]@{
                    'Total' = $users.Count; 'Activés' = $en.Count; 'Désactivés' = ($users.Count - $en.Count)
                    "Activés inactifs > $StaleDays j" = $stale.Count
                    'Mot de passe n''expire jamais (activés)' = @($en | Where-Object { $_.PasswordNeverExpires }).Count
                    'Mot de passe non requis' = @($en | Where-Object { $_.PasswordNotRequired }).Count
                    'Pré-auth Kerberos désactivée (AS-REP roastable)' = @($en | Where-Object { $_.DoesNotRequirePreAuth }).Count
                    'Chiffrement réversible' = @($en | Where-Object { $_.AllowReversiblePasswordEncryption }).Count
                    'DES uniquement' = @($en | Where-Object { $_.UseDESKeyOnly }).Count
                    'Avec SPN (kerberoastables)' = $kerb.Count
                    'adminCount=1' = @($en | Where-Object { $_.adminCount -eq 1 }).Count
                })
            $flag = foreach ($u in $en) {
                $r = @()
                if ($u.PasswordNotRequired) { $r += 'MDP non requis' }
                if ($u.DoesNotRequirePreAuth) { $r += 'Pas de pré-auth' }
                if ($u.AllowReversiblePasswordEncryption) { $r += 'Chiffrement réversible' }
                if ($u.UseDESKeyOnly) { $r += 'DES uniquement' }
                if ($u.ServicePrincipalName -and $u.SamAccountName -ne 'krbtgt') { $r += 'SPN' }
                if ($u.PasswordNeverExpires -and $u.adminCount -eq 1) { $r += 'Admin + MDP sans expiration' }
                if ($r.Count) { [pscustomobject]@{ Compte = $u.SamAccountName; 'Problèmes' = ($r -join ', '); 'Dernier MDP' = $u.PasswordLastSet; 'Dernière connexion' = $(if ($u.LastLogonTimestamp) { [datetime]::FromFileTime($u.LastLogonTimestamp) }); SPN = ($u.ServicePrincipalName -join '; ') } }
            }
            Add-Table 'Comptes activés à risque' $flag
            Add-Table "Comptes activés inactifs > $StaleDays jours" ($stale | Select-Object SamAccountName, Name, @{n = 'Dernière connexion'; e = { if ($_.LastLogonTimestamp) { [datetime]::FromFileTime($_.LastLogonTimestamp) } } }, PasswordLastSet, WhenCreated, Description)
            if (@($en | Where-Object { $_.UseDESKeyOnly }).Count) { Add-Finding Eleve 'Sécurité' 'Comptes configurés en DES uniquement' '' 'DES est désactivé par défaut : ces comptes ne pourront pas s''authentifier en Kerberos.' }
            if ($stale.Count -gt 0) { Add-Finding Faible 'Active Directory' "$($stale.Count) comptes utilisateurs activés inactifs > $StaleDays j" '' 'Nettoyer (désactiver/supprimer) avant migration : réduit la surface et clarifie les licences (CAL).' }
            $krb = Get-ADUser krbtgt -Properties PasswordLastSet -Server $dc
            $age = ((Get-Date) - $krb.PasswordLastSet).Days
            Add-Note ("Mot de passe krbtgt changé il y a {0} jours ({1})" -f $age, $krb.PasswordLastSet)
            if ($age -gt 365) { Add-Finding Moyen 'Sécurité' "Mot de passe krbtgt non changé depuis $age jours" '' 'Après la migration (réplication saine), réinitialiser krbtgt deux fois à 10 h+ d''intervalle (script New-KrbtgtKeys).' }
        }
        Invoke-Step 'Ordinateurs et OS du parc' {
            $limit = (Get-Date).AddDays(-$StaleDays)
            $comp = @(Get-ADComputer -Filter * -Server $dc -Properties OperatingSystem, OperatingSystemVersion, LastLogonTimestamp, Enabled, IPv4Address, 'msDS-SupportedEncryptionTypes', PasswordLastSet)
            Add-Table 'Répartition des OS (comptes ordinateurs activés)' ($comp | Where-Object { $_.Enabled } | Group-Object OperatingSystem | Sort-Object Count -Descending | Select-Object @{n = 'Système'; e = { if ($_.Name) { $_.Name } else { '(non renseigné)' } } }, Count)
            Add-Table 'Serveurs (comptes ordinateurs)' ($comp | Where-Object { $_.OperatingSystem -match 'Server' } | Sort-Object Name | Select-Object Name, OperatingSystem, OperatingSystemVersion, IPv4Address, Enabled, @{n = 'Dernière connexion'; e = { if ($_.LastLogonTimestamp) { [datetime]::FromFileTime($_.LastLogonTimestamp) } } })
            $legacy = @($comp | Where-Object { $_.Enabled -and $_.OperatingSystem -match 'XP|Vista|Windows 7|Windows 8|2003|2008|2012|Windows 10' -and $_.LastLogonTimestamp -and [datetime]::FromFileTime($_.LastLogonTimestamp) -gt $limit })
            if ($legacy.Count) { Add-Finding Moyen 'Compatibilité' "$($legacy.Count) machine(s) active(s) avec un OS obsolète" (($legacy | Select-Object -First 15 | ForEach-Object { "$($_.Name) ($($_.OperatingSystem))" }) -join ', ') 'Durcissements WS2025 (NTLMv1 supprimé, LDAP/SMB signés, TLS 1.0/1.1 off, RC4 restreint) : tester ou remplacer ces machines.' }
            $staleC = @($comp | Where-Object { $_.Enabled -and (-not $_.LastLogonTimestamp -or [datetime]::FromFileTime($_.LastLogonTimestamp) -lt $limit) })
            Add-Table "Ordinateurs activés inactifs > $StaleDays j" ($staleC | Select-Object Name, OperatingSystem, @{n = 'Dernière connexion'; e = { if ($_.LastLogonTimestamp) { [datetime]::FromFileTime($_.LastLogonTimestamp) } } }, PasswordLastSet)
        }
        Invoke-Step 'Comptes de service gérés / LAPS' {
            Add-Table 'Comptes de service gérés (gMSA/sMSA)' (Get-ADServiceAccount -Filter * -Server $dc -Properties PrincipalsAllowedToRetrieveManagedPassword -ErrorAction SilentlyContinue | Select-Object Name, ObjectClass, Enabled, @{n = 'Autorisés'; e = { $_.PrincipalsAllowedToRetrieveManagedPassword -join '; ' } })
            $sch = (Get-ADRootDSE -Server $dc).schemaNamingContext
            $legacy = [bool](Get-ADObject -SearchBase $sch -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwd)' -Server $dc)
            $win = [bool](Get-ADObject -SearchBase $sch -LDAPFilter '(lDAPDisplayName=msLAPS-Password)' -Server $dc)
            $kds = @(Get-KdsRootKey -ErrorAction SilentlyContinue).Count
            Add-KV 'LAPS / KDS' ([ordered]@{ 'Schéma LAPS hérité (ms-Mcs-AdmPwd)' = $legacy; 'Schéma Windows LAPS (msLAPS-Password)' = $win; 'Clés racine KDS (gMSA)' = $kds })
            if (-not $win) { Add-Finding Faible 'Sécurité' 'Windows LAPS non déployé (schéma absent)' '' 'Profiter de la migration pour déployer Windows LAPS (natif sous 2019 à jour et 2025).' }
        }
        Invoke-Step 'Unités d''organisation' {
            Add-Table 'Unités d''organisation' (Get-ADOrganizationalUnit -Filter * -Server $dc -Properties ProtectedFromAccidentalDeletion, gPLink | Sort-Object DistinguishedName | Select-Object Name, DistinguishedName, ProtectedFromAccidentalDeletion, @{n = 'GPO liées'; e = { ([regex]::Matches("$($_.gPLink)", 'cn=\{')).Count } })
        }
        Invoke-Step 'Synchronisation Entra ID' {
            $sync = @(Get-ADUser -LDAPFilter '(|(sAMAccountName=MSOL_*)(sAMAccountName=Sync_*)(sAMAccountName=AAD_*))' -Server $dc -Properties Description | Select-Object SamAccountName, Description)
            if ($sync.Count) { Add-Table 'Comptes de synchronisation Entra ID' $sync; Add-Finding Info 'Active Directory' 'Synchronisation Entra ID (Azure AD Connect) détectée' (($sync.SamAccountName) -join ', ') 'Identifier le serveur Entra Connect et vérifier qu''il pointe vers les nouveaux DC (préférence DC) après migration.' }
        }
        Invoke-Step 'netdom' { Add-Raw 'netdom query fsmo' (Invoke-External 'netdom.exe' 'query fsmo' 60) 'netdom_fsmo.txt' }
    }
}

function Invoke-GPOCollector {
    Invoke-Collector -Id 'GPO' -Title 'Stratégies de groupe (GPO)' -When ($Script:Roles.IsDC) -Body {
        if (-not (Import-ModuleSafe 'GroupPolicy')) { throw 'Module GroupPolicy indisponible.' }
        Invoke-Step 'Liste des GPO' {
            $dom = (Get-CimInstance Win32_ComputerSystem).Domain
            $gpos = @(Get-GPO -All -Domain $dom -ErrorAction Stop)
            [xml]$xml = Get-GPOReport -All -ReportType Xml -Domain $dom -ErrorAction Stop
            $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable); $ns.AddNamespace('g', 'http://www.microsoft.com/GroupPolicy/Settings')
            $links = @{}
            foreach ($r in $xml.SelectNodes('//g:GPO', $ns)) {
                $id = $r.Identifier.Identifier.'#text'
                if (-not $id) { $id = $r.Identifier.Identifier }
                $links["$id".Trim('{}').ToLower()] = (@($r.LinksTo | ForEach-Object { '{0}{1}' -f $_.SOMPath, $(if ($_.Enabled -eq 'false') { ' (désactivé)' } else { '' }) }) -join '; ')
            }
            $rows = foreach ($g in $gpos) {
                $l = $links["$($g.Id)".ToLower()]
                [pscustomobject]@{ Nom = $g.DisplayName; Statut = $g.GpoStatus; 'Créée' = $g.CreationTime; 'Modifiée' = $g.ModificationTime; 'Version ordinateur' = $g.Computer.DSVersion; 'Version utilisateur' = $g.User.DSVersion; 'Filtre WMI' = $g.WmiFilter.Name; 'Liée à' = $l; Id = $g.Id }
            }
            Add-Table 'GPO du domaine' $rows
            $unl = @($rows | Where-Object { -not $_.'Liée à' })
            if ($unl.Count) { Add-Finding Faible 'GPO' "$($unl.Count) GPO non liée(s)" (($unl.Nom) -join ', ') 'Nettoyer ou documenter.' }
            $wmi = @($rows | Where-Object { $_.'Filtre WMI' })
            if ($wmi.Count) { Add-Finding Moyen 'GPO' "$($wmi.Count) GPO avec filtre WMI" (($wmi | ForEach-Object { "$($_.Nom) [$($_.'Filtre WMI')]" }) -join ', ') 'Vérifier que les filtres (souvent basés sur Version/Caption de l''OS) incluent WS2025 (version 10.0.26100).' }
            if (-not $Quick) {
                $f = Join-Path $Script:RawFolder 'GPO_AllReport.html'
                Get-GPOReport -All -ReportType Html -Domain $dom -Path $f -ErrorAction SilentlyContinue
                Add-Note 'Rapport détaillé de toutes les GPO : raw\GPO_AllReport.html'
            }
            $wf = @(); try { $wf = @(Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties 'msWMI-Name', 'msWMI-Parm2' -ErrorAction Stop) } catch { }
            Add-Table 'Filtres WMI' ($wf | Select-Object @{n = 'Nom'; e = { $_.'msWMI-Name' } }, @{n = 'Requête'; e = { $_.'msWMI-Parm2' } })
        }
        Invoke-Step 'Magasin central ADMX' {
            $pol = $Script:Facts.SysvolPolicies
            if (-not $pol) { $pol = '\\{0}\SYSVOL\{0}\Policies' -f (Get-CimInstance Win32_ComputerSystem).Domain }
            $pd = Join-Path $pol 'PolicyDefinitions'
            if (Test-Path $pd) {
                $admx = @(Get-ChildItem $pd -Filter *.admx -ErrorAction SilentlyContinue)
                $lang = @(Get-ChildItem $pd -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
                $newest = ($admx | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
                Add-KV 'Magasin central' ([ordered]@{ 'Chemin' = $pd; 'Nombre ADMX' = $admx.Count; 'Langues' = $lang; 'ADMX le plus récent' = $newest })
                Add-Finding Info 'GPO' 'Magasin central ADMX présent' "ADMX le plus récent : $newest" 'Mettre à jour le magasin central avec les ADMX WS2025/Windows 11 24H2 (en conservant fr-FR et en-US) après la migration.'
            } else { Add-Finding Faible 'GPO' 'Pas de magasin central ADMX' '' 'Créer le magasin central (PolicyDefinitions dans SYSVOL) avec les ADMX récents.' }
        }
    }
}

function Invoke-DNSCollector {
    Invoke-Collector -Id 'DNS' -Title 'Serveur DNS' -When $Script:Roles.IsDNS -Body {
        if (-not (Import-ModuleSafe 'DnsServer')) { throw 'Module DnsServer indisponible.' }
        Invoke-Step 'Zones' {
            $z = @(Get-DnsServerZone -ErrorAction Stop)
            Add-Table 'Zones DNS' ($z | Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate, IsReverseLookupZone, IsAutoCreated, IsPaused, IsSigned, @{n = 'Maîtres'; e = { $_.MasterServers -join ', ' } })
            $ns = @($z | Where-Object { "$($_.DynamicUpdate)" -eq 'NonsecureAndSecure' -and -not $_.IsAutoCreated })
            if ($ns.Count) { Add-Finding Moyen 'DNS' 'Mises à jour dynamiques non sécurisées autorisées' (($ns.ZoneName) -join ', ') 'Passer en "Sécurisées uniquement" pour les zones AD.' }
            $nonAD = @($z | Where-Object { "$($_.ZoneType)" -eq 'Primary' -and -not $_.IsDsIntegrated -and -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' })
            if ($nonAD.Count) { Add-Finding Moyen 'DNS' 'Zones primaires non intégrées AD' (($nonAD.ZoneName) -join ', ') 'Ces zones (fichiers .dns) ne sont pas répliquées : les copier/convertir avant de retirer ce serveur.' }
            $aging = foreach ($zz in ($z | Where-Object { "$($_.ZoneType)" -eq 'Primary' -and -not $_.IsAutoCreated })) { Get-DnsServerZoneAging -Name $zz.ZoneName -ErrorAction SilentlyContinue | Select-Object ZoneName, AgingEnabled, NoRefreshInterval, RefreshInterval }
            Add-Table 'Vieillissement des zones' $aging
        }
        Invoke-Step 'Redirecteurs / récursion / nettoyage' {
            $fw = Get-DnsServerForwarder -ErrorAction Stop
            Add-KV 'Redirecteurs' ([ordered]@{ 'Adresses' = $fw.IPAddress; 'Utiliser indications de racine' = $fw.UseRootHint; 'Délai (s)' = $fw.Timeout })
            $sc = Get-DnsServerScavenging -ErrorAction SilentlyContinue
            Add-KV 'Nettoyage (scavenging)' ([ordered]@{ 'Activé' = $sc.ScavengingState; 'Intervalle' = $sc.ScavengingInterval; 'Dernier nettoyage' = $sc.LastScavengeTime })
            if (-not $sc.ScavengingState) { Add-Finding Faible 'DNS' 'Nettoyage DNS (scavenging) désactivé' '' 'Activer avec prudence (sur un seul serveur) après vérification des enregistrements statiques.' }
            $rec = Get-DnsServerRecursion -ErrorAction SilentlyContinue
            Add-KV 'Récursion' ([ordered]@{ 'Activée' = $rec.Enable; 'Délai' = $rec.Timeout })
            $set = Get-DnsServerSetting -All -ErrorAction SilentlyContinue
            Add-KV 'Paramètres serveur' ([ordered]@{ 'Adresses d''écoute' = $set.ListeningIPAddress; 'Round robin' = $set.RoundRobin; 'Version' = ('{0}.{1}.{2}' -f $set.MajorVersion, $set.MinorVersion, $set.BuildNumber) })
            $cf = @(Get-DnsServerZone | Where-Object { "$($_.ZoneType)" -eq 'Forwarder' })
            if ($cf.Count) { Add-Finding Info 'DNS' "$($cf.Count) redirecteur(s) conditionnel(s)" (($cf | ForEach-Object { "$($_.ZoneName)→$($_.MasterServers -join ',')" }) -join ' | ') 'Vérifier leur portée (stockés dans AD ou locaux) pour qu''ils existent sur le nouveau DC.' }
        }
        Invoke-Step 'Enregistrements statiques A (zones principales)' {
            $z = Get-DnsServerZone | Where-Object { "$($_.ZoneType)" -eq 'Primary' -and -not $_.IsReverseLookupZone -and -not $_.IsAutoCreated -and $_.ZoneName -notmatch '^_msdcs|TrustAnchors' }
            $rows = foreach ($zz in $z) { Get-DnsServerResourceRecord -ZoneName $zz.ZoneName -RRType A -ErrorAction SilentlyContinue | Where-Object { -not $_.Timestamp } | Select-Object @{n = 'Zone'; e = { $zz.ZoneName } }, HostName, @{n = 'IP'; e = { $_.RecordData.IPv4Address.IPAddressToString } } }
            Add-Table 'Enregistrements A statiques' $rows -Note 'À vérifier lors d''un changement d''adresse IP de serveur.'
        }
    }
}

function Invoke-DHCPCollector {
    Invoke-Collector -Id 'DHCP' -Title 'Serveur DHCP' -When $Script:Roles.IsDHCP -Body {
        if (-not (Import-ModuleSafe 'DhcpServer')) { throw 'Module DhcpServer indisponible.' }
        Invoke-Step 'Étendues' {
            $sc = @(Get-DhcpServerv4Scope -ErrorAction Stop)
            $stats = @{}; Get-DhcpServerv4ScopeStatistics -ErrorAction SilentlyContinue | ForEach-Object { $stats["$($_.ScopeId)"] = $_ }
            Add-Table 'Étendues IPv4' ($sc | Select-Object ScopeId, Name, SubnetMask, StartRange, EndRange, State, LeaseDuration, @{n = 'Utilisé %'; e = { [math]::Round($stats["$($_.ScopeId)"].PercentageInUse, 1) } }, @{n = 'Libres'; e = { $stats["$($_.ScopeId)"].Free } })
            $full = @($sc | Where-Object { $stats["$($_.ScopeId)"].PercentageInUse -gt 85 })
            if ($full.Count) { Add-Finding Faible 'DHCP' 'Étendue(s) DHCP > 85 %' (($full.ScopeId) -join ', ') 'Surveiller ; ajuster pendant la migration.' }
            Add-Table 'Options serveur' (Get-DhcpServerv4OptionValue -All -ErrorAction SilentlyContinue | Select-Object OptionId, Name, @{n = 'Valeur'; e = { $_.Value -join ', ' } })
            $opt = foreach ($s in $sc) { Get-DhcpServerv4OptionValue -ScopeId $s.ScopeId -ErrorAction SilentlyContinue | Select-Object @{n = 'Étendue'; e = { $s.ScopeId } }, OptionId, Name, @{n = 'Valeur'; e = { $_.Value -join ', ' } } }
            Add-Table 'Options d''étendue' $opt
            $res = foreach ($s in $sc) { Get-DhcpServerv4Reservation -ScopeId $s.ScopeId -ErrorAction SilentlyContinue | Select-Object ScopeId, IPAddress, ClientId, Name, Description }
            Add-Table 'Réservations' $res
            $fo = @(Get-DhcpServerv4Failover -ErrorAction SilentlyContinue)
            Add-Table 'Basculement DHCP' ($fo | Select-Object Name, PartnerServer, Mode, State, @{n = 'Étendues'; e = { $_.ScopeId -join ', ' } })
            Add-Table 'Serveurs DHCP autorisés dans AD' (Get-DhcpServerInDC -ErrorAction SilentlyContinue | Select-Object DnsName, IPAddress)
            $dns = Get-DhcpServerv4DnsSetting -ErrorAction SilentlyContinue
            if ($dns) { Add-KV 'Mise à jour DNS par DHCP' ([ordered]@{ 'DynamicUpdates' = $dns.DynamicUpdates; 'Supprimer à expiration' = $dns.DeleteDnsRROnLeaseExpiry; 'Mise à jour clients anciens' = $dns.UpdateDnsRRForOlderClients }) }
            $cred = $null; try { $cred = Get-DhcpServerDnsCredential -ErrorAction Stop } catch { }
            if ($cred -and $cred.UserName) { Add-Note "Identifiants DNS DHCP : $($cred.DomainName)\$($cred.UserName)" }
            elseif ($Script:Roles.IsDC) { Add-Finding Faible 'DHCP' 'DHCP sur DC sans identifiants de mise à jour DNS dédiés' '' 'Configurer un compte dédié (Set-DhcpServerDnsCredential) pour éviter les enregistrements DNS détenus par le compte machine du DC.' }
            if (-not $fo.Count) { Add-Finding Info 'DHCP' 'Pas de basculement DHCP' '' 'Pendant la migration le service DHCP sera interrompu : planifier (bail long, migration via Export/Import-DhcpServer).' }
        }
        Invoke-Step 'Export DHCP' {
            $f = Join-Path $Script:RawFolder 'dhcp_export.xml'
            Export-DhcpServer -File $f -Leases -Force -ErrorAction Stop
            Add-Note 'Export complet DHCP (configuration + baux) : raw\dhcp_export.xml — réimportable via Import-DhcpServer sur la cible.'
        }
    }
}
#endregion

#region ===================== RDS =====================
function Invoke-RDSCollector {
    Invoke-Collector -Id 'RDS' -Title 'Services Bureau à distance (RDS)' -When $Script:Roles.IsRDS -Body {
        $fqdn = if ($Script:CS.PartOfDomain) { '{0}.{1}' -f $env:COMPUTERNAME, $Script:CS.Domain } else { $env:COMPUTERNAME }
        Invoke-Step 'Licences côté hôte de session' {
            $ts = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName Win32_TerminalServiceSetting -ErrorAction Stop
            $grace = $null; try { $grace = (Invoke-CimMethod -InputObject $ts -MethodName GetGracePeriodDays -ErrorAction Stop).DaysLeft } catch { }
            $lsList = $null; try { $lsList = (Invoke-CimMethod -InputObject $ts -MethodName GetSpecifiedLicenseServerList -ErrorAction Stop).SpecifiedLSList } catch { }
            $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            $polMode = Get-RegValue $polKey 'LicensingMode'; $polSrv = Get-RegValue $polKey 'LicenseServers'
            $regMode = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core' 'LicensingMode'
            $modeMap = @{ 2 = 'Par périphérique'; 4 = 'Par utilisateur'; 5 = 'Non configuré' }
            $eff = if ($polMode) { $polMode } elseif ($regMode) { $regMode } else { $ts.LicensingType }
            $Script:Facts.RDSLicMode = $modeMap[[int]$eff]
            Add-KV 'Licences RDS (hôte de session)' ([ordered]@{
                    'Mode RDSH (TerminalServerMode : 1 = serveur d''applications)' = $ts.TerminalServerMode
                    'Mode de licence effectif'         = ('{0} ({1})' -f $modeMap[[int]$eff], $eff)
                    'Description WMI'                  = $ts.LicensingDescription
                    'Mode imposé par GPO'              = $polMode
                    'Serveurs de licences (GPO)'       = $polSrv
                    'Serveurs de licences (spécifiés)' = $lsList
                    'Jours de grâce restants'          = $grace
                })
            if ($Script:Roles.IsRDSH) {
                if ([int]$eff -eq 5 -or -not $eff) { Add-Finding Eleve 'RDS' 'Mode de licence RDS non configuré' '' 'Configurer le mode (utilisateur/périphérique) et le serveur de licences (déploiement ou GPO).' }
                if (-not $lsList -and -not $polSrv) { Add-Finding Eleve 'RDS' 'Aucun serveur de licences RDS spécifié' "Jours de grâce restants : $grace" 'Configurer le serveur de licences ; sans CAL valides les connexions seront refusées après la période de grâce (120 j).' }
                if ($grace -gt 0 -and $grace -lt 120) { Add-Finding Moyen 'RDS' "Période de grâce RDS active ($grace j restants)" 'Indique que les licences ne sont pas (ou pas correctement) délivrées.' 'Vérifier serveur de licences, mode et CAL installées (Diagnostic des licences RD).' }
                Add-Finding Eleve 'Licences' 'CAL RDS 2025 obligatoires pour un hôte de session WS2025' 'Les CAL RDS 2019 ne sont pas valides pour des hôtes de session 2025, et le serveur de licences doit être d''une version ≥ à celle des hôtes (donc 2025).' "Acheter des CAL RDS 2025 (mode actuel : $($modeMap[[int]$eff])) en nombre suffisant et les installer sur un serveur de licences 2025 AVANT la bascule des hôtes de session."
            }
        }
        if ($Script:Roles.IsRDLicensing) {
            Invoke-Step 'Serveur de licences RDS' {
                $kp = @(Get-CimInstance -ClassName Win32_TSLicenseKeyPack -ErrorAction Stop)
                $typeMap = @{ 0 = 'Inconnu'; 1 = 'Retail'; 2 = 'Volume'; 3 = 'Concurrent'; 4 = 'Temporaire'; 5 = 'Open'; 6 = 'Non supporté'; 7 = 'Spécial' }
                Add-Table 'Packs de licences (CAL) installés' ($kp | Select-Object KeyPackId, @{n = 'Type'; e = { $typeMap[[int]$_.KeyPackType] } }, ProductVersion, ProductType, TypeAndModel, TotalLicenses, AvailableLicenses, IssuedLicenses, ExpirationDate)
                $real = @($kp | Where-Object { [int]$_.KeyPackType -ne 4 -and $_.TotalLicenses -gt 0 })
                $v2025 = @($real | Where-Object { $_.ProductVersion -match '2025' })
                if (-not $v2025.Count) { Add-Finding Eleve 'Licences' 'Aucune CAL RDS 2025 installée sur le serveur de licences' (($real | ForEach-Object { "$($_.ProductVersion) $($_.TypeAndModel) : $($_.TotalLicenses)" }) -join ' | ') 'Le serveur de licences doit passer en 2025 et recevoir des CAL RDS 2025 avant migration des hôtes de session.' }
                try {
                    $ls = Get-CimInstance -ClassName Win32_TSLicenseServer -ErrorAction Stop
                    $act = (Invoke-CimMethod -InputObject $ls -MethodName GetActivationStatus -ErrorAction Stop).ActivationStatus
                    Add-Note ("Statut d'activation du serveur de licences : {0}" -f $(if ($act -eq 0) { 'Activé' } else { "Non activé ($act)" }))
                    if ($act -ne 0) { Add-Finding Eleve 'RDS' 'Serveur de licences RDS non activé' '' 'Activer le serveur de licences.' }
                } catch { }
                $iss = @(Get-CimInstance -ClassName Win32_TSIssuedLicense -ErrorAction SilentlyContinue)
                Add-Table 'Licences délivrées (par périphérique / suivies)' ($iss | Select-Object sIssuedToComputer, sIssuedToUser, ProductVersion, IssueDate, ExpirationDate, LicenseStatus | Select-Object -First 1000)
            }
        }
        Invoke-Step 'Déploiement RDS (RemoteDesktop)' {
            if (-not (Import-ModuleSafe 'RemoteDesktop')) { Add-Note 'Module RemoteDesktop indisponible (déploiement non géré par le Gestionnaire de serveur ?).'; return }
            $cb = $fqdn
            $srv = $null
            try { $srv = @(Get-RDServer -ConnectionBroker $cb -ErrorAction Stop) } catch {
                $alt = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings' 'SessionDirectoryLocation'
                if ($alt) { $cb = $alt; $srv = @(Get-RDServer -ConnectionBroker $cb -ErrorAction Stop) } else { throw }
            }
            $Script:Facts.RDBroker = $cb
            Add-Table 'Serveurs du déploiement' ($srv | Select-Object Server, @{n = 'Rôles'; e = { $_.Roles -join ', ' } })
            $col = @(Get-RDSessionCollection -ConnectionBroker $cb -ErrorAction SilentlyContinue)
            Add-Table 'Collections de sessions' ($col | Select-Object CollectionName, CollectionDescription, ResourceType, Size, AutoAssignPersonalDesktop)
            foreach ($c in $col) {
                $g = Get-RDSessionCollectionConfiguration -CollectionName $c.CollectionName -ConnectionBroker $cb -ErrorAction SilentlyContinue
                $u = Get-RDSessionCollectionConfiguration -CollectionName $c.CollectionName -ConnectionBroker $cb -UserProfileDisk -ErrorAction SilentlyContinue
                $s = Get-RDSessionCollectionConfiguration -CollectionName $c.CollectionName -ConnectionBroker $cb -Security -ErrorAction SilentlyContinue
                $cl = Get-RDSessionCollectionConfiguration -CollectionName $c.CollectionName -ConnectionBroker $cb -Client -ErrorAction SilentlyContinue
                Add-KV "Collection « $($c.CollectionName) »" ([ordered]@{
                        'Groupes autorisés'               = $g.UserGroup
                        'Déconnexion après inactivité'    = $g.IdleSessionLimitMin
                        'Fin session déconnectée (min)'   = $g.DisconnectedSessionLimitMin
                        'Durée session active (min)'      = $g.ActiveSessionLimitMin
                        'Action à la limite'              = $g.BrokenConnectionAction
                        'Reconnexion auto'                = $g.AutomaticReconnectionEnabled
                        'Disques de profil (UPD) activés' = $u.EnableUserProfileDisk
                        'Emplacement UPD'                 = $u.DiskPath
                        'Taille max UPD (Go)'             = $u.MaxUserProfileDiskSizeGB
                        'Couche de sécurité'              = $s.SecurityLayer
                        'Niveau de chiffrement'           = $s.EncryptionLevel
                        'NLA'                             = $s.AuthenticateUsingNLA
                        'Redirections client'             = $cl.ClientDeviceRedirectionOptions
                        'Imprimantes clientes'            = $cl.ClientPrinterRedirected
                    })
                if ($u.EnableUserProfileDisk) { Add-Finding Moyen 'RDS' "Disques de profil utilisateur (UPD) sur « $($c.CollectionName) »" "Emplacement : $($u.DiskPath)" 'Sauvegarder le partage UPD ; vérifier la compatibilité des profils (le format de profil change entre versions : prévoir tests, voire migration vers FSLogix).' }
                $apps = @(Get-RDRemoteApp -CollectionName $c.CollectionName -ConnectionBroker $cb -ErrorAction SilentlyContinue)
                Add-Table "RemoteApp « $($c.CollectionName) »" ($apps | Select-Object DisplayName, Alias, FilePath, CommandLineSetting, RequiredCommandLine, ShowInWebAccess, @{n = 'Groupes'; e = { $_.UserGroups -join ', ' } })
            }
            $certs = @(Get-RDCertificate -ConnectionBroker $cb -ErrorAction SilentlyContinue)
            Add-Table 'Certificats du déploiement' ($certs | Select-Object Role, Level, Subject, IssuedBy, ExpiresOn, Thumbprint, SubjectAlternateName)
            foreach ($ce in $certs) {
                if ("$($ce.Level)" -match 'Untrusted|NotConfigured') { Add-Finding Moyen 'RDS' "Certificat RDS « $($ce.Role) » : $($ce.Level)" $ce.Subject 'Utiliser un certificat public/PKI reconnu (SAN = nom RD Web / Gateway / Broker).' }
                elseif ($ce.ExpiresOn -and ([datetime]$ce.ExpiresOn) -lt (Get-Date).AddDays(60)) { Add-Finding Moyen 'RDS' "Certificat RDS « $($ce.Role) » expire le $($ce.ExpiresOn)" $ce.Subject 'Renouveler ; exporter le PFX pour la cible.' }
            }
            $lic = Get-RDLicenseConfiguration -ConnectionBroker $cb -ErrorAction SilentlyContinue
            if ($lic) { Add-KV 'Licences du déploiement' ([ordered]@{ 'Mode' = $lic.Mode; 'Serveurs de licences' = $lic.LicenseServer }) }
            $gw = Get-RDDeploymentGatewayConfiguration -ConnectionBroker $cb -ErrorAction SilentlyContinue
            if ($gw) { Add-KV 'Passerelle du déploiement' ([ordered]@{ 'Mode' = $gw.GatewayMode; 'FQDN externe' = $gw.GatewayExternalFqdn; 'Méthode auth.' = $gw.LogonMethod; 'Ignorer pour adresses locales' = $gw.BypassLocal; 'Identifiants partagés' = $gw.UseCachedCredentials }) }
            $ha = Get-RDConnectionBrokerHighAvailability -ConnectionBroker $cb -ErrorAction SilentlyContinue
            if ($ha) { Add-KV 'Haute disponibilité Broker' ([ordered]@{ 'Brokers' = $ha.ConnectionBroker; 'Base' = $ha.DatabaseConnectionString; 'DNS' = $ha.ClientAccessName }) }
            Add-Finding Info 'RDS' 'Ordre de migration d''un déploiement RDS' "Broker : $cb" 'Ordre supporté : 1) serveur de licences RD (2025 + CAL 2025), 2) Service Broker (tous les brokers HA avant le reste), 3) hôtes de session (les retirer de la collection, upgrade/rebuild, réintégrer), 4) Accès Web / Passerelle. Ne jamais avoir un hôte de session plus récent que le broker.'
        }
        Invoke-Step 'Stratégies RDS (GPO)' {
            $p = Get-RegKeyValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if ($p) { Add-KV 'Stratégies Terminal Services appliquées' $p } else { Add-Note 'Aucune stratégie RDS appliquée par GPO.' }
        }
        Invoke-Step 'Paramètres RDP-Tcp' {
            $g = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop
            Add-KV 'Écouteur RDP-Tcp' ([ordered]@{ 'Certificat (SHA1)' = $g.SSLCertificateSHA1Hash; 'Type de certificat' = $g.SSLCertificateSHA1HashType; 'NLA requis' = $g.UserAuthenticationRequired; 'Couche de sécurité' = $g.SecurityLayer; 'Niveau de chiffrement min.' = $g.MinEncryptionLevel })
        }
        Invoke-Step 'Sessions en cours' { Add-Raw 'quser / qwinsta' ((Invoke-External 'quser.exe' '' 30) + "`r`n" + (Invoke-External 'qwinsta.exe' '' 30)) 'sessions.txt' }
        Invoke-Step 'Profils utilisateurs' {
            $prof = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special })
            $rows = foreach ($p in $prof) {
                $name = $null; try { $name = (New-Object System.Security.Principal.SecurityIdentifier($p.SID)).Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $p.SID }
                $size = if (-not $Quick) { Get-DirectorySizeGB $p.LocalPath } else { $null }
                [pscustomobject]@{ Compte = $name; Chemin = $p.LocalPath; 'Dernière utilisation' = $p.LastUseTime; Chargé = $p.Loaded; 'Taille (Go)' = $size; 'Itinérant' = $p.RoamingConfigured; Statut = $p.Status }
            }
            $rows = @($rows | Sort-Object 'Taille (Go)' -Descending)
            Add-Table 'Profils locaux' $rows -Note $(if ($Quick) { 'Tailles non calculées (-Quick).' } else { '' })
            $tot = ($rows | Measure-Object 'Taille (Go)' -Sum).Sum
            Add-Note ("{0} profils, {1:N1} Go au total" -f $rows.Count, $tot)
            $old = @($rows | Where-Object { $_.'Dernière utilisation' -and ([datetime]$_.'Dernière utilisation') -lt (Get-Date).AddDays(-$StaleDays) })
            if ($old.Count -gt 5) { Add-Finding Faible 'RDS' "$($old.Count) profils non utilisés depuis $StaleDays j" '' 'Nettoyer les profils obsolètes avant l''upgrade (gain d''espace et de durée).' }
            if ($Script:Roles.IsRDSH -and $rows.Count -gt 0) { Add-Finding Moyen 'RDS' "Profils locaux sur l'hôte de session ($($rows.Count) profils, $([math]::Round($tot,1)) Go)" 'Les profils locaux d''un hôte reconstruit sont perdus ; en upgrade sur place ils sont conservés mais peuvent poser problème (cache, applis Store).' 'Décider : upgrade sur place (profils conservés) vs nouveau serveur + migration des données utilisateurs (Bureau, Documents, signatures Outlook, favoris, fichiers PST) ou FSLogix.' }
        }
        Invoke-Step 'FSLogix' {
            $fx = Get-RegKeyValues 'HKLM:\SOFTWARE\FSLogix\Profiles'
            if ($fx) { Add-KV 'FSLogix Profiles' $fx; $Script:Facts.FSLogix = $true }
            $fxo = Get-RegKeyValues 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC'
            if ($fxo) { Add-KV 'FSLogix ODFC' $fxo }
        }
        Invoke-Step 'Microsoft Office' {
            $c2r = Get-RegKeyValues 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
            if ($c2r) {
                Add-KV 'Office Click-to-Run' ([ordered]@{ 'Produits' = $c2r['ProductReleaseIds']; 'Version' = $c2r['VersionToReport']; 'Canal' = $c2r['CDNBaseUrl']; 'Plateforme' = $c2r['Platform']; 'Activation partagée (SharedComputerLicensing)' = $c2r['SharedComputerLicensing'] })
                if ($Script:Roles.IsRDSH -and $c2r['ProductReleaseIds'] -match 'O365|M365' -and "$($c2r['SharedComputerLicensing'])" -ne '1') { Add-Finding Eleve 'RDS' 'Microsoft 365 Apps sans activation partagée sur un hôte RDS' $c2r['ProductReleaseIds'] 'Activer SharedComputerLicensing=1 (obligatoire et licence M365 adaptée : E3/E5/Business Premium).' }
                if ($Script:Roles.IsRDSH) { Add-Finding Info 'RDS' "Office C2R : $($c2r['ProductReleaseIds']) $($c2r['VersionToReport'])" '' 'Vérifier le support de cette édition d''Office sur WS2025 (M365 Apps et Office LTSC 2024/2021 volume ; Office 2016/2019 hors support).' }
            }
            $msi = @($Script:Facts.Apps | Where-Object { $_.Nom -match '^Microsoft Office (Professional|Standard|Professionnel|Famille|Home)' })
            if ($msi.Count -and $Script:Roles.IsRDSH) { Add-Finding Moyen 'RDS' "Office MSI/volume : $(($msi.Nom) -join ', ')" '' 'Office 2016/2019 ne sont plus supportés (fin de support oct. 2025) : prévoir Office LTSC 2024 volume ou M365 Apps en activation partagée.' }
        }
    }
}
#endregion

#region ===================== Hyper-V =====================
function Invoke-HyperVCollector {
    Invoke-Collector -Id 'HyperV' -Title 'Hyper-V (hôte)' -When $Script:Roles.IsHyperV -Body {
        if (-not (Import-ModuleSafe 'Hyper-V')) { throw 'Module Hyper-V indisponible (RSAT-Hyper-V-Tools-PowerShell).' }
        $vms = @()
        Invoke-Step 'Hôte' {
            $h = Hyper-V\Get-VMHost -ErrorAction Stop
            Add-KV 'Configuration de l''hôte' ([ordered]@{
                    'Processeurs logiques' = $h.LogicalProcessorCount; 'Mémoire (Go)' = [math]::Round($h.MemoryCapacity / 1GB, 1)
                    'Chemin VHD par défaut' = $h.VirtualHardDiskPath; 'Chemin VM par défaut' = $h.VirtualMachinePath
                    'NUMA spanning' = $h.NumaSpanningEnabled; 'Session améliorée' = $h.EnableEnhancedSessionMode
                    'Migration dynamique' = $h.VirtualMachineMigrationEnabled; 'Migrations simultanées' = $h.MaximumVirtualMachineMigrations; 'Auth. migration' = $h.VirtualMachineMigrationAuthenticationType
                    'Migrations stockage simultanées' = $h.MaximumStorageMigrations; 'Version VM par défaut' = (Hyper-V\Get-VMHostSupportedVersion -Default -ErrorAction SilentlyContinue).Version
                })
            Add-Table 'Versions de configuration VM supportées' (Hyper-V\Get-VMHostSupportedVersion -ErrorAction SilentlyContinue | Select-Object Name, Version, IsDefault)
        }
        Invoke-Step 'Commutateurs virtuels' {
            $sw = @(Hyper-V\Get-VMSwitch -ErrorAction Stop)
            Add-Table 'vSwitch' ($sw | Select-Object Name, SwitchType, @{n = 'Carte(s)'; e = { $_.NetAdapterInterfaceDescriptions -join ' | ' } }, AllowManagementOS, EmbeddedTeamingEnabled, BandwidthReservationMode, IovEnabled)
            foreach ($s in $sw) {
                $desc = "$($s.NetAdapterInterfaceDescription) $($s.NetAdapterInterfaceDescriptions -join ' ')"
                if ($desc -match 'Multiplexor|Multiplexeur') {
                    Add-Finding Critique 'Hyper-V' "vSwitch « $($s.Name) » lié à une équipe LBFO" $desc 'LBFO lié à un vSwitch n''est plus supporté depuis WS2022 : après upgrade le vSwitch peut être inutilisable (VM coupées du réseau). Recréer le vSwitch en SET (New-VMSwitch -EnableEmbeddedTeaming $true -NetAdapterName ...) AVANT l''upgrade, en fenêtre de maintenance.'
                }
            }
            $set = @(Hyper-V\Get-VMSwitchTeam -ErrorAction SilentlyContinue)
            if ($set.Count) { Add-Table 'Équipes SET' ($set | Select-Object Name, TeamingMode, LoadBalancingAlgorithm, @{n = 'Membres'; e = { $_.NetAdapterInterfaceDescription -join ' | ' } }) }
            Add-Table 'Cartes virtuelles de l''hôte (ManagementOS)' (Hyper-V\Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue | Select-Object Name, SwitchName, MacAddress, @{n = 'VLAN'; e = { (Hyper-V\Get-VMNetworkAdapterVlan -VMNetworkAdapter $_).AccessVlanId } })
        }
        Invoke-Step 'Machines virtuelles' {
            $script:vms = @(Hyper-V\Get-VM -ErrorAction Stop)
            $vms = $script:vms
            Add-Table 'Machines virtuelles' ($vms | Select-Object Name, State, Generation, Version, ProcessorCount, @{n = 'RAM démarrage (Go)'; e = { [math]::Round($_.MemoryStartup / 1GB, 1) } }, DynamicMemoryEnabled, @{n = 'RAM min (Go)'; e = { [math]::Round($_.MemoryMinimum / 1GB, 1) } }, @{n = 'RAM max (Go)'; e = { [math]::Round($_.MemoryMaximum / 1GB, 1) } }, @{n = 'RAM assignée (Go)'; e = { [math]::Round($_.MemoryAssigned / 1GB, 1) } }, Uptime, AutomaticStartAction, AutomaticStartDelay, AutomaticStopAction, CheckpointType, IntegrationServicesVersion, ReplicationState, IsClustered, Path, Notes)
            $Script:Facts.VMs = $vms | ForEach-Object { $_.Name }
            $old = @($vms | Where-Object { [version]"$($_.Version)" -lt [version]'8.0' })
            if ($old.Count) { Add-Finding Moyen 'Hyper-V' "VM en version de configuration ancienne (< 8.0)" (($old | ForEach-Object { "$($_.Name)=$($_.Version)" }) -join ', ') 'Après migration de l''hôte et validation, mettre à jour (Update-VMVersion, irréversible, VM éteinte).' }
            Add-Finding Info 'Hyper-V' 'Version de configuration des VM après upgrade de l''hôte' 'Les VM gardent leur version (9.0 pour 2019) et restent déplaçables vers un hôte 2019 tant qu''elles ne sont pas mises à jour.' 'Ne lancer Update-VMVersion qu''une fois le retour arrière exclu.'
            $stopAct = @($vms | Where-Object { "$($_.AutomaticStopAction)" -eq 'Save' })
            if ($stopAct.Count) { Add-Finding Faible 'Hyper-V' "VM avec action d'arrêt « Enregistrer »" (($stopAct.Name) -join ', ') 'Avant l''upgrade de l''hôte, ARRÊTER proprement les VM (pas d''état enregistré : incompatibilités possibles entre versions).' }
            $saved = @($vms | Where-Object { "$($_.State)" -match 'Saved|Paused' })
            if ($saved.Count) { Add-Finding Moyen 'Hyper-V' 'VM en état enregistré/suspendu' (($saved.Name) -join ', ') 'Démarrer puis arrêter proprement ces VM avant l''upgrade.' }
        }
        $vms = $script:vms
        Invoke-Step 'Processeurs virtuels' {
            $p = foreach ($v in $vms) { Hyper-V\Get-VMProcessor -VM $v | Select-Object @{n = 'VM'; e = { $v.Name } }, Count, CompatibilityForMigrationEnabled, CompatibilityForOlderOperatingSystemsEnabled, ExposeVirtualizationExtensions, Reserve, Maximum, RelativeWeight }
            Add-Table 'Processeurs virtuels' $p
            $cm = @($p | Where-Object { $_.CompatibilityForMigrationEnabled -or $_.CompatibilityForOlderOperatingSystemsEnabled })
            if ($cm.Count) { Add-Finding Critique 'Hyper-V' 'Compatibilité processeur activée sur des VM' (($cm.VM) -join ', ') 'Ce mode masque des instructions (dont SSE4.2/POPCNT) : un invité WS2025 ne peut pas s''installer/démarrer. VM éteinte : Set-VMProcessor -VMName <VM> -CompatibilityForMigrationEnabled $false.' }
        }
        Invoke-Step 'Disques virtuels' {
            $rows = foreach ($v in $vms) {
                foreach ($d in (Hyper-V\Get-VMHardDiskDrive -VM $v)) {
                    $vhd = $null; if ($d.Path -and $null -eq $d.DiskNumber) { try { $vhd = Hyper-V\Get-VHD -Path $d.Path -ErrorAction Stop } catch { } }
                    [pscustomobject]@{
                        VM = $v.Name; Contrôleur = ('{0} {1}:{2}' -f $d.ControllerType, $d.ControllerNumber, $d.ControllerLocation); Chemin = $d.Path
                        'Disque physique (pass-through)' = $d.DiskNumber; Format = $vhd.VhdFormat; Type = $vhd.VhdType
                        'Taille max (Go)' = $(if ($vhd) { [math]::Round($vhd.Size / 1GB, 1) }); 'Taille fichier (Go)' = $(if ($vhd) { [math]::Round($vhd.FileSize / 1GB, 1) })
                        'Fragmentation %' = $vhd.FragmentationPercentage; Parent = $vhd.ParentPath
                    }
                }
            }
            $rows = @($rows)
            Add-Table 'Disques virtuels' $rows
            $pt = @($rows | Where-Object { $_.'Disque physique (pass-through)' -ne $null -and "$($_.'Disque physique (pass-through)')" -ne '' })
            if ($pt.Count) { Add-Finding Moyen 'Hyper-V' 'Disques pass-through' (($pt | ForEach-Object { "$($_.VM) → disque $($_.'Disque physique (pass-through)')" }) -join ', ') 'Pas de checkpoint ni de sauvegarde au niveau hôte pour ces disques : sauvegarde depuis l''invité obligatoire.' }
            $diff = @($rows | Where-Object { $_.Type -match 'Differencing' })
            if ($diff.Count) { Add-Finding Moyen 'Hyper-V' 'Disques de différenciation (AVHDX / checkpoints)' (($diff | ForEach-Object { "$($_.VM): $(Split-Path $_.Chemin -Leaf)" }) -join ', ') 'Fusionner (supprimer les checkpoints) avant l''upgrade et la sauvegarde finale.' }
            # Surallocation des volumes
            $byVol = $rows | Where-Object { $_.Chemin -and $_.Type -eq 'Dynamic' } | Group-Object { ([System.IO.Path]::GetPathRoot($_.Chemin)) }
            $over = foreach ($g in $byVol) {
                $grow = ($g.Group | ForEach-Object { $_.'Taille max (Go)' - $_.'Taille fichier (Go)' } | Measure-Object -Sum).Sum
                $free = $null; try { $free = [math]::Round((Get-Volume -FilePath $g.Name -ErrorAction Stop).SizeRemaining / 1GB, 1) } catch { try { $free = [math]::Round((Get-PSDrive ($g.Name.Substring(0, 1))).Free / 1GB, 1) } catch { } }
                [pscustomobject]@{ Volume = $g.Name; 'Croissance potentielle VHDX dynamiques (Go)' = [math]::Round($grow, 1); 'Espace libre (Go)' = $free; 'Surallocation' = ($free -ne $null -and $grow -gt $free) }
            }
            Add-Table 'Surallocation du stockage (VHDX dynamiques)' $over
            foreach ($o in @($over | Where-Object { $_.Surallocation })) { Add-Finding Eleve 'Hyper-V' "Surallocation sur $($o.Volume)" ("Croissance possible {0} Go pour {1} Go libres" -f $o.'Croissance potentielle VHDX dynamiques (Go)', $o.'Espace libre (Go)') 'Risque de VM en pause (disque plein), notamment pendant l''upgrade d''un invité. Prévoir de l''espace ou des VHDX fixes.' }
        }
        Invoke-Step 'Cartes réseau des VM' {
            $na = @(Hyper-V\Get-VMNetworkAdapter -VMName * -ErrorAction Stop)
            Add-Table 'Cartes réseau des VM' ($na | Select-Object VMName, Name, SwitchName, MacAddress, DynamicMacAddressEnabled, @{n = 'IP'; e = { $_.IPAddresses -join ', ' } }, @{n = 'VLAN'; e = { (Hyper-V\Get-VMNetworkAdapterVlan -VMNetworkAdapter $_).AccessVlanId } }, MacAddressSpoofing, DhcpGuard, RouterGuard, Status)
            $dyn = @($na | Where-Object { $_.DynamicMacAddressEnabled })
            if ($dyn.Count) { Add-Finding Faible 'Hyper-V' 'Adresses MAC dynamiques' (($dyn.VMName | Select-Object -Unique) -join ', ') 'En cas de déplacement/recréation, la MAC peut changer (réservations DHCP, licences liées à la MAC) : envisager des MAC statiques.' }
        }
        Invoke-Step 'Lecteurs DVD' {
            $dvd = @(Hyper-V\Get-VMDvdDrive -VMName * -ErrorAction SilentlyContinue | Where-Object { $_.Path })
            if ($dvd.Count) { Add-Table 'ISO montées' ($dvd | Select-Object VMName, Path); Add-Finding Faible 'Hyper-V' 'ISO montées dans des VM' (($dvd | ForEach-Object { "$($_.VMName): $($_.Path)" }) -join ' | ') 'Éjecter avant export/migration (chemins cassés).' }
        }
        Invoke-Step 'Services d''intégration' {
            $is = foreach ($v in $vms) { Hyper-V\Get-VMIntegrationService -VM $v | Select-Object @{n = 'VM'; e = { $v.Name } }, Name, Enabled, PrimaryStatusDescription }
            Add-Table 'Services d''intégration' $is
            $Script:Facts.TimeSyncOn = @($is | Where-Object { $_.Name -match 'Time|heure' -and $_.Enabled } | ForEach-Object { $_.VM })
        }
        Invoke-Step 'OS invités (KVP)' {
            $cs = @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_ComputerSystem -Filter "Caption='Virtual Machine'" -ErrorAction Stop)
            $rows = foreach ($c in $cs) {
                $kvp = Get-CimAssociatedInstance -InputObject $c -ResultClassName Msvm_KvpExchangeComponent -ErrorAction SilentlyContinue
                $d = @{}
                foreach ($item in @($kvp.GuestIntrinsicExchangeItems)) {
                    try { $x = [xml]$item; $n = ($x.INSTANCE.PROPERTY | Where-Object { $_.NAME -eq 'Name' }).VALUE; $val = ($x.INSTANCE.PROPERTY | Where-Object { $_.NAME -eq 'Data' }).VALUE; $d[$n] = $val } catch { }
                }
                [pscustomobject]@{ VM = $c.ElementName; FQDN = $d['FullyQualifiedDomainName']; 'OS invité' = $d['OSName']; 'Version' = $d['OSVersion']; 'IPv4' = $d['NetworkAddressIPv4']; 'Intégration' = $d['IntegrationServicesVersion'] }
            }
            Add-Table 'Systèmes invités (Key-Value Pair Exchange)' $rows -Note 'Remonté par les services d''intégration (VM démarrées uniquement).'
            $Script:Facts.GuestMap = $rows
            foreach ($r in $rows) {
                if ($Script:Facts.TimeSyncOn -contains $r.VM -and $r.FQDN) {
                    # On ne sait pas depuis l'hôte si l'invité est DC : signalé à titre informatif
                }
            }
            if ($Script:Facts.TimeSyncOn.Count) { Add-Finding Info 'Hyper-V' 'Synchronisation horaire Hyper-V active sur des VM' (($Script:Facts.TimeSyncOn | Select-Object -Unique) -join ', ') 'Pour les VM contrôleurs de domaine : désactiver la synchro du fournisseur VMICTimeProvider dans l''invité (ou le service d''intégration) afin que le PDC suive le NTP externe.' }
        }
        Invoke-Step 'Points de contrôle' {
            $snap = @(Hyper-V\Get-VMSnapshot -VMName * -ErrorAction SilentlyContinue)
            Add-Table 'Points de contrôle (checkpoints)' ($snap | Select-Object VMName, Name, SnapshotType, CreationTime, ParentSnapshotName)
            if ($snap.Count) {
                $old = @($snap | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-7) })
                Add-Finding $(if ($old.Count) { 'Eleve' } else { 'Moyen' }) 'Hyper-V' "$($snap.Count) checkpoint(s) existant(s) ($($old.Count) de plus de 7 j)" (($snap | ForEach-Object { "$($_.VMName): $($_.Name) ($($_.CreationTime.ToString('yyyy-MM-dd')))" }) -join ' | ') 'Supprimer/fusionner les anciens checkpoints. Ne JAMAIS restaurer un checkpoint standard d''un DC (risque USN rollback) : utiliser les checkpoints de production + sauvegarde état système.'
            }
        }
        Invoke-Step 'Réplica / sécurité' {
            $rep = @(Hyper-V\Get-VMReplication -ErrorAction SilentlyContinue)
            if ($rep.Count) { Add-Table 'Hyper-V Réplica' ($rep | Select-Object VMName, State, Mode, Health, PrimaryServer, ReplicaServer, FrequencySec, LastReplicationTime); Add-Finding Moyen 'Hyper-V' 'Hyper-V Réplica configuré' (($rep.VMName) -join ', ') 'Ordre : mettre à niveau le serveur Réplica AVANT le primaire (un réplica peut être plus récent que le primaire, pas l''inverse).' }
            $sec = foreach ($v in ($vms | Where-Object { $_.Generation -eq 2 })) { Hyper-V\Get-VMSecurity -VM $v -ErrorAction SilentlyContinue | Select-Object @{n = 'VM'; e = { $v.Name } }, TpmEnabled, Shielded, EncryptStateAndVmMigrationTraffic, @{n = 'SecureBoot'; e = { (Hyper-V\Get-VMFirmware -VM $v).SecureBoot } }, @{n = 'Modèle SecureBoot'; e = { (Hyper-V\Get-VMFirmware -VM $v).SecureBootTemplate } } }
            Add-Table 'Sécurité des VM génération 2' $sec
            $tpm = @($sec | Where-Object { $_.TpmEnabled })
            if ($tpm.Count) { Add-Finding Eleve 'Hyper-V' 'VM avec vTPM' (($tpm.VM) -join ', ') 'Le vTPM est protégé par les certificats « Shielded VM Local Certificates » de l''hôte : les EXPORTER (certlm.msc > Shielded VM Local Certificates, avec clé privée) avant toute réinstallation/migration d''hôte, sinon VM non démarrables (et BitLocker invité bloqué).' }
        }
        Invoke-Step 'Capacité mémoire' {
            $h = Hyper-V\Get-VMHost
            $need = ($vms | Where-Object { "$($_.State)" -eq 'Running' } | ForEach-Object { if ($_.DynamicMemoryEnabled) { $_.MemoryAssigned } else { $_.MemoryStartup } } | Measure-Object -Sum).Sum
            $pct = if ($h.MemoryCapacity) { [math]::Round(100 * $need / $h.MemoryCapacity, 1) } else { $null }
            Add-Note ("Mémoire allouée aux VM démarrées : {0:N1} Go / {1:N1} Go ({2} %)" -f ($need / 1GB), ($h.MemoryCapacity / 1GB), $pct)
            if ($pct -gt 90) { Add-Finding Moyen 'Hyper-V' "Mémoire de l'hôte allouée à $pct %" '' 'Peu de marge pour démarrer une VM supplémentaire (ex. nouveau DC 2025 en side-by-side).' }
            $Script:Facts.HostMemPct = $pct
        }
        Invoke-Step 'Cluster' {
            if ($Script:Roles.IsCluster -and (Import-ModuleSafe 'FailoverClusters')) {
                $cl = Get-Cluster -ErrorAction Stop
                Add-KV 'Cluster' ([ordered]@{ 'Nom' = $cl.Name; 'Niveau fonctionnel' = $cl.ClusterFunctionalLevel; 'Quorum' = (Get-ClusterQuorum).QuorumResource })
                Add-Table 'Nœuds' (Get-ClusterNode | Select-Object Name, State, NodeWeight)
                Add-Table 'CSV' (Get-ClusterSharedVolume -ErrorAction SilentlyContinue | Select-Object Name, State, OwnerNode)
                Add-Finding Info 'Cluster' 'Cluster de basculement' $cl.Name 'Utiliser la mise à niveau propagée (Cluster OS Rolling Upgrade) : un nœud à la fois, puis Update-ClusterFunctionalLevel en fin de migration.'
            }
        }
        Add-Finding Info 'Hyper-V' 'Stratégie hyperviseur' ("{0} VM hébergée(s)" -f $vms.Count) 'Avant upgrade de l''hôte : sauvegarde complète des VM (export ou sauvegarde applicative), arrêt propre de toutes les VM, désactivation du démarrage auto, vérification console hors bande (iDRAC/iLO). Vérifier que le serveur physique figure dans la liste de compatibilité WS2025 du constructeur.'
    }
}

function Invoke-GuestCollector {
    Invoke-Collector -Id 'Guest' -Title 'Machine virtuelle (vue invité)' -When $Script:Roles.IsVM -Body {
        Invoke-Step 'Composants invités' {
            $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^vmic|VMTools|QEMU-GA|vioser|xenagent|XenSvc|nutanix' } | Select-Object Name, DisplayName, Status, StartType
            Add-Table 'Services d''intégration / outils invités' $svc
            $ts = Invoke-External 'w32tm.exe' '/query /source' 20
            Add-KV 'Source de temps' ([ordered]@{ 'w32tm /query /source' = $ts.Trim() })
            if ($Script:Roles.IsDC -and $ts -match 'VM IC|Hyper-V|VMware') { Add-Finding Moyen 'Active Directory' 'DC virtuel synchronisé sur l''hyperviseur' $ts.Trim() 'Désactiver la synchro horaire de l''hyperviseur pour ce DC (Hyper-V : reg VMICTimeProvider Enabled=0 dans l''invité ; VMware : désactiver la synchro VMware Tools) et le faire suivre la hiérarchie AD/NTP.' }
            if ($Script:VMPlatform -ne 'Hyper-V') { Add-Finding Info 'Virtualisation' "Invité sur $($Script:VMPlatform)" '' 'Vérifier que la version de l''hyperviseur supporte WS2025 en invité et mettre à jour les outils/pilotes invités (VMware Tools, VirtIO...). Sur VMware : EVC/compatibilité CPU doit exposer SSE4.2/POPCNT.' }
        }
    }
}
#endregion

#region ===================== Autres rôles / impression / sauvegarde =====================
function Invoke-OtherRolesCollector {
    $any = $Script:Roles.IsIIS -or $Script:Roles.IsADCS -or $Script:Roles.IsWSUS -or $Script:Roles.IsFileServer
    Invoke-Collector -Id 'OtherRoles' -Title 'Autres rôles (IIS, AD CS, WSUS, fichiers, SQL)' -When $true -Body {
        if ($Script:Roles.IsIIS) {
            Invoke-Step 'IIS' {
                if (Import-ModuleSafe 'WebAdministration') {
                    Add-Table 'Sites IIS' (Get-Website | Select-Object Name, ID, State, PhysicalPath, @{n = 'Liaisons'; e = { ($_.Bindings.Collection | ForEach-Object { '{0} {1}' -f $_.protocol, $_.bindingInformation }) -join ' | ' } })
                    Add-Table 'Pools d''applications' (Get-ChildItem IIS:\AppPools | Select-Object Name, State, managedRuntimeVersion, managedPipelineMode, @{n = 'Identité'; e = { $_.processModel.identityType } }, @{n = 'Compte'; e = { $_.processModel.userName } })
                    Add-Table 'Liaisons SSL' (Get-ChildItem IIS:\SslBindings -ErrorAction SilentlyContinue | Select-Object IPAddress, Port, Host, Thumbprint, Store)
                }
            }
        }
        if ($Script:Roles.IsADCS) {
            Invoke-Step 'AD CS' {
                Add-Raw 'certutil -cainfo' (Invoke-External 'certutil.exe' '-cainfo' 60) 'certutil_cainfo.txt'
                Add-Raw 'certutil -catemplates' (Invoke-External 'certutil.exe' '-catemplates' 60) 'certutil_catemplates.txt'
                Add-KV 'Configuration AD CS' (Get-RegKeyValues 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration')
                Add-Finding Eleve 'PKI' 'Autorité de certification installée sur ce serveur' '' 'Avant toute opération : sauvegarde CA (certutil -backup avec clé privée + export du registre CertSvc\Configuration + liste des modèles). Migration d''une CA = procédure dédiée (même nom de CA).'
            }
        }
        if ($Script:Roles.IsWSUS) {
            Invoke-Step 'WSUS' {
                Add-KV 'WSUS' (Get-RegKeyValues 'HKLM:\SOFTWARE\Microsoft\Update Services\Server\Setup')
            }
        }
        Invoke-Step 'DFS' {
            if (Test-Cmd 'Get-DfsnRoot') { $r = @(Get-DfsnRoot -ErrorAction SilentlyContinue); if ($r.Count) { Add-Table 'Racines DFS-N' ($r | Select-Object Path, Type, State, Description); Add-Finding Info 'Fichiers' 'Espaces de noms DFS présents' (($r.Path) -join ', ') 'Ajouter le nouveau serveur comme cible de namespace avant retrait de l''ancien.' } }
            if (Test-Cmd 'Get-DfsReplicationGroup') { $g = @(Get-DfsReplicationGroup -ErrorAction SilentlyContinue | Where-Object { $_.GroupName -ne 'Domain System Volume' }); if ($g.Count) { Add-Table 'Groupes DFS-R (hors SYSVOL)' ($g | Select-Object GroupName, State, Description) } }
        }
        Invoke-Step 'SQL Server' {
            $inst = Get-RegKeyValues 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
            if ($inst) {
                $rows = foreach ($k in $inst.Keys) {
                    $setup = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($inst[$k])\Setup"
                    [pscustomobject]@{ Instance = $k; Id = $inst[$k]; Version = Get-RegValue $setup 'Version'; 'Édition' = Get-RegValue $setup 'Edition'; 'Patch' = Get-RegValue $setup 'PatchLevel'; 'Données' = Get-RegValue $setup 'SQLDataRoot' }
                }
                Add-Table 'Instances SQL Server' $rows
                Add-Finding Eleve 'Applications' "SQL Server présent ($(($rows | ForEach-Object { "$($_.Instance) v$($_.Version)" }) -join ', '))" 'Versions SQL anciennes (2016 et antérieures) : support WS2025 à confirmer / non garanti.' 'Vérifier la matrice Microsoft « SQL Server on Windows Server 2025 », appliquer le dernier CU, sauvegarder toutes les bases (y compris master/msdb) avant l''upgrade.'
            }
        }
        if (-not $any) { Add-Note 'Aucun rôle IIS / AD CS / WSUS / serveur de fichiers spécifique détecté.' }
    }
}

function Invoke-PrintingCollector {
    Invoke-Collector -Id 'Printing' -Title 'Impression' -Body {
        Invoke-Step 'Imprimantes' {
            $p = @(Get-Printer -ErrorAction Stop)
            Add-Table 'Imprimantes' ($p | Select-Object Name, DriverName, PortName, Shared, ShareName, Published, Type, PrinterStatus)
            $d = @(Get-PrinterDriver -ErrorAction SilentlyContinue)
            Add-Table 'Pilotes d''imprimante' ($d | Select-Object Name, Manufacturer, MajorVersion, @{n = 'Version'; e = { $_.DriverVersion } }, PrinterEnvironment, IsPackageAware, InfPath)
            $Script:Facts.PrinterCount = $p.Count
            $np = @($d | Where-Object { -not $_.IsPackageAware -and $_.Manufacturer -notmatch 'Microsoft' })
            if ($np.Count -and ($Script:Roles.IsRDSH -or $Script:Roles.IsPrintServer)) { Add-Finding Moyen 'Impression' "$($np.Count) pilote(s) d'imprimante non « package-aware »" (($np.Name | Select-Object -Unique -First 10) -join ', ') 'Durcissements Point and Print : préférer des pilotes v4 / package-aware récents compatibles WS2025 ; préparer l''installation des pilotes sur la cible.' }
            $ports = @(Get-PrinterPort -ErrorAction SilentlyContinue | Where-Object { $_.PrinterHostAddress })
            Add-Table 'Ports TCP/IP d''imprimante' ($ports | Select-Object Name, PrinterHostAddress, PortNumber, SNMPEnabled)
        }
    }
}

function Invoke-BackupCollector {
    Invoke-Collector -Id 'Backup' -Title 'Sauvegarde et VSS' -Body {
        $script:found = $false
        Invoke-Step 'Sauvegarde Windows Server' {
            if (Import-ModuleSafe 'WindowsServerBackup') {
                $s = Get-WBSummary -ErrorAction Stop
                Add-KV 'Windows Server Backup' ([ordered]@{ 'Dernière réussie' = $s.LastSuccessfulBackupTime; 'Dernier résultat (HRESULT)' = ('0x{0:X}' -f $s.LastBackupResultHR); 'Dernière tentative' = $s.LastBackupTime; 'Versions' = $s.NumberOfVersions; 'Prochaine' = $s.NextBackupTime })
                $pol = Get-WBPolicy -ErrorAction SilentlyContinue
                if ($pol) { Add-KV 'Stratégie WSB' ([ordered]@{ 'Planification' = $pol.Schedule; 'État système' = $pol.SystemState; 'Bare Metal' = $pol.BMR; 'Volumes' = ($pol.VolumesToBackup | ForEach-Object { $_.MountPath }) }) }
                if ($s.LastSuccessfulBackupTime -and $s.LastSuccessfulBackupTime -gt (Get-Date).AddDays(-3)) { $script:found = $true }
            } else { Add-Note 'Windows Server Backup non installé.' }
            Add-Raw 'wbadmin get versions' (Invoke-External 'wbadmin.exe' 'get versions' 120) 'wbadmin_versions.txt'
        }
        Invoke-Step 'Writers VSS' {
            $o = Invoke-External 'vssadmin.exe' 'list writers' 120
            Add-Raw 'vssadmin list writers' $o 'vss_writers.txt'
            $bad = @([regex]::Matches($o, '(?im)^\s*(State|État)\s*:\s*\[(\d+)\]\s*(.+)$') | Where-Object { $_.Groups[2].Value -ne '1' })
            $err = @([regex]::Matches($o, '(?im)^\s*(Last error|Dernière erreur)\s*:\s*(.+)$') | Where-Object { $_.Groups[2].Value -notmatch 'No error|Aucune erreur|Pas d.erreur' })
            if ($bad.Count -or $err.Count) { Add-Finding Eleve 'Sauvegarde' 'Writers VSS en erreur' ((@($bad | ForEach-Object { $_.Value.Trim() }) + @($err | ForEach-Object { $_.Value.Trim() })) -join ' | ') 'Corriger (redémarrage des services concernés / du serveur) : sinon sauvegardes applicatives incohérentes (AD, SQL, Hyper-V).' }
        }
        $tp = @($Script:Facts.SensitiveApps | Where-Object { $_.'Catégorie' -eq 'Sauvegarde' })
        if ($tp.Count) { Add-Note ("Logiciel(s) de sauvegarde tiers détecté(s) : {0}" -f (($tp.Logiciel) -join ', ')); $script:found = $true }
        if (-not $script:found -and -not $Script:Roles.IsVM) { Add-Finding Eleve 'Sauvegarde' 'Aucune sauvegarde récente identifiée localement' 'Ni Windows Server Backup récent, ni agent tiers détecté.' 'Confirmer la stratégie de sauvegarde (sauvegarde au niveau hyperviseur ?) et réaliser une sauvegarde complète testée avant la migration.' }
        Add-Finding Info 'Sauvegarde' 'Plan de retour arrière' '' 'Avant upgrade : sauvegarde complète vérifiée (+ état système pour un DC) ; pour une VM : export ou checkpoint de production de la VM éteinte (supprimé ensuite) ; noter les identifiants admin locaux / DSRM ; clés BitLocker ; accès console.'
    }
}

function Invoke-SetupCompatCollector {
    Invoke-Collector -Id 'SetupCompat' -Title 'Scan de compatibilité Microsoft (setup.exe /compat scanonly)' -When ([bool]$SetupMediaPath) -Body {
        $setup = Join-Path $SetupMediaPath 'setup.exe'
        if (-not (Test-Path $setup)) { throw "setup.exe introuvable dans $SetupMediaPath" }
        $idx = $SetupImageIndex
        if (-not $idx) {
            $dc = ($Script:CV.EditionID -match 'Datacenter'); $core = ($Script:CV.InstallationType -eq 'Server Core')
            $idx = if ($dc) { if ($core) { 3 } else { 4 } } else { if ($core) { 1 } else { 2 } }
        }
        Invoke-Step 'Images du média' {
            $wim = @('sources\install.wim', 'sources\install.esd') | ForEach-Object { Join-Path $SetupMediaPath $_ } | Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($wim) { Add-Table 'Images disponibles sur le média' (Get-WindowsImage -ImagePath $wim -ErrorAction Stop | Select-Object ImageIndex, ImageName, ImageSize) }
        }
        Write-Log "   Lancement du scan de compatibilité (index $idx) - peut durer 10 à 40 min..." 'WARN'
        $setupArgs = "/auto upgrade /quiet /noreboot /compat scanonly /dynamicupdate disable /eula accept /imageindex $idx /copylogs `"$($Script:RawFolder)\SetupLogs`""
        $p = Start-Process -FilePath $setup -ArgumentList $setupArgs -PassThru -WindowStyle Hidden
        if (-not $p.WaitForExit(3600 * 1000)) { try { $p.Kill() } catch { }; throw 'Scan de compatibilité interrompu après 60 min.' }
        $code = '0x{0:X8}' -f $p.ExitCode
        $map = @{ '0xC1900210' = 'Aucun problème de compatibilité détecté'; '0xC1900208' = 'Application(s) incompatible(s) à désinstaller'; '0xC1900204' = 'Chemin de migration non disponible (édition/langue/type différent)'; '0xC1900200' = 'Machine non éligible (prérequis matériels)'; '0xC190020E' = 'Espace disque insuffisant'; '0xC1900201' = 'Pilote système bloquant'; '0xC1900107' = 'Nettoyage d''une précédente installation requis (redémarrer)' }
        $label = if ($map[$code]) { $map[$code] } else { 'Code non répertorié : voir journaux Panther' }
        Add-KV 'Résultat du scan' ([ordered]@{ 'Média' = $SetupMediaPath; 'Index image' = $idx; 'Code retour' = $code; 'Signification' = $label })
        if ($code -eq '0xC1900210') { Add-Finding Info 'Mise à niveau' 'Scan de compatibilité Microsoft : aucun blocage' $code 'OK pour planifier l''upgrade sur place (sous réserve des autres points).' }
        else { Add-Finding Critique 'Mise à niveau' "Scan de compatibilité Microsoft : $label" $code 'Analyser C:\$WINDOWS.~BT\Sources\Panther\CompatData_*.xml et setupact.log (copiés dans raw\SetupLogs).' }
        Invoke-Step 'CompatData' {
            $cd = Get-ChildItem 'C:\$WINDOWS.~BT\Sources\Panther' -Filter 'CompatData*.xml' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($cd) {
                Copy-Item $cd.FullName $Script:RawFolder -Force
                [xml]$x = Get-Content $cd.FullName -Raw
                $rows = @()
                foreach ($n in $x.SelectNodes('//*[local-name()="HardwareItem" or local-name()="Program" or local-name()="DriverPackage"]')) {
                    $ci = $n.SelectSingleNode('*[local-name()="CompatibilityInfo"]')
                    $rows += [pscustomobject]@{ Type = $n.LocalName; Nom = $(if ($n.Name) { $n.Name } else { $n.Inf }); Bloquant = $ci.BlockingType; Message = $ci.Message; 'Statut' = $ci.StatusDetail }
                }
                Add-Table 'Éléments remontés par CompatData' $rows
            }
        }
    }
}
#endregion

#region ===================== Rapport HTML / JSON =====================
function ConvertTo-HtmlEncoded { param($v) if ($null -eq $v) { return '' }; return [System.Net.WebUtility]::HtmlEncode([string]$v) }

function ConvertTo-HtmlTableFragment {
    param($Rows, [string]$Class = 'data', [int]$Max = 2000)
    $rows = @($Rows)
    if (-not $rows.Count) { return '<p class="empty">Aucune donnée.</p>' }
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($r in ($rows | Select-Object -First 300)) { foreach ($p in $r.PSObject.Properties) { if (-not $cols.Contains($p.Name)) { $cols.Add($p.Name) } } }
    $sb = New-Object System.Text.StringBuilder
    if ($rows.Count -gt 12) { [void]$sb.Append('<input class="tf" type="search" placeholder="Filtrer ce tableau…" oninput="filterTable(this)">') }
    [void]$sb.Append("<div class=`"tw`"><table class=`"$Class`"><thead><tr>")
    foreach ($c in $cols) { [void]$sb.Append('<th onclick="sortTable(this)">' + (ConvertTo-HtmlEncoded $c) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    $statusCls = @{ 'OK' = 'ok'; 'BLOQUANT' = 'ko'; 'À VÉRIFIER' = 'warn'; 'LIMITE' = 'warn'; 'RECOMMANDÉ' = 'warn'; 'INDÉTERMINÉ' = 'warn'; 'True' = 'b-true'; 'False' = 'b-false' }
    foreach ($r in ($rows | Select-Object -First $Max)) {
        [void]$sb.Append('<tr>')
        foreach ($c in $cols) {
            $v = $r.$c
            $cls = $statusCls["$v"]
            if ($cls) { [void]$sb.Append("<td class=`"$cls`">" + (ConvertTo-HtmlEncoded $v) + '</td>') }
            else { [void]$sb.Append('<td>' + (ConvertTo-HtmlEncoded $v) + '</td>') }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($rows.Count -gt $Max) { [void]$sb.Append("<p class=`"note`">$($rows.Count) lignes, $Max affichées : voir le CSV.</p>") }
    else { [void]$sb.Append("<p class=`"count`">$($rows.Count) ligne(s)</p>") }
    return $sb.ToString()
}

function Get-Verdict {
    param($Findings)
    $c = @($Findings | Where-Object { $_.Severity -eq 'Critique' }).Count
    $h = @($Findings | Where-Object { $_.Severity -eq 'Eleve' }).Count
    if ($c) { return @{ Text = 'NON PRÊT — points bloquants à traiter'; Class = 'v-ko' } }
    if ($h) { return @{ Text = 'PRÊT SOUS CONDITIONS — points élevés à traiter'; Class = 'v-warn' } }
    return @{ Text = 'PRÊT — pas de point bloquant détecté'; Class = 'v-ok' }
}

function Get-StrategyAdvice {
    $a = New-Object System.Collections.Generic.List[string]
    $a.Add('Traiter d''abord tous les points CRITIQUE puis ÉLEVÉ ci-dessous ; refaire tourner l''audit pour valider (comparaison avant/après).')
    $a.Add('Sauvegarde complète vérifiée (test de restauration) + documentation des comptes/mots de passe (admin local, DSRM, comptes de service) avant toute action.')
    if ($Script:Roles.IsHyperV) {
        $a.Add('HYPERVISEUR : vérifier le support WS2025 du serveur physique chez le constructeur (firmware/pilotes à jour). Choix : upgrade sur place (VM conservées, vSwitch LBFO à convertir en SET au préalable) ou réinstallation propre (export des VM + certificats vTPM, réimport). Mettre l''hôte à jour AVANT de passer les invités en 2025 (la prise en charge d''un invité 2025 sur un hôte 2019 est à vérifier dans la matrice Microsoft).')
        $a.Add('Licence : une licence Windows Server 2025 Standard couvrant tous les cœurs de l''hôte autorise 2 VM Windows Server (2025 ou antérieures) ; empiler des licences Standard pour plus de VM, ou Datacenter.')
    }
    if ($Script:Roles.IsDC) {
        $a.Add('ACTIVE DIRECTORY : privilégier le side-by-side — nouvelle VM WS2025 (génération 2), promotion DC + DNS + GC (adprep automatique), contrôle réplication (repadmin/dcdiag), transfert des 5 rôles FSMO, bascule DNS des clients/DHCP, puis rétrogradation de l''ancien DC. Plus sûr et réversible qu''un upgrade sur place d''un DC.')
        if ($Script:Roles.IsDHCP) { $a.Add('DHCP : Export-DhcpServer (fait par ce script dans raw\) puis Import-DhcpServer sur le nouveau serveur ; autoriser le nouveau serveur dans AD, désautoriser l''ancien.') }
    }
    if ($Script:Roles.IsRDS) {
        $a.Add('RDS : acheter les CAL RDS 2025 ; ordre Licences → Broker → Hôtes de session → Web/Gateway ; tester les applications métier, l''impression et les profils (UPD/FSLogix) sur un hôte pilote avant bascule des utilisateurs.')
    }
    if ($Script:Roles.IsVM) { $a.Add('VM : juste avant l''upgrade, VM éteinte → export ou checkpoint de production (jamais de restauration de checkpoint standard d''un DC) ; supprimer le checkpoint une fois validé.') }
    $a.Add('Après migration : relancer cet audit, comparer, mettre à jour le magasin ADMX, réactiver les sauvegardes et la supervision, mettre à jour la documentation.')
    return $a
}

function Export-AuditReport {
    $end = Get-Date
    $dur = [math]::Round(($end - $Script:Start).TotalMinutes, 1)
    $findings = @($Script:Findings | Sort-Object @{ e = { $Script:SeverityOrder[$_.Severity] } }, Area, Title)
    $verdict = Get-Verdict $findings
    $counts = [ordered]@{}; foreach ($s in 'Critique', 'Eleve', 'Moyen', 'Faible', 'Info') { $counts[$s] = @($findings | Where-Object { $_.Severity -eq $s }).Count }
    $roles = @($Script:RoleLabels.Keys | Where-Object { $Script:Roles[$_] } | ForEach-Object { $Script:RoleLabels[$_] })
    $advice = Get-StrategyAdvice

    # ---------- CSV des constats ----------
    $findings | Select-Object Host, @{n = 'Sévérité'; e = { $Script:SeverityLabel[$_.Severity] } }, @{n = 'Domaine'; e = { $_.Area } }, @{n = 'Constat'; e = { $_.Title } }, @{n = 'Détail'; e = { $_.Detail } }, @{n = 'Recommandation'; e = { $_.Recommendation } } |
        Export-Csv -Path (Join-Path $Script:RunFolder 'findings.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    # ---------- JSON ----------
    $factKeys = 'OSLanguage', 'SchemaVersion', 'DCCount', 'SysvolState', 'RDSLicMode', 'RDBroker', 'SSE42', 'UEFI', 'SystemFreeGB', 'LastPatch', 'PhysicalCores', 'Sockets', 'HostMemPct', 'VMs', 'FSLogix', 'PrinterCount'
    $facts = [ordered]@{}; foreach ($k in $factKeys) { if ($Script:Facts.ContainsKey($k)) { $facts[$k] = Format-Value $Script:Facts[$k] } }
    if ($Script:Facts.GuestMap) { $facts['GuestMap'] = @(ConvertTo-FlatObject $Script:Facts.GuestMap) }
    $json = [ordered]@{
        Meta     = [ordered]@{
            Host = $Script:HostName; Domain = $Script:CS.Domain; OS = $Script:OS.Caption; Build = ('{0}.{1}' -f $Script:CV.CurrentBuild, $Script:CV.UBR); EditionID = $Script:CV.EditionID
            InstallationType = $Script:CV.InstallationType; VMPlatform = $Script:VMPlatform; AuditVersion = $Script:AuditVersion
            Start = $Script:Start.ToString('yyyy-MM-dd HH:mm:ss'); End = $end.ToString('yyyy-MM-dd HH:mm:ss'); DurationMin = $dur
            Verdict = $verdict.Text; Counts = $counts; Roles = $roles; IsAdmin = (Test-IsAdmin)
        }
        Facts    = $facts
        Findings = $findings
        Sections = @($Script:Sections | ForEach-Object { [ordered]@{ Id = $_.Id; Title = $_.Title; DurationSec = $_.DurationSec; Errors = @($_.Errors); Items = @($_.Items | Where-Object { $_.Type -ne 'raw' } | ForEach-Object { [ordered]@{ Type = $_.Type; Title = $_.Title; Note = $_.Note; Data = $_.Data } }) } })
    }
    try { $json | ConvertTo-Json -Depth 7 -Compress | Out-File -FilePath (Join-Path $Script:RunFolder 'audit.json') -Encoding utf8 } catch { Write-Log "Export JSON : $($_.Exception.Message)" 'WARN' }

    # ---------- HTML ----------
    $css = @'
:root{--bg:#f5f6f8;--card:#fff;--txt:#1d2433;--mut:#5b6476;--bd:#dde1e8;--acc:#1f5fbf;--crit:#b3261e;--high:#d9480f;--med:#c98a00;--low:#2b7a78;--info:#5b6476;--ok:#1e7d32}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 "Segoe UI",system-ui,-apple-system,Arial,sans-serif;background:var(--bg);color:var(--txt)}
header{background:#14213d;color:#fff;padding:22px 28px}header h1{margin:0 0 4px;font-size:22px}header .sub{opacity:.85}
main{display:grid;grid-template-columns:250px minmax(0,1fr);gap:20px;padding:20px 28px;max-width:1700px;margin:auto}main>div{min-width:0}
@media (max-width:900px){main{grid-template-columns:1fr;padding:12px}nav{position:static;max-height:none}}
nav{position:sticky;top:12px;align-self:start;background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px;max-height:92vh;overflow:auto}
nav a{display:block;color:var(--txt);text-decoration:none;padding:4px 6px;border-radius:6px;font-size:13px}nav a:hover{background:#eef3fb}
nav .err{color:var(--crit);font-size:11px}
section,.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px 18px;margin-bottom:18px}
h2{margin:0 0 12px;font-size:18px;color:#14213d}h3{font-size:15px;margin:18px 0 8px;color:#22314f}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}.cnt{flex:1;min-width:120px;border-radius:10px;padding:12px;color:#fff;text-align:center;cursor:pointer}
.cnt b{display:block;font-size:26px}.c-Critique{background:var(--crit)}.c-Eleve{background:var(--high)}.c-Moyen{background:var(--med)}.c-Faible{background:var(--low)}.c-Info{background:var(--info)}
.verdict{font-size:18px;font-weight:700;padding:12px 14px;border-radius:8px;margin:6px 0 14px}.v-ko{background:#fdecea;color:var(--crit)}.v-warn{background:#fff4e5;color:var(--high)}.v-ok{background:#e8f5e9;color:var(--ok)}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}
.role{display:inline-block;background:#e7eefb;color:#1f3d7a;padding:3px 9px;border-radius:12px;margin:2px;font-size:12px}
.tw{overflow:auto;max-height:620px;border:1px solid var(--bd);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:12.5px}th{position:sticky;top:0;background:#eef1f6;text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd);cursor:pointer;white-space:nowrap}
td{padding:5px 8px;border-bottom:1px solid #eceff4;vertical-align:top;word-break:break-word;max-width:640px}tr:hover td{background:#f8fafd}
table.kv td:first-child{font-weight:600;width:330px;color:#33415c}
td.ok{color:var(--ok);font-weight:700}td.ko{color:var(--crit);font-weight:700}td.warn{color:var(--high);font-weight:700}td.b-true{color:#1e7d32}td.b-false{color:#8a8f99}
pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;max-height:520px;font-size:12px}
details>summary{cursor:pointer;font-weight:600;padding:4px 0}.note,.count{color:var(--mut);font-size:12px;margin:4px 0}.empty{color:var(--mut);font-style:italic}
.errs{background:#fff4f4;border:1px solid #f3c2c2;color:#8c1d18;padding:8px 12px;border-radius:8px;font-size:12px}
input.tf,#fsearch{padding:6px 10px;border:1px solid var(--bd);border-radius:6px;margin:4px 0 8px;width:320px;max-width:100%}
ul.adv li{margin:6px 0}.meta td:first-child{font-weight:600;width:220px}
footer{color:var(--mut);text-align:center;padding:20px;font-size:12px}
@media print{nav,input{display:none}main{display:block}.tw{max-height:none;overflow:visible}details{display:block}}
'@
    $js = @'
function filterTable(i){var q=i.value.toLowerCase();var t=i.nextElementSibling.querySelector('table');t.querySelectorAll('tbody tr').forEach(function(r){r.style.display=r.innerText.toLowerCase().indexOf(q)>-1?'':'none'})}
function sortTable(th){var t=th.closest('table'),i=Array.prototype.indexOf.call(th.parentNode.children,th),asc=th.dataset.asc!=='1';th.dataset.asc=asc?'1':'0';var rows=Array.prototype.slice.call(t.tBodies[0].rows);rows.sort(function(a,b){var x=a.cells[i].innerText,y=b.cells[i].innerText,nx=parseFloat(x.replace(',','.')),ny=parseFloat(y.replace(',','.'));if(!isNaN(nx)&&!isNaN(ny)){return asc?nx-ny:ny-nx}return asc?x.localeCompare(y):y.localeCompare(x)});rows.forEach(function(r){t.tBodies[0].appendChild(r)})}
var curSev='';function sevFilter(s){curSev=(curSev===s)?'':s;applyF()}
function applyF(){var q=(document.getElementById('fsearch').value||'').toLowerCase();document.querySelectorAll('#ftable tbody tr').forEach(function(r){var okS=!curSev||r.dataset.sev===curSev;var okQ=r.innerText.toLowerCase().indexOf(q)>-1;r.style.display=(okS&&okQ)?'':'none'})}
'@
    $sevColor = @{ 'Critique' = 'var(--crit)'; 'Eleve' = 'var(--high)'; 'Moyen' = 'var(--med)'; 'Faible' = 'var(--low)'; 'Info' = 'var(--info)' }
    $sb = New-Object System.Text.StringBuilder
    $title = "Audit pré-migration WS2025 — $($Script:HostName)"
    [void]$sb.Append("<!DOCTYPE html><html lang=`"fr`"><head><meta charset=`"utf-8`"><meta name=`"viewport`" content=`"width=device-width,initial-scale=1`"><title>$(ConvertTo-HtmlEncoded $title)</title><style>$css</style><script>$js</script></head><body>")
    [void]$sb.Append("<header><h1>$(ConvertTo-HtmlEncoded $title)</h1><div class=`"sub`">$(ConvertTo-HtmlEncoded $Script:OS.Caption) — build $($Script:CV.CurrentBuild).$($Script:CV.UBR) — domaine $(ConvertTo-HtmlEncoded $Script:CS.Domain) — audit du $($Script:Start.ToString('dd/MM/yyyy HH:mm')) ($dur min) — v$($Script:AuditVersion)</div></header><main><nav><b>Sommaire</b>")
    [void]$sb.Append('<a href="#synthese">Synthèse</a><a href="#constats">Points d''attention</a>')
    foreach ($s in $Script:Sections) { $e = if ($s.Errors.Count) { " <span class=`"err`">($($s.Errors.Count) err.)</span>" } else { '' }; [void]$sb.Append("<a href=`"#sec-$($s.Id)`">$(ConvertTo-HtmlEncoded $s.Title)$e</a>") }
    [void]$sb.Append('</nav><div>')

    # Synthèse
    [void]$sb.Append('<section id="synthese"><h2>Synthèse</h2>')
    [void]$sb.Append("<div class=`"verdict $($verdict.Class)`">Verdict : $(ConvertTo-HtmlEncoded $verdict.Text)</div><div class=`"cards`">")
    foreach ($k in $counts.Keys) { [void]$sb.Append("<div class=`"cnt c-$k`" onclick=`"sevFilter('$k');location.hash='constats'`"><b>$($counts[$k])</b>$($Script:SeverityLabel[$k])</div>") }
    [void]$sb.Append('</div><p><b>Rôles détectés :</b> ')
    if ($roles.Count) { foreach ($r in $roles) { [void]$sb.Append("<span class=`"role`">$(ConvertTo-HtmlEncoded $r)</span>") } } else { [void]$sb.Append('<span class="role">Serveur membre (aucun rôle suivi)</span>') }
    [void]$sb.Append('</p><h3>Stratégie recommandée</h3><ul class="adv">')
    foreach ($a in $advice) { [void]$sb.Append('<li>' + (ConvertTo-HtmlEncoded $a) + '</li>') }
    [void]$sb.Append('</ul>')
    if (-not (Test-IsAdmin)) { [void]$sb.Append('<div class="errs">Audit exécuté SANS droits administrateur : de nombreuses informations sont manquantes. Relancer depuis une console « Exécuter en tant qu''administrateur ».</div>') }
    $errTotal = ($Script:Sections | ForEach-Object { $_.Errors.Count } | Measure-Object -Sum).Sum
    [void]$sb.Append("<p class=`"note`">$($Script:Sections.Count) sections collectées, $errTotal erreur(s) de collecte (détails dans chaque section et audit.log). Données brutes : dossiers csv\ et raw\.</p></section>")

    # Constats
    [void]$sb.Append('<section id="constats"><h2>Points d''attention</h2><input id="fsearch" type="search" placeholder="Rechercher un constat…" oninput="applyF()"> <span class="note">Cliquer sur un compteur de la synthèse pour filtrer par sévérité.</span>')
    [void]$sb.Append('<div class="tw" style="max-height:none"><table id="ftable"><thead><tr><th onclick="sortTable(this)">Sévérité</th><th onclick="sortTable(this)">Domaine</th><th>Constat</th><th>Détail</th><th>Recommandation</th></tr></thead><tbody>')
    foreach ($f in $findings) {
        [void]$sb.Append("<tr data-sev=`"$($f.Severity)`"><td><span class=`"badge`" style=`"background:$($sevColor[$f.Severity])`">$($Script:SeverityLabel[$f.Severity])</span></td><td>$(ConvertTo-HtmlEncoded $f.Area)</td><td><b>$(ConvertTo-HtmlEncoded $f.Title)</b></td><td>$(ConvertTo-HtmlEncoded $f.Detail)</td><td>$(ConvertTo-HtmlEncoded $f.Recommendation)</td></tr>")
    }
    [void]$sb.Append('</tbody></table></div></section>')

    # Sections
    foreach ($s in $Script:Sections) {
        [void]$sb.Append("<section id=`"sec-$($s.Id)`"><h2>$(ConvertTo-HtmlEncoded $s.Title)</h2><p class=`"note`">Durée de collecte : $($s.DurationSec) s</p>")
        if ($s.Errors.Count) { [void]$sb.Append('<div class="errs"><b>Erreurs de collecte :</b><br>' + (($s.Errors | ForEach-Object { ConvertTo-HtmlEncoded $_ }) -join '<br>') + '</div>') }
        foreach ($it in $s.Items) {
            switch ($it.Type) {
                'table' { [void]$sb.Append('<h3>' + (ConvertTo-HtmlEncoded $it.Title) + '</h3>'); if ($it.Note) { [void]$sb.Append('<p class="note">' + (ConvertTo-HtmlEncoded $it.Note) + '</p>') }; [void]$sb.Append((ConvertTo-HtmlTableFragment $it.Data)) }
                'kv' { [void]$sb.Append('<h3>' + (ConvertTo-HtmlEncoded $it.Title) + '</h3>'); if ($it.Note) { [void]$sb.Append('<p class="note">' + (ConvertTo-HtmlEncoded $it.Note) + '</p>') }; [void]$sb.Append((ConvertTo-HtmlTableFragment $it.Data -Class 'kv')) }
                'raw' { [void]$sb.Append('<details><summary>' + (ConvertTo-HtmlEncoded $it.Title) + ' <span class="note">(' + (ConvertTo-HtmlEncoded $it.Note) + ')</span></summary><pre>' + (ConvertTo-HtmlEncoded $it.Data) + '</pre></details>') }
                'note' { [void]$sb.Append('<p>' + (ConvertTo-HtmlEncoded $it.Data) + '</p>') }
            }
        }
        [void]$sb.Append('</section>')
    }
    [void]$sb.Append("</div></main><footer>Généré par Invoke-PreUpgradeAudit.ps1 v$($Script:AuditVersion) — script en lecture seule — $($end.ToString('dd/MM/yyyy HH:mm'))</footer></body></html>")
    $htmlPath = Join-Path $Script:RunFolder ("Rapport_{0}.html" -f $Script:HostName)
    [System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
    return [pscustomobject]@{ Html = $htmlPath; Verdict = $verdict.Text; Counts = $counts }
}
#endregion

#region ===================== Exécution =====================
Write-Host ''
Write-Host '  ╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '  ║   Audit pré-migration Windows Server 2019 → 2025 (lecture)  ║' -ForegroundColor Cyan
Write-Host '  ╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Log "Hôte : $Script:HostName — sortie : $Script:RunFolder"
if ($env:OS -ne 'Windows_NT') { Write-Log 'Système non Windows : exécution de test uniquement, la plupart des collecteurs échoueront.' 'WARN' }
if (-not (Test-IsAdmin)) { Write-Log 'ATTENTION : console non élevée, résultats incomplets. Relancer « en tant qu''administrateur ».' 'WARN' }

Initialize-Context
Write-Log ('Rôles détectés : ' + ((@($Script:RoleLabels.Keys | Where-Object { $Script:Roles[$_] } | ForEach-Object { $Script:RoleLabels[$_] })) -join ', '))

$collectors = @(
    'Invoke-SystemCollector', 'Invoke-HardwareCollector', 'Invoke-StorageCollector', 'Invoke-NetworkCollector',
    'Invoke-FeaturesCollector', 'Invoke-UpdatesCollector', 'Invoke-SoftwareCollector', 'Invoke-SecurityCollector',
    'Invoke-PoliciesCollector', 'Invoke-ADCollector', 'Invoke-GPOCollector', 'Invoke-DNSCollector', 'Invoke-DHCPCollector',
    'Invoke-RDSCollector', 'Invoke-HyperVCollector', 'Invoke-GuestCollector', 'Invoke-OtherRolesCollector',
    'Invoke-PrintingCollector', 'Invoke-BackupCollector', 'Invoke-EventsCollector', 'Invoke-LegacyAuthCollector',
    'Invoke-SetupCompatCollector'
)
for ($i = 0; $i -lt $collectors.Count; $i++) {
    $Script:Progress = '[{0,2}/{1}]' -f ($i + 1), $collectors.Count
    & $collectors[$i]
}

Write-Host ''
Write-Log 'Génération du rapport...' 'HEAD'
$res = Export-AuditReport
$zip = $null
if (-not $NoZip) {
    try {
        $zip = "$($Script:RunFolder).zip"
        Compress-Archive -Path (Join-Path $Script:RunFolder '*') -DestinationPath $zip -Force -ErrorAction Stop
    } catch { Write-Log "Archive ZIP : $($_.Exception.Message)" 'WARN'; $zip = $null }
}
Write-Log ("Verdict : {0}" -f $res.Verdict) $(if ($res.Verdict -like 'NON*') { 'ERR' } elseif ($res.Verdict -like '*CONDITIONS*') { 'WARN' } else { 'OK' })
Write-Log ("Constats : {0}" -f (($res.Counts.Keys | ForEach-Object { '{0}={1}' -f $Script:SeverityLabel[$_], $res.Counts[$_] }) -join ' | '))
Write-Log "Rapport : $($res.Html)" 'OK'
if ($zip) { Write-Log "Archive : $zip" 'OK' }

# ---------- Récapitulatif console des problèmes de collecte ----------
$errSecs = @($Script:Sections | Where-Object { $_.Errors.Count })
Write-Host ''
if ($errSecs.Count) {
    Write-Log ("RÉCAPITULATIF : {0} section(s) avec erreurs de collecte (données partielles) :" -f $errSecs.Count) 'WARN'
    foreach ($s in $errSecs) { foreach ($e in $s.Errors) { Write-Log ("   [{0}] {1}" -f $s.Id, $e) 'WARN' } }
    Write-Log 'Causes fréquentes : console non élevée, module RSAT absent, compte sans droits AD, service arrêté. Détails : audit.log et section concernée du rapport.' 'INFO'
} else { Write-Log 'RÉCAPITULATIF : aucune erreur de collecte.' 'OK' }
$slow = @($Script:ExternalLog | Where-Object { $_.Code -eq 'TIMEOUT' -or ($_.Code -is [int] -and $_.Code -ne 0) })
if ($slow.Count) { Write-Log ("{0} commande(s) externe(s) en échec ou en délai dépassé :" -f $slow.Count) 'WARN'; foreach ($x in $slow) { Write-Log ("   {0} -> {1}" -f $x.Commande, $x.Code) 'WARN' } }
$crit = @($Script:Findings | Where-Object { $_.Severity -in 'Critique', 'Eleve' })
if ($crit.Count) { Write-Log 'Points CRITIQUE / ÉLEVÉ à traiter :' 'WARN'; foreach ($f in ($crit | Sort-Object { $Script:SeverityOrder[$_.Severity] })) { Write-Log ('   [{0}] {1}' -f $Script:SeverityLabel[$f.Severity], $f.Title) 'FIND' $(if ($f.Severity -eq 'Critique') { 'Red' } else { 'DarkYellow' }) } }
Write-Log ('Durée totale : {0:N1} min' -f ((Get-Date) - $Script:Start).TotalMinutes) 'INFO'
[pscustomobject]@{ ComputerName = $Script:HostName; Report = $res.Html; Folder = $Script:RunFolder; Zip = $zip; Verdict = $res.Verdict }
#endregion
