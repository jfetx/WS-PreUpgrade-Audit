#Requires -Version 5.1
<#
.SYNOPSIS
    Compare deux audits d'un même serveur (avant / après remédiation ou migration).

.DESCRIPTION
    Accepte un dossier Audit_<HOTE>_<date>, son archive .zip ou directement un audit.json.
    Produit Comparaison_<HOTE>.html et Comparaison_<HOTE>.csv :
      - constats RÉSOLUS, NOUVEAUX et PERSISTANTS (comparaison insensible aux nombres
        contenus dans les titres, ex. « 12 comptes inactifs » = « 9 comptes inactifs »)
      - évolution des compteurs par sévérité et du verdict
      - différences des informations clés (build, édition, rôles, schéma, CAL...)
      - évolution du nombre de lignes de chaque tableau du rapport

.EXAMPLE
    PS> .\Compare-AuditReports.ps1 -Before .\Audit_SRV-AD01_20261105_0900.zip -After .\Audit_SRV-AD01_20261120_1400.zip
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Before,
    [Parameter(Mandatory)][string]$After,
    [string]$OutputFolder = (Get-Location).Path
)
$ErrorActionPreference = 'Stop'

function Enc { param($v) if ($null -eq $v) { return '' }; [System.Net.WebUtility]::HtmlEncode([string]$v) }

function Read-Audit {
    param([string]$Path)
    $p = (Resolve-Path $Path).Path
    if ($p -like '*.zip') {
        $dest = Join-Path ([System.IO.Path]::GetTempPath()) ('cmp_' + [guid]::NewGuid().ToString('N'))
        Expand-Archive -Path $p -DestinationPath $dest -Force
        $p = $dest
    }
    if ((Get-Item $p).PSIsContainer) {
        $j = Get-ChildItem $p -Filter 'audit.json' -Recurse | Select-Object -First 1
        if (-not $j) { throw "audit.json introuvable dans $Path" }
        $p = $j.FullName
    }
    Write-Host "Lecture : $p" -ForegroundColor DarkGray
    return (Get-Content $p -Raw -Encoding UTF8 | ConvertFrom-Json)
}

# Clé de rapprochement : hôte + domaine + titre sans les nombres
function Get-Key { param($f) return ('{0}|{1}|{2}' -f $f.Host, $f.Area, ($f.Title -replace '\d+([.,]\d+)?', '#')).ToLowerInvariant() }

$a = Read-Audit $Before
$b = Read-Audit $After
if ($a.Meta.Host -ne $b.Meta.Host) { Write-Warning "Hôtes différents : $($a.Meta.Host) / $($b.Meta.Host) — comparaison quand même effectuée." }

$ka = @{}; foreach ($f in $a.Findings) { $ka[(Get-Key $f)] = $f }
$kb = @{}; foreach ($f in $b.Findings) { $kb[(Get-Key $f)] = $f }
$resolved = @($ka.Keys | Where-Object { -not $kb.ContainsKey($_) } | ForEach-Object { $ka[$_] })
$new = @($kb.Keys | Where-Object { -not $ka.ContainsKey($_) } | ForEach-Object { $kb[$_] })
$kept = @($kb.Keys | Where-Object { $ka.ContainsKey($_) } | ForEach-Object { [pscustomobject]@{ Avant = $ka[$_]; Apres = $kb[$_] } })

$sevOrder = @{ 'Critique' = 0; 'Eleve' = 1; 'Moyen' = 2; 'Faible' = 3; 'Info' = 4 }
$sevLabel = @{ 'Critique' = 'CRITIQUE'; 'Eleve' = 'ÉLEVÉ'; 'Moyen' = 'MOYEN'; 'Faible' = 'FAIBLE'; 'Info' = 'INFO' }
$sevColor = @{ 'Critique' = '#b3261e'; 'Eleve' = '#d9480f'; 'Moyen' = '#c98a00'; 'Faible' = '#2b7a78'; 'Info' = '#5b6476' }

# Informations clés
$facts = New-Object System.Collections.Generic.List[object]
function Add-Diff($name, $x, $y) { $facts.Add([pscustomobject]@{ 'Information' = $name; 'Avant' = "$x"; 'Après' = "$y"; 'Changé' = ("$x" -ne "$y") }) }
Add-Diff 'Système' $a.Meta.OS $b.Meta.OS
Add-Diff 'Build' $a.Meta.Build $b.Meta.Build
Add-Diff 'Édition' $a.Meta.EditionID $b.Meta.EditionID
Add-Diff 'Rôles' ($a.Meta.Roles -join ', ') ($b.Meta.Roles -join ', ')
Add-Diff 'Verdict' $a.Meta.Verdict $b.Meta.Verdict
$names = @($a.Facts.PSObject.Properties.Name) + @($b.Facts.PSObject.Properties.Name) | Where-Object { $_ -ne 'GuestMap' } | Select-Object -Unique
foreach ($n in $names) { Add-Diff $n $a.Facts.$n $b.Facts.$n }

# Volumétrie des tableaux
$tables = @{}
foreach ($pair in @(@{ S = $a; K = 'Avant' }, @{ S = $b; K = 'Après' })) {
    foreach ($sec in $pair.S.Sections) { foreach ($it in $sec.Items) { if ($it.Type -eq 'table') {
                $k = "$($sec.Title) › $($it.Title)"
                if (-not $tables.ContainsKey($k)) { $tables[$k] = @{ 'Avant' = $null; 'Après' = $null } }
                $tables[$k][$pair.K] = @($it.Data).Count
            } } }
}
$tabRows = foreach ($k in ($tables.Keys | Sort-Object)) { $t = $tables[$k]; if ($t['Avant'] -ne $t['Après']) { [pscustomobject]@{ Tableau = $k; Avant = $t['Avant']; 'Après' = $t['Après'] } } }

# CSV
$hostName = $b.Meta.Host
$csv = Join-Path $OutputFolder "Comparaison_$hostName.csv"
$out = @()
$out += $resolved | ForEach-Object { [pscustomobject]@{ Statut = 'RÉSOLU'; 'Sévérité' = $sevLabel[$_.Severity]; Domaine = $_.Area; Constat = $_.Title; Recommandation = $_.Recommendation } }
$out += $new | ForEach-Object { [pscustomobject]@{ Statut = 'NOUVEAU'; 'Sévérité' = $sevLabel[$_.Severity]; Domaine = $_.Area; Constat = $_.Title; Recommandation = $_.Recommendation } }
$out += $kept | ForEach-Object { [pscustomobject]@{ Statut = 'PERSISTANT'; 'Sévérité' = $sevLabel[$_.Apres.Severity]; Domaine = $_.Apres.Area; Constat = $_.Apres.Title; Recommandation = $_.Apres.Recommendation } }
$out | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -Delimiter ';'

# HTML
function Rows($list, $label, $color) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($f in ($list | Sort-Object { $sevOrder[$_.Severity] })) {
        [void]$sb.Append("<tr><td><span class=`"st`" style=`"background:$color`">$label</span></td><td><span class=`"b`" style=`"background:$($sevColor[$f.Severity])`">$($sevLabel[$f.Severity])</span></td><td>$(Enc $f.Area)</td><td><b>$(Enc $f.Title)</b></td><td>$(Enc $f.Recommendation)</td></tr>")
    }
    $sb.ToString()
}
$cnt = foreach ($s in 'Critique', 'Eleve', 'Moyen', 'Faible', 'Info') { $x = [int]$a.Meta.Counts.$s; $y = [int]$b.Meta.Counts.$s; "<tr><td>$($sevLabel[$s])</td><td>$x</td><td>$y</td><td style=`"color:$(if ($y -lt $x) { '#1e7d32' } elseif ($y -gt $x) { '#b3261e' } else { '#5b6476' });font-weight:700`">$(if ($y -ge $x) { '+' })$($y - $x)</td></tr>" }
$factHtml = ($facts | ForEach-Object { "<tr$(if ($_.'Changé') { ' class="chg"' })><td>$(Enc $_.Information)</td><td>$(Enc $_.Avant)</td><td>$(Enc $_.'Après')</td></tr>" }) -join ''
$tabHtml = (@($tabRows) | ForEach-Object { "<tr><td>$(Enc $_.Tableau)</td><td>$($_.Avant)</td><td>$($_.'Après')</td></tr>" }) -join ''
$html = @"
<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Comparaison $(Enc $hostName)</title><style>
body{margin:0;font:14px/1.45 "Segoe UI",system-ui,Arial,sans-serif;background:#f5f6f8;color:#1d2433}header{background:#14213d;color:#fff;padding:20px 28px}h1{margin:0;font-size:21px}
.wrap{max-width:1500px;margin:auto;padding:20px 28px}section{background:#fff;border:1px solid #dde1e8;border-radius:10px;padding:16px 18px;margin-bottom:18px}h2{margin:0 0 12px;font-size:17px;color:#14213d}
table{border-collapse:collapse;width:100%;font-size:12.5px}th{background:#eef1f6;text-align:left;padding:6px 8px}td{padding:5px 8px;border-bottom:1px solid #eceff4;vertical-align:top}
.b,.st{display:inline-block;padding:2px 8px;border-radius:12px;color:#fff;font-size:11px;font-weight:700}.chg td{background:#fff8e1}.kpi{display:flex;gap:12px;flex-wrap:wrap}.kpi div{flex:1;min-width:150px;border-radius:10px;padding:12px;color:#fff;text-align:center}.kpi b{display:block;font-size:26px}
</style></head><body><header><h1>Comparaison d'audits — $(Enc $hostName)</h1><div>Avant : $(Enc $a.Meta.Start) ($(Enc $a.Meta.Build)) → Après : $(Enc $b.Meta.Start) ($(Enc $b.Meta.Build))</div></header><div class="wrap">
<section><div class="kpi"><div style="background:#1e7d32"><b>$($resolved.Count)</b>résolus</div><div style="background:#b3261e"><b>$($new.Count)</b>nouveaux</div><div style="background:#5b6476"><b>$($kept.Count)</b>persistants</div></div></section>
<section><h2>Compteurs par sévérité</h2><table><thead><tr><th>Sévérité</th><th>Avant</th><th>Après</th><th>Écart</th></tr></thead><tbody>$($cnt -join '')</tbody></table></section>
<section><h2>Constats</h2><table><thead><tr><th>Statut</th><th>Sévérité</th><th>Domaine</th><th>Constat</th><th>Recommandation</th></tr></thead><tbody>$(Rows $new 'NOUVEAU' '#b3261e')$(Rows $resolved 'RÉSOLU' '#1e7d32')$(Rows ($kept | ForEach-Object { $_.Apres }) 'PERSISTANT' '#5b6476')</tbody></table></section>
<section><h2>Informations clés (lignes modifiées surlignées)</h2><table><thead><tr><th>Information</th><th>Avant</th><th>Après</th></tr></thead><tbody>$factHtml</tbody></table></section>
<section><h2>Tableaux dont le volume a changé</h2><table><thead><tr><th>Tableau</th><th>Lignes avant</th><th>Lignes après</th></tr></thead><tbody>$tabHtml</tbody></table></section>
</div></body></html>
"@
$file = Join-Path $OutputFolder "Comparaison_$hostName.html"
[System.IO.File]::WriteAllText($file, $html, (New-Object System.Text.UTF8Encoding($true)))
Write-Host ("Résolus : {0} | Nouveaux : {1} | Persistants : {2}" -f $resolved.Count, $new.Count, $kept.Count) -ForegroundColor Cyan
Write-Host "Rapport : $file" -ForegroundColor Green
Write-Host "CSV     : $csv" -ForegroundColor Green
