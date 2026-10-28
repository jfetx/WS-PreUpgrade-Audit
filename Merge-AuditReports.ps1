#Requires -Version 5.1
<#
.SYNOPSIS
    Consolide les audits de plusieurs serveurs (audit.json) en un rapport unique de cadrage.

.DESCRIPTION
    Parcourt un dossier contenant les résultats d'Invoke-PreUpgradeAudit.ps1
    (dossiers Audit_<HOTE>_<date> ou archives .zip), ne garde que l'audit le plus
    récent par serveur, et produit :
      - Rapport_Consolide.html : vue d'ensemble, verdict par serveur, tous les constats,
        contrôles croisés (VM non auditées, DC, licences RDS) et ordre de migration proposé
      - Constats_Consolides.csv : tous les constats (séparateur ;) pour Excel / plan d'action

.PARAMETER Path
    Dossier contenant les résultats (défaut : dossier courant).

.PARAMETER OutputFolder
    Dossier de sortie (défaut : -Path).

.EXAMPLE
    PS> .\Merge-AuditReports.ps1 -Path .\AuditResults
#>
[CmdletBinding()]
param(
    [string]$Path = (Get-Location).Path,
    [string]$OutputFolder
)
$ErrorActionPreference = 'Stop'
if (-not $OutputFolder) { $OutputFolder = $Path }
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }

function Enc { param($v) if ($null -eq $v) { return '' }; [System.Net.WebUtility]::HtmlEncode([string]$v) }
$sevOrder = @{ 'Critique' = 0; 'Eleve' = 1; 'Moyen' = 2; 'Faible' = 3; 'Info' = 4 }
$sevLabel = @{ 'Critique' = 'CRITIQUE'; 'Eleve' = 'ÉLEVÉ'; 'Moyen' = 'MOYEN'; 'Faible' = 'FAIBLE'; 'Info' = 'INFO' }
$sevColor = @{ 'Critique' = '#b3261e'; 'Eleve' = '#d9480f'; 'Moyen' = '#c98a00'; 'Faible' = '#2b7a78'; 'Info' = '#5b6476' }

# 1) Décompresser les ZIP non encore extraits
Get-ChildItem -Path $Path -Filter 'Audit_*.zip' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $dest = Join-Path $_.DirectoryName ($_.BaseName)
    if (-not (Test-Path $dest)) { Write-Host "Extraction $($_.Name)"; Expand-Archive -Path $_.FullName -DestinationPath $dest -Force }
}

# 2) Charger les audit.json (le plus récent par hôte)
$audits = @{}
foreach ($f in (Get-ChildItem -Path $Path -Filter 'audit.json' -Recurse -ErrorAction SilentlyContinue)) {
    try {
        $j = Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $h = $j.Meta.Host
        if (-not $audits.ContainsKey($h) -or [datetime]$j.Meta.Start -gt [datetime]$audits[$h].Meta.Start) {
            $j | Add-Member -NotePropertyName Folder -NotePropertyValue $f.DirectoryName -Force
            $audits[$h] = $j
        }
    } catch { Write-Warning "Lecture impossible : $($f.FullName) ($($_.Exception.Message))" }
}
if (-not $audits.Count) { throw "Aucun audit.json trouvé sous $Path" }
Write-Host "$($audits.Count) serveur(s) : $(($audits.Keys | Sort-Object) -join ', ')"

$all = foreach ($a in $audits.Values) { foreach ($f in $a.Findings) { $f } }
$all = @($all | Sort-Object @{ e = { $sevOrder[$_.Severity] } }, Host, Area)

# 3) Contrôles croisés
$cross = New-Object System.Collections.Generic.List[object]
function Add-Cross($sev, $title, $detail, $reco) { $cross.Add([pscustomobject]@{ Host = '(global)'; Severity = $sev; Area = 'Contrôle croisé'; Title = $title; Detail = $detail; Recommendation = $reco }) }

$auditedNames = @($audits.Keys | ForEach-Object { $_.ToUpper() })
$guests = foreach ($a in $audits.Values) { foreach ($g in @($a.Facts.GuestMap)) { if ($g) { [pscustomobject]@{ Hote = $a.Meta.Host; VM = $g.VM; FQDN = $g.FQDN; OS = $g.'OS invité'; IPv4 = $g.IPv4 } } } }
$guests = @($guests)
$notAudited = @($guests | Where-Object { $n = if ($_.FQDN) { ($_.FQDN -split '\.')[0].ToUpper() } else { "$($_.VM)".ToUpper() }; $auditedNames -notcontains $n })
if ($notAudited.Count) { Add-Cross 'Moyen' "$($notAudited.Count) VM non auditée(s)" (($notAudited | ForEach-Object { "$($_.VM) [$($_.OS)] sur $($_.Hote)" }) -join ' | ') 'Lancer Invoke-PreUpgradeAudit.ps1 sur ces VM (Windows) ou documenter leur rôle (Linux, appliance...).' }

$dcs = @($audits.Values | Where-Object { $_.Meta.Roles -contains 'Contrôleur de domaine' })
$dcCount = ($dcs | ForEach-Object { $_.Facts.DCCount } | Measure-Object -Maximum).Maximum
if ($dcs.Count -and $dcCount -lt 2) { Add-Cross 'Eleve' 'Domaine avec un seul DC' "DC audité(s) : $(($dcs.Meta.Host) -join ', ')" 'Commencer la migration par l''ajout d''un DC WS2025 (side-by-side) : cela crée la redondance avant de toucher au reste.' }
$hv = @($audits.Values | Where-Object { $_.Meta.Roles -contains 'Hôte Hyper-V' })
$rds = @($audits.Values | Where-Object { $_.Meta.Roles -match 'RDS' })
foreach ($h in $hv) { foreach ($r in @($dcs + $rds)) { if ($r.Meta.Host -eq $h.Meta.Host) { Add-Cross 'Eleve' "Rôles AD/RDS sur l'hyperviseur $($h.Meta.Host)" ($r.Meta.Roles -join ', ') 'Sortir ces rôles de l''hôte vers des VM dédiées pendant la migration.'; break } } }
$modes = @($rds | ForEach-Object { $_.Facts.RDSLicMode } | Where-Object { $_ } | Select-Object -Unique)
if ($modes.Count -gt 1) { Add-Cross 'Moyen' 'Modes de licence RDS hétérogènes' ($modes -join ', ') 'Unifier le mode de licence (CAL utilisateur ou périphérique) avant l''achat des CAL 2025.' }
$all = @($cross.ToArray()) + $all

# 4) Ordre de migration proposé
$plan = New-Object System.Collections.Generic.List[string]
$plan.Add('Phase 0 — Remédiation : traiter les constats CRITIQUE / ÉLEVÉ de chaque serveur, mettre à jour (CU), sauvegardes complètes testées, achats licences (cœurs WS2025, CAL WS2025, CAL RDS 2025).')
if ($hv.Count) { $plan.Add("Phase 1 — Hyperviseur(s) $(($hv.Meta.Host) -join ', ') : firmware/pilotes constructeur, conversion LBFO → SET, désactivation compatibilité CPU des VM, export certificats vTPM, puis upgrade sur place ou réinstallation propre ; VM arrêtées proprement pendant l'opération.") }
if ($dcs.Count) { $plan.Add("Phase 2 — Active Directory : nouveau DC WS2025 (VM gén. 2), DNS/GC, contrôle réplication, transfert FSMO, bascule DNS/DHCP, rétrogradation de $(($dcs.Meta.Host) -join ', ').") }
if ($rds.Count) { $plan.Add("Phase 3 — RDS ($(($rds.Meta.Host) -join ', ')) : serveur de licences 2025 + CAL RDS 2025 → Broker → hôtes de session (pilote avec quelques utilisateurs) → Accès Web / Passerelle.") }
$plan.Add('Phase 4 — Post-migration : relancer l''audit sur tous les serveurs, comparer, nettoyer (anciens serveurs, DNS, comptes), mettre à jour ADMX, documentation, supervision.')

# 5) CSV
$csv = Join-Path $OutputFolder 'Constats_Consolides.csv'
$all | Select-Object @{n = 'Serveur'; e = { $_.Host } }, @{n = 'Sévérité'; e = { $sevLabel[$_.Severity] } }, @{n = 'Domaine'; e = { $_.Area } }, @{n = 'Constat'; e = { $_.Title } }, @{n = 'Détail'; e = { $_.Detail } }, @{n = 'Recommandation'; e = { $_.Recommendation } }, @{n = 'Responsable'; e = { '' } }, @{n = 'Échéance'; e = { '' } }, @{n = 'Statut'; e = { 'À traiter' } } |
    Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -Delimiter ';'

# 6) HTML
$sb = New-Object System.Text.StringBuilder
[void]$sb.Append(@'
<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Audit pré-migration WS2025 — consolidé</title><style>
body{margin:0;font:14px/1.45 "Segoe UI",system-ui,Arial,sans-serif;background:#f5f6f8;color:#1d2433}header{background:#14213d;color:#fff;padding:22px 28px}h1{margin:0;font-size:22px}
.wrap{max-width:1600px;margin:auto;padding:20px 28px}section{background:#fff;border:1px solid #dde1e8;border-radius:10px;padding:16px 18px;margin-bottom:18px}h2{margin:0 0 12px;font-size:18px;color:#14213d}
table{border-collapse:collapse;width:100%;font-size:12.5px}th{background:#eef1f6;text-align:left;padding:6px 8px;position:sticky;top:0;cursor:pointer}td{padding:5px 8px;border-bottom:1px solid #eceff4;vertical-align:top}
.b{display:inline-block;padding:2px 8px;border-radius:12px;color:#fff;font-size:11px;font-weight:700}.tw{overflow:auto;max-height:760px;border:1px solid #dde1e8;border-radius:8px}
.v-ko{color:#b3261e;font-weight:700}.v-warn{color:#d9480f;font-weight:700}.v-ok{color:#1e7d32;font-weight:700}ol li{margin:6px 0}input{padding:6px 10px;border:1px solid #dde1e8;border-radius:6px;width:320px;max-width:100%;margin-bottom:8px}
a{color:#1f5fbf}
</style><script>
function f(i){var q=i.value.toLowerCase();document.querySelectorAll('#all tbody tr').forEach(function(r){r.style.display=r.innerText.toLowerCase().indexOf(q)>-1?'':'none'})}
function sortTable(th){var t=th.closest('table'),i=Array.prototype.indexOf.call(th.parentNode.children,th),asc=th.dataset.asc!=='1';th.dataset.asc=asc?'1':'0';var rows=Array.prototype.slice.call(t.tBodies[0].rows);rows.sort(function(a,b){var x=a.cells[i].innerText,y=b.cells[i].innerText;return asc?x.localeCompare(y,undefined,{numeric:true}):y.localeCompare(x,undefined,{numeric:true})});rows.forEach(function(r){t.tBodies[0].appendChild(r)})}
</script></head><body>
'@)
[void]$sb.Append("<header><h1>Audit pré-migration Windows Server 2025 — rapport consolidé</h1><div>$($audits.Count) serveur(s) — généré le $((Get-Date).ToString('dd/MM/yyyy HH:mm'))</div></header><div class=`"wrap`">")
[void]$sb.Append('<section><h2>Vue d''ensemble</h2><div class="tw"><table><thead><tr><th onclick="sortTable(this)">Serveur</th><th>Système</th><th>Build</th><th>Plateforme</th><th>Rôles</th><th>Verdict</th><th>Crit.</th><th>Élevé</th><th>Moyen</th><th>Faible</th><th>Info</th><th>Audit</th><th>Rapport</th></tr></thead><tbody>')
foreach ($a in ($audits.Values | Sort-Object { $_.Meta.Host })) {
    $m = $a.Meta; $vc = if ($m.Verdict -like 'NON*') { 'v-ko' } elseif ($m.Verdict -like '*CONDITIONS*') { 'v-warn' } else { 'v-ok' }
    $rep = Get-ChildItem $a.Folder -Filter 'Rapport_*.html' -ErrorAction SilentlyContinue | Select-Object -First 1
    $base = (Resolve-Path $OutputFolder).Path.TrimEnd('\', '/')
    $rel = if ($rep) { if ($rep.FullName.StartsWith($base)) { $rep.FullName.Substring($base.Length).TrimStart('\', '/') } else { 'file:///' + $rep.FullName } } else { '' }
    $link = if ($rel) { '<a href="' + (Enc ($rel -replace '\\', '/')) + '">ouvrir</a>' } else { '' }
    [void]$sb.Append("<tr><td><b>$(Enc $m.Host)</b></td><td>$(Enc $m.OS)</td><td>$(Enc $m.Build)</td><td>$(Enc $(if ($m.VMPlatform) { "VM $($m.VMPlatform)" } else { 'Physique' }))</td><td>$(Enc ($m.Roles -join ', '))</td><td class=`"$vc`">$(Enc $m.Verdict)</td><td>$($m.Counts.Critique)</td><td>$($m.Counts.Eleve)</td><td>$($m.Counts.Moyen)</td><td>$($m.Counts.Faible)</td><td>$($m.Counts.Info)</td><td>$(Enc $m.Start)</td><td>$link</td></tr>")
}
[void]$sb.Append('</tbody></table></div></section>')
[void]$sb.Append('<section><h2>Ordre de migration proposé</h2><ol>'); foreach ($p in $plan) { [void]$sb.Append("<li>$(Enc $p)</li>") }; [void]$sb.Append('</ol></section>')
if ($guests.Count) {
    [void]$sb.Append('<section><h2>VM détectées sur les hyperviseurs</h2><div class="tw"><table><thead><tr><th>Hyperviseur</th><th>VM</th><th>FQDN</th><th>OS invité</th><th>IPv4</th><th>Auditée</th></tr></thead><tbody>')
    foreach ($g in $guests) { $n = if ($g.FQDN) { ($g.FQDN -split '\.')[0].ToUpper() } else { "$($g.VM)".ToUpper() }; [void]$sb.Append("<tr><td>$(Enc $g.Hote)</td><td>$(Enc $g.VM)</td><td>$(Enc $g.FQDN)</td><td>$(Enc $g.OS)</td><td>$(Enc $g.IPv4)</td><td>$(if ($auditedNames -contains $n) { '✔' } else { '<b style="color:#d9480f">non</b>' })</td></tr>") }
    [void]$sb.Append('</tbody></table></div></section>')
}
[void]$sb.Append("<section><h2>Tous les constats ($($all.Count))</h2><input type=`"search`" placeholder=`"Filtrer (serveur, sévérité, mot-clé)…`" oninput=`"f(this)`"><div class=`"tw`"><table id=`"all`"><thead><tr><th onclick=`"sortTable(this)`">Serveur</th><th onclick=`"sortTable(this)`">Sévérité</th><th onclick=`"sortTable(this)`">Domaine</th><th>Constat</th><th>Détail</th><th>Recommandation</th></tr></thead><tbody>")
foreach ($x in $all) { [void]$sb.Append("<tr><td>$(Enc $x.Host)</td><td><span class=`"b`" style=`"background:$($sevColor[$x.Severity])`">$($sevLabel[$x.Severity])</span></td><td>$(Enc $x.Area)</td><td><b>$(Enc $x.Title)</b></td><td>$(Enc $x.Detail)</td><td>$(Enc $x.Recommendation)</td></tr>") }
[void]$sb.Append('</tbody></table></div></section></div></body></html>')
$html = Join-Path $OutputFolder 'Rapport_Consolide.html'
[System.IO.File]::WriteAllText($html, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
Write-Host "Rapport consolidé : $html" -ForegroundColor Green
Write-Host "Plan d'action CSV : $csv" -ForegroundColor Green
