#Requires -Version 7.0
<#
.SYNOPSIS
    Test de fumée exécutable hors Windows (PowerShell 7, Linux/macOS/CI).

.DESCRIPTION
    1) Vérifie la syntaxe de tous les scripts .ps1 du dépôt.
    2) Exécute Invoke-PreUpgradeAudit.ps1 contre des modules Windows SIMULÉS (tests/mocks)
       qui décrivent un hôte Hyper-V 2019 « à problèmes » (DC + RDS sur l'hôte, LBFO,
       niveaux fonctionnels 2012 R2, NTLMv1...).
    3) Vérifie la présence des sorties et des constats attendus.
    4) Teste Merge-AuditReports.ps1 et Compare-AuditReports.ps1.

    Les commandes natives Windows (dcdiag, repadmin...) échouent forcément hors Windows :
    ces erreurs de collecte sont attendues et ignorées ici.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fail = 0
function Check($cond, $msg) { if ($cond) { Write-Host "  [OK]   $msg" -ForegroundColor Green } else { Write-Host "  [FAIL] $msg" -ForegroundColor Red; $script:fail++ } }

Write-Host '== 1. Syntaxe' -ForegroundColor Cyan
foreach ($f in Get-ChildItem $root -Filter *.ps1 -Recurse | Where-Object { $_.FullName -notmatch '[\\/]mocks[\\/]' }) {
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
    Check (-not $e) "$($f.Name) $(if ($e) { $e[0].Message + ' L' + $e[0].Extent.StartLineNumber })"
}

Write-Host '== 2. Audit sur environnement simulé' -ForegroundColor Cyan
$out = Join-Path ([System.IO.Path]::GetTempPath()) ('smoke_' + [guid]::NewGuid().ToString('N'))
$env:PSModulePath = (Join-Path $PSScriptRoot 'mocks') + [System.IO.Path]::PathSeparator + $env:PSModulePath
$env:COMPUTERNAME = 'SRV-HV01'
Import-Module WinStubs -Force
$res = & (Join-Path $root 'Invoke-PreUpgradeAudit.ps1') -OutputPath $out -EventDays 3 -NoDownload 6>$null 3>$null | Select-Object -Last 1
Check ($res -and (Test-Path $res.Report)) 'Rapport HTML généré'
Check ($res.Zip -and (Test-Path $res.Zip)) 'Archive ZIP générée'
$json = Get-Content (Join-Path $res.Folder 'audit.json') -Raw | ConvertFrom-Json
Check ($json.Meta.Host -eq 'SRV-HV01') 'audit.json lisible'
$titles = $json.Findings.Title -join "`n"
foreach ($exp in 'Niveaux fonctionnels insuffisants', 'équipe LBFO', 'Compatibilité processeur activée', 'NTLMv1 encore utilisé', 'Binds LDAP non signés', 'Aucune CAL RDS 2025', 'Un seul contrôleur de domaine', 'Serveur SMTP', 'pour les checkpoints sur') {
    Check ($titles -match [regex]::Escape($exp)) "Constat attendu : $exp"
}
Check ($json.Meta.Verdict -like 'NON PRÊT*') 'Verdict NON PRÊT'

Write-Host '== 3. Consolidation et comparaison' -ForegroundColor Cyan
& (Join-Path $root 'Merge-AuditReports.ps1') -Path $out | Out-Null
Check (Test-Path (Join-Path $out 'Rapport_Consolide.html')) 'Rapport consolidé'
& (Join-Path $root 'Compare-AuditReports.ps1') -Before $res.Folder -After $res.Zip -OutputFolder $out | Out-Null
Check (Test-Path (Join-Path $out 'Comparaison_SRV-HV01.html')) 'Rapport de comparaison'

Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
if ($fail) { Write-Host "$fail échec(s)" -ForegroundColor Red; exit 1 } else { Write-Host 'Tous les tests sont passés.' -ForegroundColor Green }
