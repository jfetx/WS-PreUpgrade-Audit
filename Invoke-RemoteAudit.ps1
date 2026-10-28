#Requires -Version 5.1
<#
.SYNOPSIS
    Lance Invoke-PreUpgradeAudit.ps1 à distance (WinRM) sur plusieurs serveurs,
    rapatrie les archives puis génère le rapport consolidé.

.DESCRIPTION
    Pour chaque serveur : ouverture d'une session PowerShell Remoting, copie du script
    (et de Coreinfo64.exe s'il est présent à côté), exécution, récupération du ZIP,
    nettoyage du dossier temporaire distant. Enfin Merge-AuditReports.ps1 est appelé.

    LIMITE "double saut" Kerberos : depuis une session distante, les commandes qui
    interrogent d'AUTRES serveurs (repadmin /showrepl *, dcdiag vers d'autres DC,
    partages UPD sur un NAS...) peuvent échouer en "accès refusé". Pour un DC ou un
    déploiement RDS multi-serveurs, l'exécution LOCALE reste la plus complète.

.PARAMETER ComputerName
    Liste des serveurs (nom ou FQDN). Pour un hôte en groupe de travail : IP/nom + -Credential
    (et l'hôte dans TrustedHosts côté poste d'administration).

.PARAMETER Credential
    Identifiants (ex. Get-Credential CONTOSO\admin).

.PARAMETER Destination
    Dossier local de collecte. Défaut : .\AuditResults

.PARAMETER AuditParameters
    Paramètres transmis au script d'audit, ex. @{ EventDays = 30; Quick = $true }

.EXAMPLE
    PS> .\Invoke-RemoteAudit.ps1 -ComputerName SRV-HV01,SRV-AD01,SRV-RDS01 -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [pscredential]$Credential,
    [string]$Destination = (Join-Path (Get-Location).Path 'AuditResults'),
    [hashtable]$AuditParameters = @{},
    [string]$RemoteTemp = 'C:\Windows\Temp\PreUpgradeAudit',
    [switch]$UseSSL
)
$ErrorActionPreference = 'Stop'
$auditScript = Join-Path $PSScriptRoot 'Invoke-PreUpgradeAudit.ps1'
if (-not (Test-Path $auditScript)) { throw "Introuvable : $auditScript" }
if (-not (Test-Path $Destination)) { New-Item -ItemType Directory -Path $Destination -Force | Out-Null }
$extra = @('Coreinfo64.exe', 'Coreinfo.exe') | ForEach-Object { Join-Path $PSScriptRoot $_ } | Where-Object { Test-Path $_ }

$summary = foreach ($c in $ComputerName) {
    Write-Host "`n=== $c ===" -ForegroundColor Cyan
    $s = $null
    try {
        $so = @{ ComputerName = $c; ErrorAction = 'Stop' }
        if ($Credential) { $so.Credential = $Credential }
        if ($UseSSL) { $so.UseSSL = $true }
        $s = New-PSSession @so
        Invoke-Command -Session $s -ScriptBlock { param($d) if (Test-Path $d) { Remove-Item $d -Recurse -Force }; New-Item -ItemType Directory -Path $d -Force | Out-Null } -ArgumentList $RemoteTemp
        Copy-Item -Path $auditScript -Destination $RemoteTemp -ToSession $s -Force
        foreach ($e in $extra) { Copy-Item -Path $e -Destination $RemoteTemp -ToSession $s -Force }
        $res = Invoke-Command -Session $s -ScriptBlock {
            param($dir, $params)
            $out = Join-Path $dir 'Out'
            & (Join-Path $dir 'Invoke-PreUpgradeAudit.ps1') -OutputPath $out @params
        } -ArgumentList $RemoteTemp, $AuditParameters
        $r = @($res | Where-Object { $_.PSObject.Properties.Name -contains 'Zip' -and $_.Zip }) | Select-Object -Last 1
        if (-not $r) { throw 'Aucune archive produite (voir sortie ci-dessus).' }
        Copy-Item -FromSession $s -Path $r.Zip -Destination $Destination -Force
        Invoke-Command -Session $s -ScriptBlock { param($d) Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue } -ArgumentList $RemoteTemp
        [pscustomobject]@{ Serveur = $c; Statut = 'OK'; Verdict = $r.Verdict; Archive = (Join-Path $Destination (Split-Path $r.Zip -Leaf)) }
    } catch {
        Write-Warning "$c : $($_.Exception.Message)"
        [pscustomobject]@{ Serveur = $c; Statut = 'ÉCHEC'; Verdict = $_.Exception.Message; Archive = $null }
    } finally { if ($s) { Remove-PSSession $s } }
}
$summary | Format-Table -AutoSize
$merge = Join-Path $PSScriptRoot 'Merge-AuditReports.ps1'
if ((Test-Path $merge) -and @($summary | Where-Object { $_.Statut -eq 'OK' }).Count) { & $merge -Path $Destination }
