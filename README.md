# WS2025-PreUpgrade-Audit

Kit d'audit **en lecture seule** pour la journée de cadrage d'une migration
**Windows Server 2019 → Windows Server 2025** : hyperviseur Hyper-V, contrôleur(s) de domaine
(AD DS / DNS / DHCP / GPO), Services Bureau à distance (RDS) et rôles courants.

Un seul script à lancer sur chaque serveur. Il détecte les rôles installés, collecte tout ce qui
est utile à la décision, puis produit un **rapport HTML** avec un verdict (prêt / sous conditions /
non prêt), des **points d'attention classés par sévérité** avec leurs recommandations, et les données
brutes (CSV, JSON, sorties d'outils) pour la documentation.

```
┌────────────────────┐     ┌────────────────────┐     ┌────────────────────┐
│  Hôte Hyper-V      │     │  DC (VM)           │     │  RDS (VM)          │
│  Invoke-PreUpgrade │     │  Invoke-PreUpgrade │     │  Invoke-PreUpgrade │
│  Audit.ps1         │     │  Audit.ps1         │     │  Audit.ps1         │
└─────────┬──────────┘     └─────────┬──────────┘     └─────────┬──────────┘
          │ Audit_HOTE_date.zip      │                          │
          └──────────────┬───────────┴──────────────────────────┘
                         ▼
              Merge-AuditReports.ps1  →  Rapport_Consolide.html + Constats_Consolides.csv
```

## Contenu du dépôt

| Fichier | Rôle |
|---|---|
| `Invoke-PreUpgradeAudit.ps1` | Script principal, à lancer sur chaque serveur (auto-détection des rôles) |
| `Run-Audit.cmd` | Lanceur double-clic (élévation UAC + ExecutionPolicy Bypass pour le processus) |
| `Invoke-RemoteAudit.ps1` | Optionnel : exécution à distance via WinRM sur plusieurs serveurs + consolidation |
| `Merge-AuditReports.ps1` | Consolide plusieurs audits en un rapport unique + plan d'action CSV |
| `docs/CHECKLIST-CADRAGE.md` | Ce que le script ne peut pas deviner : questions d'entretien, Go/No-Go, plan type |

## Démarrage rapide (recommandé : exécution locale sur chaque serveur)

1. Copier le dossier sur le serveur (ex. `C:\Temp\Audit`). Optionnel : y déposer
   [`Coreinfo64.exe`](https://learn.microsoft.com/sysinternals/downloads/coreinfo) pour une
   vérification formelle de SSE4.2/POPCNT.
2. Débloquer les fichiers téléchargés depuis GitHub :
   ```powershell
   Get-ChildItem C:\Temp\Audit | Unblock-File
   ```
3. Lancer **en tant qu'administrateur** (sur un DC : compte Domain Admins) :
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   C:\Temp\Audit\Invoke-PreUpgradeAudit.ps1
   ```
   ou double-cliquer sur `Run-Audit.cmd`.
4. Récupérer `C:\AuditPreUpgrade\Audit_<HOTE>_<date>.zip` sur chaque serveur.
5. Sur le poste d'administration :
   ```powershell
   .\Merge-AuditReports.ps1 -Path D:\Cadrage\Client\Audits
   ```

Durée typique : 2 à 10 min par serveur (plus sur un DC avec `dcdiag` et un grand annuaire,
ou un RDS avec beaucoup de profils — utiliser `-Quick` si besoin).

### Paramètres utiles

| Paramètre | Effet |
|---|---|
| `-OutputPath E:\Audit` | Dossier de sortie (défaut `C:\AuditPreUpgrade`) |
| `-EventDays 30` | Profondeur d'analyse des journaux (défaut 14 j) |
| `-StaleDays 180` | Seuil d'inactivité des comptes AD (défaut 90 j) |
| `-Quick` | Pas de calcul de taille des profils, pas de `dcdiag /test:dns`, pas de rapport GPO HTML complet |
| `-SkipSection Events,Software` | Ignorer des sections |
| `-CoreinfoPath C:\Tools\Coreinfo64.exe` | Vérification SSE4.2/POPCNT par Coreinfo |
| `-SetupMediaPath D:\` | Lance aussi le **scan de compatibilité officiel Microsoft** (`setup.exe /auto upgrade /compat scanonly`) avec l'ISO WS2025 montée. Crée `C:\$WINDOWS.~BT` mais n'installe rien. 10 à 40 min. |
| `-SetupImageIndex 2` | Index d'image du média (1 Std Core, 2 Std Bureau, 3 DC Core, 4 DC Bureau) — déduit sinon |
| `-NoZip` | Pas d'archive |

### Exécution à distance (optionnelle)

```powershell
.\Invoke-RemoteAudit.ps1 -ComputerName SRV-HV01,SRV-AD01,SRV-RDS01 -Credential (Get-Credential) `
    -AuditParameters @{ EventDays = 30 }
```
⚠️ Problème de **double saut Kerberos** : depuis une session WinRM, les commandes qui interrogent
*d'autres* machines (`repadmin /showrepl *`, partage UPD sur un NAS, autres DC…) peuvent échouer.
Pour un DC ou un déploiement RDS, l'exécution locale donne le résultat le plus complet.
Un hôte Hyper-V en groupe de travail nécessite `TrustedHosts` côté poste d'administration.

## Ce que l'audit collecte

**Sur tous les serveurs**
- Système : édition, build/UBR, langue de base (doit correspondre au média), type d'installation,
  licence et canal (OEM/Volume/Retail), uptime, .NET, rôles détectés.
- **Prérequis WS2025** : SSE4.2 + POPCNT (nouveau prérequis), CPU/RAM, taille et espace libre du
  volume système, UEFI/Secure Boot, TPM, VBS ; calcul des cœurs à licencier (hôte physique).
- Stockage : disques, volumes, BitLocker, VSS, pagefile, Storage Spaces, déduplication.
- Réseau : cartes/pilotes, IP (DHCP sur un serveur d'infra), DNS client, IPv6, **teaming LBFO**,
  profils réseau, pare-feu et règles personnalisées, ports en écoute, **flux établis** (cartographie
  des dépendances), SMB1 / signature SMB / invités, partages et permissions, proxy, hosts.
- Rôles/fonctionnalités et **fonctionnalités supprimées/dépréciées dans WS2025**
  (SMTP Server, console IIS 6, PowerShell 2.0, WINS, WSUS, SMB1…).
- Mises à jour : correctifs, redémarrage en attente, source WSUS, historique WU, santé DISM.
- Logiciels (avec repérage des **logiciels sensibles** : AV/EDR, sauvegarde, RMM, SQL, Exchange,
  ERP français, Office, Entra Connect…), services tiers et comptes de service, tâches planifiées
  (WMIC/VBScript), pilotes tiers anciens, filtres minifilter.
- Sécurité : administrateurs, Defender et exclusions, NTLM/LmCompatibilityLevel (**NTLMv1 supprimé**),
  WDigest, TLS/Schannel (**TLS 1.0/1.1 désactivés par défaut**), RDP/NLA, LAPS, certificats.
- Stratégies appliquées (gpresult HTML), auditpol, secedit.
- Journaux : erreurs groupées, arrêts brutaux, erreurs disque/NTFS/WHEA, temps, GPO, KDC,
  **échecs d'ouverture de session 4625 par IP** (force brute RDP).
- Sauvegarde (WSB, writers VSS), impression (pilotes, ports), IIS / AD CS / WSUS / DFS / SQL.

**Contrôleur de domaine** : forêt/domaine, **niveaux fonctionnels (≥ 2016 requis pour un DC 2025)**,
version de schéma, FSMO, DC, **SYSVOL FRS/DFSR**, scripts NETLOGON (VBS), NTDS, signature LDAP,
réplication (repadmin), dernière sauvegarde AD, dcdiag, temps du PDC, sites/sous-réseaux, trusts,
corbeille AD, tombstone, Exchange/AD CS dans la forêt, politiques de mot de passe, groupes à
privilèges, comptes à risque (pré-auth, DES, SPN…), comptes inactifs, krbtgt, OS du parc,
gMSA/KDS, LAPS, OU, Entra Connect, **GPO** (liens, filtres WMI, magasin central), **DNS**
(zones, mises à jour non sécurisées, zones non intégrées AD, redirecteurs, scavenging,
enregistrements statiques), **DHCP** (étendues, options, réservations, basculement + **export
complet réimportable**).

**RDS** : mode et serveur de licences, période de grâce, **packs de CAL (présence de CAL 2025)**,
activation, déploiement (serveurs, collections, UPD, RemoteApp, certificats, passerelle, HA),
stratégies RDS, profils (taille, obsolescence), FSLogix, Office (activation partagée).

**Hyper-V** : hôte, versions de configuration, **vSwitch lié à LBFO** (bloquant), SET, VM
(génération, version, mémoire, actions auto), **compatibilité processeur** (masque SSE4.2),
disques (pass-through, différenciation, fragmentation, **surallocation**), cartes réseau/VLAN/MAC,
ISO montées, services d'intégration, **OS invités via KVP**, checkpoints, Réplica, **vTPM**
(certificats à exporter), capacité mémoire, cluster.

## Sorties

```
C:\AuditPreUpgrade\Audit_<HOTE>_<yyyyMMdd_HHmm>\
├── Rapport_<HOTE>.html   ← à ouvrir en premier
├── findings.csv          ← points d'attention (séparateur ;)
├── audit.json            ← données structurées (consolidation)
├── audit.log             ← journal d'exécution
├── csv\                  ← un CSV par tableau du rapport
└── raw\                  ← dcdiag, repadmin, gpresult.html, GPO_AllReport.html, dhcp_export.xml…
```

Sévérités : **CRITIQUE** (bloque l'upgrade ou risque majeur) · **ÉLEVÉ** (à traiter avant) ·
**MOYEN** (à planifier/tester) · **FAIBLE** (hygiène) · **INFO** (contexte, rappels).

## Sécurité et confidentialité

- Aucune modification du système (seule exception : `-SetupMediaPath`, opt-in, qui lance le scan
  de compatibilité Microsoft sans installation).
- Le rapport contient des informations sensibles (comptes, groupes à privilèges, IP, partages,
  configuration de sécurité) : **ne pas committer les résultats** dans le dépôt (voir `.gitignore`),
  les transmettre de façon chiffrée et les supprimer des serveurs après récupération.
- Aucun mot de passe ni secret n'est collecté (les exports DHCP et secedit ne contiennent pas de secrets).

## Compatibilité

Windows PowerShell 5.1, Windows Server 2016 / 2019 / 2022 / 2025 (conçu pour 2019).
Modules utilisés s'ils sont présents : ActiveDirectory, GroupPolicy, DnsServer, DhcpServer,
RemoteDesktop, Hyper-V, FailoverClusters, WindowsServerBackup, WebAdministration.
Chaque collecteur est isolé : une erreur est consignée dans la section concernée sans arrêter l'audit.

## Références Microsoft

- [Fonctionnalités supprimées / dépréciées dans Windows Server 2025](https://learn.microsoft.com/windows-server/get-started/removed-deprecated-features-windows-server-2025)
- [Niveaux fonctionnels AD DS](https://learn.microsoft.com/windows-server/identity/ad-ds/active-directory-functional-levels)
- [Mise à niveau sur place de Windows Server](https://learn.microsoft.com/windows-server/get-started/perform-in-place-upgrade)
- [Prérequis matériels Windows Server 2025](https://learn.microsoft.com/windows-server/get-started/hardware-requirements)

## Licence

MIT — voir `LICENSE`.
