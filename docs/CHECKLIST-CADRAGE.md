# Journée de cadrage — migration Windows Server 2019/2022 → 2025

Le script collecte l'état technique. Cette checklist couvre ce qu'**aucun script ne peut deviner** :
contexte métier, contraintes, licences, interlocuteurs. À dérouler avec le client pendant la journée.

## 1. Déroulé proposé de la journée

| Créneau | Activité | Livrable |
|---|---|---|
| 09:00 – 09:45 | Kick-off : objectifs, périmètre, contraintes, interlocuteurs | Section 2 remplie |
| 09:45 – 11:30 | Exécution de `Invoke-PreUpgradeAudit.ps1` sur hyperviseur, DC, RDS (en parallèle de l'entretien) | ZIP par serveur |
| 11:30 – 12:30 | Entretien applications métier / utilisateurs RDS / impression | Section 4 remplie |
| 13:30 – 14:30 | `Merge-AuditReports.ps1`, lecture des points CRITIQUE / ÉLEVÉ | Rapport consolidé |
| 14:30 – 16:00 | Vérifications ciblées (console iDRAC/iLO, sauvegardes, licences, accès éditeurs) | Sections 3 et 5 |
| 16:00 – 17:00 | Restitution : verdict, stratégie (sur place vs side-by-side), planning, devis licences | Plan d'action CSV + Go/No-Go |

## 2. Contexte et contraintes

- [ ] Objectif du client : fin de support, sécurité, nouveau matériel, conformité (NIS2, cyber-assurance) ?
- [ ] Fenêtres de maintenance possibles (soir, week-end) et durée d'interruption acceptable par service
- [ ] RTO / RPO attendus ; interlocuteur décisionnaire pour le Go/No-Go
- [ ] Périodes à éviter (clôture comptable, paie, saison, inventaire)
- [ ] Sites distants / VPN / télétravailleurs dépendants du RDS
- [ ] Prestataires tiers (infogérance, éditeurs, opérateur, constructeur) et leurs contacts / délais

## 3. Infrastructure

- [ ] Modèle exact du serveur physique + **support WS2025 chez le constructeur** (HPE / Dell / Lenovo…), garantie / contrat de support
- [ ] Accès console hors bande (iDRAC/iLO/IPMI) testé, identifiants disponibles
- [ ] Firmware/BIOS/contrôleur RAID : versions actuelles vs recommandées WS2025
- [ ] Capacité disque disponible pour une VM supplémentaire (nouveau DC) et pour les exports
- [ ] Onduleur et arrêt automatique (agent sur l'hôte ?)
- [ ] Switchs : configuration des ports de l'hôte (LACP/LBFO vs SET : SET n'utilise PAS LACP → mode « switch independent »)
- [ ] Plan d'adressage, VLAN, DHCP, DNS publics, enregistrements externes (RD Gateway, webmail…)

## 4. Applications et utilisateurs

- [ ] Liste des applications métier (RDS et serveurs) + **attestation éditeur de compatibilité WS2025**
- [ ] Bases de données (SQL Server version/édition, autres SGBD) et procédure de réinstallation / licence
- [ ] Nombre d'utilisateurs RDS simultanés / nommés, horaires, utilisateurs externes
- [ ] Profils : local / UPD / FSLogix ; données dans les profils (PST, signatures, favoris)
- [ ] Imprimantes / copieurs / scanners (scan vers dossier SMB, carnet LDAP, SMTP relais)
- [ ] Équipements anciens : NAS, onduleurs, badgeuses, automates, téléphonie (SMB1, NTLMv1, TLS 1.0, LDAP non signé)
- [ ] Antivirus / EDR : console, désactivation possible pendant l'upgrade, version compatible
- [ ] Sauvegarde : solution, rétention, externalisation, **dernier test de restauration**, compatibilité WS2025

## 5. Licences et comptes

- [ ] Preuves de licences actuelles (OEM / OLP / CSP), Software Assurance ?
- [ ] Devis : licences cœurs WS2025 (Standard ×2 VM / Datacenter), **CAL WS2025**, **CAL RDS 2025** (utilisateur ou périphérique), Office (LTSC 2024 / M365 Apps en activation partagée)
- [ ] Mots de passe disponibles : admin local de chaque serveur, **DSRM** des DC, comptes de service, compte de sauvegarde, comptes éditeurs
- [ ] Clés de récupération BitLocker
- [ ] Certificats publics (RD Gateway / RD Web) : fournisseur, date d'expiration, PFX disponible

## 6. Critères Go / No-Go (avant chaque phase)

- [ ] Aucun constat CRITIQUE ouvert ; ÉLEVÉ traités ou acceptés par écrit
- [ ] Sauvegarde complète < 24 h **et** restauration testée (état système pour les DC)
- [ ] Réplication AD saine (`repadmin /replsummary` sans erreur, `dcdiag` propre)
- [ ] Redémarrage de contrôle effectué et serveur revenu à l'état nominal
- [ ] Licences et médias WS2025 (même langue, même édition) disponibles
- [ ] Plan de retour arrière écrit (checkpoint de production / export VM / restauration) et durée estimée
- [ ] Utilisateurs et éditeurs prévenus ; interlocuteur client joignable pendant l'intervention

## 7. Plan de migration type (petite structure : 1 hôte, 1 DC, 1 RDS)

1. **Remédiation** : CU à jour, nettoyage disque, SMB1/NTLMv1/TLS, FRS→DFSR et niveaux fonctionnels 2016 si besoin, LBFO→SET, compatibilité CPU des VM désactivée, exports (DHCP, GPO, certificats, vTPM).
2. **Hyperviseur** : sauvegarde des VM, arrêt propre, upgrade sur place (ou réinstallation + réimport), contrôle vSwitch/VM, mise à jour.
3. **AD (side-by-side)** : nouvelle VM WS2025 → DC/DNS/GC → contrôle réplication → transfert FSMO → bascule DNS (DHCP option 6, IP statiques) → DHCP migré → rétrogradation de l'ancien DC → nettoyage métadonnées/DNS.
4. **RDS** : serveur de licences 2025 + CAL 2025 → (nouvel) hôte de session 2025 pilote → applications, imprimantes, profils → bascule des utilisateurs → décommissionnement.
5. **Post-migration** : relancer l'audit sur tous les serveurs, comparer, ADMX, sauvegardes/supervision, documentation, réinitialisation krbtgt (×2), retrait des droits Schema Admins.
