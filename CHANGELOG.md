# Changelog

## 1.1.0 — 2026-10-28

### Ajouté
- **Téléchargement automatique de Coreinfo** (Sysinternals) pour vérifier SSE4.2/POPCNT, avec
  vérification de la signature Authenticode Microsoft avant exécution ; repli sur live.sysinternals.com ;
  support du proxy système ; `-NoDownload` pour les serveurs isolés.
- **Console détaillée** : progression `[n/22]`, sous-étapes, commandes externes (durée, code retour,
  délai dépassé), constats affichés au fil de l'eau en couleur, récapitulatif final des erreurs de
  collecte, des commandes en échec et des points CRITIQUE/ÉLEVÉ ; numéros de ligne dans les erreurs.
- **Section « Usage réel des protocoles hérités »** : NTLMv1 / NTLM (4624), binds LDAP non signés
  (2887 / 2889), tickets Kerberos RC4/DES (4769), avec top des clients/services concernés.
- `Compare-AuditReports.ps1` : comparaison avant/après (résolus, nouveaux, persistants).
- `tests/Invoke-SmokeTest.ps1` + modules Windows simulés ; workflow GitHub Actions (test de fumée,
  PSScriptAnalyzer, exécution réelle sur runner Windows Server).

### Corrigé
- Faux positif DISM : « No component store corruption detected » / « Aucun endommagement » était
  interprété comme une corruption.
- L'échec de l'API `IsProcessorFeaturePresent` n'empêche plus l'exécution de Coreinfo.
- Disposition du dépôt : `.gitattributes` / `.gitignore` restaurés, checklist dans `docs/`.

## 1.0.0 — 2026-10-28
- Version initiale.
