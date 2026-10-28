function O([hashtable]$h){[pscustomobject]$h}
function Get-ADForest { param($Server) O @{Name='contoso.local';ForestMode='Windows2012R2Forest';SchemaMaster='SRV-AD01.contoso.local';DomainNamingMaster='SRV-AD01.contoso.local';Domains=@('contoso.local');Sites=@('Default-First-Site-Name');GlobalCatalogs=@('SRV-AD01.contoso.local');UPNSuffixes=@()} }
function Get-ADDomain { param($Server) O @{DNSRoot='contoso.local';NetBIOSName='CONTOSO';DomainMode='Windows2012R2Domain';PDCEmulator='SRV-HV01.contoso.local';RIDMaster='x';InfrastructureMaster='x';DomainSID='S-1-5-21-1-2-3';DistinguishedName='DC=contoso,DC=local';ComputersContainer='CN=Computers';UsersContainer='CN=Users'} }
function Get-ADRootDSE { param($Server) O @{schemaNamingContext='CN=Schema,CN=Configuration,DC=contoso,DC=local';configurationNamingContext='CN=Configuration,DC=contoso,DC=local'} }
function Get-ADObject { param([Parameter(Position=0)]$Identity,$Properties,$Server,$SearchBase,$LDAPFilter,$Filter,$SearchScope)
  if("$Identity" -like 'CN=Schema*'){ return O @{objectVersion=88} }
  if("$Identity" -like 'CN=DFSR-GlobalSettings*'){ return O @{'msDFSR-Flags'=48} }
  if("$Identity" -like 'CN=Domain System Volume*'){ return O @{Name='Domain System Volume'} }
  if("$Identity" -like 'CN=Directory Service*'){ return O @{tombstoneLifetime=180} }
  if($LDAPFilter -like '*ms-Mcs*'){ return O @{Name='ms-Mcs-AdmPwd'} }
  return $null }
function Get-ADDomainController { param($Filter,$Server) O @{Name='SRV-HV01';HostName='SRV-HV01.contoso.local';IPv4Address='192.168.1.10';OperatingSystem='Windows Server 2019 Standard';OperatingSystemVersion='10.0 (17763)';Site='Default';IsGlobalCatalog=$true;IsReadOnly=$false;OperationMasterRoles=@('PDCEmulator','RIDMaster')} }
function Get-ADReplicationAttributeMetadata { param($Object,$Server,$Properties) O @{LastOriginatingChangeTime=(Get-Date).AddDays(-30)} }
function Get-ADReplicationSite { O @{Name='Default';Description=''} }
function Get-ADReplicationSubnet { }
function Get-ADReplicationSiteLink { O @{Name='DEFAULTIPSITELINK';Cost=100;ReplicationFrequencyInMinutes=180;SitesIncluded=@('Default')} }
function Get-ADTrust { }
function Get-ADOptionalFeature { param($Filter,$Server) O @{Name='Recycle Bin Feature';EnabledScopes=@()} }
function Get-ADDefaultDomainPasswordPolicy { param($Server) O @{ComplexityEnabled=$true;MinPasswordLength=7;PasswordHistoryCount=24;MaxPasswordAge=[timespan]::FromDays(42);MinPasswordAge=[timespan]::FromDays(1);LockoutThreshold=0;LockoutDuration=[timespan]::FromMinutes(30);LockoutObservationWindow=[timespan]::FromMinutes(30);ReversibleEncryptionEnabled=$false} }
function Get-ADFineGrainedPasswordPolicy { }
function Get-ADGroup { param([Parameter(Position=0)]$Identity,$Server) O @{Name=$(if("$Identity" -like '*-512'){'Domain Admins'}elseif("$Identity" -like '*-518'){'Schema Admins'}else{"G $Identity"})} }
function Get-ADGroupMember { param($Identity,[switch]$Recursive,$Server) O @{SamAccountName='administrator';Name='Administrator';objectClass='user'} }
function Get-ADUser { param([Parameter(Position=0)]$Identity,$Filter,$LDAPFilter,$Server,$Properties)
  if($Identity -eq 'krbtgt'){ return O @{PasswordLastSet=(Get-Date).AddYears(-5)} }
  if($LDAPFilter){ return O @{SamAccountName='MSOL_abc';Description='Azure AD Connect'} }
  1..3 | % { O @{SamAccountName="user$_";Name="User $_";Enabled=$true;LastLogonTimestamp=(Get-Date).AddDays(-200).ToFileTime();PasswordLastSet=(Get-Date).AddDays(-400);PasswordNeverExpires=$true;PasswordNotRequired=$false;DoesNotRequirePreAuth=($_ -eq 2);AllowReversiblePasswordEncryption=$false;UseDESKeyOnly=$false;ServicePrincipalName=$(if($_ -eq 3){@('MSSQLSvc/x')}else{$null});adminCount=1;WhenCreated=(Get-Date);Description=''} } }
function Get-ADComputer { param($Filter,$Server,$Properties) O @{Name='PC-OLD';OperatingSystem='Windows 7 Professional';OperatingSystemVersion='6.1';LastLogonTimestamp=(Get-Date).ToFileTime();Enabled=$true;IPv4Address='1.1.1.1';PasswordLastSet=(Get-Date)} }
function Get-ADServiceAccount { }
function Get-ADOrganizationalUnit { param($Filter,$Server,$Properties) O @{Name='Servers';DistinguishedName='OU=Servers,DC=contoso,DC=local';ProtectedFromAccidentalDeletion=$true;gPLink='[LDAP://cn={A},cn=policies][LDAP://cn={B}]'} }
Export-ModuleMember -Function *
