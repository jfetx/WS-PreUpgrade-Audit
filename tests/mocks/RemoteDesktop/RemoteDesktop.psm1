function O([hashtable]$h){[pscustomobject]$h}
function Get-RDServer { param($ConnectionBroker) O @{Server='SRV-HV01.contoso.local';Roles=@('RDS-RD-SERVER','RDS-CONNECTION-BROKER','RDS-LICENSING')} }
function Get-RDSessionCollection { param($ConnectionBroker) O @{CollectionName='Bureau';CollectionDescription='';ResourceType='Remote Desktop';Size=1;AutoAssignPersonalDesktop=$false} }
function Get-RDSessionCollectionConfiguration { param($CollectionName,$ConnectionBroker,[switch]$UserProfileDisk,[switch]$Security,[switch]$Client) if($UserProfileDisk){O @{EnableUserProfileDisk=$true;DiskPath='\\nas\upd';MaxUserProfileDiskSizeGB=20}}elseif($Security){O @{SecurityLayer='Negotiate';EncryptionLevel='ClientCompatible';AuthenticateUsingNLA=$true}}elseif($Client){O @{ClientDeviceRedirectionOptions='Clipboard';ClientPrinterRedirected=$true}}else{O @{UserGroup=@('CONTOSO\Domain Users');IdleSessionLimitMin=0;DisconnectedSessionLimitMin=0;ActiveSessionLimitMin=0;BrokenConnectionAction='None';AutomaticReconnectionEnabled=$true}} }
function Get-RDRemoteApp { }
function Get-RDCertificate { param($ConnectionBroker) O @{Role='RDGateway';Level='NotConfigured';Subject='';IssuedBy='';ExpiresOn=$null;Thumbprint='';SubjectAlternateName=''} }
function Get-RDLicenseConfiguration { param($ConnectionBroker) O @{Mode='PerUser';LicenseServer=@('SRV-HV01.contoso.local')} }
function Get-RDDeploymentGatewayConfiguration { }
function Get-RDConnectionBrokerHighAvailability { }
Export-ModuleMember -Function *
