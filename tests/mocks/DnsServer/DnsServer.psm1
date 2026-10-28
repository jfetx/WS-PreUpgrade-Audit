function O([hashtable]$h){[pscustomobject]$h}
function Get-DnsServerZone { param() @( (O @{ZoneName='contoso.local';ZoneType='Primary';IsDsIntegrated=$true;ReplicationScope='Domain';DynamicUpdate='Secure';IsReverseLookupZone=$false;IsAutoCreated=$false;IsPaused=$false;IsSigned=$false;MasterServers=@()}), (O @{ZoneName='old.lan';ZoneType='Primary';IsDsIntegrated=$false;ReplicationScope='None';DynamicUpdate='NonsecureAndSecure';IsReverseLookupZone=$false;IsAutoCreated=$false;IsPaused=$false;IsSigned=$false;MasterServers=@()}) ) }
function Get-DnsServerZoneAging { param($Name) O @{ZoneName=$Name;AgingEnabled=$false;NoRefreshInterval=[timespan]::FromDays(7);RefreshInterval=[timespan]::FromDays(7)} }
function Get-DnsServerForwarder { param() O @{IPAddress=@('1.1.1.1');UseRootHint=$true;Timeout=3} }
function Get-DnsServerScavenging { param() O @{ScavengingState=$false;ScavengingInterval=[timespan]::Zero;LastScavengeTime=$null} }
function Get-DnsServerRecursion { param() O @{Enable=$true;Timeout=8} }
function Get-DnsServerSetting { param([switch]$All) O @{ListeningIPAddress=@('192.168.1.10');RoundRobin=$true;MajorVersion=10;MinorVersion=0;BuildNumber=17763} }
function Get-DnsServerResourceRecord { param($ZoneName,$RRType) O @{HostName='nas';Timestamp=$null;RecordData=(O @{IPv4Address=[ipaddress]'192.168.1.20'})} }
Export-ModuleMember -Function *
