function O([hashtable]$h){[pscustomobject]$h}
function Get-DhcpServerv4Scope { param() O @{ScopeId=[ipaddress]'192.168.1.0';Name='LAN';SubnetMask='255.255.255.0';StartRange='192.168.1.100';EndRange='192.168.1.200';State='Active';LeaseDuration=[timespan]::FromDays(8)} }
function Get-DhcpServerv4ScopeStatistics { O @{ScopeId=[ipaddress]'192.168.1.0';PercentageInUse=90.5;Free=10} }
function Get-DhcpServerv4OptionValue { param([switch]$All,$ScopeId) O @{OptionId=6;Name='DNS Servers';Value=@('192.168.1.10')} }
function Get-DhcpServerv4Reservation { }
function Get-DhcpServerv4Failover { }
function Get-DhcpServerInDC { O @{DnsName='srv-hv01.contoso.local';IPAddress='192.168.1.10'} }
function Get-DhcpServerv4DnsSetting { O @{DynamicUpdates='OnClientRequest';DeleteDnsRROnLeaseExpiry=$true;UpdateDnsRRForOlderClients=$false} }
function Get-DhcpServerDnsCredential { throw 'none' }
function Export-DhcpServer { param($File,[switch]$Leases,[switch]$Force) 'x' | Set-Content $File }
Export-ModuleMember -Function *
