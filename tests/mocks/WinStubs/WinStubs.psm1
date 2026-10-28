function New-O { param([hashtable]$h) [pscustomobject]$h }
function Get-CimInstance { param([Parameter(Position=0)]$ClassName,$Namespace,$Filter)
  switch ($ClassName) {
    'Win32_ComputerSystem' { New-O @{Domain='contoso.local';DomainRole=5;PartOfDomain=$true;Manufacturer='HPE';Model='ProLiant DL380 Gen10';TotalPhysicalMemory=128GB;Workgroup=$null} }
    'Win32_OperatingSystem' { New-O @{Caption='Microsoft Windows Server 2019 Standard';Version='10.0.17763';OSArchitecture='64-bit';InstallDate=(Get-Date).AddYears(-4);LastBootUpTime=(Get-Date).AddDays(-80);OSLanguage=1036;MUILanguages=@('fr-FR')} }
    'Win32_BIOS' { New-O @{SerialNumber='CZ123';Manufacturer='HPE';SMBIOSBIOSVersion='U30'} }
    'SoftwareLicensingProduct' { New-O @{Name='Windows(R), ServerStandard edition';Description='OEM_DM';ProductKeyChannel='OEM:DM';PartialProductKey='ABCDE';LicenseStatus=1;KeyManagementServiceMachine=$null;GracePeriodRemaining=0} }
    'Win32_Processor' { 1..2 | % { New-O @{Name='Intel Xeon Silver 4110';Manufacturer='GenuineIntel';NumberOfCores=8;NumberOfLogicalProcessors=16;MaxClockSpeed=2100;SocketDesignation="CPU $_";AddressWidth=64;VirtualizationFirmwareEnabled=$false;SecondLevelAddressTranslationExtensions=$false;VMMonitorModeExtensions=$false} } }
    'Win32_PhysicalMemory' { New-O @{BankLabel='A1';DeviceLocator='PROC 1 DIMM 1';Capacity=32GB;Speed=2666;Manufacturer='HPE';PartNumber='x'} }
    'Win32_Tpm' { New-O @{IsEnabled_InitialValue=$true;IsActivated_InitialValue=$true;IsOwned_InitialValue=$true;SpecVersion='2.0, 0, 1.16';ManufacturerIdTxt='NTC';ManufacturerVersion='7.2'} }
    'Win32_DeviceGuard' { New-O @{VirtualizationBasedSecurityStatus=0;SecurityServicesConfigured=@(0);SecurityServicesRunning=@(0);AvailableSecurityProperties=@(1,2)} }
    'Win32_LogicalDisk' { New-O @{Size=120GB;FreeSpace=18GB} }
    'Win32_PageFileUsage' { New-O @{Name='C:\pagefile.sys';AllocatedBaseSize=8192;CurrentUsage=100;PeakUsage=200} }
    'Win32_Service' { @( (New-O @{Name='VeeamAgent';DisplayName='Veeam Agent';State='Running';StartMode='Auto';StartName='CONTOSO\svc_veeam';PathName='"C:\Program Files\Veeam\agent.exe"';ExitCode=0}), (New-O @{Name='Dnscache';DisplayName='DNS';State='Running';StartMode='Auto';StartName='NT AUTHORITY\NetworkService';PathName='C:\Windows\system32\svchost.exe -k';ExitCode=0}), (New-O @{Name='Foo';DisplayName='Foo';State='Stopped';StartMode='Auto';StartName='LocalSystem';PathName='C:\foo.exe';ExitCode=1}) ) }
    'Win32_PnPSignedDriver' { New-O @{DeviceName='HPE Ethernet 1Gb 4-port 331i';DeviceClass='NET';DriverProviderName='Broadcom';DriverVersion='214.0.0.0';DriverDate=(Get-Date).AddYears(-8);InfName='oem3.inf';IsSigned=$true} }
    'Win32_StartupCommand' { $null }
    'Win32_TerminalServiceSetting' { New-O @{TerminalServerMode=1;LicensingType=4;LicensingDescription='Per User'} }
    'Win32_TSGeneralSetting' { New-O @{SSLCertificateSHA1Hash='AB12';SSLCertificateSHA1HashType=2;UserAuthenticationRequired=1;SecurityLayer=2;MinEncryptionLevel=2} }
    'Win32_TSLicenseKeyPack' { @( (New-O @{KeyPackId=2;KeyPackType=2;ProductVersion='Windows Server 2019';ProductType='Per User';TypeAndModel='RDS Per User CAL';TotalLicenses=25;AvailableLicenses=25;IssuedLicenses=0;ExpirationDate=$null}), (New-O @{KeyPackId=3;KeyPackType=6;ProductVersion='Windows Server 2012';ProductType='Per Device';TypeAndModel='Built-in';TotalLicenses=0;AvailableLicenses=0;IssuedLicenses=3;ExpirationDate=$null}) ) }
    'Win32_TSLicenseServer' { New-O @{Name='x'} }
    'Win32_TSIssuedLicense' { $null }
    'Win32_UserProfile' { @( (New-O @{SID='S-1-5-21-1-2-3-1001';LocalPath='/tmp';LastUseTime=(Get-Date).AddDays(-200);Special=$false;Loaded=$false;RoamingConfigured=$false;Status=0}) ) }
    'Msvm_ComputerSystem' { New-O @{ElementName='SRV-AD01'} }
    default { $null }
  }
}
function Invoke-CimMethod { param($InputObject,$MethodName) switch($MethodName){ 'GetGracePeriodDays'{New-O @{DaysLeft=0}} 'GetSpecifiedLicenseServerList'{New-O @{SpecifiedLSList=@('SRV-HV01.contoso.local')}} 'GetActivationStatus'{New-O @{ActivationStatus=0}} } }
function Get-CimAssociatedInstance { param($InputObject,$ResultClassName)
  $mk = { param($n,$d) "<INSTANCE CLASSNAME=`"Msvm_KvpExchangeDataItem`"><PROPERTY NAME=`"Data`" TYPE=`"string`"><VALUE>$d</VALUE></PROPERTY><PROPERTY NAME=`"Name`" TYPE=`"string`"><VALUE>$n</VALUE></PROPERTY></INSTANCE>" }
  New-O @{GuestIntrinsicExchangeItems=@((& $mk 'FullyQualifiedDomainName' 'SRV-AD01.contoso.local'),(& $mk 'OSName' 'Windows Server 2019 Standard'),(& $mk 'OSVersion' '10.0.17763'))} }
function Get-WindowsFeature { param() 'Hyper-V','RDS-RD-Server','RDS-Licensing','RDS-Connection-Broker','AD-Domain-Services','DNS','DHCP','FS-FileServer','FS-SMB1','SMTP-Server','Web-Server' | % { New-O @{Name=$_;DisplayName="DN $_";Installed=$true;FeatureType=$(if($_ -match 'Hyper|AD-|DNS|DHCP'){'Role'}else{'Feature'});Path=$_;Depth=1} } }
function Get-HotFix { param() New-O @{HotFixID='KB5034127';Description='Security Update';InstalledOn=(Get-Date).AddDays(-90);InstalledBy='NT AUTHORITY\SYSTEM'} }
function Get-Service { param([Parameter(Position=0)]$Name) if($Name){ New-O @{Name=$Name;Status='Running';DisplayName=$Name;StartType='Automatic'} } else { New-O @{Name='vmicheartbeat';DisplayName='HB';Status='Running';StartType='Manual'} } }
function Get-WinEvent { param($FilterHashtable,$MaxEvents,$ListLog,$LogName,$FilterXPath)
  if($FilterXPath -like '*NTLM V1*'){ return 1..4 | % { $e = New-O @{Id=4624;TimeCreated=(Get-Date)}; $e | Add-Member ScriptMethod ToXml { '<Event><EventData><Data Name="WorkstationName">COPIEUR01</Data><Data Name="IpAddress">10.0.0.50</Data><Data Name="TargetUserName">scan</Data><Data Name="TargetDomainName">CONTOSO</Data><Data Name="LmPackageName">NTLM V1</Data></EventData></Event>' }; $e } }
  if($FilterXPath -like '*4769*'){ return 1..2 | % { $e = New-O @{Id=4769;TimeCreated=(Get-Date)}; $e | Add-Member ScriptMethod ToXml { '<Event><EventData><Data Name="ServiceName">svc_sql</Data><Data Name="IpAddress">::ffff:10.0.0.9</Data><Data Name="TargetUserName">user1@CONTOSO</Data><Data Name="TicketEncryptionType">0x17</Data></EventData></Event>' }; $e } }
  if($FilterXPath){ return $null }
  if($FilterHashtable.Id -eq 2887){ return New-O @{TimeCreated=(Get-Date);Properties=@((New-O @{Value=12}),(New-O @{Value=3}))} }
  if($FilterHashtable.Id -eq 2889){ return $null }
  if($ListLog){ return New-O @{LogName='System';MaximumSizeInBytes=20MB;RecordCount=1000;LogMode='Circular';IsEnabled=$true} }
  if($FilterHashtable.LogName -eq 'Security'){ return 1..600 | % { $e = New-O @{Id=4625}; $e | Add-Member ScriptMethod ToXml { '<Event><EventData><Data Name="IpAddress">45.1.2.3</Data><Data Name="TargetUserName">administrator</Data><Data Name="LogonType">10</Data></EventData></Event>' }; $e } }
  if($FilterHashtable.Id -contains 41){ return New-O @{TimeCreated=(Get-Date).AddDays(-1);ProviderName='Microsoft-Windows-Kernel-Power';Id=41} }
  if($FilterHashtable.Level){ return 1..3 | % { New-O @{LogName=$FilterHashtable.LogName;ProviderName='Srv';Id=2019;LevelDisplayName='Error';TimeCreated=(Get-Date);Message='Une erreur est survenue'} } }
}
function Get-Disk { New-O @{Number=0;FriendlyName='HPE LOGICAL VOLUME';SerialNumber='x';BusType='RAID';PartitionStyle='GPT';Size=1TB;HealthStatus='Healthy';OperationalStatus='Online';IsBoot=$true;IsSystem=$true;IsOffline=$false;IsReadOnly=$false} }
function Get-PhysicalDisk { New-O @{DeviceId=0;FriendlyName='SSD';MediaType='SSD';BusType='SAS';Size=1TB;HealthStatus='Healthy';OperationalStatus='OK';FirmwareVersion='1';SerialNumber='x'} }
function Get-StoragePool { }
function Get-Volume { param($FilePath) if($FilePath){ return New-O @{SizeRemaining=100GB} }; @( (New-O @{DriveLetter='C';FileSystemLabel='';FileSystem='NTFS';Size=120GB;SizeRemaining=18GB;HealthStatus='Healthy';DriveType='Fixed';DedupMode=$null}), (New-O @{DriveLetter='D';FileSystemLabel='VMs';FileSystem='NTFS';Size=900GB;SizeRemaining=150GB;HealthStatus='Healthy';DriveType='Fixed';DedupMode=$null}) ) }
function Get-Partition { New-O @{DiskNumber=0;PartitionNumber=1;DriveLetter='C';Type='Basic';Size=120GB;IsBoot=$true;IsSystem=$false;IsActive=$false;GptType='{}'} }
function Get-BitLockerVolume { New-O @{MountPoint='C:';VolumeStatus='FullyEncrypted';ProtectionStatus='On';EncryptionMethod='XtsAes128';EncryptionPercentage=100;LockStatus='Unlocked';KeyProtector=@((New-O @{KeyProtectorType='Tpm'}))} }
function Get-NetAdapter { param([switch]$IncludeHidden) New-O @{Name='NIC1';InterfaceDescription='Microsoft Network Adapter Multiplexor Driver';Status='Up';LinkSpeed='2 Gbps';MacAddress='00-11';VlanID=0;DriverProvider='Microsoft';DriverVersion='10';DriverDate='2006';ifIndex=5;HardwareInterface=$false;Virtual=$true} }
function Get-NetIPAddress { param($AddressFamily) New-O @{InterfaceAlias='vEthernet (LAN)';AddressFamily='IPv4';IPAddress='192.168.1.10';PrefixLength=24;PrefixOrigin='Manual';SuffixOrigin='Manual';AddressState='Preferred'} }
function Get-NetRoute { New-O @{InterfaceAlias='vEthernet (LAN)';DestinationPrefix='0.0.0.0/0';NextHop='192.168.1.1';RouteMetric=0;Protocol='NetMgmt'} }
function Get-DnsClientServerAddress { param() New-O @{InterfaceAlias='vEthernet (LAN)';AddressFamily=2;ServerAddresses=@('127.0.0.1','8.8.8.8')} }
function Get-DnsClient { }
function Get-NetAdapterBinding { param($ComponentID) New-O @{Name='NIC1';Enabled=$false} }
function Get-NetLbfoTeam { New-O @{Name='Team1';TeamingMode='SwitchIndependent';LoadBalancingAlgorithm='Dynamic';Status='Up';Members=@('NIC1','NIC2')} }
function Get-NetConnectionProfile { New-O @{InterfaceAlias='vEthernet (LAN)';Name='contoso.local';NetworkCategory='DomainAuthenticated';IPv4Connectivity='Internet'} }
function Get-NetFirewallProfile { 'Domain','Private','Public' | % { New-O @{Name=$_;Enabled=$($_ -ne 'Domain');DefaultInboundAction='Block';DefaultOutboundAction='Allow';LogAllowed=$false;LogBlocked=$false;LogFileName='x'} } }
function Get-NetFirewallRule { New-O @{DisplayName='RDP custom';Profile='Any';Action='Allow';Direction='Inbound';Group=$null} }
function Get-NetFirewallPortFilter { New-O @{LocalPort='3389';Protocol='TCP'} }
function Get-NetFirewallAddressFilter { New-O @{RemoteAddress='Any'} }
function Get-NetTCPConnection { param($State) New-O @{LocalAddress='0.0.0.0';LocalPort=3389;OwningProcess=$PID;RemoteAddress='10.0.0.5';RemotePort=50000} }
function Get-NetUDPEndpoint { New-O @{LocalAddress='0.0.0.0';LocalPort=53;OwningProcess=$PID} }
function Get-SmbServerConfiguration { New-O @{EnableSMB1Protocol=$true;EnableSMB2Protocol=$true;RequireSecuritySignature=$true;EnableSecuritySignature=$true;EncryptData=$false} }
function Get-SmbClientConfiguration { New-O @{RequireSecuritySignature=$false;EnableSecuritySignature=$true;EnableInsecureGuestLogons=$false} }
function Get-SmbShare { New-O @{Name='Data';Path='D:\Data';Description='';ShareType='FileSystemDirectory';Special=$false;FolderEnumerationMode='AccessBased';CachingMode='Manual';EncryptData=$false;CurrentUsers=3} }
function Get-SmbShareAccess { param($Name) New-O @{Name=$Name;AccountName='Everyone';AccessControlType='Allow';AccessRight='Full'} }
function Get-SmbSession { }
function Get-ScheduledTask { New-O @{TaskName='Backup';TaskPath='\';State='Ready';Author='admin';Principal=(New-O @{UserId='CONTOSO\svc_task'});Actions=@((New-O @{Execute='cscript.exe';Arguments='C:\s\x.vbs'}))} }
function Get-ScheduledTaskInfo { New-O @{LastRunTime=(Get-Date);LastTaskResult=0;NextRunTime=(Get-Date).AddDays(1)} }
function Get-LocalGroupMember { param($SID) throw 'DC' }
function Get-LocalUser { }
function Get-MpComputerStatus { New-O @{AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$true;AMRunningMode='Normal';AMEngineVersion='1';AMProductVersion='4';AntivirusSignatureLastUpdated=(Get-Date);IsTamperProtected=$false} }
function Get-MpPreference { New-O @{ExclusionPath=@('D:\VMs');ExclusionExtension=$null;ExclusionProcess=@('vmms.exe')} }
function Get-Printer { New-O @{Name='HP-RDC';DriverName='HP Universal';PortName='IP_10.0.0.50';Shared=$true;ShareName='HP';Published=$false;Type='Local';PrinterStatus='Normal'} }
function Get-PrinterDriver { New-O @{Name='HP Universal';Manufacturer='HP';MajorVersion=3;DriverVersion='1';PrinterEnvironment='Windows x64';IsPackageAware=$false;InfPath='x'} }
function Get-PrinterPort { New-O @{Name='IP_10.0.0.50';PrinterHostAddress='10.0.0.50';PortNumber=9100;SNMPEnabled=$true} }
function Get-TimeZone { New-O @{Id='Romance Standard Time'} }
function Get-WinSystemLocale { New-O @{Name='fr-FR'} }
function Confirm-SecureBootUEFI { $true }
function Get-ExecutionPolicy { param([switch]$List) New-O @{Scope='LocalMachine';ExecutionPolicy='RemoteSigned'} }
function Get-KdsRootKey { }
function Get-DfsnRoot { }
Export-ModuleMember -Function *
