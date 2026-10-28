function O([hashtable]$h){[pscustomobject]$h}
function Get-VMHost { O @{LogicalProcessorCount=32;MemoryCapacity=128GB;VirtualHardDiskPath='D:\VMs';VirtualMachinePath='D:\VMs';NumaSpanningEnabled=$true;EnableEnhancedSessionMode=$false;VirtualMachineMigrationEnabled=$false;MaximumVirtualMachineMigrations=2;VirtualMachineMigrationAuthenticationType='CredSSP';MaximumStorageMigrations=2} }
function Get-VMHostSupportedVersion { param([switch]$Default) O @{Name='WS2019';Version=[version]'9.0';IsDefault=$true} }
function Get-VMSwitch { O @{Name='LAN';SwitchType='External';NetAdapterInterfaceDescription='Microsoft Network Adapter Multiplexor Driver';NetAdapterInterfaceDescriptions=@('Microsoft Network Adapter Multiplexor Driver');AllowManagementOS=$true;EmbeddedTeamingEnabled=$false;BandwidthReservationMode='Absolute';IovEnabled=$false} }
function Get-VMSwitchTeam { }
function Get-VMNetworkAdapter { param([switch]$ManagementOS,$VMName) O @{Name='Network Adapter';VMName='SRV-AD01';SwitchName='LAN';MacAddress='00155D';DynamicMacAddressEnabled=$true;IPAddresses=@('192.168.1.11');MacAddressSpoofing='Off';DhcpGuard='Off';RouterGuard='Off';Status='Ok'} }
function Get-VMNetworkAdapterVlan { param($VMNetworkAdapter) O @{AccessVlanId=0} }
function Get-VM { @( (O @{Name='SRV-AD01';State='Running';Generation=1;Version='8.0';ProcessorCount=2;MemoryStartup=4GB;DynamicMemoryEnabled=$false;MemoryMinimum=1GB;MemoryMaximum=4GB;MemoryAssigned=4GB;Uptime=[timespan]::FromDays(10);AutomaticStartAction='StartIfRunning';AutomaticStartDelay=0;AutomaticStopAction='Save';CheckpointType='Production';IntegrationServicesVersion='';ReplicationState='Disabled';IsClustered=$false;Path='D:\VMs';Notes=''}), (O @{Name='SRV-RDS01';State='Running';Generation=2;Version='9.0';ProcessorCount=8;MemoryStartup=32GB;DynamicMemoryEnabled=$false;MemoryMinimum=1GB;MemoryMaximum=32GB;MemoryAssigned=32GB;Uptime=[timespan]::FromDays(10);AutomaticStartAction='StartIfRunning';AutomaticStartDelay=0;AutomaticStopAction='ShutDown';CheckpointType='Production';IntegrationServicesVersion='';ReplicationState='Disabled';IsClustered=$false;Path='D:\VMs';Notes=''}) ) }
function Get-VMProcessor { param($VM) O @{Count=$VM.ProcessorCount;CompatibilityForMigrationEnabled=($VM.Name -eq 'SRV-RDS01');CompatibilityForOlderOperatingSystemsEnabled=$false;ExposeVirtualizationExtensions=$false;Reserve=0;Maximum=100;RelativeWeight=100} }
function Get-VMHardDiskDrive { param($VM) O @{ControllerType='SCSI';ControllerNumber=0;ControllerLocation=0;Path="D:\VMs\$($VM.Name).vhdx";DiskNumber=$null} }
function Get-VHD { param($Path) O @{VhdFormat='VHDX';VhdType='Dynamic';Size=500GB;FileSize=100GB;FragmentationPercentage=5;ParentPath=$null} }
function Get-VMDvdDrive { param($VMName) O @{VMName='SRV-AD01';Path='D:\ISO\win.iso'} }
function Get-VMIntegrationService { param($VM) O @{Name='Time Synchronization';Enabled=$true;PrimaryStatusDescription='OK'} }
function Get-VMSnapshot { param($VMName) O @{VMName='SRV-AD01';Name='avant MAJ';SnapshotType='Standard';CreationTime=(Get-Date).AddDays(-100);ParentSnapshotName=$null} }
function Get-VMReplication { }
function Get-VMSecurity { param($VM) O @{TpmEnabled=$true;Shielded=$false;EncryptStateAndVmMigrationTraffic=$false} }
function Get-VMFirmware { param($VM) O @{SecureBoot='On';SecureBootTemplate='MicrosoftWindows'} }
Export-ModuleMember -Function *
