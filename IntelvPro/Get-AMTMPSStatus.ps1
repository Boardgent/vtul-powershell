Function get-AMTMPSStatus {
<#
  .Synopsis 
    Returns the status of the Intel Fast Call for Help Management Presence Server (MPS) interface settings 
  .Description
    Returns the status of the Intel Fast Call for Help Management Presence Server (MPS) interface settings 
  .Notes
  
  .Link
    http:\\vproexpert.com
    http:\\www.intel.com\vpro
    http:\\www.intel.com

  .Example
    get-AMTMPSStatus

    HTTPProxy                     SOCKSProxy                    Client                   Enabled
    ---------                     ----------                    ------                   -------
    HTTP Proxy address            SOCKS Proxy address                                       True
#>
[CmdletBinding()]
Param ()
Process {
[System.Reflection.Assembly]::LoadWithPartialName("Intel.Management.Wsman") 

$mps = new-object Intel.Management.Wsman.MpsManager
$Results = @()

foreach($Hostname in $mps.hosts)
{
    $Obj = new-object psobject
    $Obj | Add-Member -MemberType noteproperty -Name HTTPProxy -value $mps.HttpProxy
    $Obj | Add-Member -MemberType noteproperty -Name SOCKSProxy -value $mps.SocksProxy
    $Obj | Add-Member -MemberType noteproperty -Name Client -value $Hostname
    $Obj | Add-Member -MemberType noteproperty -Name Enabled -value $mps.Enabled
    $Results += $Obj
}
if($mps.hosts.count -eq 0)
{
    $Obj = new-object psobject
    $Obj | Add-Member -MemberType noteproperty -Name HTTPProxy -value $mps.HttpProxy
    $Obj | Add-Member -MemberType noteproperty -Name SOCKSProxy -value $mps.SocksProxy
    $Obj | Add-Member -MemberType noteproperty -Name Client -value ""
    $Obj | Add-Member -MemberType noteproperty -Name Enabled -value $mps.Enabled
    $Results += $Obj
}

Write-Output $Results
}
}