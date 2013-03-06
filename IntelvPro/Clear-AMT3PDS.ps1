Function Clear-AMT3PDS {
<#
  .Synopsis 
    Deletes data from the Intel Active Management Technology Third Party Data Storage
  .Description
    This CmdLet deletes data from the Intel Active Management Technology (AMT) Third Party Data Storage (3PDS) from clients that have Intel AMT firmware version 3.0 or higher.
  .Notes
    Supported AMT Firmware Versions: 3.0 or higher.

    Understanding 3PDS structure:
    Data stored within the 3PDS is stored within blocks of nonvolatile memory in a hierarchical structure. Each block must be associated to a tiered structure of Enterprise -> Vendor -> Application -> Block Name.  

    3PDS Machine UUID:
    When a block is created the application that created the block will specify a GUID to identify itself as the entity that created the block. When modifying blocks that were created by a different entity it may be necessary to specify the Machine UUID as part of the CMDLet parameter.
    
    AMT Provisioning:
      The vPro client AMT firmware must be provisioned prior to accessing AMT functionality. This CMDLet will fail if it is run against a vPro client that has not been provisioned.
        
    AMT Client Authentication:
      To invoke commands against AMT enabled clients credentials to authenticate must be specified. 
      When no credential is provided as a parameter, the script will use the local logged on Kerberos credential.
      When only the username (Kerberos or Digest) parameter is included the user will be prompted to provide the associated password.
      Credentials should be stored as a PowerShell variable then passed into the Cmdlet with the credential parameter.
      $AMTCredential = get-credential
     
    AMT Client Encryption:
      If the Intel vPro client has been configured to use TLS (a web server certificate has been issued to the Intel Management Engine) the Cmdlet must be called with a -TLS switch.

      When managing an Intel vPro client over TLS (Port 16993) it is important that the computername parameter matchs the primary subject name of the issued TLS certificate. Typically this is the fully qualified domain name (FQDN).

    Status:
      Status output designates if the Cmdlet was run successfully. For failed attempts additional status may be provided.
  .Link
    http:\\vproexpert.com
    http:\\www.intel.com\vpro
    http:\\www.intel.com


  .Example
    Clear-AMT3PDS -computer:vproclient.vprodemo.com -TLS -Enterprise:Intel
        
    Will delete all block data under enterprise value specified.
        
    ComputerName                  Port                          Operation                     Status
    ------------                  ----                          ---------                     ------
    vproclient.vprodemo.com       16993                         Delete                        Successful
  .Example
    Clear-AMT3PDS 192.168.1.100 -credential $AMTCredential -Enterprise:Intel -Vendor:Intel

    Will delete all block data under Enterprise, Vendor value specified.
        
    ComputerName                  Port                          Operation                     Status
    ------------                  ----                          ---------                     ------
    192.168.1.100                 16992                         Delete                        Successful
  .Example
    Clear-AMT3PDS vproclient 16992 -Username:amtuser -Enterprise:Intel -Vendor:Intel -Application:PowerShell

    Will delete all block data under Enterprise, Vendor, Application value specified.
        
    ComputerName                  Port                          Operation                     Status
    ------------                  ----                          ---------                     ------
    vproclient                    16992                         Delete                        Successful
  .Example
    Clear-AMT3PDS vproclient.vprodemo.com -credential $AMTCredential -Enterprise:Intel -Vendor:Intel -Application:PowerShell -Block:Test

    Will delete block data under Enterprise, Vendor, Application, Block specified.

    ComputerName                  Port                          Operation                     Status
    ------------                  ----                          ---------                     ------
    vproclient.vprodemo.com       16992                         Delete                        Successful
  .Example
    Get-Content computers.txt | Clear-AMT3PDS -TLS -Enterprise:Intel -Vendor:Intel -Application:PowerShell -Block:Test

    ComputerName                  Port                          Operation                     Status
    ------------                  ----                          ---------                     ------
    computer1.vprodemo.com        16993                         Delete                        Successful
    computer2.vprodemo.com        16993                         Delete                        Successful
    computer3.vprodemo.com        16993                         Delete                        Successful

#>
[CmdletBinding()]
Param (
  [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true, position=0, HelpMessage="Hostname, FQDN, or IP Address")] [String[]] $ComputerName,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Valid Ports are 16992 (non-TLS) or 16993 (TLS)")][ValidateSet("16992", "16993")] [String] $Port,
  [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=2, HelpMessage="Name of the Enterprise")] [string] $Enterprise,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=3, HelpMessage="Name of the Vendor")] [string] $Vendor,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=4, HelpMessage="Name of the Application")] [string] $Application,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=5, HelpMessage="Name of the Block")] [string] $Block,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=6, HelpMessage="Machine UUID")] [string] $MachineUUID,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Use TLS (Port 16993)")] [switch] $TLS,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Digest of Kerberos User")] [string] $Username,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Digest of Kerberos Password")] [string] $Password,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=7, HelpMessage="PS Credential")] [System.Management.Automation.PSCredential] $Credential
) 


PROCESS {

  function DeleteEnterprise($Connection, $EnterpriseHandle)
  {
    $AdminService_EPR = $Connection.NewReference("AMT_ThirdPartyDataStorageAdministrationService")
    $InputObj = $AdminService_EPR.CreateMethodInput("RemoveStorageEaclEntry")
    $InputObj.SetProperty("Handle",$EnterpriseHandle)
    $Output = $AdminService_EPR.InvokeMethod($InputObj) 
    if($Output.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }
    else
    {
        return $true
    }
  }
  function GetEnterpriseHandle($Connection, $EnterpriseName, [ref]$EnterpriseHandle)
  {
    $AdminService_EPR = $Connection.NewReference("AMT_ThirdPartyDataStorageAdministrationService")
    $InputObj = $AdminService_EPR.CreateMethodInput("EnumerateStorageEaclEntries")
    $Output = $AdminService_EPR.InvokeMethod($InputObj) 
    if($Output.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }
    
    $Handles = $Output.GetProperty("Handles")
    for($i=0;$i -lt $Handles.Count;++$i)
    {
        $InputObj = $AdminService_EPR.CreateMethodInput("GetStorageEaclEntry")
        $InputObj.SetProperty("Handle",$Handles.Item($i).ToString())
        $OutObj = $AdminService_EPR.InvokeMethod($InputObj)
        if($OutObj.GetProperty("ReturnValue").ToString() -ne "0")
        {
            return $false
        }
        if($OutObj.GetProperty("EnterpriseName").ToString() -eq $EnterpriseName)
        {
            $EnterpriseHandle.Value = $Handles.Item($i).ToString()
            return $true
        }
    }
    $EnterpriseHandle.Value = ""
    return $true
  }
  function EnumerateEnterprise($Connection)
  {
    $RetVal = @()
    
    $AdminService_EPR = $Connection.NewReference("AMT_ThirdPartyDataStorageAdministrationService")
    $InputObj = $AdminService_EPR.CreateMethodInput("EnumerateStorageEaclEntries")
    $Output = $AdminService_EPR.InvokeMethod($InputObj) 
    $Handles = $Output.GetProperty("Handles")
    foreach($Handle in $Handles)
    {
        $InputObj = $AdminService_EPR.CreateMethodInput("GetStorageEaclEntry")
        $InputObj.SetProperty("Handle",$Handle.ToString())
        $OutObj = $AdminService_EPR.InvokeMethod($InputObj)
        $RetVal += @($OutObj.GetProperty("EnterpriseName").ToString())
    }
    return ,$RetVal
  }
  function DeallocateBlock($Connection, $sessionHandle, $blockHandle)
  {
    $DataStorageService_EPR = $Connection.NewReference("AMT_ThirdPartyDataStorageService")
    $InputObject = $DataStorageService_EPR.CreateMethodInput("DeallocateBlock")
    $InputObject.SetProperty("SessionHandle",$sessionHandle)
    $InputObject.SetProperty("BlockHandle",$blockHandle)
    $OutputObject = $DataStorageService_EPR.InvokeMethod($InputObject)
    if($OutputObject.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }
    else
    {
        return $true
    }
  }

  function GetUUID()
  {
    $compname = hostname
    $uuid = (Get-WmiObject Win32_ComputerSystemProduct -ComputerName $compname).UUID
    
    $uuid = $uuid.Replace("-","")
     
    return $uuid
  }
    
  function RegisterApplication($Connection, $uuid, $vendorName, $appName, $entName, [ref]$SessionHandle)
  {
        
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageService")
    $InputObj = $objref.CreateMethodInput("RegisterApplication")
    $InputObj.SetProperty("CallerUUID", $uuid)
    $InputObj.SetProperty("VendorName", $vendorName)
    $InputObj.SetProperty("ApplicationName", $appName)
    $InputObj.SetProperty("EnterpriseName", $entName)
    $OutObj = $objRef.InvokeMethod($InputObj)
    
    if($OutObj.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return($false)
    }
    else
    {
       $SessionHandle.Value = $OutObj.GetProperty('SessionHandle').ToString()
       return($true) 
    }
  }
  function GetApplicationHandle($Connection, $SessionHandle, [ref]$ApplicationHandle)
  {
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageService")
    $InputObj = $objref.CreateMethodInput("GetCurrentApplicationHandle")
    $InputObj.SetProperty("SessionHandle", "$SessionHandle")
    $OutObj = $objRef.InvokeMethod($InputObj)
    
    if($OutObj.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }
    else
    {
        $ApplicationHandle.Value = $OutObj.GetProperty('ApplicationHandle').ToString()
        return $true 
    }    
  }
  
  function GetAllocatedBlocks($Connection, $SessionHandle, $ApplicationHandle)
  {
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageService")
    $InputObj = $objref.CreateMethodInput("GetAllocatedBlocks")
    $InputObj.SetProperty("SessionHandle", "$SessionHandle")
    $InputObj.SetProperty("BlockOwnerApplication", "$ApplicationHandle")
    $OutObj = $objRef.InvokeMethod($InputObj)
    
    $BlockHandles = $OutObj.GetProperty('BlockHandles')
    $blocks = @()
    
    if($BlockHandles.IsArray)
    {
        for($i=0;$i -lt $BlockHandles.Count;++$i)
        {
           $blocks = $blocks + @($BlockHandles.Item($i).ToString()) 
        }
    }
    else 
    {
        if(!$BlockHandles.IsNull)
        {
            $blocks = @($BlockHandles.ToString())
        }
        $blocks = ,$blocks
    }
    
    Return $blocks
  }
  
  function GetBlockName($Connection, $SessionHandle, $BlockHandle)
  {
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageService")
    $InputObj = $objref.CreateMethodInput("GetBlockAttributes")
    $InputObj.SetProperty("SessionHandle", "$SessionHandle")
    $InputObj.SetProperty("BlockHandle", "$BlockHandle")
    $OutObj = $objRef.InvokeMethod($InputObj)
    
    $BlockName = $OutObj.GetProperty('BlockName').ToString()
    $BlockName
  }
  function RemoveStorageFpaclEntry($Connection, $Handle)
  {
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageAdministrationService")
    $InputObj = $objref.CreateMethodInput("RemoveStorageFpaclEntry") 
    $InputObj.SetProperty("Handle",$Handle)
    $OutObj = $objRef.InvokeMethod($InputObj)
    if($OutObj.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }
    else
    {
        return $true
    }
  }
  function GetStorageFpaclEntry($Connection, $ApplicationName, $VendorName, [ref]$Handle)
  {
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageAdministrationService")
    $InputObj = $objref.CreateMethodInput("EnumerateStorageAllocEntries")
    $OutObj = $objRef.InvokeMethod($InputObj)
    if($OutObj.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }     
    else
    {
        $handles = $OutObj.GetProperty("Handles")
        for($i=0;$i -lt $handles.Count;++$i)
        {
            $h = $handles.Item($i).ToString()
            $InputObj = $objref.CreateMethodInput("GetStorageAllocEntry")
            $InputObj.SetProperty("Handle",$h)
            $OutObj = $objRef.InvokeMethod($InputObj)
            if($OutObj.GetProperty("ReturnValue").ToString() -ne "0")
            {
                return $false
            }
            else
            {
                if($OutObj.GetProperty("ApplicationName").ToString() -eq $ApplicationName -and $OutObj.GetProperty("VendorName").ToString() -eq $VendorName)
                {
                    $Handle.Value = $h
                    return $true
                }
            }
        }
    }
    return $false
  }
  function RemoveApplication($Connection, $SessionHandle)
  {
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageService")
    $InputObj = $objref.CreateMethodInput("RemoveApplication")
    $InputObj.SetProperty("SessionHandle", "$SessionHandle") 
    $OutObj = $objRef.InvokeMethod($InputObj)
    
    if($OutObj.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }
    else
    {
        return $true
    }
  }
  function UnregisterApplication($Connection, $sessionHandle)
  {
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageService")
    $InputObj = $objref.CreateMethodInput("UnregisterApplication")
    $InputObj.SetProperty("SessionHandle", "$SessionHandle")
    $OutObj = $objRef.InvokeMethod($InputObj)
  }
  
  function AdminGetRegisteredApplications([ref]$ApplicationHandles)
  {
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageAdministrationService")
    $InputObj = $objref.CreateMethodInput("AdminGetRegisteredApplications")
    $OutObj = $objRef.InvokeMethod($InputObj)
    if($OutObj.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }
    
    $en = $OutObj.GetProperty('ApplicationHandles')
    $ApplicationHandles.Value = @()
    if($en.IsArray)
    {
        For($i=0;$i -lt $en.Count;++$i)
        {
            $ApplicationHandles.Value += @($en.Item($i).ToString())
        }
    }
    return $true
  }
  
  function AdminGetApplicationAttributes($appHandle, [ref]$uuid, [ref]$VendorName, [ref]$ApplicationName, [ref]$EnterpriseName)
  {
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageAdministrationService")
    $InputObj = $objref.CreateMethodInput("AdminGetApplicationAttributes")
    $InputObj.SetProperty("Handle", "$appHandle")
    
    $OutObj = $objRef.InvokeMethod($InputObj)
    if($OutObj.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }
    
    $uuid.Value = $OutObj.GetProperty('UUID').ToString()
    $VendorName.Value = $OutObj.GetProperty('VendorName').ToString()
    $ApplicationName.Value = $OutObj.GetProperty('ApplicationName').ToString()
    $EnterpriseName.Value = $OutObj.GetProperty('EnterpriseName').ToString()
    return $true
  }

	#create a connection object
	$Connection = New-Object Intel.Management.Wsman.WsmanConnection 

	if ($Credential.username.Length -gt 0) {
		$Connection.SetCredentials($Credential.Username, $Credential.Password)  
	} elseif ($Username.length -gt 0) {
		if ($Password.length -gt 0) {
			$Connection.SetCredentials($Username, $Password)  
		} else {
			$Cred = Get-Credential $Username
			$Connection.SetCredentials($Cred.Username, $Cred.Password)
		}
	}  
    
    if ($Port.Length -lt 1) {
        if ($TLS.IsPresent) {
          $Port = 16993;
        }
        else {
          $Port = 16992;
        }
    }

#----------------- Code below this line is specific to each script.

    $Results = @()
	ForEach ($Comp in $ComputerName) 
    {
        $skip = $false
		$Obj = new-object psobject
        
        $Obj | Add-Member -MemberType noteproperty -Name ComputerName -value $Comp
        $Obj | Add-Member -MemberType noteproperty -Name Port -value $Port
        $Obj | Add-Member -MemberType noteproperty -Name Operation -value "Delete"
        
		try 
        {
			#Attempt Connection with Client
			$Connection.SetHost($Comp, $Port)
      #---------------------------------
            if($MachineUUID -ne "")
            {
                $uuid = $MachineUUID
            }
            else
            {
                $uuid = GetUUID
            }
            
            $SessionHandle = ""
            $ApplicationHandle = ""
            
            
            if($Enterprise -ne "" -and $Vendor -eq "" -and $Application -eq "" -and $Block -eq "")
            {
                # Delete Enterprise
                $Handle = ""
                $Success = GetEnterpriseHandle $Connection $Enterprise ([ref]$Handle)
                if(!$Success)
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "GetEnterpriseHandleFailed"
                    $Results += $Obj
                    continue  
                }
                elseif($Success -and $Handle -eq "")
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "EnterpriseNotFound[$Enterprise]"
                    $Results += $Obj
                    continue 
                }
                $Success = DeleteEnterprise $Connection $Handle
                if(!$Success)
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "Failed"
                }
                else
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "Successful"
                }
            }
            elseif($Enterprise -ne "" -and $Vendor -ne "" -and $Application -ne "" -and $Block -eq "")
            {
                # Get Application
                $Success = RegisterApplication $Connection $uuid $Vendor $Application $Enterprise ([ref]$SessionHandle)
                if(!$Success)
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "RegisterApplicationFailed"
                    $Results += $Obj
                    continue  
                }
                # Remove Application (This also unregisters)
                $Success = RemoveApplication $Connection $SessionHandle
                if(!$Success)
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "RemoveApplicationFailed"
                    $Results += $Obj
                    continue  
                }
                # Remove PACL Entry
                $Handle = ""
                $Success = GetStorageFpaclEntry $Connection $Application $Vendor ([ref]$Handle)
                if(!$Success)
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "FpaclProcessingFailed"
                    $Results += $Obj
                    continue   
                }
                $Success = RemoveStorageFpaclEntry $Connection $Handle
                if(!$Success)
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "Success[FpaclEntryMayBeInUse]"
                    $Results += $Obj
                    continue  
                }
                $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "Successful"            
            }
            elseif($Enterprise -ne "" -and $Vendor -ne "" -and $Application -ne "" -and $Block -ne "")
            {
                # Delete Block
                $Success = RegisterApplication $Connection $uuid $Vendor $Application $Enterprise ([ref]$SessionHandle)
                if(!$Success)
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "RegisterApplicationFailed"
                    $Results += $Obj
                    continue  
                }
                $Success = GetApplicationHandle $Connection $SessionHandle ([ref]$ApplicationHandle)
                if(!$Success)
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "GetApplicationHandleFailed"
                    $Results += $Obj
                    continue  
                }

                $BlockHandles = GetAllocatedBlocks $Connection $SessionHandle $ApplicationHandle 
                $Found = $false
                foreach ($tempBlockHandle in $BlockHandles)
                {      
                    $tempBlockName = GetBlockName $Connection $SessionHandle $tempBlockHandle
                    if ($tempBlockName -eq $Block)
                    { 
                        $Found = $true
                        # Delete the associated blocks
                        $Success = DeallocateBlock $Connection $sessionHandle $tempBlockHandle
                        if(!$Success)
                        {
                            $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "DeallocateBlockFailed"
                            $Results += $Obj
                            continue  
                        }
                    }
                }
                if($Found)
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "Successful"
                }
                else
                {
                    $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "NoBlocksFound"
                }

                UnregisterApplication $Connection $SessionHandle
            }
      
      

            
      
      
      #------------------------------------


		} catch {
			#Add Member to Object noting failed attempt 
			$Obj | Add-Member -MemberType noteproperty -Name ComputerName -value $Comp
			$Obj | Add-Member -MemberType noteproperty -Name Port -value $Port
			$Obj | Add-Member -MemberType noteproperty -Name Operation -value $Operation
			$Obj | Add-Member -MemberType noteproperty -Name Status -value "ExceptionThrown"
		}
        $Results += $Obj
	}
    Write-Output $Results
  }
}

# SIG # Begin signature block
# MIIZSAYJKoZIhvcNAQcCoIIZOTCCGTUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULkdWIB5eh4oboCljKAHFXAmo
# YcOgghWzMIIDPTCCAqagAwIBAgIDBbD/MA0GCSqGSIb3DQEBBQUAME4xCzAJBgNV
# BAYTAlVTMRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3Vy
# ZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDYwMjE2MTgwMTMwWhcNMTYwMjE5
# MTgwMTMwWjBSMQswCQYDVQQGEwJVUzEaMBgGA1UEChMRSW50ZWwgQ29ycG9yYXRp
# b24xJzAlBgNVBAMTHkludGVsIEV4dGVybmFsIEJhc2ljIFBvbGljeSBDQTCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMGl39c5v1BWoRnyZDXTjZN04irc
# BMMixXbEPK3fTIvIxHlaO26zRufcH6F7z0GI078s/r6sXMTCUPnk+Vf4csYgp400
# b3t2rJzfQUSURSNnNNkWrY3h7eRUn9cAQSAA3NXy/2qnupbDG6A+B9zfP0GRii34
# KJ+jN7Ectv+ERmP7IhIJTrWRFm+5JDQTXXJgvh1GByCUl5oejehfnuu8hyRouxhX
# n/UCP5HwMzU+mT3rldAAqwd+fJPsLhLnRPiVWfiXPfrA501mf/N6AbXOnjWWehMV
# 9Pgq4pUkfnHtgPWnopuAkIoui+e6Ma6iGq4E191cqlmS/Pqka/6ILUdrAl0CAwEA
# AaOBoDCBnTAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFBrGDErER2+o260r8PRW
# BqPtN1QMMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwuZ2VvdHJ1c3QuY29t
# L2NybHMvc2VjdXJlY2EuY3JsMB8GA1UdIwQYMBaAFEjmaPkr0rKV10fYIyAQTzOY
# kJ/UMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAExA4raRUpUiV
# RbAtN3LAn57Y748L+5CW0rYXeVHKs98Gfr206Qg/hKAMk5+zHKhsis8t7vmQEvD4
# OibXc4EOn8QxklnUKCVB9VXxyj2ZPdpkyNIYZCIyCQktHeMx+v3TR9dkqPld6oIn
# 4k/SYSEkYR1UJj4UWWSwmNXzp8OurVAwggOfMIICh6ADAgECAhB5oqWF+dEVQhPZ
# uD72to3tMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5W
# ZXJpU2lnbiwgSW5jLjErMCkGA1UEAxMiVmVyaVNpZ24gVGltZSBTdGFtcGluZyBT
# ZXJ2aWNlcyBDQTAeFw0xMjA1MDEwMDAwMDBaFw0xMjEyMzEyMzU5NTlaMGIxCzAJ
# BgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjE0MDIGA1UE
# AxMrU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBTaWduZXIgLSBHMzCB
# nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqVlmdNo9in162Pz1gER7/kdqFFVO
# UEcL7NPtzvY4909pubHwtniCCox2FmfiAq23DaWK9gP8ZtP8CC3MtXNZe4ncM25m
# Wl5SN7Ri0ZJZNRSLRaxZsk0kopiUaEJynzpo4muLniIt9JhOmsavs+SgqzwovyPh
# 13Kk8hBTZ653r1ECAwEAAaOB4zCB4DAMBgNVHRMBAf8EAjAAMDMGA1UdHwQsMCow
# KKAmoCSGImh0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3Rzcy1jYS5jcmwwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC52ZXJpc2lnbi5jb20wDgYDVR0PAQH/BAQDAgeAMB4GA1UdEQQX
# MBWkEzARMQ8wDQYDVQQDEwZUU0ExLTMwHQYDVR0OBBYEFLS38YlJJmDnZepzrtzT
# OM2/V5JvMA0GCSqGSIb3DQEBBQUAA4IBAQAemKont3i1CLXJcm2338AOmKY1xIjJ
# 0vZt8Usa+9X5LZkAntHnm4vhP705gAxmzQe8XJhUppS6ENFOi6v1b2XMZwmigHxS
# 6A4D1mt6xgUY7MisQnwHLKc9CGbcAO39lB1z8nKYk7ER1o/vjuqs9JZRDNCN3zFS
# T16vfadKdeZOziufKSvnz12fA35uJ3sjrWIpZq+S6CzOvZx/3M0XPEPCCT91Rcee
# 5Ndgf5fG5KrHafX8zXSsLLBIwVBOcFYetTXTjr6x7ay9/gzshX3Vu4VmRBldn5Pr
# grpjntN8Yf/IG9kjWH8wo2ahOSZeksM8yzcy+vWjjdzVsKPpJTZV14H6MIIDxDCC
# Ay2gAwIBAgIQR78Zld+NUkZD99ttSA0xpDANBgkqhkiG9w0BAQUFADCBizELMAkG
# A1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIGA1UEBxMLRHVyYmFu
# dmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhhd3RlIENlcnRpZmlj
# YXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcgQ0EwHhcNMDMxMjA0
# MDAwMDAwWhcNMTMxMjAzMjM1OTU5WjBTMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# VmVyaVNpZ24sIEluYy4xKzApBgNVBAMTIlZlcmlTaWduIFRpbWUgU3RhbXBpbmcg
# U2VydmljZXMgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpyrKk
# zM0grwp9iayHdfC0TvHfwQ+/Z2G9o2Qc2rv5yjOrhDCJWH6M22vdNp4Pv9HsePJ3
# pn5vPL+Trw26aPRslMq9Ui2rSD31ttVdXxsCn/ovax6k96OaphrIAuF/TFLjDmDs
# QBx+uQ3eP8e034e9X3pqMS4DmYETqEcgzjFzDVctzXg0M5USmRK53mgvqubjwoqM
# KsOLIYdmvYNYV291vzyqJoddyhAVPJ+E6lTBCm7E/sVK3bkHEZcifNs+J9EeeOyf
# Mcnx5iIZ28SzR0OaGl+gHpDkXvXufPF9q2IBj/VNC97QIlaolc2uiHau7roN8+RN
# 2aD7aKCuFDuzh8G7AgMBAAGjgdswgdgwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC52ZXJpc2lnbi5jb20wEgYDVR0TAQH/BAgwBgEB/wIB
# ADBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vY3JsLnZlcmlzaWduLmNvbS9UaGF3
# dGVUaW1lc3RhbXBpbmdDQS5jcmwwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDgYDVR0P
# AQH/BAQDAgEGMCQGA1UdEQQdMBukGTAXMRUwEwYDVQQDEwxUU0EyMDQ4LTEtNTMw
# DQYJKoZIhvcNAQEFBQADgYEASmv56ljCRBwxiXmZK5a/gqwB1hxMzbCKWG7fCCmj
# XsjKkxPnBFIN70cnLwA4sOTJk06a1CJiFfc/NyFPcDGA8Ys4h7Po6JcA/s9Vlk4k
# 0qknTnqut2FB8yrO58nZXt27K4U+tZ212eFX/760xX71zwye8Jf+K9M7UhsbOCf3
# P0owggV1MIIEXaADAgECAgov9eV6AAEAAF/vMA0GCSqGSIb3DQEBBQUAMFYxCzAJ
# BgNVBAYTAlVTMRowGAYDVQQKExFJbnRlbCBDb3Jwb3JhdGlvbjErMCkGA1UEAxMi
# SW50ZWwgRXh0ZXJuYWwgQmFzaWMgSXNzdWluZyBDQSAzQTAeFw0xMTA0MTgxNTAx
# MzVaFw0xNDA0MDIxNTAxMzVaMIGQMRQwEgYDVQQKEwtJbnRlbCBDb3JwLjEgMB4G
# A1UECxMXQ2xpZW50IENvbXBvbmVudHMgR3JvdXAxNDAyBgNVBAMTK0ludGVsIENv
# cnBvcmF0aW9uIC0gQ2xpZW50IENvbXBvbmVudHMgR3JvdXAxIDAeBgkqhkiG9w0B
# CQEWEXN1cHBvcnRAaW50ZWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
# gQCU94fi/Xj4Tii7DNEFFxZS07I6ZF+nHPPgQhZgkMnPh7UIw4QkAc8eO8rN4y5K
# 133c0I0l3FWGYGULpffKIgkLATczXWnB7PavM/WprDmgb5pmFCTKzKSc+iCRPm2h
# zzbZ0XrFvLaCsrA8diFLoK8m6MkW0045jeckwzWV+9kI4QIDAQABo4ICjDCCAogw
# CwYDVR0PBAQDAgeAMD0GCSsGAQQBgjcVBwQwMC4GJisGAQQBgjcVCIbDjHWEmeVR
# g/2BKIWOn1OCkcAJZ4Tbwz6HtZ4tAgFkAgEHMB0GA1UdDgQWBBS8gzCIBVJgHqHh
# hWnVHyRoGy66CTAfBgNVHSMEGDAWgBSqFmavtz1WU2CuDcLt8+4Hy1FgfjCBzwYD
# VR0fBIHHMIHEMIHBoIG+oIG7hldodHRwOi8vd3d3LmludGVsLmNvbS9yZXBvc2l0
# b3J5L0NSTC9JbnRlbCUyMEV4dGVybmFsJTIwQmFzaWMlMjBJc3N1aW5nJTIwQ0El
# MjAzQSgxKS5jcmyGYGh0dHA6Ly9jZXJ0aWZpY2F0ZXMuaW50ZWwuY29tL3JlcG9z
# aXRvcnkvQ1JML0ludGVsJTIwRXh0ZXJuYWwlMjBCYXNpYyUyMElzc3VpbmclMjBD
# QSUyMDNBKDEpLmNybDCB9QYIKwYBBQUHAQEEgegwgeUwbAYIKwYBBQUHMAKGYGh0
# dHA6Ly93d3cuaW50ZWwuY29tL3JlcG9zaXRvcnkvY2VydGlmaWNhdGVzL0ludGVs
# JTIwRXh0ZXJuYWwlMjBCYXNpYyUyMElzc3VpbmclMjBDQSUyMDNBKDEpLmNydDB1
# BggrBgEFBQcwAoZpaHR0cDovL2NlcnRpZmljYXRlcy5pbnRlbC5jb20vcmVwb3Np
# dG9yeS9jZXJ0aWZpY2F0ZXMvSW50ZWwlMjBFeHRlcm5hbCUyMEJhc2ljJTIwSXNz
# dWluZyUyMENBJTIwM0EoMSkuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGCSsG
# AQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwDQYJKoZIhvcNAQEFBQADggEBAD1iEzZt
# vZkHprhC+b4ypOe/OW/D3VFirocFaFQaD4ycpP4L8SKkBb7mIgx2hH/gOtI9dEOq
# 8O5nY3Luoh8mOvr0smlZk0VI67XZQlxYjlJd8uNyAQ3s8iNh6e98Iqp2AKFZFo/n
# piO/AKfOgBtQ5WjTtApjA4araXBr9I1zwkPO6Nz/PF6nM7qTLkqskPJY5WSJwv2Q
# vnNIf/nBfT0FqoBPIAbc+QvlJ+gcldSoJCWeHvdU7/TVdKkS2/d3puDDMqDKWSt4
# KGHJCEHMW2KoUSwi+3qwHVsW5cgXHsx/iLkg+07UcKhlkTMGcXO94mOljx1lnV7T
# U8T3tGOF1R2ZdOQwggWKMIIEcqADAgECAgphHoC3AAAAAAAHMA0GCSqGSIb3DQEB
# BQUAMFIxCzAJBgNVBAYTAlVTMRowGAYDVQQKExFJbnRlbCBDb3Jwb3JhdGlvbjEn
# MCUGA1UEAxMeSW50ZWwgRXh0ZXJuYWwgQmFzaWMgUG9saWN5IENBMB4XDTA5MDUx
# NTE5MjUxM1oXDTE1MDUxNTE5MzUxM1owVjELMAkGA1UEBhMCVVMxGjAYBgNVBAoT
# EUludGVsIENvcnBvcmF0aW9uMSswKQYDVQQDEyJJbnRlbCBFeHRlcm5hbCBCYXNp
# YyBJc3N1aW5nIENBIDNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# wY+AYuc47kg7OUdF+vVd8JVv3tXgFHZBWk9nsKtwhD4UZrYocP/p0+PDE4iu0VN1
# 9bgFiKR0WbFRlUFZFZnlXJ7ZwJ0bMVaogQ4TV7Xuc3HWMzxnoZkSpsNRL68G4+UE
# UcpChWbkFo0genKfZdnGrCNX2Pn9ysh8+sIay2T7bO1SFVLw4cSDM7vzg+AP2k6A
# GecBtkeYQzUVhiZDqJtL6BUIfOhsNgb5hF5GIekUpYHGlS4/5fRZgXD8lrUlbs3y
# kQsAUPDRQUFYWCK/VAi6x0u9LLyZywsnnDLTnQ5VzFKGqhTGHD/C/K66hDG+YQ+O
# FFrULahIKYY3TTTcYyFBYwIDAQABo4ICXDCCAlgwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQUqhZmr7c9VlNgrg3C7fPuB8tRYH4wCwYDVR0PBAQDAgGGMBIGCSsG
# AQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFMIrCFPH6F0ywoKA6ZbAuCNC
# wBX5MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMB8GA1UdIwQYMBaAFBrGDErE
# R2+o260r8PRWBqPtN1QMMIG9BgNVHR8EgbUwgbIwga+ggayggamGTmh0dHA6Ly93
# d3cuaW50ZWwuY29tL3JlcG9zaXRvcnkvQ1JML0ludGVsJTIwRXh0ZXJuYWwlMjBC
# YXNpYyUyMFBvbGljeSUyMENBLmNybIZXaHR0cDovL2NlcnRpZmljYXRlcy5pbnRl
# bC5jb20vcmVwb3NpdG9yeS9DUkwvSW50ZWwlMjBFeHRlcm5hbCUyMEJhc2ljJTIw
# UG9saWN5JTIwQ0EuY3JsMIHjBggrBgEFBQcBAQSB1jCB0zBjBggrBgEFBQcwAoZX
# aHR0cDovL3d3dy5pbnRlbC5jb20vcmVwb3NpdG9yeS9jZXJ0aWZpY2F0ZXMvSW50
# ZWwlMjBFeHRlcm5hbCUyMEJhc2ljJTIwUG9saWN5JTIwQ0EuY3J0MGwGCCsGAQUF
# BzAChmBodHRwOi8vY2VydGlmaWNhdGVzLmludGVsLmNvbS9yZXBvc2l0b3J5L2Nl
# cnRpZmljYXRlcy9JbnRlbCUyMEV4dGVybmFsJTIwQmFzaWMlMjBQb2xpY3klMjBD
# QS5jcnQwDQYJKoZIhvcNAQEFBQADggEBAJRj/V3QxLpU9OUhw6GjVdaHX3c8PmQk
# MlI92mEsdB0zWgoD7CEx0gGhjVXNMMMr4L4TLglzKdrt+kLy5Waf9HP+L0xm3Jzu
# p7M+1lOf1TI5G8mZ10f47H9HJwbB7dqCzyNR2ykQKitg6QnJmSycMiVNVS9tHvDJ
# j6AYlirFZeqtxUUSIyxa7z84iV/sXaABgwHDWRnnl2fiVYEgzRaq9F5ak++Fh43t
# j7cwoR1IyRDtNmI1t91nkP/wp9Y0xMnhUeW06AIvWUDm3H8XhHX3bSySkvl67dKP
# rnRFR7es5expXk3InMHAHfX7XOyaV5V0UPST8XD0fFdsBATfm5w3/sIxggL/MIIC
# +wIBATBkMFYxCzAJBgNVBAYTAlVTMRowGAYDVQQKExFJbnRlbCBDb3Jwb3JhdGlv
# bjErMCkGA1UEAxMiSW50ZWwgRXh0ZXJuYWwgQmFzaWMgSXNzdWluZyBDQSAzQQIK
# L/XlegABAABf7zAJBgUrDgMCGgUAoHAwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwIwYJKoZIhvcNAQkEMRYEFDOr9eEhIRtCGG7QcY/oajDGDM/lMA0GCSqGSIb3
# DQEBAQUABIGAbaFK+ht0+h8VLF3Fx32QmawlxmU/ULb1xNvxY8c5Za8hCOM+8s3p
# WQsLDNHnhBbk43Gh4Y9UUFi4rWXmkdsWTb5HKYejFHPkDNispGUgkQwfbirt+dCO
# 7Gr821rPrSimsFF3PSwijVMNVQwxBuOqiD6QEZbm/aNhVEtm8qzIZ2ChggF/MIIB
# ewYJKoZIhvcNAQkGMYIBbDCCAWgCAQEwZzBTMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMOVmVyaVNpZ24sIEluYy4xKzApBgNVBAMTIlZlcmlTaWduIFRpbWUgU3RhbXBp
# bmcgU2VydmljZXMgQ0ECEHmipYX50RVCE9m4Pva2je0wCQYFKw4DAhoFAKBdMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTEyMDcxNzIw
# MTM0NlowIwYJKoZIhvcNAQkEMRYEFEL6TMjdyINwhZgzf+YPD3AG9R6gMA0GCSqG
# SIb3DQEBAQUABIGAQyAvYvW5XRr0yhdimuqjTB0A6qOa1R4OblVTb8kZfNrKTKHS
# TWRFLm0v6M1EpuRQgLgaUwKT7JLx02gDT5KCsFXJZpJ3r9T7VIcOXtJ1vZF9yAnj
# fnCPeQPdvhIS/RsySCUbaDXGMeq9j5B90hkTSzJRortdZcbn1okFSMJaCCc=
# SIG # End signature block
