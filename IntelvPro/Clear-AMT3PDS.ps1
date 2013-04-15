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
# MIIZUwYJKoZIhvcNAQcCoIIZRDCCGUACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULkdWIB5eh4oboCljKAHFXAmo
# YcOgghW+MIIDPTCCAqagAwIBAgIDBbD/MA0GCSqGSIb3DQEBBQUAME4xCzAJBgNV
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
# 4k/SYSEkYR1UJj4UWWSwmNXzp8OurVAwggN6MIICYqADAgECAhA4Jdf6+GGvnvSQ
# 5ya11lrVMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5W
# ZXJpU2lnbiwgSW5jLjErMCkGA1UEAxMiVmVyaVNpZ24gVGltZSBTdGFtcGluZyBT
# ZXJ2aWNlcyBDQTAeFw0wNzA2MTUwMDAwMDBaFw0xMjA2MTQyMzU5NTlaMFwxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjE0MDIGA1UEAxMrVmVy
# aVNpZ24gVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBTaWduZXIgLSBHMjCBnzANBgkq
# hkiG9w0BAQEFAAOBjQAwgYkCgYEAxLXyUhW8iIZgKRZKWy9LkWuHkfM1VFg16tE2
# XmJNUlE0ccJ7Zh2JyN0qxGoK9jfZmHSR9pKusLV2lvGpSmNFRy5rC5JOSyuM7lhK
# i9QH5Bos+IKqWNnNQvMtwHXejavHjh2abEwIlR7e2+9n4XLCScKeYDzh4r4Wo2N4
# aRR7rS0CAwEAAaOBxDCBwTA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLnZlcmlzaWduLmNvbTAMBgNVHRMBAf8EAjAAMDMGA1UdHwQsMCow
# KKAmoCSGImh0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3Rzcy1jYS5jcmwwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgbAMB4GA1UdEQQXMBWkEzAR
# MQ8wDQYDVQQDEwZUU0ExLTIwDQYJKoZIhvcNAQEFBQADggEBAFDFS8gkgN/kDSTC
# 3hqxoQKhpoItDIMVgTcKgg4ssFoXYbXYBf6I2/GRkbNWGkCm65K+ODmwdTZ0OphP
# 5De6mYnKlUIdsLnHoI1X4PrVZARCNU4B0TOiF8hNqifH8uGGTAI4TYN4xvxT4Ovg
# BofdpJaeXgyY4qW+v4KFw2Dh360o2MelS2Taxxtbvaw5CNU4IqEziy+Kmuu8ByE/
# REEJB7VlHCS8SNNEgOuhz8kCtBTPVMcWo4Bc+Xk+XXJ9iBeeLEOiylPOfT32Kjq4
# T5QApW0Kg135XlP0GLNXD3DD+/WtlaAOF97EFoBgyQ8rboYE8ev0eCfRBcXuNFte
# uUky8jMwggPEMIIDLaADAgECAhBHvxmV341SRkP3221IDTGkMA0GCSqGSIb3DQEB
# BQUAMIGLMQswCQYDVQQGEwJaQTEVMBMGA1UECBMMV2VzdGVybiBDYXBlMRQwEgYD
# VQQHEwtEdXJiYW52aWxsZTEPMA0GA1UEChMGVGhhd3RlMR0wGwYDVQQLExRUaGF3
# dGUgQ2VydGlmaWNhdGlvbjEfMB0GA1UEAxMWVGhhd3RlIFRpbWVzdGFtcGluZyBD
# QTAeFw0wMzEyMDQwMDAwMDBaFw0xMzEyMDMyMzU5NTlaMFMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjErMCkGA1UEAxMiVmVyaVNpZ24gVGlt
# ZSBTdGFtcGluZyBTZXJ2aWNlcyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAKnKsqTMzSCvCn2JrId18LRO8d/BD79nYb2jZBzau/nKM6uEMIlYfozb
# a902ng+/0ex48nemfm88v5OvDbpo9GyUyr1SLatIPfW21V1fGwKf+i9rHqT3o5qm
# GsgC4X9MUuMOYOxAHH65Dd4/x7Tfh71femoxLgOZgROoRyDOMXMNVy3NeDQzlRKZ
# ErneaC+q5uPCiowqw4shh2a9g1hXb3W/PKomh13KEBU8n4TqVMEKbsT+xUrduQcR
# lyJ82z4n0R547J8xyfHmIhnbxLNHQ5oaX6AekORe9e588X2rYgGP9U0L3tAiVqiV
# za6Idq7uug3z5E3ZoPtooK4UO7OHwbsCAwEAAaOB2zCB2DA0BggrBgEFBQcBAQQo
# MCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLnZlcmlzaWduLmNvbTASBgNVHRMB
# Af8ECDAGAQH/AgEAMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwudmVyaXNp
# Z24uY29tL1RoYXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEF
# BQcDCDAOBgNVHQ8BAf8EBAMCAQYwJAYDVR0RBB0wG6QZMBcxFTATBgNVBAMTDFRT
# QTIwNDgtMS01MzANBgkqhkiG9w0BAQUFAAOBgQBKa/nqWMJEHDGJeZkrlr+CrAHW
# HEzNsIpYbt8IKaNeyMqTE+cEUg3vRycvADiw5MmTTprUImIV9z83IU9wMYDxiziH
# s+jolwD+z1WWTiTSqSdOeq63YUHzKs7nydle3bsrhT61nbXZ4Vf/vrTFfvXPDJ7w
# l/4r0ztSGxs4J/c/SjCCBYowggRyoAMCAQICCmEegLcAAAAAAAcwDQYJKoZIhvcN
# AQEFBQAwUjELMAkGA1UEBhMCVVMxGjAYBgNVBAoTEUludGVsIENvcnBvcmF0aW9u
# MScwJQYDVQQDEx5JbnRlbCBFeHRlcm5hbCBCYXNpYyBQb2xpY3kgQ0EwHhcNMDkw
# NTE1MTkyNTEzWhcNMTUwNTE1MTkzNTEzWjBWMQswCQYDVQQGEwJVUzEaMBgGA1UE
# ChMRSW50ZWwgQ29ycG9yYXRpb24xKzApBgNVBAMTIkludGVsIEV4dGVybmFsIEJh
# c2ljIElzc3VpbmcgQ0EgM0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDBj4Bi5zjuSDs5R0X69V3wlW/e1eAUdkFaT2ewq3CEPhRmtihw/+nT48MTiK7R
# U3X1uAWIpHRZsVGVQVkVmeVcntnAnRsxVqiBDhNXte5zcdYzPGehmRKmw1Evrwbj
# 5QRRykKFZuQWjSB6cp9l2casI1fY+f3KyHz6whrLZPts7VIVUvDhxIMzu/OD4A/a
# ToAZ5wG2R5hDNRWGJkOom0voFQh86Gw2BvmEXkYh6RSlgcaVLj/l9FmBcPyWtSVu
# zfKRCwBQ8NFBQVhYIr9UCLrHS70svJnLCyecMtOdDlXMUoaqFMYcP8L8rrqEMb5h
# D44UWtQtqEgphjdNNNxjIUFjAgMBAAGjggJcMIICWDAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBSqFmavtz1WU2CuDcLt8+4Hy1FgfjALBgNVHQ8EBAMCAYYwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUwisIU8foXTLCgoDplsC4
# I0LAFfkwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwHwYDVR0jBBgwFoAUGsYM
# SsRHb6jbrSvw9FYGo+03VAwwgb0GA1UdHwSBtTCBsjCBr6CBrKCBqYZOaHR0cDov
# L3d3dy5pbnRlbC5jb20vcmVwb3NpdG9yeS9DUkwvSW50ZWwlMjBFeHRlcm5hbCUy
# MEJhc2ljJTIwUG9saWN5JTIwQ0EuY3JshldodHRwOi8vY2VydGlmaWNhdGVzLmlu
# dGVsLmNvbS9yZXBvc2l0b3J5L0NSTC9JbnRlbCUyMEV4dGVybmFsJTIwQmFzaWMl
# MjBQb2xpY3klMjBDQS5jcmwwgeMGCCsGAQUFBwEBBIHWMIHTMGMGCCsGAQUFBzAC
# hldodHRwOi8vd3d3LmludGVsLmNvbS9yZXBvc2l0b3J5L2NlcnRpZmljYXRlcy9J
# bnRlbCUyMEV4dGVybmFsJTIwQmFzaWMlMjBQb2xpY3klMjBDQS5jcnQwbAYIKwYB
# BQUHMAKGYGh0dHA6Ly9jZXJ0aWZpY2F0ZXMuaW50ZWwuY29tL3JlcG9zaXRvcnkv
# Y2VydGlmaWNhdGVzL0ludGVsJTIwRXh0ZXJuYWwlMjBCYXNpYyUyMFBvbGljeSUy
# MENBLmNydDANBgkqhkiG9w0BAQUFAAOCAQEAlGP9XdDEulT05SHDoaNV1odfdzw+
# ZCQyUj3aYSx0HTNaCgPsITHSAaGNVc0wwyvgvhMuCXMp2u36QvLlZp/0c/4vTGbc
# nO6nsz7WU5/VMjkbyZnXR/jsf0cnBsHt2oLPI1HbKRAqK2DpCcmZLJwyJU1VL20e
# 8MmPoBiWKsVl6q3FRRIjLFrvPziJX+xdoAGDAcNZGeeXZ+JVgSDNFqr0XlqT74WH
# je2PtzChHUjJEO02YjW33WeQ//Cn1jTEyeFR5bToAi9ZQObcfxeEdfdtLJKS+Xrt
# 0o+udEVHt6zl7GleTcicwcAd9ftc7JpXlXRQ9JPxcPR8V2wEBN+bnDf+wjCCBaUw
# ggSNoAMCAQICCh62qikAAQAAShkwDQYJKoZIhvcNAQEFBQAwVjELMAkGA1UEBhMC
# VVMxGjAYBgNVBAoTEUludGVsIENvcnBvcmF0aW9uMSswKQYDVQQDEyJJbnRlbCBF
# eHRlcm5hbCBCYXNpYyBJc3N1aW5nIENBIDNBMB4XDTEwMDcxNTIxMzYwMVoXDTEz
# MDYyOTIxMzYwMVowgcAxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJPUjESMBAGA1UE
# BxMJSGlsbHNib3JvMQ4wDAYDVQQKEwVJbnRlbDEkMCIGA1UECxMbU29mdHdhcmUg
# YW5kIFNlcnZpY2VzIEdyb3VwMTgwNgYDVQQDEy9JbnRlbCBDb3Jwb3JhdGlvbiAt
# IFNvZnR3YXJlIGFuZCBTZXJ2aWNlcyBHcm91cDEgMB4GCSqGSIb3DQEJARYRc3Vw
# cG9ydEBpbnRlbC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMihmXfE
# hpjLhii2JcsRRi6EVbC/Wz8T+EIkg+p/BEtiIeUNYgQiVgEvt3uKpQdznlUor9vT
# 5p4+aMG1ROPoILqSLwvzgFNeoWrZ1+2PhBj8BbOyBzT01n4bQ3uwYFLRl+CJY130
# DViORKMuztmBLUtDw+L39982muuOROtnsP8tAgMBAAGjggKMMIICiDALBgNVHQ8E
# BAMCB4AwPQYJKwYBBAGCNxUHBDAwLgYmKwYBBAGCNxUIhsOMdYSZ5VGD/YEohY6f
# U4KRwAlnhNvDPoe1ni0CAWQCAQcwHQYDVR0OBBYEFPdzxwqJLckXvKmer4pbk59O
# eFOzMB8GA1UdIwQYMBaAFKoWZq+3PVZTYK4Nwu3z7gfLUWB+MIHPBgNVHR8Egccw
# gcQwgcGggb6ggbuGV2h0dHA6Ly93d3cuaW50ZWwuY29tL3JlcG9zaXRvcnkvQ1JM
# L0ludGVsJTIwRXh0ZXJuYWwlMjBCYXNpYyUyMElzc3VpbmclMjBDQSUyMDNBKDEp
# LmNybIZgaHR0cDovL2NlcnRpZmljYXRlcy5pbnRlbC5jb20vcmVwb3NpdG9yeS9D
# UkwvSW50ZWwlMjBFeHRlcm5hbCUyMEJhc2ljJTIwSXNzdWluZyUyMENBJTIwM0Eo
# MSkuY3JsMIH1BggrBgEFBQcBAQSB6DCB5TBsBggrBgEFBQcwAoZgaHR0cDovL3d3
# dy5pbnRlbC5jb20vcmVwb3NpdG9yeS9jZXJ0aWZpY2F0ZXMvSW50ZWwlMjBFeHRl
# cm5hbCUyMEJhc2ljJTIwSXNzdWluZyUyMENBJTIwM0EoMSkuY3J0MHUGCCsGAQUF
# BzAChmlodHRwOi8vY2VydGlmaWNhdGVzLmludGVsLmNvbS9yZXBvc2l0b3J5L2Nl
# cnRpZmljYXRlcy9JbnRlbCUyMEV4dGVybmFsJTIwQmFzaWMlMjBJc3N1aW5nJTIw
# Q0ElMjAzQSgxKS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYJKwYBBAGCNxUK
# BA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQUFAAOCAQEADTFDUUzK/MDGa8nh
# QwzwB4grDB2+juDUd9M7H1Wegd1ZvFhDzEeScebHyJ0JF/YbXybdg/JI4f7napvI
# zqBSG2QPfN2fkR/MvCBBnWJoFJofg2CM74nHDtoL8duXr1rAYO6Ojf/2qx9eA2DO
# kvcm7e37thoDgy8KKWjXFHPZYpONIWkenJaJyGxWx/Q0zUZfLZNvMRxUNryMpv7Q
# TYZPUWSW2rWTE2ZgJ1TgurT2mm3pudKtOhaBsdduE/a9ctfo47zD9nb0a119zPMl
# XXLXglY0J1/XaQyocp6W2v2wepnXQnGdEfzZv2TnmW+TQtKBzRQmqQVlJlSmUXiJ
# 1wEd+TGCAv8wggL7AgEBMGQwVjELMAkGA1UEBhMCVVMxGjAYBgNVBAoTEUludGVs
# IENvcnBvcmF0aW9uMSswKQYDVQQDEyJJbnRlbCBFeHRlcm5hbCBCYXNpYyBJc3N1
# aW5nIENBIDNBAgoetqopAAEAAEoZMAkGBSsOAwIaBQCgcDAQBgorBgEEAYI3AgEM
# MQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUM6v14SEhG0IYbtBxj+hqMMYM
# z+UwDQYJKoZIhvcNAQEBBQAEgYBzvIO5absnHm2c37gMF2Diy88xybduQcElWqwv
# 3fDdiiRYPI4xOmFAcyqg0WcwLn7Z21/NtGZTGyO29cTjHN8ftnjMKkrnnfY31x0T
# b8oLPMY8JKkvYz2n7nvz60aPb5OViwe+dIOGlpuUJdVFU13rCPnVfQaaXoC4AgXK
# o/2RkKGCAX8wggF7BgkqhkiG9w0BCQYxggFsMIIBaAIBATBnMFMxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjErMCkGA1UEAxMiVmVyaVNpZ24g
# VGltZSBTdGFtcGluZyBTZXJ2aWNlcyBDQQIQOCXX+vhhr570kOcmtdZa1TAJBgUr
# DgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUx
# DxcNMTIwMTE5MjMxNzE4WjAjBgkqhkiG9w0BCQQxFgQUToWnW96qsI2bwZeMHL+L
# 3i+6Td0wDQYJKoZIhvcNAQEBBQAEgYAF7T4u76I2z01lVCwpn4XeOEXmI8vbgSy/
# +BLinTKH6+W3/hQtiRUHdSxvxB6zooWIafGbMbweqV2FeV0oUkhFDXT2z1zBuIiK
# c4Y7VilucccUfN9UxBLkLk7o6pboEESJdAH6x/LwrSueFtqgn91fM1RVb+WWUANW
# gjF81pCPSQ==
# SIG # End signature block
