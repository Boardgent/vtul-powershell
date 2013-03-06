Function Get-AMT3PDS {
<#
  .Synopsis 
    Retrieves data from the Intel Active Management Technology Third Party Data Storage
  .Description
    This CmdLet enables the user to retreive data from Intel Active Management Technology (AMT) Third Party Data Storage (3PDS) from clients that have Intel AMT firmware version 3.0 or higher.
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
    Get-AMT3PDS -computerName:vproclient.vprodemo.com -TLS -Operation:ListBlocks

    Retrieves all the availible blocks.

    ComputerName   : vproclient.vprodemo.com
    Port           : 16993
    Operation      : listblocks
    Status         : Success
    UUID           : BEAEE8BF2C09406DAE533F16080D2A6F
    Enterprise     : Virtualization
    Vendor         : Microsoft
    Application    : System Center ConfigMgr
    BlockName      : Out Of Band Management
    NumberOfBlocks : 1

  .Example
    Get-AMT3PDS 192.168.1.100 ListBlocks -credential $AMTCredential -TLS

    ComputerName   : 192.168.1.100
    Port           : 16993
    Operation      : listblocks
    Status         : Success
    UUID           : A1DF77DC16E2469188B2E1F389E5A472
    Enterprise     : Intel
    Vendor         : Intel
    Application    : PowerShell
    BlockName      : Test
    NumberOfBlocks : 1

  .Example
    Get-AMT3PDS vproclient.vprodemo.com -Operation:Read -Username:vprodemo\ITHelpDesk -Enterprise:Intel -Vendor:Intel -Application:PowerShell -Block:Test

    Will prompt for Kerberos username password and then retrieve Data.

    ComputerName : vproclient.vprodemo.com
    Port         : 16992
    Operation    : read
    Status       : Success
    Blocks       : 1
    Data         : Test Data

  .Example
    Get-Content computers.txt | Get-AMT3PDS -TLS -Operation:ListBlocks 

    Will pull the list of amt clients from a text file and pipe them in the Get-AMT3PDS CMDLet.
  .Example
    Get-AMT3PDS-computerName:vproclient.vprodemo.com -port:16993 -Operation:read -Enterprise:"Virtualization" -Vendor:"Microsoft" -Application:"System Center ConfigMgr" -Block:"Out Of Band Management" -MachineUUID:"BEAEE8BF2C09406DAE533F16080D2A6F"

        Example to pull data from the AMT 3PDS accessible by System Center Configuration Manager
#>
[CmdletBinding()]
Param (
  [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true, position=0, HelpMessage="Hostname, FQDN, or IP Address")] [String[]] $ComputerName,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Valid Ports are 16992 (non-TLS) or 16993 (TLS)")][ValidateSet("16992", "16993")] [String] $Port,
  [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=1, HelpMessage="Valid Operations are Read and ListBlocks")][ValidateSet("Read","ListBlocks")] [String] $Operation,
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=2, HelpMessage="Name of the Enterprise")] [string] $Enterprise,
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

  function CreateApplication($Connection, $VendorName, $AppName)
  {
    $AdminService_EPR = $Connection.NewReference("AMT_ThirdPartyDataStorageAdministrationService")
    $InputObj = $AdminService_EPR.CreateMethodInput("AddStorageFpaclEntry")
    $InputObj.SetProperty("AttrType","1")
    $InputObj.SetProperty("ApplicationName",$AppName)
    $InputObj.SetProperty("VendorName",$VendorName)
    $InputObj.SetProperty("IsPartner", "true")
    $InputObj.SetProperty("TotalAllocationSize","49152")
    
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
  
  function CreateEnterprise($Connection, $enterpriseName, [ref]$Handle)
  {
    $AdminService_EPR = $Connection.NewReference("AMT_ThirdPartyDataStorageAdministrationService")
    $InputObj = $AdminService_EPR.CreateMethodInput("AddStorageEaclEntry")
    $InputObj.SetProperty("EnterpriseName",$enterpriseName)
    $Output = $AdminService_EPR.InvokeMethod($InputObj)    
    
    if($Output.GetProperty("ReturnValue").ToString() -ne "0")
    {
        # Error
        return $false  
    }
    $Handle.Value = $Output.GetProperty("Handle").ToString()
    return $true
  }
  
  function EnumerateEnterprise($Connection)
  {
    $RetVal = @()
    
    $AdminService_EPR = $Connection.NewReference("AMT_ThirdPartyDataStorageAdministrationService")
    $InputObj = $AdminService_EPR.CreateMethodInput("EnumerateStorageEaclEntries")
    $Output = $AdminService_EPR.InvokeMethod($InputObj) 
    $Handles = $Output.GetProperty("Handles")
    for($i=0;$i -lt $Handles.Count;++$i)
    {
        $InputObj = $AdminService_EPR.CreateMethodInput("GetStorageEaclEntry")
        $InputObj.SetProperty("Handle",$Handles.Item($i).ToString())
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
  function AllocateBlock($Connection, $sessionHandle, $blockName, $blockHidden, [ref]$BlockHandle)
  {
    $DataStorageService_EPR = $Connection.NewReference("AMT_ThirdPartyDataStorageService")
    $InputObject = $DataStorageService_EPR.CreateMethodInput("AllocateBlock")
    $InputObject.SetProperty("SessionHandle",$sessionHandle)
    $InputObject.SetProperty("BytesRequested","4096")
    if($blockHidden)
    {
        $InputObject.SetProperty("BlockHidden","1")
    }
    else
    {
        $InputObject.SetProperty("BlockHidden","0")
    }
    $InputObject.SetProperty("BlockName",$blockName)
    $OutputObject = $DataStorageService_EPR.InvokeMethod($InputObject)
    
    if($OutputObject.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return($false)
    }
    else
    {
        $BlockHandle.Value = $OutputObject.GetProperty("BlockHandle").ToString()
        return($true)
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
  
  function ReadBlockRaw($Connection, $SessionHandle, $BlockHandle, $ReadOffset, $ReadLength, [ref]$Bytes)
  {
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageService")
    $InputObj = $objref.CreateMethodInput("ReadBlock")
    $InputObj.SetProperty("SessionHandle", "$SessionHandle")
    $InputObj.SetProperty("BlockHandle", "$BlockHandle")
    $InputObj.SetProperty("ByteOffset", $ReadOffset)
    $InputObj.SetProperty("ByteCount", $ReadLength)
    $OutObj = $objRef.InvokeMethod($InputObj)
    
    if($OutObj.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }
    else
    {    
        $Bytes.Value = $OutObj.GetProperty('Data').ToString()
        return $true   
    }
  }
  
  function CalculateBase64Length($InputBufferSize)
  {
    $input_size = $InputBufferSize
    $code_size    = (($input_size * 4) / 3)
    if($input_size % 3 -ne 0)
    {
        $padding_size = 3 - ($input_size % 3)
    }
    else
    {
        $padding_size = 0
    }    
    $total_size   = $code_size + $padding_size 
    return $total_size
  }
  function CalculateMaxProcessingSize($InputBufferSize, $OutputBufferSizeContraint)
  {
    do
    {
        $OutSize = CalculateBase64Length $InputBufferSize
        --$InputBufferSize
    }while($OutSize -gt $OutputBufferSizeContraint)
    return $InputBufferSize + 1
  }
  
  function WriteBlockRaw($Connection, $sessionHandle, $blockHandle, $RawBytes, $RawBytesOffset, $RawBytesLength, $start)
  {
    $encodedData = [System.Convert]::ToBase64String($RawBytes, $RawBytesOffset, $RawBytesLength)
  
    $objRef = $Connection.NewReference("AMT_ThirdPartyDataStorageService")
    $InputObj = $objref.CreateMethodInput("WriteBlock")
    $InputObj.SetProperty("SessionHandle",$sessionHandle)
    $InputObj.SetProperty("BlockHandle",$blockHandle)
    $InputObj.SetProperty("ByteOffset",$start.ToString())
    $InputObj.SetProperty("Data",$encodedData)
    
    $OutputObj = $objRef.InvokeMethod($InputObj)
    if($OutputObj.GetProperty("ReturnValue").ToString() -ne "0")
    {
        return $false
    }
    else
    {
        return $true
    } 
  }
  function WriteBlock($Connection, $sessionHandle, $blockHandle, $data, $start)
  {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
    $Success = WriteBlockRaw $Connection $sessionHandle $blockHandle $bytes 0 $bytes.Length $start
    return $Success
  }  
  
  function WriteBlock_Smart($Connection, $SessionHandle, $BlockName, $CurrentBlockHandle, $BlockHidden, $data)
  {
   
    # Read data that is already written in this block   
    $ReadData = ""
    $Success = ReadBlock $Connection $SessionHandle $CurrentBlockHandle ([ref]$ReadData)
    if(!$Success)
    {
        return $false
    }
      
    $WriteString = $ReadData + $data 
    $rawBytes = [System.Text.Encoding]::UTF8.GetBytes($WriteString)
    $Position = 0
    
    $Success = $true
    do
    {
        $WriteLength = CalculateMaxProcessingSize ($rawBytes.Length - $Position) (4095)
        $encodedData = [System.Convert]::ToBase64String($rawBytes, $Position, $WriteLength)
        
        $Success = WriteBlockRaw $Connection $SessionHandle $CurrentBlockHandle $rawBytes $Position $WriteLength 0
        if(!$Success)
        {
            break
        }
        $Position += $WriteLength
        if($Position -lt $rawBytes.Length)
        {
            # Still have more data to write, so we need to allocate more blocks
            $Success = AllocateBlock $Connection $SessionHandle $BlockName $BlockHidden ([ref]$CurrentBlockHandle)
            if(!$Success)
            {
                break
            }
        }
    } while($Position -lt $rawBytes.Length)
    
    return $Success
  }
  
  function ReadBlock($Connection, $SessionHandle, $BlockHandle, [ref]$OutputData)
  {
    $Bytes = ""
    $Success = ReadBlockRaw $Connection $SessionHandle $BlockHandle "0" "4095" ([ref]$Bytes)
    if(!$Success)
    {
        return $false
    }

        
    $DecodedData = [System.Convert]::FromBase64String($Bytes)
    
    foreach ($byte in $DecodedData)
    {
        if ($byte -ne 255)
        {
            $tempArray = $tempArray + @($byte)
        }
    }
    
    if ($tempArray.length -gt 0)
    {
        $data = [System.Text.Encoding]::UTF8.GetString($tempArray)
    }
    else
    {
        $data = ""   
    }
    $OutputData.Value = $data
    return $true
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
    else
    {
        $ApplicationHandles.Value += @($en.ToString())
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
        $Obj | Add-Member -MemberType noteproperty -Name Operation -value $Operation
        
		try {
			#Attempt Connection with Client
			$Connection.SetHost($Comp, $Port)
      #---------------------------------
      
      switch ($operation)
      {
        "Read" 
        {
            if($MachineUUID -eq "")
            {
                $uuid = GetUUID
            }
            else
            {
                $uuid = $MachineUUID
            }
            $SessionHandle = ""
            $ApplicationHandle = ""
            $Success = RegisterApplication $Connection $uuid $Vendor $Application $Enterprise ([ref]$SessionHandle)
            if(!$Success)
            {
                $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "RegisterApplicationFailed"
                continue  
            }
            $Success = GetApplicationHandle $Connection $SessionHandle ([ref]$ApplicationHandle)
            if(!$Success)
            {
                $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "GetApplicationHandleFailed"
                continue  
            }

            $BlockHandles = GetAllocatedBlocks $Connection $SessionHandle $ApplicationHandle 
            $ReadBuffer = New-Object System.Text.StringBuilder           
            $NumberOfBlocks = 0
            foreach ($tempBlockHandle in $BlockHandles)
            {      
                $tempBlockName = GetBlockName $Connection $SessionHandle $tempBlockHandle
                if ($tempBlockName -eq $Block)
                { 
                    # Read data that is already written in this block   
                    $ReadData = ""
                    $Success = ReadBlock $Connection $SessionHandle $tempBlockHandle ([ref]$ReadData)
                    if(!$Success)
                    {
                        $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "ReadFailed"
                        break;
                    }
                    [void] $ReadBuffer.Append($ReadData)
                    ++$NumberOfBlocks
                }
            }
            $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "Successful"
            $Obj | Add-Member -MemberType noteproperty -Name "Blocks" -value $NumberOfBlocks.ToString()
            $Obj | Add-Member -MemberType noteproperty -Name "Data" -value $ReadBuffer.ToString()

            UnregisterApplication $Connection $SessionHandle
        }
        "ListBlocks" 
        {
          $AppHandles = ""
          $Success = AdminGetRegisteredApplications ([ref]$AppHandles)
          if(!$Success)
          {
            $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "AdminGetRegisteredApplicationsFailed"
            continue  
          }
          
          if($AppHandles.Count -eq 0)
          {
            # No Registered Applications, so let's just enumerate Enterprises
            $EnterpriseNames = EnumerateEnterprise $Connection
            foreach($EnterpriseName in $EnterpriseNames)
            {
                $TObj = new-object psobject
                $TObj | Add-Member -MemberType noteproperty -Name ComputerName -value $Comp
                $TObj | Add-Member -MemberType noteproperty -Name Port -value $Port
                $TObj | Add-Member -MemberType noteproperty -Name Operation -value $Operation
                $TObj | Add-Member -MemberType noteproperty -Name Status -value "Successful"
                $TObj | Add-Member -MemberType noteproperty -Name Enterprise -value $EnterpriseName
                $skip = $true
                    
                Write-Output $TObj
            }
          }
          
          foreach ($tempAppHandle in $AppHandles)
          {
            $uuid = ""
            $VendorName = ""
            $ApplicationName = ""
            $EnterpriseName = ""
            $sessionHandle = ""
            
            $Success = AdminGetApplicationAttributes $tempAppHandle ([ref]$uuid) ([ref]$VendorName) ([ref]$ApplicationName) ([ref]$EnterpriseName)
            if(!$Success)
            {
                $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "AdminGetApplicationAttributesFailed"
                continue  
            }
            $uuid = [System.BitConverter]::ToString([System.Convert]::FromBase64String($uuid)).Replace("-","")
            
            $Success = RegisterApplication $Connection $uuid $vendorName $applicationName $enterpriseName ([ref]$sessionHandle)
            if(!$Success)
            {
                $Obj | Add-Member -MemberType noteproperty -Name Status -value "RegisterApplicationFailed"
                continue
            }
            if($Enterprise -ne "" -and $Enterprise -ne $EnterpriseName)
            {
                continue
            }
            if($Application -ne "" -and $ApplicationName -ne $Application)
            {
                continue
            }
            if($Vendor -ne "" -and $VendorName -ne $Vendor)
            {
                continue
            }
            
            $blockHandles = GetAllocatedBlocks $Connection $sessionHandle $tempAppHandle
            if($blockHandles.Count -eq 0)
            {
                $TObj = new-object psobject
                $TObj | Add-Member -MemberType noteproperty -Name ComputerName -value $Comp
                $TObj | Add-Member -MemberType noteproperty -Name Port -value $Port
                $TObj | Add-Member -MemberType noteproperty -Name Operation -value $Operation
                $TObj | Add-Member -MemberType noteproperty -Name Status -value "Successful"
                $TObj | Add-Member -MemberType noteproperty -Name UUID -value $uuid
                $TObj | Add-Member -MemberType noteproperty -Name Enterprise -value $EnterpriseName
                $TObj | Add-Member -MemberType noteproperty -Name Vendor -value $vendorName
                $TObj | Add-Member -MemberType noteproperty -Name Application -value $ApplicationName
                $skip = $true
                    
                Write-Output $TObj
            }
            else
            {
                $BlockTable = New-Object System.Collections.Hashtable
                for($i=0;$i -lt $blockHandles.Count;++$i)
                {
                    $tempBlockName = GetBlockName $Connection $sessionHandle $blockHandles[$i]
                    $Counter = 0
                    if($BlockTable.ContainsKey($tempBlockName))
                    {
                        $Counter = $tempBlockName[$tempBlockName]
                    }

                    ++$Counter
                    $BlockTable[$tempBlockName] = $Counter              
                }
    
                $en = $BlockTable.GetEnumerator()

                while($en.MoveNext())
                {
                    $TObj = new-object psobject
                    $TObj | Add-Member -MemberType noteproperty -Name ComputerName -value $Comp
                    $TObj | Add-Member -MemberType noteproperty -Name Port -value $Port
                    $TObj | Add-Member -MemberType noteproperty -Name Operation -value $Operation
                    $TObj | Add-Member -MemberType noteproperty -Name Status -value "Successful"
                    $TObj | Add-Member -MemberType noteproperty -Name UUID -value $uuid
                    $TObj | Add-Member -MemberType noteproperty -Name Enterprise -value $EnterpriseName
                    $TObj | Add-Member -MemberType noteproperty -Name Vendor -value $vendorName
                    $TObj | Add-Member -MemberType noteproperty -Name Application -value $ApplicationName
                    $TObj | Add-Member -MemberType noteproperty -Name BlockName -value $en.Key.ToString()
                    $TObj | Add-Member -MemberType noteproperty -Name NumberOfBlocks -value $en.Value.ToString()
                    $skip = $true
                    
                    Write-Output $TObj
                }
            }  
          }  
          if(!$skip)
          {
            $Obj | Add-Member -MemberType noteproperty -Name Status -value "No Entries"
          }       
        }
      }
      
      #------------------------------------


		} catch {
			#Add Member to Object noting failed attempt 
			$Obj | Add-Member -MemberType noteproperty -Name Status -value "ExceptionThrown"
		}

		#Append to Result 
        if(!$skip)
        {
		  $Results += $Obj
        }
	}
    
	#Write out Results
	Write-Output $Results
}
}
# SIG # Begin signature block
# MIIZSAYJKoZIhvcNAQcCoIIZOTCCGTUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYQHrjzC3UYTMmi7/MJRbu9//
# OQ6gghWzMIIDPTCCAqagAwIBAgIDBbD/MA0GCSqGSIb3DQEBBQUAME4xCzAJBgNV
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
# ARUwIwYJKoZIhvcNAQkEMRYEFEMTaMUrLBTh/ZDE9eI8EcQsQy+/MA0GCSqGSIb3
# DQEBAQUABIGACsI4HjyF9zB3rOdH75QOrfIQ+YnyFxNXFn1mgF57/zthrdYNwG7X
# ouERmZ5EGodkFCxsdqadPGNiwXHNMOYURL1mDyVi/OTdncvcrvNPSMrYXFOkzyc1
# XZd0MhogaUretDiU38PPBA86xkmK7rTApAQ3EcXkuzmtkiFYJkhraCmhggF/MIIB
# ewYJKoZIhvcNAQkGMYIBbDCCAWgCAQEwZzBTMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMOVmVyaVNpZ24sIEluYy4xKzApBgNVBAMTIlZlcmlTaWduIFRpbWUgU3RhbXBp
# bmcgU2VydmljZXMgQ0ECEHmipYX50RVCE9m4Pva2je0wCQYFKw4DAhoFAKBdMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTEyMDcxNzIw
# MTM1MVowIwYJKoZIhvcNAQkEMRYEFKrEsbIkdKKpDOnsfjcuDxuWKpyrMA0GCSqG
# SIb3DQEBAQUABIGAI3XuaoPI5xcydo1SadCUqm68bUzGXpQYEkTD57sr5o98frLS
# IubXnUtthmueKFdvQV111rNHvhYHHIOyWMy6gJ3srGJwbokjAohQDAzm8jN7TlL3
# 2DYfcRi9sbNtfT+2nEdJEf31VHu9AtIE6HzbUusbXO+lpudM6+a5czzIdUI=
# SIG # End signature block
