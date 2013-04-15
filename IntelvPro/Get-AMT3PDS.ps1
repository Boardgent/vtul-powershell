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
# MIIZUwYJKoZIhvcNAQcCoIIZRDCCGUACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYQHrjzC3UYTMmi7/MJRbu9//
# OQ6gghW+MIIDPTCCAqagAwIBAgIDBbD/MA0GCSqGSIb3DQEBBQUAME4xCzAJBgNV
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUQxNoxSssFOH9kMT14jwRxCxD
# L78wDQYJKoZIhvcNAQEBBQAEgYCL24ECK8Ix2EdqebausbYhbzdhhVjqtDq1V72P
# 9wGXn00DgJ4E24kbZGG/mMu+nyPQTu5n70dHxQb9EDkl2kV0I0Iu8VAf0BF5/IvN
# 2CJs6oedH/qDtoci537gVK4Cbk8ef5ynUvMfdQaT0hkU66gdlk7iNTSRM5tR0Te5
# 3m0Xs6GCAX8wggF7BgkqhkiG9w0BCQYxggFsMIIBaAIBATBnMFMxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjErMCkGA1UEAxMiVmVyaVNpZ24g
# VGltZSBTdGFtcGluZyBTZXJ2aWNlcyBDQQIQOCXX+vhhr570kOcmtdZa1TAJBgUr
# DgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUx
# DxcNMTIwMTE5MjMxNzIxWjAjBgkqhkiG9w0BCQQxFgQU47pH6PXcZRRLKLscQbeC
# FcdDbAkwDQYJKoZIhvcNAQEBBQAEgYCqHkglX0/PDAjwjpBxqvyUa6skFtgOwMHR
# oo6uBrb6lGrkpMiWmd/bK+y96+0BJ41y5sXqCJrO2piXQvLtfPTa9MUb48CgwAqy
# Yy1rUsNzxKsu2WIhtyeBshktFT6HqH9XEEKWIhZSqn0u3Ctkn1DI7vWBm2oQ3lRJ
# ZtaG8pdbLA==
# SIG # End signature block
