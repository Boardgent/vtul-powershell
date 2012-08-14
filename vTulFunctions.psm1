function High-CpuUsage{
		param($Computer,$maximum)
		$Processes = Get-Process -ComputerName $Computer
		$counter = 0
		foreach ($Process in $Processes){
			if ($Process.CPU -ge $maximum){
				$counter++
			}
		}
		if ($counter -eq 1){
			Add-Results "There is $counter process in $Computer with a CPU Usage greater or equal to $maximum"
			Add-Logs "There is $counter process in $Computer with a CPU Usage greater or equal to  $maximum"
		}
		else {
			Add-Results "There are $counter processes in $Computer with a CPU Usage greater or equal to  $maximum"
			Add-Logs "There are $counter processes in $Computer with a CPU Usage greater or equal to  $maximum"
		}
	}

#region Test-Port 
	
	function Test-Port
	{
	        
	    <#
	        .Synopsis 
	            Test a host to see if the specified port is open.
	            
	        .Description
	            Test a host to see if the specified port is open.
	                        
	        .Parameter TCPPort 
	            Port to test (Default 135.)
	            
	        .Parameter Timeout 
	            How long to wait (in milliseconds) for the TCP connection (Default 3000.)
	            
	        .Parameter ComputerName 
	            Computer to test the port against (Default in localhost.)
	            
	        .Example
	            Test-Port -tcp 3389
	            Description
	            -----------
	            Returns $True if the localhost is listening on 3389
	            
	        .Example
	            Test-Port -tcp 3389 -ComputerName MyServer1
	            Description
	            -----------
	            Returns $True if MyServer1 is listening on 3389
	                    
	        .OUTPUTS
	            System.Boolean
	            
	        .INPUTS
	            System.String
	            
	        .Link
	            Test-Host
	            Wait-Port
	            
	        .Notes
	            NAME:      Test-Port
	            AUTHOR:    bsonposh
	            Website:   http://www.bsonposh.com
	            Version:   1
	            #Requires -Version 2.0
	    #>
	    
	    [Cmdletbinding()]
	    Param(
	        [Parameter()]
	        [int]$TCPport = 135,
	        [Parameter()]
	        [int]$TimeOut = 3000,
	        [Alias("dnsHostName")]
	        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
	        [String]$ComputerName = $env:COMPUTERNAME
	    )
	    Begin 
	    {
	        Write-Verbose " [Test-Port] :: Start Script"
	        Write-Verbose " [Test-Port] :: Setting Error state = 0"
	    }
	    
	    Process 
	    {
	    
	        Write-Verbose " [Test-Port] :: Creating [system.Net.Sockets.TcpClient] instance"
	        $tcpclient = New-Object system.Net.Sockets.TcpClient
	        
	        Write-Verbose " [Test-Port] :: Calling BeginConnect($ComputerName,$TCPport,$null,$null)"
	        try
	        {
	            $iar = $tcpclient.BeginConnect($ComputerName,$TCPport,$null,$null)
	            Write-Verbose " [Test-Port] :: Waiting for timeout [$timeout]"
	            $wait = $iar.AsyncWaitHandle.WaitOne($TimeOut,$false)
	        }
	        catch [System.Net.Sockets.SocketException]
	        {
	            Write-Verbose " [Test-Port] :: Exception: $($_.exception.message)"
	            Write-Verbose " [Test-Port] :: End"
	            return $false
	        }
	        catch
	        {
	            Write-Verbose " [Test-Port] :: General Exception"
	            Write-Verbose " [Test-Port] :: End"
	            return $false
	        }
	    
	        if(!$wait)
	        {
	            $tcpclient.Close()
	            Write-Verbose " [Test-Port] :: Connection Timeout"
	            Write-Verbose " [Test-Port] :: End"
	            return $false
	        }
	        else
	        {
	            Write-Verbose " [Test-Port] :: Closing TCP Socket"
	            try
	            {
	                $tcpclient.EndConnect($iar) | out-Null
	                $tcpclient.Close()
	            }
	            catch
	            {
	                Write-Verbose " [Test-Port] :: Unable to Close TCP Socket"
	            }
	            $true
	        }
	    }
	    End 
	    {
	        Write-Verbose " [Test-Port] :: End Script"
	    }
	}  
	#endregion 
#region Invoke-GPUpdate
	function Invoke-GPUpdate(){
		param($ComputerName = ".")
		$targetOSInfo = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
		
		If (
			$targetOSInfo -eq $null){return "Unable to connect to $ComputerName"}
		Else{
			If ($targetOSInfo.version -ge 5.1){Invoke-WmiMethod -ComputerName $ComputerName -Path win32_process -Name create -ArgumentList "gpupdate /target:Computer /force /wait:0"}
			Else{Invoke-WmiMethod -ComputerName $ComputerName -Path win32_process -Name create ?ArgumentList "secedit /refreshpolicy machine_policy /enforce"}
		}
	}
#endregion

#region Get-InstalledSoftware
	
	function Get-InstalledSoftware
	{
	
	    <#
	        .Synopsis
	            Gets the installed software using Uninstall regkey for specified host.
	
	        .Description
	            Gets the installed software using Uninstall regkey for specified host.
	
	        .Parameter ComputerName
	            Name of the Computer to get the installed software from (Default is localhost.)
	
	        .Example
	            Get-InstalledSoftware
	            Description
	            -----------
	            Gets installed software from local machine
	
	        .Example
	            Get-InstalledSoftware -ComputerName MyServer
	            Description
	            -----------
	            Gets installed software from MyServer
	
	        .Example
	            $Servers | Get-InstalledSoftware
	            Description
	            -----------
	            Gets installed software for each machine in the pipeline
	
	        .OUTPUTS
	            PSCustomObject
	
	        .Notes
	            NAME:      Get-InstalledSoftware
	            AUTHOR:    YetiCentral\bshell
	            Website:   www.bsonposh.com
	            #Requires -Version 2.0
	    #>
	
	    [Cmdletbinding()]
	    Param(
	        [alias('dnsHostName')]
	        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
	        [string]$ComputerName = $Env:COMPUTERNAME
	    )
	    begin 
	    {
	
	            Write-Verbose " [Get-InstalledPrograms] :: Start Begin"
	            $Culture = New-Object System.Globalization.CultureInfo("en-US")
	            Write-Verbose " [Get-InstalledPrograms] :: End Begin"
	
	    }
	    process 
	    {
	
	        Write-Verbose " [Get-InstalledPrograms] :: Start Process"
	        if($ComputerName -match "(.*)(\$)$")
	        {
	            $ComputerName = $ComputerName -replace "(.*)(\$)$",'$1'
	
	        }
	        Write-Verbose " [Get-InstalledPrograms] :: `$ComputerName - $ComputerName"
	        Write-Verbose " [Get-InstalledPrograms] :: Testing Connectivity"
	        if(Test-Host $ComputerName -TCPPort 135)
	        {
	            try
	            {
	                $RegKey = Get-RegistryKey -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ComputerName $ComputerName
	                foreach($key in $RegKey.GetSubKeyNames())   
	                {   
	                    $SubKey = $RegKey.OpenSubKey($key)
	                    if($SubKey.GetValue("DisplayName"))
	                    {
	                        $myobj = @{
	                            Name    = $SubKey.GetValue("DisplayName")   
	                            Version = $SubKey.GetValue("DisplayVersion")   
	                            Vendor  = $SubKey.GetValue("Publisher")
	                        }
	                        $obj = New-Object PSObject -Property $myobj
	                        $obj.PSTypeNames.Clear()
	                        $obj.PSTypeNames.Add('BSonPosh.SoftwareInfo')
	                        $obj
	                    }
	                }   
	            }
	            catch
	            {
	                Write-Host " Host [$ComputerName] Failed with Error: $($Error[0])" -ForegroundColor Red
	            }
	        }
	        else
	        {
	            Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
	        }
	        Write-Verbose " [Get-InstalledPrograms] :: End Process"
	
	    }
	}
	
	#endregion 


#region Test-Host 
	
	function Test-Host
	{
	        
	    <#
	        .Synopsis 
	            Test a host for connectivity using either WMI ping or TCP port
	            
	        .Description
	            Allows you to test a host for connectivity before further processing
	            
	        .Parameter Server
	            Name of the Server to Process.
	            
	        .Parameter TCPPort
	            TCP Port to connect to. (default 135)
	            
	        .Parameter Timeout
	            Timeout for the TCP connection (default 1 sec)
	            
	        .Parameter Property
	            Name of the Property that contains the value to test.
	            
	        .Example
	            cat ServerFile.txt | Test-Host | Invoke-DoSomething
	            Description
	            -----------
	            To test a list of hosts.
	            
	        .Example
	            cat ServerFile.txt | Test-Host -tcp 80 | Invoke-DoSomething
	            Description
	            -----------
	            To test a list of hosts against port 80.
	            
	        .Example
	            Get-ADComputer | Test-Host -property dnsHostname | Invoke-DoSomething
	            Description
	            -----------
	            To test the output of Get-ADComputer using the dnshostname property
	            
	            
	        .OUTPUTS
	            System.Object
	            
	        .INPUTS
	            System.String
	            
	        .Link
	            Test-Port
	            
	        NAME:      Test-Host
	        AUTHOR:    YetiCentral\bshell
	        Website:   www.bsonposh.com
	        LASTEDIT:  02/04/2009 18:25:15
	        #Requires -Version 2.0
	    #>
	    
	    [CmdletBinding()]
	    
	    Param(
	    
	        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,Mandatory=$True)]
	        [string]$ComputerName,
	        
	        [Parameter()]
	        [int]$TCPPort=80,
	        
	        [Parameter()]
	        [int]$timeout=3000,
	        
	        [Parameter()]
	        [string]$property
	        
	    )
	    Begin 
	    {
	    
	        function PingServer 
	        {
	            Param($MyHost)
	            $ErrorActionPreference = "SilentlyContinue"
	            Write-Verbose " [PingServer] :: Pinging [$MyHost]"
	            try
	            {
	                $pingresult = Get-WmiObject win32_pingstatus -f "address='$MyHost'"
	                $ResultCode = $pingresult.statuscode
	                Write-Verbose " [PingServer] :: Ping returned $ResultCode"
	                if($ResultCode -eq 0) {$true} else {$false}
	            }
	            catch
	            {
	                Write-Verbose " [PingServer] :: Ping Failed with Error: ${error[0]}"
	                $false
	            }
	        }
	    
	    }
	    
	    Process 
	    {
	    
	        Write-Verbose " [Test-Host] :: Begin Process"
	        if($ComputerName -match "(.*)(\$)$")
	        {
	            $ComputerName = $ComputerName -replace "(.*)(\$)$",'$1'
	        }
	        Write-Verbose " [Test-Host] :: ComputerName   : $ComputerName"
	        if($TCPPort)
	        {
	            Write-Verbose " [Test-Host] :: Timeout  : $timeout"
	            Write-Verbose " [Test-Host] :: Port     : $TCPPort"
	            if($property)
	            {
	                Write-Verbose " [Test-Host] :: Property : $Property"
	                $Result = Test-Port $_.$property -tcp $TCPPort -timeout $timeout
	                if($Result)
	                {
	                    if($_){ $_ }else{ $ComputerName }
	                }
	            }
	            else
	            {
	                Write-Verbose " [Test-Host] :: Running - 'Test-Port $ComputerName -tcp $TCPPort -timeout $timeout'"
	                $Result = Test-Port $ComputerName -tcp $TCPPort -timeout $timeout
	                if($Result)
	                {
	                    if($_){ $_ }else{ $ComputerName }
	                } 
	            }
	        }
	        else
	        {
	            if($property)
	            {
	                Write-Verbose " [Test-Host] :: Property : $Property"
	                try
	                {
	                    if(PingServer $_.$property)
	                    {
	                        if($_){ $_ }else{ $ComputerName }
	                    } 
	                }
	                catch
	                {
	                    Write-Verbose " [Test-Host] :: $($_.$property) Failed Ping"
	                }
	            }
	            else
	            {
	                Write-Verbose " [Test-Host] :: Simple Ping"
	                try
	                {
	                    if(PingServer $ComputerName){$ComputerName}
	                }
	                catch
	                {
	                    Write-Verbose " [Test-Host] :: $ComputerName Failed Ping"
	                }
	            }
	        }
	        Write-Verbose " [Test-Host] :: End Process"
	    
	    }
	    
	}
	    
	#endregion 

#region Get-MotherBoard
	
	function Get-MotherBoard
	{
	        
	    <#
	        .Synopsis 
	            Gets the Mother Board info for specified host.
	            
	        .Description
	            Gets the Mother Board info for specified host.
	            
	        .Parameter ComputerName
	            Name of the Computer to get the Mother Board info from (Default is localhost.) 
	            
	        .Example
	            Get-MotherBoard
	            Description
	            -----------
	            Gets Mother Board info from local machine
	    
	        .Example
	            Get-MotherBoard -ComputerName MyOtherDesktop
	            Description
	            -----------
	            Gets Mother Board info from MyOtherDesktop
	            
	        .Example
	            $Windows7Machines | Get-MotherBoard
	            Description
	            -----------
	            Gets Mother Board info for each machine in the pipeline
	            
	        .OUTPUTS
	            PSCustomObject
	            
	        .INPUTS
	            System.String
	            
	        .Link
	            N/A
	            
	        .Notes
	            NAME:      Get-MotherBoard
	            AUTHOR:    bsonposh
	            Website:   http://www.bsonposh.com
	            Version:   1
	            #Requires -Version 2.0
	    #>
	    
	    [Cmdletbinding()]
	    Param(
	        [alias('dnsHostName')]
	        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
	        [string]$ComputerName = $Env:COMPUTERNAME
	    )
	    
	    Process 
	    {
	    
	        if($ComputerName -match "(.*)(\$)$")
	        {
	            $ComputerName = $ComputerName -replace "(.*)(\$)$",'$1'
	        }
	        if(Test-Host -ComputerName $ComputerName -TCPPort 135)
	        {
	            try
	            {
	                $MBInfo = Get-WmiObject Win32_BaseBoard -ComputerName $ComputerName -ea STOP
	                $myobj = @{
	                    ComputerName     = $ComputerName
	                    Name             = $MBInfo.Product
	                    Manufacturer     = $MBInfo.Manufacturer
	                    Version          = $MBInfo.Version
	                    SerialNumber     = $MBInfo.SerialNumber
	                 }
	                
	                $obj = New-Object PSObject -Property $myobj
	                $obj.PSTypeNames.Clear()
	                $obj.PSTypeNames.Add('BSonPosh.Computer.MotherBoard')
	                $obj
	            }
	            catch
	            {
	                Write-Host " Host [$ComputerName] Failed with Error: $($Error[0])" -ForegroundColor Red
	            }
	        }
	        else
	        {
	            Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
	        }
	    
	    }
	}
	    
	#endregion # Get-MotherBoard

#region Get-Processor
	
	function Get-Processor
	{
	        
	    <#
	        .Synopsis 
	            Gets the Computer Processor info for specified host.
	            
	        .Description
	            Gets the Computer Processor info for specified host.
	            
	        .Parameter ComputerName
	            Name of the Computer to get the Computer Processor info from (Default is localhost.)
	            
	        .Example
	            Get-Processor
	            Description
	            -----------
	            Gets Computer Processor info from local machine
	    
	        .Example
	            Get-Processor -ComputerName MyServer
	            Description
	            -----------
	            Gets Computer Processor info from MyServer
	            
	        .Example
	            $Servers | Get-Processor
	            Description
	            -----------
	            Gets Computer Processor info for each machine in the pipeline
	            
	        .OUTPUTS
	            PSCustomObject
	            
	        .INPUTS
	            System.String
	            
	        .Link
	            N/A
	            
	        .Notes
	            NAME:      Get-Processor
	            AUTHOR:    bsonposh
	            Website:   http://www.bsonposh.com
	            Version:   1
	            #Requires -Version 2.0
	    #>
	    
	    [Cmdletbinding()]
	    Param(
	        [alias('dnsHostName')]
	        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
	        [string]$ComputerName = $Env:COMPUTERNAME
	    )
	    
	    Process 
	    {
	    
	        if($ComputerName -match "(.*)(\$)$")
	        {
	            $ComputerName = $ComputerName -replace "(.*)(\$)$",'$1'
	        }
	        if(Test-Host -ComputerName $ComputerName -TCPPort 135)
	        {
	            try
	            {
	                $CPUS = Get-WmiObject Win32_Processor -ComputerName $ComputerName -ea STOP
	                foreach($CPU in $CPUs)
	                {
	                    $myobj = @{
	                        ComputerName = $ComputerName
	                        Name         = $CPU.Name
	                        Manufacturer = $CPU.Manufacturer
	                        Speed        = $CPU.MaxClockSpeed
	                        Cores        = $CPU.NumberOfCores
	                        L2Cache      = $CPU.L2CacheSize
	                        Stepping     = $CPU.Stepping
	                    }
	                }
	                $obj = New-Object PSObject -Property $myobj
	                $obj.PSTypeNames.Clear()
	                $obj.PSTypeNames.Add('BSonPosh.Computer.Processor')
	                $obj
	            }
	            catch
	            {
	                Write-Host " Host [$ComputerName] Failed with Error: $($Error[0])" -ForegroundColor Red
	            }
	        }
	        else
	        {
	            Write-Host " Host [$ComputerName] Failed Connectivity Test " -ForegroundColor Red
	        }
	    
	    }
	}
	    
	#endregion

#region Get-SaveFileTxt
Function Get-SaveFileTxt($initialDirectory)
{ 
[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
Out-Null

$SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
$SaveFileDialog.ShowHelp = $true
$SaveFileDialog.initialDirectory = $initialDirectory
$SaveFileDialog.AddExtension  = $true
$SaveFileDialog.DefaultExt  = "txt"
$SaveFileDialog.filter = "Text Files (*.txt)| *.txt"
$SaveFileDialog.ShowDialog() | Out-Null
$SaveFileDialog.filename
} 

#endregion Get-SaveFileTxt

#region Get-SaveFileCsv
Function Get-SaveFileCsv($initialDirectory)
{ 
[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
Out-Null

$SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
$SaveFileDialog.ShowHelp = $true
$SaveFileDialog.initialDirectory = $initialDirectory
$SaveFileDialog.AddExtension  = $true
$SaveFileDialog.DefaultExt  = "csv"
$SaveFileDialog.filter = "CSV (Comma Delimited)(*.csv)| *.csv"
$SaveFileDialog.ShowDialog() | Out-Null
$SaveFileDialog.filename
} 

#endregion Get-SaveFileCsv

#region GenereateFormAD
function Add-Node { 
        param ( 
            $selectedNode, 
            $name
        ) 
        $newNode = new-object System.Windows.Forms.TreeNode  
        $newNode.Name = $name 
        $newNode.Text = $name 
        $selectedNode.Nodes.Add($newNode) | Out-Null 
        return $newNode 
} 

function Get-NextLevel {
    param (
        $selectedNode,
        $dn
   )
   
    $OUs = Get-ADObject -Filter 'ObjectClass -eq "organizationalUnit" -or ObjectClass -eq "container"' -SearchScope OneLevel -SearchBase $dn

    If ($OUs -eq $null) {
        $node = Add-Node $selectedNode $dn
    } Else {
        $node = Add-Node $selectedNode $dn
        
        $OUs | % {
            Get-NextLevel $node $_.distinguishedName
        }
    }
}
 
function Build-TreeView { 
    if ($treeNodes)  
    {  
          $treeview1.Nodes.remove($treeNodes) 
        $form1.Refresh() 
    } 
    
    $treeNodes = New-Object System.Windows.Forms.TreeNode 
    $treeNodes.text = "Active Directory Hierarchy" 
    $treeNodes.Name = "Active Directory Hierarchy" 
    $treeNodes.Tag = "root" 
    $treeView1.Nodes.Add($treeNodes) | Out-Null 
     
    $treeView1.add_AfterSelect({ 
        $textbox1.Text = $this.SelectedNode.Name
    }) 
     
    #Generate Module nodes 
    $OUs = Get-NextLevel $treeNodes $strDomainDN
    
    $treeNodes.Expand() 
} 
 
function GenerateFormAD { 
 
    #region Import the Assemblies 
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
    [reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null 
    $objIPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $strDNSDomain = $objIPProperties.DomainName.toLower()
    $strDomainDN = $strDNSDomain.toString().split('.'); foreach ($strVal in $strDomainDN) {$strTemp += "dc=$strVal,"}; $strDomainDN = $strTemp.TrimEnd(",").toLower()
    #endregion 
     
    #region Generated Form Objects 
    $form1 = New-Object System.Windows.Forms.Form 
    $treeView1 = New-Object System.Windows.Forms.TreeView 
    $label1 = New-Object System.Windows.Forms.Label
    $textbox1 = New-Object System.Windows.Forms.TextBox
    $InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState 
	$buttonOk = New-Object 'System.Windows.Forms.Button'
    #endregion Generated Form Objects 
     
    #---------------------------------------------- 
    #Generated Event Script Blocks 
    #---------------------------------------------- 
      
    $OnLoadForm_StateCorrection= 
    {Build-TreeView 
    } 
     
    #---------------------------------------------- 
    #region Generated Form Code 
    $form1.Text = "Import from Active Directory DS" 
    $form1.Name = "form1" 
	$form1.MaximizeBox = $false
    $form1.DataBindings.DefaultDataSourceUpdateMode = 0 
    $form1.ClientSize = New-Object System.Drawing.Size(400,500) 
     
    $treeView1.Size = New-Object System.Drawing.Size(350,375)
    $treeView1.Name = "treeView1" 
    $treeView1.Location = New-Object System.Drawing.Size(15,15)
    $treeView1.DataBindings.DefaultDataSourceUpdateMode = 0 
    $treeView1.TabIndex = 0 
    $form1.Controls.Add($treeView1)
    
    $label1.Name = "label1" 
    $label1.Location = New-Object System.Drawing.Size(15,400)
    $label1.Size = New-Object System.Drawing.Size(350,20)
    $label1.Text = "Active Directory Path:"
    $form1.Controls.Add($label1) 
    
    $textbox1.Name = "textbox1" 
    $textbox1.Location = New-Object System.Drawing.Size(15,425)
    $textbox1.Size = New-Object System.Drawing.Size(350,20)
    $textbox1.Text = ""
    $form1.Controls.Add($textbox1) 
	
	$buttonOk.Name= "ButtonOk"
	$buttonOk.Location = New-Object System.Drawing.Size(15,460)
	$buttonOk.Size = New-Object System.Drawing.Size(350,20)
	$buttonOk.Text = "Ok"
	$buttonOk.add_Click({
	$form1.Close()
	})
	$form1.Controls.Add($buttonOk)
     
     
    #endregion Generated Form Code 
     
    #Save the initial state of the form 
    $InitialFormWindowState = $form1.WindowState 
    #Init the OnLoad event to correct the initial state of the form 
    $form1.add_Load($OnLoadForm_StateCorrection) 
    #Show the Form 
    $form1.ShowDialog()| Out-Null 

	$AdPath = $textbox1.text
	$TargetFullAd = Get-ADComputer -Filter * -SearchBase $AdPath
	$Target = @()
	foreach ($Computer in $TargetFullAd)
	{
		$Target += $Computer.Name
	}
	return $Target
} #Endregion GenerateFormAD

#region Test-PSRemoting
	
	function Test-PSRemoting 
	{ 
	    Param(
	        [alias('dnsHostName')]
	        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
	        [string]$ComputerName
	    )
	    Process
	    {
	        Write-Verbose " [Test-PSRemoting] :: Start Process"
	        if($ComputerName -match "(.*)(\$)$")
	        {
	            $ComputerName = $ComputerName -replace "(.*)(\$)$",'$1'
	        }
	        
	        try 
	        { 
	            
	            $result = Invoke-Command -ComputerName $computername { 1 } -ErrorAction SilentlyContinue
	            
	            if($result -eq 1 )
	            {
	                return $True
	            }
	            else
	            {
	                return $False
	            }
	        } 
	        catch 
	        { 
	            return $False 
	        } 
	    }
	} 
	
	#endregion
