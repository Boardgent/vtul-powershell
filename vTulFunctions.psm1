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
		[CmdletBinding()]
	    
	    Param(
   	        [string]$ComputerName
	    )
	
	    # Branch of the Registry  
		$Branch='LocalMachine'  
		 
		# Main Sub Branch you need to open  
		$SubBranch="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"  
		 
		$registry=[microsoft.win32.registrykey]::OpenRemoteBaseKey('Localmachine',$computername)  
		$registrykey=$registry.OpenSubKey($Subbranch)  
		$SubKeys=$registrykey.GetSubKeyNames()  
		 
		# Drill through each key from the list and pull out the value of  
		# ?DisplayName? ? Write to the Host console the name of the computer  
		# with the application beside it  
		$AllSoftware = @()
		Foreach ($key in $subkeys)  
		{  
		    $exactkey=$key  
		    $NewSubKey=$SubBranch+"\\"+$exactkey  
		    $ReadUninstall=$registry.OpenSubKey($NewSubKey)
		    $Value=$ReadUninstall.GetValue("DisplayName")
			if ($Value){
			$AllSoftware += $Value
			}
		}  
		return $AllSoftware
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
$SaveFileDialog.filter = "Text File (*.txt)| *.txt"
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
$SaveFileDialog.filter = "Comma Delimited (*.csv)| *.csv"
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
		$Target += $Computer.DNSHostName
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

# SIG # Begin signature block
# MIIfXQYJKoZIhvcNAQcCoIIfTjCCH0oCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbPha/6Inhgkv3xQ1Ja7facU3
# bOKgghqTMIIGbzCCBVegAwIBAgIQA4uW8HDZ4h5VpUJnkuHIOjANBgkqhkiG9w0B
# AQUFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVk
# IElEIENBLTEwHhcNMTIwNDA0MDAwMDAwWhcNMTMwNDE4MDAwMDAwWjBHMQswCQYD
# VQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJTAjBgNVBAMTHERpZ2lDZXJ0IFRp
# bWVzdGFtcCBSZXNwb25kZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDGf7tj+/F8Q0mIJnRfituiDBM1pYivqtEwyjPdo9B2gRXW1tvhNC0FIG/BofQX
# Z7dN3iETYE4Jcq1XXniQO7XMLc15uGLZTzHc0cmMCAv8teTgJ+mn7ra9Depw8wXb
# 82jr+D8RM3kkwHsqfFKdphzOZB/GcvgUnE0R2KJDQXK6DqO+r9L9eNxHlRdwbJwg
# wav5YWPmj5mAc7b+njHfTb/hvE+LgfzFqEM7GyQoZ8no89SRywWpFs++42Pf6oKh
# qIXcBBDsREA0NxnNMHF82j0Ctqh3sH2D3WQIE3ome/SXN8uxb9wuMn3Y07/HiIEP
# kUkd8WPenFhtjzUmWSnGwHTPAgMBAAGjggM6MIIDNjAOBgNVHQ8BAf8EBAMCB4Aw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCCAcQGA1UdIASC
# AbswggG3MIIBswYJYIZIAYb9bAcBMIIBpDA6BggrBgEFBQcCARYuaHR0cDovL3d3
# dy5kaWdpY2VydC5jb20vc3NsLWNwcy1yZXBvc2l0b3J5Lmh0bTCCAWQGCCsGAQUF
# BwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUA
# cgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMA
# YwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMAZQByAHQA
# IABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkAbgBnACAA
# UABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkA
# bQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4A
# YwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYA
# ZQByAGUAbgBjAGUALjAfBgNVHSMEGDAWgBQVABIrE5iymQftHt+ivlcNK2cCzTAd
# BgNVHQ4EFgQUJqoP9EMNo5gXpV8S9PiSjqnkhDQwdwYIKwYBBQUHAQEEazBpMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKG
# NWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENB
# LTEuY3J0MH0GA1UdHwR2MHQwOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRENBLTEuY3JsMDigNqA0hjJodHRwOi8vY3JsNC5k
# aWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURDQS0xLmNybDANBgkqhkiG9w0B
# AQUFAAOCAQEAvCT5g9lmKeYy6GdDbzfLaXlHl4tifmnDitXp13GcjqH52v4k498m
# bK/g0s0vxJ8yYdB2zERcy+WPvXhnhhPiummK15cnfj2EE1YzDr992ekBaoxuvz/P
# MZivhUgRXB+7ycJvKsrFxZUSDFM4GS+1lwp+hrOVPNxBZqWZyZVXrYq0xWzxFjOb
# vvA8rWBrH0YPdskbgkNe3R2oNWZtNV8hcTOgHArLRWmJmaX05mCs7ksBKGyRlK+/
# +fLFWOptzeUAtDnjsEWFuzG2wym3BFDg7gbFFOlvzmv8m7wkfR2H3aiObVCUNeZ8
# AB4TB5nkYujEj7p75UsZu62Y9rXC8YkgGDCCBoUwggVtoAMCAQICEAoRwI5hesxJ
# rmI9b3rpSsowDQYJKoZIhvcNAQEFBQAwczELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEyMDAGA1UE
# AxMpRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2UgQ29kZSBTaWduaW5nIENBLTEwHhcN
# MTIxMDAyMDAwMDAwWhcNMTMxMjA2MTIwMDAwWjBTMQswCQYDVQQGEwJDTzEaMBgG
# A1UEBwwRQm9nb3TDoSwgQ29sb21iaWExEzARBgNVBAoTClR1bHBlcCBTQVMxEzAR
# BgNVBAMTClR1bHBlcCBTQVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDAD6mSHDZ0aJJ7Wj1tZpU+afBusiRHaf9/oaxaYCi549jbe0qGAEBo3aZPL7CB
# nzoBv5zyMicaTWZhSUgJBoL8rjY3/sWRzJm20m0OJd+mOZ8H2c00jH0sCboPJYWc
# chyRPTMJATwIk9Oebl/0ze15h9RVvU/lcmlxcyWqGiBWYh5ilMKVWFA0+KEQNEco
# rw8WXlIdZdPYmkxkFjxmgbEqg/Pk4cVIrsPCu7kqIc6BBN/TpCuwz8bfBPY+1q4+
# ycc0ij0tUYNUwNS06F9LAfnwIHzHd+JuH/R3yIm1rFjAfB9ky5nb+I1MkRZ+FW29
# 0Sq7axV7XEZiLvNCXB8KKKZfAgMBAAGjggMzMIIDLzAfBgNVHSMEGDAWgBSXSAPr
# FQhrubJYI8yULvHGZdJkjjAdBgNVHQ4EFgQU2PqO8IlmzfPc6ieNK5y5FZ8cNS8w
# DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMGkGA1UdHwRiMGAw
# LqAsoCqGKGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9oYS1jcy0yMDExYS5jcmww
# LqAsoCqGKGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9oYS1jcy0yMDExYS5jcmww
# ggHEBgNVHSAEggG7MIIBtzCCAbMGCWCGSAGG/WwDATCCAaQwOgYIKwYBBQUHAgEW
# Lmh0dHA6Ly93d3cuZGlnaWNlcnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0w
# ggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgA
# aQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQA
# ZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcA
# aQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwA
# eQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkA
# YwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEA
# cgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIA
# eQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wgYYGCCsGAQUFBwEBBHoweDAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFAGCCsGAQUFBzAChkRodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlQ29k
# ZVNpZ25pbmdDQS0xLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBBQUAA4IB
# AQCFocEfKdaqUyFBoVGG/myYz6nB6W3TxS3jNRGiEyBzFKo+lRctDL3ViN29gu2P
# SeuFMuDsFfeXcXu+GMeRQzMJRscg8a6WoN/8np9cDC/eoe61wL5BkMjgPod27NUL
# rIqeYIGrM61bYXhnDSrUcJFuwhvCa5/tNhXOCkxdmyf1hv+qlfttRkF9Vcu1dWvo
# fOvnlQ2aBVJeCQaokItOBHbIyg/cV1Hoy2SMonKak0OEWw9yqt5vWOrG+OZnG7di
# hVbFC1BKEa1Xe5wZYbGxpYn6dPsZYCiHhYC7Z70p/Gp1B3Vbim0di8qW18x+oceZ
# atbVHetJA/OTMLYAUQfLDG2mMIIGwjCCBaqgAwIBAgIQAsTR5YpKaAxWjaMEfn5N
# XzANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdp
# Q2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMB4XDTExMDIxMTEyMDAwMFoX
# DTI2MDIxMDEyMDAwMFowczELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEyMDAGA1UEAxMpRGlnaUNl
# cnQgSGlnaCBBc3N1cmFuY2UgQ29kZSBTaWduaW5nIENBLTEwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQDF+SPmlCfEgBSkgDJfQKONb3DA5TZxcTp1pKoa
# kpSJXqwjcctOZ31BP6rjS7d7vp3BqDiPaS86JOl3WRLHZgRDwg0mgolAGfIs6udM
# 53wFGrj/iAlPJjfvOqT6ImyIyUobYfKuEF5vvNF5m1kYYOXuKbUDKqTO8YMZT2kF
# cygJ+yIQkyKgkBkaTDHy0yvYhEOvPGP/mNsg0gkrVMHq/WqD5xCjEnH11tfhEnrV
# 4FZazuoBW2hlW8E/WFIzqTVhTiLLgco2oxLLBtbPG00YfrmSuRLPQCbYmjaFsxWq
# R5OEawe7vNWz3iUAEYkAaMEpPOo+Le5Qq9ccMAZ4PKUQI2eRAgMBAAGjggNXMIID
# UzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwggHDBgNVHSAE
# ggG6MIIBtjCCAbIGCGCGSAGG/WwDMIIBpDA6BggrBgEFBQcCARYuaHR0cDovL3d3
# dy5kaWdpY2VydC5jb20vc3NsLWNwcy1yZXBvc2l0b3J5Lmh0bTCCAWQGCCsGAQUF
# BwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUA
# cgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMA
# YwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMAZQByAHQA
# IABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkAbgBnACAA
# UABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkA
# bQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4A
# YwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYA
# ZQByAGUAbgBjAGUALjASBgNVHRMBAf8ECDAGAQH/AgEAMH8GCCsGAQUFBwEBBHMw
# cTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEkGCCsGAQUF
# BzAChj1odHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNz
# dXJhbmNlRVZSb290Q0EuY3J0MIGPBgNVHR8EgYcwgYQwQKA+oDyGOmh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVlJvb3RDQS5j
# cmwwQKA+oDyGOmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEhpZ2hB
# c3N1cmFuY2VFVlJvb3RDQS5jcmwwHQYDVR0OBBYEFJdIA+sVCGu5slgjzJQu8cZl
# 0mSOMB8GA1UdIwQYMBaAFLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEB
# BQUAA4IBAQBJ63xgvq7vyXyzxbpLZN8WaeKG+inZ3piFfUBmJjMvRFWqqpDpNXAK
# NL7TrlQujmUA1noyID5sJriYqTmxvJXHqun17kZmxrPoEvizl53/dFiCNJl1UKxE
# j+iSzn2LDzGWx9zTETCYdBbG5WtFdqOUAc0zAHpI9m+GMclWKzMi1fgBtkTOjLTK
# iNLkFuPn9uI+4QnAnXlDQ39VXAWtkxDGLA1rwJ7qeOXSd9a42pqYf7pMkiudvaSI
# sd2vw0zSl5sDxq5fG0QPMzcV48v/L1bTFqRbVWedosrbNGwMc0q1e6S2s+k1Anhw
# 7AB6y/xLTyI2uxSEyY+R3Q88dYzKC4jnMIIGzTCCBbWgAwIBAgIQBv35A5YDreoA
# Cus/J7u6GzANBgkqhkiG9w0BAQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQD
# ExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcN
# MjExMTEwMDAwMDAwWjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2Vy
# dCBBc3N1cmVkIElEIENBLTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDogi2Z+crCQpWlgHNAcNKeVlRcqcTSQQaPyTP8TUWRXIGf7Syc+BZZ3561JBXC
# mLm0d0ncicQK2q/LXmvtrbBxMevPOkAMRk2T7It6NggDqww0/hhJgv7HxzFIgHwe
# og+SDlDJxofrNj/YMMP/pvf7os1vcyP+rFYFkPAyIRaJxnCI+QWXfaPHQ90C6Ds9
# 7bFBo+0/vtuVSMTuHrPyvAwrmdDGXRJCgeGDboJzPyZLFJCuWWYKxI2+0s4Grq2E
# b0iEm09AufFM8q+Y+/bOQF1c9qjxL6/siSLyaxhlscFzrdfx2M8eCnRcQrhofrfV
# dwonVnwPYqQ/MhRglf0HBKIJAgMBAAGjggN6MIIDdjAOBgNVHQ8BAf8EBAMCAYYw
# OwYDVR0lBDQwMgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUH
# AwQGCCsGAQUFBwMIMIIB0gYDVR0gBIIByTCCAcUwggG0BgpghkgBhv1sAAEEMIIB
# pDA6BggrBgEFBQcCARYuaHR0cDovL3d3dy5kaWdpY2VydC5jb20vc3NsLWNwcy1y
# ZXBvc2l0b3J5Lmh0bTCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMA
# ZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8A
# bgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAA
# dABoAGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAA
# dABoAGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0A
# ZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQA
# eQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgA
# ZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1s
# AxUwEgYDVR0TAQH/BAgwBgEB/wIBADB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNy
# dDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDQuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAdBgNVHQ4EFgQU
# FQASKxOYspkH7R7for5XDStnAs0wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6ch
# nfNtyA8wDQYJKoZIhvcNAQEFBQADggEBAEZQPsm3KCSnOB22WymvUs9S6TFHq1Zc
# e9UNC0Gz7+x1H3Q48rJcYaKclcNQ5IK5I9G6OoZyrTh4rHVdFxc0ckeFlFbR67s2
# hHfMJKXzBBlVqefj56tizfuLLZDCwNK1lL1eT7EF0g49GqkUW6aGMWKoqDPkmzmn
# xPXOHXh2lCVz5Cqrz5x2S+1fwksW5EtwTACJHvzFebxMElf+X+EevAJdqP77BzhP
# DcZdkbkPZ0XN1oPt55INjbFpjE/7WeAjD9KqrgB87pxCDs+R1ye3Fu4Pw718CqDu
# LAhVhSK46xgaTfwqIa1JMYNHlXdx3LEbS0scEJx3FMGdTy9alQgpECYxggQ0MIIE
# MAIBATCBhzBzMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTIwMAYDVQQDEylEaWdpQ2VydCBIaWdo
# IEFzc3VyYW5jZSBDb2RlIFNpZ25pbmcgQ0EtMQIQChHAjmF6zEmuYj1veulKyjAJ
# BgUrDgMCGgUAoHAwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcN
# AQkEMRYEFA2oWJicPCn+7dbE4teOtZ+TGsjKMA0GCSqGSIb3DQEBAQUABIIBAFmg
# U8lgRgX9GYgKKVueZwFJL1g82oFD2Vxwo5bTr3/QCFC5VWFiqlWPrMDKHnAKrL7m
# dqN1LBqcWnT67WidquwbGpx+oxGaptT3v4tws/wLvEvIvDKrXhRpz1R4OliurWRH
# V6WvNxzQ8SzmDN48TpFhEpXaqKUclg1PVy+Wgf5/XUdLzV+Jk4B8njHBHW+iIo2T
# QExajg48sJC/bv6eCEXooYpCMn0co18CbbjMyfdJeko5XU8s3Je9zMO7i9iZlu7e
# EeGzHwr8bQv4jXMh43fwcmjriVuikiSF4RCxKcf4lH7HtLDDhrUgxVhZaO8O/qEp
# KAzZ/cvhtr/K2Kq3YTehggIPMIICCwYJKoZIhvcNAQkGMYIB/DCCAfgCAQEwdjBi
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVkIElEIENB
# LTECEAOLlvBw2eIeVaVCZ5LhyDowCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTEyMTAwMzAwMjEyNFowIwYJKoZI
# hvcNAQkEMRYEFDA56nIC6R3YPgDvAHHRqy/pdBJDMA0GCSqGSIb3DQEBAQUABIIB
# AH8CD5IEWllvqpv9tjdyW+3FpRBFgZ1K7MgX6Qx6WtZF05vEXhpADd/95/vH1VA1
# d/82CETB/mByiWdQpefpDln7sRs2msgr1xYm/GdZJK0X+kdjtgS6v0SnbM7aMGFj
# o76NOI4AMR7b4XSb7trtLmYmVGecVKE4M15MhQ2SXbE+O8PTLiJJnQ/9+0S2wXJS
# meWKiLXdb9gEHmHGMdO7aBoeheSkLhWFnHzYCCMhqkgO93e4PiDa3fRt2bSHwtCI
# sygqBTWzpL3eJXawdaSemYYPFLFPC4Xps5Cx7VM9NbSJmI+7Je10iLeHMyOV1c38
# +KP8vr1kn3cXR4KaDJX/3QQ=
# SIG # End signature block
