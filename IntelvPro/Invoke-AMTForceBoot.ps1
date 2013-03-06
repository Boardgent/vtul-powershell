Function Invoke-AMTForceBoot {
<#
  .Synopsis 
    Invokes the Intel Active Management Technology force boot command 
  .Description
    This CmdLet invokes an Intel Active Management Technology (AMT) force boot to a PXE server, the local hard drive, CD/DVD ROM drive, or remote DVD/CD ISO image from clients that have Intel AMT firmware version 3.0 or higher.
  .Notes
    Supported AMT Firmware Versions: 3.0 or higher.
    
   AMT Provisioning:
      The vPro client AMT firmware must be provisioned prior to accessing AMT functionality. This Cmdlet will fail if it is run against a vPro client that has not been provisioned.
        
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
    Invoke-AMTForceBoot vproclient.vprodemo.com -TLS -Operation:PowerOn -Device:PXE -Credential $AMTCredential

    ComputerName            Port                    Operation               Device                  Status
    ------------            ----                    ---------               ------                  ------
    vproclient.vprodemo.com 16993                   PowerOn                 PXE                     Successful
  .Example
    Invoke-AMTForceBoot vproclient.vprodemo.com -Operation PowerOn -Device:HardDrive -Username:vprodemo\ITHelpDesk

    Will prompt for Kerberos username password.

    ComputerName            Port                    Operation               Device                  Status
    ------------            ----                    ---------               ------                  ------
    vproclient.vprodemo.com 16992                   PowerOn                 HardDrive               Successful
  .Example
    Invoke-AMTForceBoot vproclient -Operation:Reset -Device:IDER -IDERPath:"C:\bootable_image.iso" -Credential $AMTCredential
             
    Will boot remote client to ISO img with no SOL interaction.
 	
    ComputerName            Port                    Operation               Device                  Status
    ------------            ----                    ---------               ------                  ------
    vproclient              16992                   PowerOn                 IDER                    Successful
  .Example
    Invoke-AMTForceBoot Computer:vproclient -Operation:Reset -Device:BIOSSetup -Credential $AMTCredential -Console SOL -SOLTerminalPath $SOLTerminalPath -SOLTerminalArgList $SOLTerminalArgList
             
    Will boot remote client to BIOS with SOL interaction through a specifed terminal client.
	To use Microsoft telnet the following would be defined
	$SOLTerminalPath = "telnet"
	$SOLTerminalArgList = "-t ANSI 127.0.0.1 %Port"
 	The $SOLTerminalArgList must have a %Port defined so the CMDLet will know where to insert the port

    ComputerName            Port                    Operation               Device                  Status
    ------------            ----                    ---------               ------                  ------
    vproclient              16992                   PowerOn                 BIOSSetup               Successful
  .Example
    Invoke-AMTForceBoot -ComputerName computer1.vprodemo.com,doesnotexist.vprodemo.com -TLS -Operation Reset -Device:Optical | Where {$_.Status -eq "Failed"}

    Will perform the power operation on every AMT client in the list, but only display the ones that failed.

    ComputerName            Port                    Operation               Device                  Status
    ------------            ----                    ---------               ------                  ------
    doesnotexist.vprodem... 16993                   Reset                   Optical                 Failed
  .Example
    Get-Content computers.txt | Invoke-AMTForceBoot -TLS -Operation:PowerOn -Device:PXE

    Will pull the list of amt clients from a text file and pipe them in the Invoke-AMTForceBoot CMDLet.

    ComputerName            Port                    Operation               Device                  Status
    ------------            ----                    ---------               ------                  ------
    computer1.vprodemo.com  16993                   PowerOn                 PXE                     Successful
    computer2.vprodemo.com  16993                   PowerOn                 PXE                     Successful
    computer3.vprodemo.com  16993                   PowerOn                 PXE                     Successful
  .Example
    Get-SomeDataFromOtherCMDLet | Select ComputerName | Invoke-AMTForceBoot -TLS -Operation PowerOn -Device:HardDrive 

    Get-SomeDataFromOtherCMDLet is a custom script that has an output of ComputerName, Port, and Operation; however, you only select ComputerName.  Remaining parameters are manually provided.

    ComputerName            Port                    Operation               Device                  Status
    ------------            ----                    ---------               ------                  ------
    computer1.vprodemo.com  16993                   PowerOn                 HardDrive               Successful
    computer2.vprodemo.com  16993                   PowerOn                 HardDrive               Successful
    computer3.vprodemo.com  16993                   PowerOn                 HardDrive               Successful
  .Example  
    Invoke-AMTForceBoot vproclient.vprodemo.com -Operation:Reset -Device:BIOSSetup -Credential $AMTCredential -Console SOL -SOLTerminalPath "telnet" -SOLTerminalArgList "-t ANSI 127.0.0.1 %Port" 
   
    This will reboot the client to the BIOS Setup screens while connecting SOL to a telnet window.

    Ok

    ComputerName : 192.168.1.106
    Port         : 16992
    Operation    : reset
    Device       : BIOSSetup
    Status       : Successful

#>
[CmdletBinding()]
Param (
	[Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true, position=0, HelpMessage="Hostname, FQDN, or IP Address")] [String[]] $ComputerName,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=1, HelpMessage="Valid Ports are 16992 (non-TLS) or 16993 (TLS)")][ValidateSet("16992", "16993")] [String] $Port,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Use TLS (Port 16993)")] [switch] $TLS,  
	[Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=2, HelpMessage="Valid Operations are PowerOn or Reset")][ValidateSet("PowerOn", "Reset")] [String] $Operation,
	[Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=3, HelpMessage="Valid Devices are Default, HardDrive, PXE, Optical, IDER or BIOSSetup")][ValidateSet("Default", "HardDrive", "PXE", "Optical", "IDER", "BIOSSetup")] [String] $Device,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=4, HelpMessage="Enter valid path to ISO or IMG file")] [String] $IDERPath,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=5, HelpMessage="Valid Consoles are SOL")][ValidateSet("SOL")] [String] $Console,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=6, HelpMessage="Path to SOL console")] [String] $SOLTerminalPath,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=7, HelpMessage="Path to SOL console")] [String] $SOLTerminalArgList,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Digest or Kerberos User")] [string] $Username,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Digest or Kerberos Password")] [string] $Password,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=8, HelpMessage="PS Credential")] [System.Management.Automation.PSCredential] $Credential
)


Process {
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

	switch ($Operation) {
	  "PowerOn" {$PowerInt = 2}
	  "Reset" {$PowerInt = 10}
	}

	if($Console -eq "SOL")
		{
			if($SOLTerminalArgList -ne "")
			{
				if($SOLTerminalArgList.contains("%Port")) {}
				else
				{
				write-output ""
				write-output 'The $SOLTerminalArgList parameter must contain a "%Port" parameter.'
				write-output 'To use Microsoft telnet the following would be defined'
				write-output '$SOLTerminalPath = "telnet"'
				write-output '$SOLTerminalArgList = "-t ANSI 127.0.0.1 %Port"'
				write-output ""
				return
				}		
			}

			if(($SOLTerminalPath -eq "") -or ($SOLTerminalArgList -eq ""))
			{
				write-output ""
				write-output 'If "-console SOL" is specifed:'
				write-output '  -SOLTerminalPath parameter containing the path to the terminal application must be present.'
				write-output '  -SOLTerminalArgList parameter containing the arguments to pass to the terminal application must be present.'

				write-output 'To use Microsoft telnet the following would be defined'
				write-output '$SOLTerminalPath = "telnet"'
				write-output '$SOLTerminalArgList = "-t ANSI 127.0.0.1 %Port"'
				write-output ""
				return
			}
		}
	

	$Results = @()
	ForEach ($Comp in $ComputerName) {
		$Obj = new-object psobject
	
		try {
			#Attempt Connection with Client
			$Connection.SetHost($Comp, $Port)
			#Identify if redirection library required
			if (($device -eq "IDER") -or ($console -eq "SOL")) {
	
				if ($device -eq "IDER") {
					$IDERPath = $IDERPath.ToLower()

					#params for doing redirection
					if ($IDERPath.EndsWith("iso")) {
						$floppyFile = "$env:TEMP\floppy.img"
						$cdFile = $IDERPath
						$iderBootDevice = "1"

						write-host "Performing IDER boot with CD image."
					} elseif ($IDERPath.EndsWith("img")) {
						$cdFile = "$env:TEMP\cd.iso"
						$floppyFile = $IDERPath
						$iderBootDevice = "0"
						write-host "Performing IDER boot with floppy image."
					} else {
						write-host "You must enter a valid ISO or IMG file."
						return
					}
				}

				$cimRef = $Connection.NewReference("SELECT * FROM http://intel.com/wbem/wscim/1/amt-schema/1/AMT_RedirectionService")
				$cimObj = $cimRef.Get();
				if (!$cimObj.GetProperty("EnabledState").ToString().Equals("32771")) {
					$cimObj.SetProperty("EnabledState", "32771")
					$cimRef.Put($cimObj)
				}
				if ($cimObj.GetProperty("ListenerEnabled").ToString().Equals("false")) {
					$cimObj.SetProperty("ListenerEnabled", "true")
					$cimRef.Put($cimObj)
				}
	
				$LibSettingsFile="$env:TEMP\MC.ini"
				$CertTrustFile="$env:TEMP\certs.pem"

				$imrLib = New-Object Intel.Management.Redirection.MediaRedirection

				#Initialize the Intel Media Redirection Library (imrLib)
				[Intel.Management.Redirection.IMRVersion]$libVersion = New-Object Intel.Management.Redirection.IMRVersion
				$imrResult = $imrLib.Init([ref] $libVersion, $LibSettingsFile)
				$imrResult=$imrLib.SetCertificateInfo($CertTrustFile, "", "")

				#define a redirection client based on the WsmanConnection Address
				$imrClient = $imrLib.GetClientInfo($Connection.Address)

				#add the redirection client to the Library (Library return a value clientID)
				[System.UInt32]$clientId=[System.UInt32]::MaxValue
				$imrResult = $imrLib.AddClient($imrClient, [ref] $clientId)

				if ($device -eq "IDER") {
					#create redirection session parameters (e.g user name and password) based on the Wsman Connection
					$iderParams = $imrLib.CreateSessionParams($Connection.Username, $Connection.Password)

					#define session timeouts
					$iderTimeouts = $imrLib.GetDefaultIDERTout()

					#Open an IDER session
					$imrResult = $imrLib.IDEROpenTCPSession($clientId, $iderParams, $iderTimeouts, $floppyFile, $cdFile)

					#after opening the session the next thing we will do is send a command to enable the IDER device for immediate use
					[Intel.Management.Redirection.IDERDeviceResult]$deviceResult = New-Object Intel.Management.Redirection.IDERDeviceResult
					[Intel.Management.Redirection.IDERDeviceCmd]$deviceCommand = New-Object Intel.Management.Redirection.IDERDeviceCmd

					$deviceCommand.pri_op = [Intel.Management.Redirection.SetOperation]::Enable
					$deviceCommand.pri_timing = [Intel.Management.Redirection.SetOption]::Immediately

					#enable the ider device for immediate use by setting the device state
					$imrResult = $imrLib.IDERSetDeviceState($clientId, $deviceCommand, [ref] $deviceResult);
				}

				if ($console -eq "SOL") {
					#create redirection session parameters (e.g user name and password) based on the Wsman Connection
					$solParams = $imrLib.CreateSessionParams($Connection.Username, $Connection.Password)

					#define session timeouts
					$solTimeouts = $imrLib.GetDefaultSOLTout()

					#openSol Session
					$imrResult = $imrLib.SOLOpenTCPSession($clientId, $solParams, $solTimeouts, $imrLib.GetDefaultSOLParams())

					Write-Host $imrResult

					$link= $imrLib.CreateTerminalLink($clientId);
					if($link.Open() -eq $false) {
						write-output "Error opening SOL Link"
						return
					}
				}
			}
		
			#Set the boot source
			$SourceRef = $Connection.NewReference("CIM_BootSourceSetting")

			switch ($Device) {
				"HardDrive" {$InstanceID = 'Intel(r) AMT: Force Hard-drive Boot'}
				"PXE" {$InstanceID = 'Intel(r) AMT: Force PXE Boot'}
				"Optical" {$InstanceID = 'Intel(r) AMT: Force CD/DVD Boot'}
			}

			$SourceRef.AddSelector("InstanceID", $InstanceID)

			$objRef = $Connection.NewReference("CIM_BootConfigSetting")
			$objRef.AddSelector("InstanceID", 'Intel(r) AMT: Boot Configuration 0')

			$InputObj = $objRef.CreateMethodInput("ChangeBootOrder")
			if (($device -eq "HardDrive") -or ($device -eq "PXE") -or ($device -eq "Optical")) {
				$InputObj.SetProperty("source", $SourceRef)
			}

			$OutObj = $objRef.InvokeMethod($InputObj)

			#Set the AMT boot settings
			$cimRef = $Connection.NewReference("SELECT * FROM AMT_BootSettingData")
			$cimObj = $cimRef.Get()


			if ($device -eq "IDER") {
				$cimObj.SetProperty("UseIDER", "true")
				$cimObj.SetProperty("IDERBootDevice", $iderBootDevice)
			} else {
				$cimObj.SetProperty("UseIDER", "false")
			}

			if ($device -eq "BIOSSetup") {
				$cimObj.SetProperty("BIOSSetup", "true")
			} else {
				$cimObj.SetProperty("BIOSSetup", "false")
			}

			if ($console -eq "SOL") {
				$cimObj.SetProperty("UseSOL", "true")
			} else {
				$cimObj.SetProperty("UseSOL", "false")
			}

			$cimObj.SetProperty("BootMediaIndex", "0");
			$cimObj.SetProperty("UserPasswordBypass", "false")
			$putResult=$cimRef.Put($cimObj)

			$BootConfigSettingRef = $Connection.NewReference("CIM_BootConfigSetting")
			$BootConfigSettingRef.AddSelector("InstanceID", 'Intel(r) AMT: Boot Configuration 0')

			$objRef = $Connection.NewReference("CIM_BootService")
			$InputObj = $objref.CreateMethodInput("SetBootConfigRole")
			$InputObj.SetProperty("BootConfigSetting", $BootConfigSettingRef)
			$InputObj.SetProperty("Role", "1")
			$OutObj = $objRef.InvokeMethod($InputObj)

			#Get a reference to the ManagedSystem (User of the Service)
			$UserRef = $Connection.NewReference("SELECT * from CIM_ComputerSystem WHERE Name='ManagedSystem'")

			#Get the Instance of CIM_AssociatedPowerManagmentService for the ManagedSystem
			$ObjRef = $Connection.NewReference("CIM_AssociatedPowerManagementService");
			$ObjRef.AddSelector("UserOfService", $userRef);
			$AssociatedObj = $ObjRef.Get()

			#Get current power state
			$PowerState = $AssociatedObj.GetProperty("PowerState").ToString()

			#If client in S4/S5 then poweron operation otherwise reset operation
			if (($PowerState -eq 8) -or ($PowerState -eq 7)) {
				$PowerInt = 2
			} else {
				$PowerInt = 10
			}

			#Now associate to the Provider of the Service (CIM_PowerManagementService)
			$ServiceRef = $AssociatedObj.GetProperty("ServiceProvided").Ref

			#Now invoke the RequestPowerStateChange
			$InputObj = $ServiceRef.CreateMethodInput("RequestPowerStateChange")
			$InputObj.SetProperty("PowerState", "$PowerInt")
			$InputObj.SetProperty("ManagedElement", $UserRef)
			$OutObj = $ServiceRef.InvokeMethod($InputObj);

			#Note Return Status
			$ReturnValue = $OutObj.GetProperty("ReturnValue").ToString()


			#Display SOL console
			if ($console -eq "SOL") {					
				$argumentlist = $SOLTerminalArgList.replace("%Port", $link.Port)
				
				start-process -FilePath $SOLTerminalPath -ArgumentList $argumentlist -Wait
			
			}


			#Identify if redirection library required
			if ($console -eq "SOL") {
				$link.Close()

				#close the session
				$imrResult = $imrLib.SOLCloseSession($clientId)
				#close the library
				$imrResult = $imrLib.Close()
			}

			if ($device -eq "IDER") {
				write-host -NoNewLine "Press any key to end the IDER session with" $Comp
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				write-host ""

				#close the session
				$imrResult = $imrLib.IDERCloseSession($clientId)
				#close the library
				$imrResult = $imrLib.Close()
			}
 
			#Add Member to Object. Include Computer Name and Operation success 
			$Obj | Add-Member -MemberType noteproperty -Name ComputerName -value $Comp
			$Obj | Add-Member -MemberType noteproperty -Name Port -value $Port
			$Obj | Add-Member -MemberType noteproperty -Name Operation -value $Operation
			$Obj | Add-Member -MemberType noteproperty -Name Device -value $Device
			if ($ReturnValue -eq 0) {
				$Obj | Add-Member -MemberType noteproperty -Name Status -value "Successful"
			} else {
				$Obj | Add-Member -MemberType noteproperty -Name Status -value "Failed"
			}

		} catch {
				if($_.ToString().Contains("Unauthorized"))
				{
					$Obj | Add-Member -MemberType noteproperty -Name Status -value "Unauthorized"
				} 
				 else
				{
					$obj | Add-Member -MemberType noteproperty -Name Status -value "Cannot connect"	
				}

			#Close the library
			if ($imrLib) {
				$imrResult = $imrLib.Close()
			}
		}

		#Append to Result 
		$Results += $Obj
	}

	#Write out Results
	Write-Output $Results

}

}

# SIG # Begin signature block
# MIIZSAYJKoZIhvcNAQcCoIIZOTCCGTUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUR9/M94a9pai7TtGZOsBqn5ND
# lkKgghWzMIIDPTCCAqagAwIBAgIDBbD/MA0GCSqGSIb3DQEBBQUAME4xCzAJBgNV
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
# ARUwIwYJKoZIhvcNAQkEMRYEFOIMMpZ2wc7JYACRut9wGvfA2e02MA0GCSqGSIb3
# DQEBAQUABIGAaFH588PbJaON4OZ/cdZdruaAFsDsAuZEHDtoGjdVTI+eDXoxXd/B
# M6lK5PQFeztMp5m2xfVLGO1hL7Ce2kAGQ1YUraTB7alUrrGc9mIEP8Pxwfo6vNgx
# uTcTgDqEzUhiXvUso4nPOecePYy692px6LR23X44ajPbuP6Nq70fp+yhggF/MIIB
# ewYJKoZIhvcNAQkGMYIBbDCCAWgCAQEwZzBTMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMOVmVyaVNpZ24sIEluYy4xKzApBgNVBAMTIlZlcmlTaWduIFRpbWUgU3RhbXBp
# bmcgU2VydmljZXMgQ0ECEHmipYX50RVCE9m4Pva2je0wCQYFKw4DAhoFAKBdMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTEyMDcxNzIw
# MTM1N1owIwYJKoZIhvcNAQkEMRYEFGIIowDuvwDlwTpTVqd9ibq+HCxaMA0GCSqG
# SIb3DQEBAQUABIGAWQ0HyqNfBuhEZO5A2DyI0RoXPb3q25CismNzTPPsnomMouYx
# MaCOvrfPaeZK4lnJFuOwH489GCDcPFgFjgC/EOrOpBdQRlOTxEZ8BNjZ7+Lhq07g
# OkK5SPd9p3mjTcwC8/DbXsAVCyzc5b+gzXPyzZde+9ZSIOlkmPLxCOgoE8M=
# SIG # End signature block
