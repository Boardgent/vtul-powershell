Function Start-AMTIDER {
<#
  .Synopsis 
    Starts an Intel Active Management Technology IDE redirection session
  .Description
    This CmdLet starts an Intel Active Management Technology(AMT) IDE redirection(IDER) session to clients that have Intel AMT firmware version 3.0 or higher.
  .Notes
    Supported AMT Firmware Versions: 3.0 and higher

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
    Start-AMTIDER -computername:192.168.1.100 -operation:Reset -iderpath:.\boot.iso -credential:$AMTCredential

    ComputerName                                  IDERSessionID IDERPath                      Status
    ------------                                  ------------- --------                      ------
    192.168.1.100                                             1 boot.iso                      Successful

#>
    [CmdletBinding()]
    Param (
      [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true, position=0, HelpMessage="Hostname, FQDN, or IP Address")] [String[]] $ComputerName,
      [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=1, HelpMessage="Valid Operations are PowerOn or Reset")][ValidateSet("PowerOn", "Reset")] [String] $Operation,
      [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=2, HelpMessage="Enter valid path to ISO or IMG file")] [String] $IDERPath,
      [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Use TLS (Port 16993)")] [switch] $TLS,
      [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Digest of Kerberos User")] [string] $Username,
      [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Digest of Kerberos Password")] [string] $Password,
      [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=3, HelpMessage="PS Credential")] [System.Management.Automation.PSCredential] $Credential
      
    )

    PROCESS {
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

	   switch ($Operation) {
		  "PowerOn" {$PowerInt = 2}
		  "Reset" {$PowerInt = 10}
	   }
       
       if ($TLS.IsPresent) {
         $Port = 16993;
       }
       else {
         $Port = 16992;
       }
	
       $gErrorText
	   $Results = @()
	   ForEach ($Comp in $ComputerName) 
       {
		  $Obj = new-object psobject
        
		  try 
          {
			 #Attempt Connection with Client
			 $Connection.SetHost($Comp, $Port)

             $IDERPath = $IDERPath.ToLower()
                
             #params for doing redirection
             if ($IDERPath.EndsWith("iso"))
             {
                 $floppyFile = "$env:TEMP\floppy.img"
                 $cdFile = $IDERPath
                 $iderBootDevice="1"
             }
             elseif ($IDERPath.EndsWith("img"))
             {
                 $cdFile = "$env:TEMP\cd.iso"
                 $floppyFile = $IDERPath
                 $iderBootDevice="0"
             }
             else
             {
                 write-output "You must enter a valid ISO or IMG file."
                 return
             }

             $LibSettingsFile="$env:TEMP\MC.ini"
             $CertTrustFile="$env:TEMP\certs.pem"
             
             if ((test-path variable:\imrLib) -eq 0)
             {
                New-Variable -scope global -name imrLib -value (New-Object Intel.Management.Redirection.MediaRedirection)
             }

             #Initialize the Intel Media Redirection Library (imrLib)
             [Intel.Management.Redirection.IMRVersion]$libVersion = New-Object Intel.Management.Redirection.IMRVersion
             $imrResult = $global:imrLib.Init([ref] $libVersion,$LibSettingsFile)
             $imrResult=$global:imrLib.SetCertificateInfo($CertTrustFile,"","")

             #define a redirection client based on the WsmanConnection Address
             $imrClient = $global:imrLib.GetClientInfo($Connection.Address)
             
             #add the redirection client to the Library (Library return a value clientID)
             [System.UInt32]$clientId=[System.UInt32]::MaxValue
             $imrResult = $global:imrLib.AddClient($imrClient,[ref] $clientId)
             
             if($imrResult -eq "DuplicateClient")
             {
                $gErrorText = "IDER Session already opened"
                Throw 
             }

             #create redirection session parameters (e.g user name and password) based on the Wsman Connection
             $iderParams = $global:imrLib.CreateSessionParams($Connection.Username,$Connection.Password)

             #define session timeouts
             $iderTimeouts = $global:imrLib.GetDefaultIDERTout()

             #Open an IDER session
             $imrResult = $global:imrLib.IDEROpenTCPSession($clientId, $iderParams, $iderTimeouts,  $floppyFile, $cdFile)
                          
             if($imrResult -eq "InvalidParameter")
             {
                $gErrorText = "Bad IDER file name"
                Throw 
             }
             
             
             #after opening the session the next thing we will do send a command to enable the IDER device for immediate use
             [Intel.Management.Redirection.IDERDeviceResult]$deviceResult = New-Object Intel.Management.Redirection.IDERDeviceResult
             [Intel.Management.Redirection.IDERDeviceCmd]$deviceCommand = New-Object Intel.Management.Redirection.IDERDeviceCmd

             $deviceCommand.pri_op = [Intel.Management.Redirection.SetOperation]::Enable
             $deviceCommand.pri_timing = [Intel.Management.Redirection.SetOption]::Immediately

             #enable the ider device for immediate use by setting the device state
             $imrResult = $global:imrLib.IDERSetDeviceState($clientId, $deviceCommand, [ref] $deviceResult);
                             
             $cimRef = $Connection.NewReference("SELECT * FROM AMT_RedirectionService")
             $cimObj = $cimRef.Get();
                
             if (!$cimObj.GetProperty("EnabledState").ToString().Equals("32771"))
             {
                 $cimObj.SetProperty("EnabledState", "327711")
                 $cimRef.Put($cimObj)
             }
             if ($cimObj.GetProperty("ListenerEnabled").ToString().Equals("false"))
             {
                 $cimObj.SetProperty("ListenerEnabled", "true")
                 $cimRef.Put($cimObj)
             }

             $SourceRef = $Connection.NewReference("CIM_BootSourceSetting")
  
             $SourceRef.AddSelector("InstanceID", $InstanceID)
  
             $objRef = $Connection.NewReference("CIM_BootConfigSetting")
             $objRef.AddSelector("InstanceID", 'Intel(r) AMT: Boot Configuration 0')
             $InputObj = $objRef.CreateMethodInput("ChangeBootOrder") 
             
             $OutObj = $objRef.InvokeMethod($InputObj)
             
             #Set the AMT boot settings
             $cimRef = $Connection.NewReference("SELECT * FROM AMT_BootSettingData")
             $cimObj = $cimRef.Get()

             $cimObj.SetProperty("UseSOL", "false")
             
             $cimObj.SetProperty("UseIDER", "true")
             $cimObj.SetProperty("IDERBootDevice", $iderBootDevice)

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

			 #Get a reference to the  ManagedSystem (User of the Service)
			 $UserRef = $Connection.NewReference("SELECT * from CIM_ComputerSystem WHERE Name='ManagedSystem'")
  
			 #Get the Instance of CIM_AssociatedPowerManagmentService for the ManagedSystem
			 $ObjRef = $Connection.NewReference("CIM_AssociatedPowerManagementService");
			 $ObjRef.AddSelector("UserOfService",$userRef);
			 $AssociatedObj = $ObjRef.Get()
  
			 #Now Assoctate to the Provider of the Service (CIM_PowerManagementService)
			 $ServiceRef = $AssociatedObj.GetProperty("ServiceProvided").Ref
  
			 #Now invoke the RequestPowerStateChange
			 $InputObj = $ServiceRef.CreateMethodInput("RequestPowerStateChange")
			 $InputObj.SetProperty("PowerState", "$PowerInt")
			 $InputObj.SetProperty("ManagedElement", $UserRef)
			 $OutObj = $ServiceRef.InvokeMethod($InputObj);

			 #Note Return Status  
			 $ReturnValue = $OutObj.GetProperty("ReturnValue").ToString()
             
             if ((test-path variable:\AMTIDERSessions) -eq 0)
             {
                New-Variable -scope global -name AMTIDERSessions -value (New-Object System.Collections.ArrayList)
             }
             
             $session = new-object psobject -property @{IDERSessionID=$clientId; IDERPath=$IDERPath}
             [void]$global:AMTIDERSessions.Add($session)

			 #Add Member to Object.  Include Computer Name and Operation sucess 
			 $Obj | Add-Member -MemberType noteproperty -Name ComputerName -value $Comp
             $Obj | Add-Member -MemberType noteproperty -Name IDERSessionID -value $clientId
             $Obj | Add-Member -MemberType noteproperty -Name IDERPath -value $IDERPath
			 if ($ReturnValue -eq 0) {
				$Obj | Add-Member -MemberType noteproperty -Name Status -value "Successful"  
			 } else {
				$Obj | Add-Member -MemberType noteproperty -Name Status -value "Failed"   
			 }
             

		  } catch {
			#Add Member to Object noting failed attempt 
         
			$Obj | Add-Member -MemberType noteproperty -Name ComputerName -value $Comp
            $Obj | Add-Member -MemberType noteproperty -Name IDERPath -value $IDERPath
            $status = "Failed:" + $gErrorText
			$Obj | Add-Member -MemberType noteproperty -Name Status -value $status
            $imrResult = $global:imrLib.IDERCloseSession($clientId)
		  }

		$Results += $Obj
	  }
               
     Write-Output $Results
  }
}

# SIG # Begin signature block
# MIIZSAYJKoZIhvcNAQcCoIIZOTCCGTUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4f2XT2AdSgP6l2Fbob0MIxzZ
# rd2gghWzMIIDPTCCAqagAwIBAgIDBbD/MA0GCSqGSIb3DQEBBQUAME4xCzAJBgNV
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
# ARUwIwYJKoZIhvcNAQkEMRYEFF1UIBpFJoj0Xb5n/CJEMarjnlq/MA0GCSqGSIb3
# DQEBAQUABIGAI6sR8FQRy6NQ6s2aI4V2VrfbN5UCxETuWO/+Zmxqe61NhT9GrhPS
# EZ6eBADRgz9gose9K6DqOdvgn4FvK+gyB3ocI3qJG3ApWUBzhN18sSO/z6GCVOEn
# DiEFiIuiOIG/cOkKeYwoGA1kTSdCT7aLyPsM4cOF28uT5yQ+Jyzn9bqhggF/MIIB
# ewYJKoZIhvcNAQkGMYIBbDCCAWgCAQEwZzBTMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMOVmVyaVNpZ24sIEluYy4xKzApBgNVBAMTIlZlcmlTaWduIFRpbWUgU3RhbXBp
# bmcgU2VydmljZXMgQ0ECEHmipYX50RVCE9m4Pva2je0wCQYFKw4DAhoFAKBdMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTEyMDcxNzIw
# MTQxN1owIwYJKoZIhvcNAQkEMRYEFECwkBy7iT/QutTf5e5V9XdQ3bi9MA0GCSqG
# SIb3DQEBAQUABIGAbBnugycMgB6vYdwzGpo0FnikxlX6J1n8TgQU55jAYzLJabIc
# 2955MpTJ5dFUUXpWt4shlcyrtso1EtLV82O86tjzqq3lcLmSMt+nmLM1l3zgFukO
# 9tA3yqx3mIJSqY3r5s8G7uK8X30c8KiFof2pfqX3ZFX7sXdOEJns2LK3a3U=
# SIG # End signature block
