Function Set-AMTAlarmClock {
<#
  .Synopsis 
    Sets a Intel Active Management Technology alarm clock timer
  .Description
    This CmdLet allows the user to set a wake timer on clients that have Intel Active Management Technology (AMT) firmware version 5.1 or higher.
  .Notes
    Supported AMT Firmware Versions: 5.1 and higher

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

    AlarmTime:
    The AlarmTime parameter is the date and time to wake the client. It is set as [YYYY]-[MM]-[DD]T[HH]:[MM]:[SS] Example: 2010-07-14T02:00:00 would wake the client on July 14, 2010 @ 02:00.
    If the user sets the alarm date and time on a client in a different timezone, the alarm time specified will be set to the proper GMT for the client. For Example if running the Cmdlet from a client in the Pacific Time zone to configure the wake up time on a client configured with Eastern Time for 08:00, the alarm clock will wake the client at 08:00 Eastern time.

    Interval:
    Interval parameter is the desired reoccurrence interval for the alarm to be set.  The format is: [DD]-[HH]-[MM]-[SS] Example: 07-00:00:00 would have a reoccurrence of every seven day at the same time; Example: 00-02:30:00 would have a reoccurrence of every 2 hours 30 minutes.

    Status:
      Status output designates if the Cmdlet was run successfully. For failed attempts additional status may be provided.
  .Link
    http:\\vproexpert.com
    http:\\www.intel.com\vpro
    http:\\www.intel.com

  .Example
    Set-AMTAlarmClock -ComputerName:vproclient.vprodemo.com -TLS -AlarmTime:2010-07-14T02:00:00

    Sets one time occurrence for wake up alarmclock.

    ComputerName  : vproclient.vprodemo.com
    Port          : 16993
    NextAlarmTime : Wednesday, July 14, 2010 2:00:00 AM
    Status        : Successful
  .Example
    Set-AMTAlarmClock vproclient.vprodemo.com -TLS -AlarmTime:2010-07-14T02:00:00 -UserName vprodemo\administrator

    Will prompt for Kerberos User Password then Sets one time occurrence for wake up alarmclock.

    ComputerName  : vproclient.vprodemo.com
    Port          : 16993
    NextAlarmTime : Wednesday, July 14, 2010 2:00:00 AM
    Status        : Successful

  .Example
    Set-AMTAlarmClock vproclient -UserName:admin -AlarmTime:2010-07-14T02:00:00 -Interval:07-00:00:00

    Will prompt for Digest User Password then sets reoccuring wake up alarmclock for once a week at that time.

    ComputerName     : vproclient
    Port             : 16992
    NextAlarmTime    : Wednesday, July 14, 2010 2:00:00 AM
    PeriodicInterval : P0Y0M07DT00H00M
    Status           : Successful
  .Example
    Get-Content computers.txt | Set-AMTAlarmClock -credential $AMTCredential -TLS -AlarmTime:2010-07-14T02:00:00 -Interval:00-01:00:00 -credential $SomeStoredPSCredential

    Will pull the list of amt clients from a text file and pipe them in the Set-AMTAlarmClock CMDLet.
    Sets reoccuring wake up alarmclock for once every hour on and after that time.

    ComputerName     : computer1.vprodemo.com
    Port             : 16993
    NextAlarmTime    : Wednesday, July 14, 2010 2:00:00 AM
    PeriodicInterval : P0Y0M00DT02H00M
    Status           : Successful

    ComputerName     : computer2.vprodemo.com
    Port             : 16993
    NextAlarmTime    : Wednesday, July 14, 2010 2:00:00 AM
    PeriodicInterval : P0Y0M00DT02H00M
    Status           : Successful

    ComputerName     : computer3.vprodemo.com
    Port             : 16993
    NextAlarmTime    : Wednesday, July 14, 2010 2:00:00 AM
    PeriodicInterval : P0Y0M00DT02H00M
    Status           : Successful
#>
[CmdletBinding()]
Param (
	[Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true, position=0, HelpMessage="Hostname, FQDN, or IP Address")] [String[]] $ComputerName,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Valid Ports are 16992 (non-TLS) or 16993 (TLS)")][ValidateSet("16992", "16993")] [String] $Port,
	[Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=1, HelpMessage="Alarm Time in YYYY-MM-DDTHH:MM:SS format")][ValidatePattern("[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]")] [string] $AlarmTime,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Periodic Interval in DD-HH:MM:SS format")][ValidatePattern("[0-9][0-9]-[0-9][0-9]:[0-9][0-9]:[0-9][0-9]")] [string] $Interval,	
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Use TLS (Port 16993)")] [switch] $TLS,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Digest of Kerberos User")] [string] $Username,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, HelpMessage="Digest of Kerberos Password")] [string] $Password,
	[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false, position=2, HelpMessage="PS Credential")] [System.Management.Automation.PSCredential] $Credential
) 



PROCESS {

$Results = @()

#create a connection object
$Connection = New-Object Intel.Management.Wsman.WsmanConnection 

if ($credential.username.Length -gt 0)
{
  $Connection.SetCredentials($credential.Username, $credential.Password)  
}
elseif ($username.length -gt 0)
{
  if ($password.length -gt 0)
  {
    $Connection.SetCredentials($username, $password)  
  }
  else
  {
    $cred = Get-Credential $username
    $Connection.SetCredentials($cred.Username, $cred.Password)
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

Foreach ($comp in $ComputerName)
{
    $Connection.SetHost($comp, $port)
    if($Port -ne "16992")
    {
        $GMTError = $false
    }
    else
    {
        $http = [System.Net.WebRequest]::Create("http://"+$Comp+":"+$port+"/logon.htm")
        $httpResponse = $http.GetResponse()
        if($httpResponse.StatusCode -eq [System.Net.HttpStatusCode]::OK)
        {
            $amtTime = [System.DateTime]::Parse($httpResponse.GetResponseHeader("Date"))
            $systemTime = [System.DateTime]::Now
            if($amtTime.Hour -ne $systemTime.Hour)
            {
                # AMT Time was not set to UTC
                $GMTError = $true
            }
        }
        $httpResponse.Close()
    }
  
    $Obj = new-object psobject
    $Obj | Add-Member -MemberType noteproperty -Name ComputerName -value $Comp
    $Obj | Add-Member -MemberType noteproperty -Name Port -value $port
    
    $AlarmClockService_EPR = $Connection.NewReference("http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AlarmClockService")
    $AlarmClockService_EPR.AddSelector("SystemName","ManagedSystem")
    try
    {
        $AlarmClockService = $AlarmClockService_EPR.Get()     
    }
    catch
    {
        $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "Failed"
            $Obj | Add-Member -MemberType noteproperty -Name "NextAlarmTime" -value "[Error]"
            $Obj | Add-Member -MemberType noteproperty -Name "PeriodicInterval" -value "[Error]"
        $Results += $Obj 
        continue     
    }
    if($AlarmTime -ne "")
    {
        if ($AlarmTime.EndsWith(":00") -eq $false)
        {
            $replace = $AlarmTime.SubString($AlarmTime.Length-3, 3)
            $NewAlarmTime = $AlarmTime.TrimEnd($replace);
            $NewAlarmTime+= ":00"
            $AlarmTime = $NewAlarmTime
        }
        $SetAlarmTime = $Connection.NewInstance("Datetime")
        try
        {   
            $TimeObj = [System.DateTime]::Parse($AlarmTime)
        }
        catch
        {
            $Obj | Add-Member -MemberType noteproperty -Name "NextAlarmTime" -value "[Parse Error]"
            $Results += $Obj
            continue
        }   
        
        if($GMTError)
        {
            # Local Time
            $SetAlarmTime.Text = $TimeObj.ToString("s")+"Z"
        }
        else
        {
            # Universal Time
            $SetAlarmTime.Text = $TimeObj.ToUniversalTime().ToString("s")+"Z"
        }
        $Obj | Add-Member -MemberType noteproperty -Name "NextAlarmTime" -value $TimeObj.ToString("F")
        $AlarmClockService.SetProperty("NextAMTAlarmTime",$SetAlarmTime)
        
    }
  
    if($Interval -ne "")
    {
        if($Interval.Contains("-"))
        {
            $temp = $Interval.Split("-")
            $Day = $temp[0]
            $TimeInterval = $temp[1]
        }
        else
        {
            $Day = "0"
            $TimeInterval = $Interval
        }
        $temp = $TimeInterval.Split(":")
        $hours = $temp[0]
        $minutes = $temp[1]
        $seconds = $temp[2]
        
        $intervalstring = "P0Y0M" + $Day + "DT" + $hours + "H" + $minutes + "M" 
        $SetIntervalTime = $Connection.NewInstance("Interval")
        try
        {
            $TimeObj = [System.DateTime]::Parse($AlarmTime)
        }
        catch
        {
            $Obj | Add-Member -MemberType noteproperty -Name "PeriodicInterval" -value "[Error]"
            $Results += $Obj
            continue
        }   


        $SetIntervalTime.Text = $intervalstring
        $Obj | Add-Member -MemberType noteproperty -Name "PeriodicInterval" -value $intervalstring
        $AlarmClockService.SetProperty("AMTAlarmClockInterval",$SetIntervalTime)
        
        
    }
    
    try
    {
        $RetVal = $AlarmClockService_EPR.Put($AlarmClockService)
        $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "Successful"
    }
    catch
    {
        $Obj | Add-Member -MemberType noteproperty -Name "Status" -value "Failed"
    }
    $Results += $Obj 
}

Write-Output $Results

}
}
# SIG # Begin signature block
# MIIZUwYJKoZIhvcNAQcCoIIZRDCCGUACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUZVaqqbVD0K034z8eoU+2iFtf
# vx+gghW+MIIDPTCCAqagAwIBAgIDBbD/MA0GCSqGSIb3DQEBBQUAME4xCzAJBgNV
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
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUqQ/+MnV7udujrZlL00GTEUzQ
# oK8wDQYJKoZIhvcNAQEBBQAEgYB8Qjd4nH9um4hsAUBc4TrE+6ip/s8YHxjUJt9f
# z+TXXnNv4vedihBMc8X+R5UzNgkjhhWoJzO5YiM0+3OqGUxEyliWVtlB4RyNqRwU
# LwU7/qKNg/8p5lVxuhgapnW9zTVJDzmzLRukrum4W//zXEk0T7BoJnGtTMXu/taJ
# eNi5nKGCAX8wggF7BgkqhkiG9w0BCQYxggFsMIIBaAIBATBnMFMxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjErMCkGA1UEAxMiVmVyaVNpZ24g
# VGltZSBTdGFtcGluZyBTZXJ2aWNlcyBDQQIQOCXX+vhhr570kOcmtdZa1TAJBgUr
# DgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUx
# DxcNMTIwMTE5MjMxNzI5WjAjBgkqhkiG9w0BCQQxFgQUwurySKcq7JS/7NngCMI4
# BS+J6o4wDQYJKoZIhvcNAQEBBQAEgYA0fcznRL6tKZXqMOSqPWAQc99+gWsC0CQp
# 592u1tvPuj4xZtMS2VW7JfMoJBX+kag4qotnvhCH0VPs5v/UUjcTQCjoKxY8b0T5
# 4yXdIzd5lEVSUN6P0agqDc7jfx1Qfv8CF0FZOoSta5QbRMYCS3ArpFJr+SLYGgGT
# yNWiI8USUg==
# SIG # End signature block
