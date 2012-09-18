#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------
#$erroractionpreference = “SilentlyContinue”
Import-Module .\vTulFunctions.psm1
Import-Module .\IntelvPro	
Import-Module ActiveDirectory
$env:Path += ";$pwd\ThirdPartyTools"

#Sample function that provides the location of the script
function Get-ScriptDirectory
{ 
	if($hostinvocation -ne $null)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

#Sample variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory