'C:\ACUConfig\ACUConfig.exe /output console configamt C:\ACUConfig\profile.xml /DecryptionPassword Pa$$w0rd' | Out-File .\ThirdPartyTools\ACUConfig\ACUConfig.bat -Encoding ASCII
		#Copy-Item $textboxFile.Text -Destination .\ThirdPartyTools\ACUConfig\profile.xml -Force
		Copy-Item .\ThirdPartyTools\ACUConfig -Destination \\localhost\C$\ -Force -Recurse
		Remove-Item .\ThirdPartyTools\ACUConfig\profile.xml -Force
		Remove-Item .\ThirdPartyTools\ACUConfig\ACUConfig.bat -Force