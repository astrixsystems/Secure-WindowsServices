<#
.SYNOPSIS
	Name: Secure-WindowsServices.ps1
	Description: The purpose of this script is to secure any Windows services with insecure permissions.

.NOTES
	Author:								Ben Hooper at Astrix
	Tested on:							Windows 7 Professional 64-bit, Windows 10 Pro 64-bit
	Version:							1.5
	Changes in v1.6 (2019/11/20 14:31):	Fixed compatibility with Windows 7 / PowerShell < 3.0.
	Changes in v1.5 (2019/11/20 13:43):	Added special handling for Windows services located in "C:\Windows\system32\" so that the permissions are reduced to read & execute instead of being removed.
	Changes in v1.4 (2019/11/20 12:33):	Added post-run report of which, if any, services were secured.
	Changes in v1.3 (2019/11/20 11:39):	Updated to bring in line with enhancements of Update-hMailServerCertificate v1.13 (write access check to log file, auto-elevate, coloured statuses, etc) and changed tags to Info, Unknown, Pass, FAIL, Success, and ERROR.
	Changes in v1.2 (2018/10/15):		Enhanced output by (1) changing output type from "check performed-action result" with just "action result" which makes it easier to read with less indentations, (2) adding tags ("[FAILED]", "[SUCCESS]", and "[NOTIFICATION]") for quick checking of results, and (3) tweaking logging behaviour.
	Changes in v1.1 (2018/10/05):		Added handling of inherited permissions.
	
.PARAMETER LogOutput
	Logs the output to the default file path "C:\<hostname>_Secure-WindowsServices.txt".
	
.PARAMETER LogFile
	When used in combination with -LogOutput, logs the output to the custom specified file path.

.EXAMPLE
	Run with the default settings:
		Secure-WindowsServices
		
.EXAMPLE 
	Run with the default settings AND logging to the default path:
		Secure-WindowsServices -LogOutput
	
.EXAMPLE 
	Run with the default settings AND logging to a custom local path:
		Secure-WindowsServices -LogOutput -LogPath "C:\$env:computername_Secure-WindowsServices.txt"
	
.EXAMPLE 
	Run with the default settings AND logging to a custom network path:
		Secure-WindowsServices -LogOutput -LogPath "\\servername\filesharename\$env:computername_Secure-WindowsServices.txt"
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Param(
	[switch]$LogOutput,
	[string]$LogPath
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$RunAsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);

$global:FirstRun = $null;
$global:Script_PS1File_Name = Split-Path $MyInvocation.MyCommand.Path -Leaf;
$global:Script_PS1File_FullPath = $MyInvocation.MyCommand.Path;

$LogPath_Default = "C:\$env:computername`_$global:Script_PS1File_Name.log";

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Secure-WindowsServices {
	Param()
	
	Begin {
		Write-Host "Securing all Windows services...";
	}
	
	Process {
		Try {
			If ($FirstRun -Eq $Null){
				$FirstRun = $False;
			} Else {
				$FirstRun = $True;
			}
			
			If ($FirstRun -Eq $False){
				[System.Collections.ArrayList]$FilesChecked = @(); # This is critical to ensuring that the array isn't a fixed size so that items can be added;
				[System.Collections.ArrayList]$FoldersChecked = @(); # This is critical to ensuring that the array isn't a fixed size so that items can be added;
				[System.Collections.ArrayList]$global:WindowsServicesSecured = @();
			}
			
			$WindowsServices = Get-WmiObject Win32_Service -ErrorAction Stop | Select Name, DisplayName, PathName | Sort-Object DisplayName;
			
			If (-Not ($WindowsServices)) {
				Write-Host -ForegroundColor Red "`t[ERROR] Could not find any Windows services. Exiting...";
				
				Break;
			}
			
			$WindowsServices_Total = $WindowsServices.Length;
			
			For ($i = 0; $i -LT $WindowsServices_Total; $i++) {
				$Count = $i + 1;
				
				$WindowsService_DisplayName = $WindowsServices[$i].DisplayName;
				$WindowsService_Path = $WindowsServices[$i].PathName;
				$WindowsService_File_Path = ($WindowsService_Path -Replace '(.+exe).*', '$1').Trim('"');
				$WindowsService_Folder_Path = Split-Path -Parent $WindowsService_File_Path;
				
				Write-Host "`tWindows service ""$WindowsService_DisplayName"" ($Count of $WindowsServices_Total)...";
				
				If ($FoldersChecked -Contains $WindowsService_Folder_Path){
					Write-Host -ForegroundColor Green "`t`t[Pass] Folder ""$WindowsService_Folder_Path"": Security has already been ensured.";
				} Else {
					$FoldersChecked += $WindowsService_Folder_Path;
					
					Write-Host -ForegroundColor Yellow "`t`t[Unknown] Folder ""$WindowsService_Folder_Path"": Security has not yet been ensured...";
					
					Ensure-InsecurePermissions -Path $WindowsService_Folder_Path -WindowsService $WindowsService_DisplayName;
				}
				
				If ($FilesChecked -Contains $WindowsService_File_Path){
					Write-Host -ForegroundColor Green "`t`t[Pass] File ""$WindowsService_File_Path"": Security has already been ensured.";
				} Else {
					$FilesChecked += $WindowsService_File_Path;
					
					Write-Host -ForegroundColor Yellow "`t`t[Unknown] File ""$WindowsService_File_Path"": Security has not yet been ensured...";
					
					Ensure-InsecurePermissions -Path $WindowsService_File_Path -WindowsService $WindowsService_DisplayName;
				}
				
				Write-Host "";
			}
		}
		
		Catch {
			Write-Host -ForegroundColor Red "[ERROR] Could not secure all Windows services.";
			$_.Exception.Message;
			$_.Exception.ItemName;
			Break;
		}
	}
	
	End {
		If($?){
			$WindowsServicesSecured_Total = $global:WindowsServicesSecured.Count;
			
			If ($WindowsServicesSecured_Total -Eq 0){
				Write-Host -ForegroundColor Green "[Pass] All Windows services were already secure.";
			} Else {
				If ($WindowsServicesSecured_Total -Eq 1){
					Write-Host -ForegroundColor Green "[Success] The sole insecure Windows service was secured:";
				} Else {
					Write-Host -ForegroundColor Green "[Success] All $WindowsServicesSecured_Total insecure Windows services were secured:";
				}
				
				For ($i = 0; $i -LT $WindowsServicesSecured_Total; $i++) {
					$Count = $i + 1;
					
					$WindowsServicesSecured_DisplayName = $global:WindowsServicesSecured[$i];
					
					Write-Host "`t$Count. ""$WindowsServicesSecured_DisplayName""";
				}
			}
		}
	}
}

Function Ensure-InsecurePermissions {
	Param(
		[Parameter(Mandatory=$true)][String]$Path,
		[Parameter(Mandatory=$true)][String]$WindowsService
	)
	
	Begin {
		
	}
	
	Process {
		Try {
			$ACL = Get-ACL $Path;
			$ACL_Access = $ACL | Select -Expand Access;
			
			$InsecurePermissionsFound = $False;
			
			ForEach ($ACE_Current in $ACL_Access) {
				$SecurityPrincipal = $ACE_Current.IdentityReference;
				$Permissions = $ACE_Current.FileSystemRights.ToString() -Split ", ";
				$Inheritance = $ACE_Current.IsInherited;
				
				ForEach ($Permission in $Permissions){
					If ((($Permission -Eq "FullControl") -Or ($Permission -Eq "Modify") -Or ($Permission -Eq "Write")) -And (($SecurityPrincipal -Eq "Everyone") -Or ($SecurityPrincipal -Eq "NT AUTHORITY\Authenticated Users") -Or ($SecurityPrincipal -Eq "BUILTIN\Users") -Or ($SecurityPrincipal -Eq "$Env:USERDOMAIN\Domain Users"))) {
						$InsecurePermissionsFound = $True;
						
						If (-Not ($global:WindowsServicesSecured -Contains $WindowsService)){
							$global:WindowsServicesSecured += $WindowsService;
						}
						
						Write-Host -ForegroundColor Yellow "`t`t`t[WARNING] Insecure Access Control Entry (ACE) found: ""$Permission"" granted to ""$SecurityPrincipal"".";
						
						If ($Inheritance -Eq $True){
							$Error.Clear();
							Try {
								$ACL.SetAccessRuleProtection($True,$True);
								Set-Acl -Path $Path -AclObject $ACL;
							} Catch {
								Write-Host -ForegroundColor Red "`t`t`t`t[FAIL] Could not convert Access Control List (ACL) from inherited to explicit.";
							}
							If (!$error){
								Write-Host -ForegroundColor Green "`t`t`t`t[Success] Converted Access Control List (ACL) from inherited to explicit.";
							}
							
							# Once permission inheritance has been disabled, the permissions need to be re-acquired in order to remove ACEs
							$ACL = Get-ACL $Path;
						}
						
						$Error.Clear();
						If ((($Path -Eq "C:\Windows\system32\svchost.exe") -Or ($Path -Eq "C:\Windows\system32")) -And ($SecurityPrincipal -Eq "BUILTIN\Users")) {
							Write-Host "`t`t`t`t[Info] Windows service is a default located in a system location so Access Control Entry (ACE) for ""BUILTIN\Users"" should be read & execute.";
							Try {
								$ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipal, "ReadAndExecute", , , "Allow");
								$ACL.SetAccessRule($ACE);
								Set-Acl -Path $Path -AclObject $ACL;
							} Catch {
								Write-Host -ForegroundColor Red "`t`t`t`t[FAIL] Insecure Access Control Entry (ACE) could not be corrected.";
							}
							If (!$error){
								Write-Host -ForegroundColor Green "`t`t`t`t[Pass] Corrected insecure Access Control Entry (ACE).";
							}
						} Else {
							Try {
								$ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipal, $Permission, , , "Allow");
								$ACL.RemoveAccessRuleAll($ACE);
								Set-Acl -Path $Path -AclObject $ACL;
							} Catch {
								Write-Host -ForegroundColor Red "`t`t`t`t[FAIL] Insecure Access Control Entry (ACE) could not be removed.";
							}
							If (!$error){
								Write-Host -ForegroundColor Green "`t`t`t`t[Pass] Removed insecure Access Control Entry (ACE).";
							}
						}
						
						
						
					}
				}
			}
			
			If ($InsecurePermissionsFound -Eq $False) {
				Write-Host -ForegroundColor Green "`t`t`t[Pass] No insecure Access Control Entries (ACEs) found.";
			}
		}
		
		Catch {
			Write-Host -ForegroundColor Red "`t`t`t[ERROR] Could not ensure security of Windows service.";
			$_.Exception.Message;
			$_.Exception.ItemName;
			Break;
		}
	}
	
	End {
		If($?){
			
		}
	}
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If (-Not $LogPath) {
	$LogPath = $LogPath_Default;
}

# Check write access to log file
If ($LogOutput -Eq $True) {
	Try {
		[io.file]::OpenWrite($LogPath).Close();
	}
	Catch {
		Write-Host -ForegroundColor Red "[ERROR] Unable to log output to file '$LogPath' due to insufficient permissions.";
		Write-Host "";
		
		$LogOutput = $False;
	}
}

# Set up logging
If ($LogOutput -Eq $True) {
	Start-Transcript -Path $LogPath -Append | Out-Null;
	
	Write-Host "Logging output to file.";
	Write-Host "Path: '$LogPath'" 
	
	Write-Host "";
	Write-Host "----------------------------------------------------------------";
	Write-Host "";
}

# Handle admin
If ($RunAsAdministrator -Eq $False) {
	Write-Host "This script requires administrative permissions but was not run as administrator. Elevate now? (y/n)";
	$Elevate = Read-Host "[Input]";

	If (($Elevate -Like "y") -Or ($Elevate -Like "yes")){
		Write-Host "'Yes' selected. Launching a new session in a new window and ending this session...";
		
		# Preserve original parameters
		$AllParameters_String = "";
		ForEach ($Parameter in $PsBoundParameters.GetEnumerator()){
			$Parameter_Key = $Parameter.Key;
			$Parameter_Value = $Parameter.Value;
			$Parameter_Value_Type = $Parameter_Value.GetType().Name;
			
			If ($Parameter_Value_Type -Eq "SwitchParameter"){
				$AllParameters_String += " -$Parameter_Key";
				
			} ElseIf ($Parameter_Value_Type -Eq "String") {
				$AllParameters_String += ' -' + $Parameter_Key + ' "' + $Parameter_Value + '"';
			} Else {
				$AllParameters_String += " -$Parameter_Key $Parameter_Value";
			}
		}
		
		$Arguments = ' -NoExit -File "' + $global:Script_PS1File_FullPath + '"' + $AllParameters_String;
		
		If ($LogOutput -Eq $True) {
			Stop-Transcript | Out-Null;
		}
		
		Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $Arguments;
		
		# Stop-Process -Id $PID;
		
		Break;
	} Else {
		Write-Host "'No' selected. Exiting...";
		
		If ($LogOutput -Eq $True) {
			Stop-Transcript | Out-Null;
		}
		
		Break;
	}
} Else {
	Secure-WindowsServices;
}

Write-Host "";
Write-Host "----------------------------------------------------------------";
Write-Host "";

Write-Host "Script complete.";

If ($LogOutput -Eq $True) {
	Stop-Transcript | Out-Null;
}
# SIG # Begin signature block
# MIIkjwYJKoZIhvcNAQcCoIIkgDCCJHwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC79FV7Nn7KlT3w
# Mc+maZDvYAqoDZw4affTw7B3z1LWsaCCH3YwggSEMIIDbKADAgECAhBCGvKUCYQZ
# H1IKS8YkJqdLMA0GCSqGSIb3DQEBBQUAMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQK
# EwtBZGRUcnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5l
# dHdvcmsxIjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3QwHhcNMDUw
# NjA3MDgwOTEwWhcNMjAwNTMwMTA0ODM4WjCBlTELMAkGA1UEBhMCVVMxCzAJBgNV
# BAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2UgQ2l0eTEeMBwGA1UEChMVVGhlIFVT
# RVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExhodHRwOi8vd3d3LnVzZXJ0cnVzdC5j
# b20xHTAbBgNVBAMTFFVUTi1VU0VSRmlyc3QtT2JqZWN0MIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAzqqBP6OjYXiqMQBVlRGeJw8fHN86m4JoMMBKYR3x
# Lw76vnn3pSPvVVGWhM3b47luPjHYCiBnx/TZv5TrRwQ+As4qol2HBAn2MJ0Yipey
# qhz8QdKhNsv7PZG659lwNfrk55DDm6Ob0zz1Epl3sbcJ4GjmHLjzlGOIamr+C3bJ
# vvQi5Ge5qxped8GFB90NbL/uBsd3akGepw/X++6UF7f8hb6kq8QcMd3XttHk8O/f
# Fo+yUpPXodSJoQcuv+EBEkIeGuHYlTTbZHko/7ouEcLl6FuSSPtHC8Js2q0yg0Hz
# peVBcP1lkG36+lHE+b2WKxkELNNtp9zwf2+DZeJqq4eGdQIDAQABo4H0MIHxMB8G
# A1UdIwQYMBaAFK29mHo0tCb3+sQmVO8DveAky1QaMB0GA1UdDgQWBBTa7WR0FJwU
# PKvdmam9WyhNizzJ2DAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAR
# BgNVHSAECjAIMAYGBFUdIAAwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2NybC51
# c2VydHJ1c3QuY29tL0FkZFRydXN0RXh0ZXJuYWxDQVJvb3QuY3JsMDUGCCsGAQUF
# BwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTAN
# BgkqhkiG9w0BAQUFAAOCAQEATUIvpsGK6weAkFhGjPgZOWYqPFosbc/U2YdVjXkL
# Eoh7QI/Vx/hLjVUWY623V9w7K73TwU8eA4dLRJvj4kBFJvMmSStqhPFUetRC2vzT
# artmfsqe6um73AfHw5JOgzyBSZ+S1TIJ6kkuoRFxmjbSxU5otssOGyUWr2zeXXbY
# H3KxkyaGF9sY3q9F6d/7mK8UGO2kXvaJlEXwVQRK3f8n3QZKQPa0vPHkD5kCu/1d
# Di4owb47Xxo/lxCEvBY+2KOcYx1my1xf2j7zDwoJNSLb28A/APnmDV1n0f2gHgMr
# 2UD3vsyHZlSApqO49Rli1dImsZgm7prLRKdFWoGVFRr1UTCCBOYwggPOoAMCAQIC
# EGJcTZCM1UL7qy6lcz/xVBkwDQYJKoZIhvcNAQEFBQAwgZUxCzAJBgNVBAYTAlVT
# MQswCQYDVQQIEwJVVDEXMBUGA1UEBxMOU2FsdCBMYWtlIENpdHkxHjAcBgNVBAoT
# FVRoZSBVU0VSVFJVU1QgTmV0d29yazEhMB8GA1UECxMYaHR0cDovL3d3dy51c2Vy
# dHJ1c3QuY29tMR0wGwYDVQQDExRVVE4tVVNFUkZpcnN0LU9iamVjdDAeFw0xMTA0
# MjcwMDAwMDBaFw0yMDA1MzAxMDQ4MzhaMHoxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# ExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoT
# EUNPTU9ETyBDQSBMaW1pdGVkMSAwHgYDVQQDExdDT01PRE8gVGltZSBTdGFtcGlu
# ZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKqC8YSpW9hxtdJd
# K+30EyAM+Zvp0Y90Xm7u6ylI2Mi+LOsKYWDMvZKNfN10uwqeaE6qdSRzJ6438xqC
# pW24yAlGTH6hg+niA2CkIRAnQJpZ4W2vPoKvIWlZbWPMzrH2Fpp5g5c6HQyvyX3R
# TtjDRqGlmKpgzlXUEhHzOwtsxoi6lS7voEZFOXys6eOt6FeXX/77wgmN/o6apT9Z
# RvzHLV2Eh/BvWCbD8EL8Vd5lvmc4Y7MRsaEl7ambvkjfTHfAqhkLtv1Kjyx5VbH+
# WVpabVWLHEP2sVVyKYlNQD++f0kBXTybXAj7yuJ1FQWTnQhi/7oN26r4tb8QMspy
# 6ggmzRkCAwEAAaOCAUowggFGMB8GA1UdIwQYMBaAFNrtZHQUnBQ8q92Zqb1bKE2L
# PMnYMB0GA1UdDgQWBBRkIoa2SonJBA/QBFiSK7NuPR4nbDAOBgNVHQ8BAf8EBAMC
# AQYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNV
# HSAECjAIMAYGBFUdIAAwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybC51c2Vy
# dHJ1c3QuY29tL1VUTi1VU0VSRmlyc3QtT2JqZWN0LmNybDB0BggrBgEFBQcBAQRo
# MGYwPQYIKwYBBQUHMAKGMWh0dHA6Ly9jcnQudXNlcnRydXN0LmNvbS9VVE5BZGRU
# cnVzdE9iamVjdF9DQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0
# cnVzdC5jb20wDQYJKoZIhvcNAQEFBQADggEBABHJPeEF6DtlrMl0MQO32oM4xpK6
# /c3422ObfR6QpJjI2VhoNLXwCyFTnllG/WOF3/5HqnDkP14IlShfFPH9Iq5w5Lfx
# sLZWn7FnuGiDXqhg25g59txJXhOnkGdL427n6/BDx9Avff+WWqcD1ptUoCPTpcKg
# jvlP0bIGIf4hXSeMoK/ZsFLu/Mjtt5zxySY41qUy7UiXlF494D01tLDJWK/HWP9i
# dBaSZEHayqjriwO9wU6uH5EyuOEkO3vtFGgJhpYoyTvJbCjCJWn1SmGt4Cf4U6d1
# FbBRMbDxQf8+WiYeYH7i42o5msTq7j/mshM/VQMETQuQctTr+7yHkFGyOBkwggT+
# MIID5qADAgECAhArc9t0YxFMWlsySvIwV3JJMA0GCSqGSIb3DQEBBQUAMHoxCzAJ
# BgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcT
# B1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSAwHgYDVQQDExdD
# T01PRE8gVGltZSBTdGFtcGluZyBDQTAeFw0xOTA1MDIwMDAwMDBaFw0yMDA1MzAx
# MDQ4MzhaMIGDMQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVz
# dGVyMRAwDgYDVQQHDAdTYWxmb3JkMRgwFgYDVQQKDA9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMMIlNlY3RpZ28gU0hBLTEgVGltZSBTdGFtcGluZyBTaWduZXIwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/UjaCOtx0Nw141X8WUBlm7boa
# mdFjOJoMZrJA26eAUL9pLjYvCmc/QKFKimM1m9AZzHSqFxmRK7VVIBn7wBo6bco5
# m4LyupWhGtg0x7iJe3CIcFFmaex3/saUcnrPJYHtNIKa3wgVNzG0ba4cvxjVDc/+
# teHE+7FHcen67mOR7PHszlkEEXyuC2BT6irzvi8CD9BMXTETLx5pD4WbRZbCjRKL
# Z64fr2mrBpaBAN+RfJUc5p4ZZN92yGBEL0njj39gakU5E0Qhpbr7kfpBQO1NArRL
# f9/i4D24qvMa2EGDj38z7UEG4n2eP1OEjSja3XbGvfeOHjjNwMtgJAPeekyrAgMB
# AAGjggF0MIIBcDAfBgNVHSMEGDAWgBRkIoa2SonJBA/QBFiSK7NuPR4nbDAdBgNV
# HQ4EFgQUru7ZYLpe9SwBEv2OjbJVcjVGb/EwDgYDVR0PAQH/BAQDAgbAMAwGA1Ud
# EwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwQAYDVR0gBDkwNzA1Bgwr
# BgEEAbIxAQIBAwgwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9D
# UFMwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybC5zZWN0aWdvLmNvbS9DT01P
# RE9UaW1lU3RhbXBpbmdDQV8yLmNybDByBggrBgEFBQcBAQRmMGQwPQYIKwYBBQUH
# MAKGMWh0dHA6Ly9jcnQuc2VjdGlnby5jb20vQ09NT0RPVGltZVN0YW1waW5nQ0Ff
# Mi5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqG
# SIb3DQEBBQUAA4IBAQB6f6lK0rCkHB0NnS1cxq5a3Y9FHfCeXJD2Xqxw/tPZzeQZ
# pApDdWBqg6TDmYQgMbrW/kzPE/gQ91QJfurc0i551wdMVLe1yZ2y8PIeJBTQnMfI
# Z6oLYre08Qbk5+QhSxkymTS5GWF3CjOQZ2zAiEqS9aFDAfOuom/Jlb2WOPeD9618
# KB/zON+OIchxaFMty66q4jAXgyIpGLXhjInrbvh+OLuQT7lfBzQSa5fV5juRvgAX
# IW7ibfxSee+BJbrPE9D73SvNgbZXiU7w3fMLSjTKhf8IuZZf6xET4OHFA61XHOFd
# kga+G8g8P6Ugn2nQacHFwsk+58Vy9+obluKUr4YuMIIFdzCCBF+gAwIBAgIQE+oo
# cFv07O0MNmMJgGFDNjANBgkqhkiG9w0BAQwFADBvMQswCQYDVQQGEwJTRTEUMBIG
# A1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFsIFRU
# UCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290MB4X
# DTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowgYgxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UE
# ChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNB
# IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAgBJlFzYOw9sIs9CsVw127c0n00ytUINh4qogTQktZAnczomfzD2p
# 7PbPwdzx07HWezcoEStH2jnGvDoZtF+mvX2do2NCtnbyqTsrkfjib9DsFiCQCT7i
# 6HTJGLSR1GJk23+jBvGIGGqQIjy8/hPwhxR79uQfjtTkUcYRZ0YIUcuGFFQ/vDP+
# fmyc/xadGL1RjjWmp2bIcmfbIWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9XWrf/zvk9
# tyy29lTdyOcSOk2uTIq3XJq0tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeUvlM3kHND
# 8zLDU+/bqv50TmnHa4xgk97Exwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP8yUmazNt
# 925H+nND5X4OpWaxKXwyhGNVicQNwZNUMBkTrNN9N6frXTpsNVzbQdcS2qlJC9/Y
# gIoJk2KOtWbPJYjNhLixP6Q5D9kCnusSTJV882sFqV4Wg8y4Z+LoE53MW4LTTLPt
# W//e5XOsIzstAL81VXQJSdhJWBp/kjbmUZIO8yZ9HE0XvMnsQybQv0FfQKlERPSZ
# 51eHnlAfV1SoPv10Yy+xUGUJ5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLevni3/GcV
# 4clXhB4PY9bpYrrWX1Uu6lzGKAgEJTm4Diup8kyXHAc/DVL17e8vgg8CAwEAAaOB
# 9DCB8TAfBgNVHSMEGDAWgBStvZh6NLQm9/rEJlTvA73gJMtUGjAdBgNVHQ4EFgQU
# U3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF
# MAMBAf8wEQYDVR0gBAowCDAGBgRVHSAAMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6
# Ly9jcmwudXNlcnRydXN0LmNvbS9BZGRUcnVzdEV4dGVybmFsQ0FSb290LmNybDA1
# BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVz
# dC5jb20wDQYJKoZIhvcNAQEMBQADggEBAJNl9jeDlQ9ew4IcH9Z35zyKwKoJ8OkL
# JvHgwmp1ocd5yblSYMgpEg7wrQPWCcR23+WmgZWnRtqCV6mVksW2jwMibDN3wXsy
# F24HzloUQToFJBv2FAY7qCUkDrvMKnXduXBBP3zQYzYhBx9G/2CkkeFnvN4ffhkU
# yWNnkepnB2u0j4vAbkN9w6GAbLIevFOFfdyQoaS8Le9Gclc1Bb+7RrtubTeZtv8j
# kpHGbkD4jylW6l/VXxRTrPBPYer3IsynVgviuDQfJtl7GQVoP7o81DgGotPmjw7j
# tHFtQELFhLRAlSv0ZaBIefYdgWOWnU914Ph85I6p0fKtirOMxyHNwu8wggWKMIIE
# cqADAgECAhAHvfU0ZuEKsr2CCQl/2DeWMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNV
# BAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1Nh
# bGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGln
# byBSU0EgQ29kZSBTaWduaW5nIENBMB4XDTE5MTExNDAwMDAwMFoXDTIwMTExMzIz
# NTk1OVowgdoxCzAJBgNVBAYTAkdCMREwDwYDVQQRDAhDRjQ1IDRTTjEWMBQGA1UE
# CAwNTWlkIEdsYW1vcmdhbjEVMBMGA1UEBwwMTW91bnRhaW4gQXNoMTEwLwYDVQQJ
# DChWZW50dXJlIEhvdXNlLCBOYXZpZ2F0aW9uIFBhcmsgQWJlcmN5bm9uMSowKAYD
# VQQKDCFBc3RyaXggSW50ZWdyYXRlZCBTeXN0ZW1zIExpbWl0ZWQxKjAoBgNVBAMM
# IUFzdHJpeCBJbnRlZ3JhdGVkIFN5c3RlbXMgTGltaXRlZDCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKGf2ZK/9edFfdkmNy2Cg+j6QkBbrO2c+lrSXEB8
# +XwIr6RgqSazOksf1Pb49T0dhox4VrUtbBIuyeQnxTrj8rUCx02gmhgNdJqX7mcx
# VkZWonSKk4FOG4B+Lba/JtedvFpg2ixNuZxDWZXJpGzhge04LYTjJO2WrIbrpJ5P
# vmUFUXnhjSEKptpKyeptikqD1bUepglUo0dWk99mbD8ufRhjqIrmvCB84UaZiOIx
# 5dO9J5H+VCrJ15+HzyhS73Ho0kRCXoeMoGpnaiqyzdPARSUOoDGdzvzMkbKP52sL
# cuLLEKf0UxjveVD/fAfHvAalC+jc7c35rD5m+YDnZpmbvhECAwEAAaOCAacwggGj
# MB8GA1UdIwQYMBaAFA7hOqhTOjHVir7Bu61nGgOFrTQOMB0GA1UdDgQWBBRa0KqE
# 4L1d64xMBilKiBhoIp0TzjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAT
# BgNVHSUEDDAKBggrBgEFBQcDAzARBglghkgBhvhCAQEEBAMCBBAwQAYDVR0gBDkw
# NzA1BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdv
# LmNvbS9DUFMwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5zZWN0aWdvLmNv
# bS9TZWN0aWdvUlNBQ29kZVNpZ25pbmdDQS5jcmwwcwYIKwYBBQUHAQEEZzBlMD4G
# CCsGAQUFBzAChjJodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FDb2Rl
# U2lnbmluZ0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5j
# b20wHwYDVR0RBBgwFoEUc3VwcG9ydEBhc3RyaXguY28udWswDQYJKoZIhvcNAQEL
# BQADggEBACol7X9UrQLifw8Q+ZH3GoRnBAcEXcb2r1DbiRi7nDOXtmt1p7iZVex8
# aQz3nTamD429kllUPm5wIYN/sicXKno/lJ6cMYIMxOLF+BAKmsmYs0JOD5qecWHQ
# gOrWwStAsmVGuNQYnUTlE/IkXMBum5OJzZRXtS9DbaXJInLsFIageSsUpZdpvTYW
# VCu88Xl0HNOb198NtfB4Y7ZvNE/zLW51uS65Cb5DcNuxLVnlVnYedfumsqWG2jrj
# ven5mNvLmLSZh/CSZUN84L6S37zm7VcZpPOjMVmecjqOvcXIuqJq9tz/93aYJqwm
# FjJaFr4gx+PzVrb9GWo70GVe8PtUzhUwggX1MIID3aADAgECAhAdokgwb5smGNCC
# 4JZ9M9NqMA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# TmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBV
# U0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZp
# Y2F0aW9uIEF1dGhvcml0eTAeFw0xODExMDIwMDAwMDBaFw0zMDEyMzEyMzU5NTla
# MHwxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
# BgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UE
# AxMbU2VjdGlnbyBSU0EgQ29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAhiKNMoV6GJ9J8JYvYwgeLdx8nxTP4ya2JWYpQIZURnQx
# YsUQ7bKHJ6aZy5UwwFb1pHXGqQ5QYqVRkRBq4Etirv3w+Bisp//uLjMg+gwZiahs
# e60Aw2Gh3GllbR9uJ5bXl1GGpvQn5Xxqi5UeW2DVftcWkpwAL2j3l+1qcr44O2Pe
# j79uTEFdEiAIWeg5zY/S1s8GtFcFtk6hPldrH5i8xGLWGwuNx2YbSp+dgcRyQLXi
# X+8LRf+jzhemLVWwt7C8VGqdvI1WU8bwunlQSSz3A7n+L2U18iLqLAevRtn5Rhzc
# jHxxKPP+p8YU3VWRbooRDd8GJJV9D6ehfDrahjVh0wIDAQABo4IBZDCCAWAwHwYD
# VR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFA7hOqhTOjHV
# ir7Bu61nGgOFrTQOMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEA
# MB0GA1UdJQQWMBQGCCsGAQUFBwMDBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUd
# IAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VT
# RVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHYGCCsGAQUFBwEB
# BGowaDA/BggrBgEFBQcwAoYzaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VTRVJU
# cnVzdFJTQUFkZFRydXN0Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51
# c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBNY1DtRzRKYaTb3moqjJvx
# AAAeHWJ7Otcywvaz4GOz+2EAiJobbRAHBE++uOqJeCLrD0bs80ZeQEaJEvQLd1qc
# KkE6/Nb06+f3FZUzw6GDKLfeL+SU94Uzgy1KQEi/msJPSrGPJPSzgTfTt2SwpiNq
# WWhSQl//BOvhdGV5CPWpk95rcUCZlrp48bnI4sMIFrGrY1rIFYBtdF5KdX6luMNs
# tc/fSnmHXMdATWM19jDTz7UKDgsEf6BLrrujpdCEAJM+U100pQA1aWy+nyAlEA0Z
# +1CQYb45j3qOTfafDh7+B1ESZoMmGUiVzkrJwX/zOgWb+W/fiH/AI57SHkN6RTHB
# nE2p8FmyWRnoao0pBAJ3fEtLzXC+OrJVWng+vLtvAxAldxU0ivk2zEOS5LpP8WKT
# KCVXKftRGcehJUBqhFfGsp2xvBwK2nxnfn0u6ShMGH7EezFBcZpLKewLPVdQ0srd
# /Z4FUeVEeN0B3rF1mA1UJP3wTuPi+IO9crrLPTru8F4XkmhtyGH5pvEqCgulufSe
# 7pgyBYWe6/mDKdPGLH29OncuizdCoGqC7TtKqpQQpOEN+BfFtlp5MxiS47V1+KHp
# jgolHuQe8Z9ahyP/n6RRnvs5gBHN27XEp6iAb+VT1ODjosLSWxr6MiYtaldwHDyk
# WC6j81tLB9wyWfOHpxptWDGCBG8wggRrAgEBMIGQMHwxCzAJBgNVBAYTAkdCMRsw
# GQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAW
# BgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGlnbyBSU0EgQ29k
# ZSBTaWduaW5nIENBAhAHvfU0ZuEKsr2CCQl/2DeWMA0GCWCGSAFlAwQCAQUAoIGE
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkE
# MSIEIJTWfh9ZjeCg+rwf3Byqk+gFkpw9lt67YPO7YM1phsxUMA0GCSqGSIb3DQEB
# AQUABIIBACwRja6u9KmAddTqGFV+UlRUdhNk31VMWD9A3Z9D2g7tl2syi7MSHXan
# 4pO2yA+OMLGJyiEnLbVDRpuoh8YSvjLBK0iS+GGiPMZcOs5J4pxaECJ//MhZtlfS
# 61cFxsnumUqZFGVRMk5/XsiNFfC0luV8Qw5hf7EXfB6hSpgw6iV2Vqj4UPbBeXQ8
# lvZThIMcnFIBSS0ivtrY/TxBkKAK0HIjyBYOpVYGdAQP85EGpRQjXq8B4+JEspNV
# uPm63II0beJjUYMTYmD/vZBmt6PqcCsXmV2xvBjisXegWCU+oSlvFCsZAOJX9XMk
# 0ql88MjfsOuN6rNp87+MN3hMDOniwwyhggIoMIICJAYJKoZIhvcNAQkGMYICFTCC
# AhECAQEwgY4wejELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hl
# c3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0
# ZWQxIDAeBgNVBAMTF0NPTU9ETyBUaW1lIFN0YW1waW5nIENBAhArc9t0YxFMWlsy
# SvIwV3JJMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0xOTExMjAxNDMyNTZaMCMGCSqGSIb3DQEJBDEWBBR3yJET
# HxWhBrsXN7Vjs+0cBRP/HzANBgkqhkiG9w0BAQEFAASCAQCDZhQMuA7XgCMLffdn
# y4OKTk6solK3qynN/up7XKnNtfJrY3EhGS2A7XE5fJvDbAhSlBh85TtD+HGL1GXP
# cn0yaeR1P6WA6JBoBoqmUVh3MSlBtKW94rkvQBSWkT8h1Tn+Xq6+BbhNwO9DHfpI
# jEQst6v7dXpRleUFcw27HCz260ngMyeQ0u+YAfhXORKlQGF1QPSYOS4Uby+OiFXR
# 265f+mbYXYEYjXwulD+jCgy2Eog9AT0nbfkHzRWcKTFHbLlp9RkMeLzSolL2UGmc
# jyj8eTOZqmA/6EPPHUwZeEtwqjk1R/dnkXPg9fGUX+aQQn7JrB1aR62l2rqt+gBx
# G5ns
# SIG # End signature block
