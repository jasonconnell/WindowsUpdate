<#
.SYNOPSIS
    This is a Powershell module for the Windows 10 Updates.

.DESCRIPTION
    This is a set of commandlets to interface directly with the Windows Update API.

.NOTES
    Version:        1.0.0
    Author:         Jason Connell
    Website:        https://github.com/jasonconnell/WindowsUpdate
    Creation Date:  3/15/2021
    Purpose/Change: Initial Script Development

#>

If (-not ($PSVersionTable)) {New-LogMessage -Message 'PS1 Detected. PowerShell Version 2.0 or higher is required.' -Severity Warning;return}
ElseIf ($PSVersionTable.PSVersion.Major -lt 3 ) {New-LogMessage -Message 'PS2 Detected. PowerShell Version 3.0 or higher may be required for full functionality.' -Severity Warning}


#Module Version
$ModuleVersion = "1.0.0"
$ModuleGuid='084a979b-91fd-45d9-b214-149bdfc168c7'

If ($env:PROCESSOR_ARCHITEW6432 -match '64' -and [IntPtr]::Size -ne 8 -and $env:PROCESSOR_ARCHITEW6432 -ne 'ARM64') {
    New-LogMessage -Message '32-bit PowerShell session detected on 64-bit OS. Attempting to launch 64-Bit session to process commands.' -Severity Information
    $pshell="${env:windir}\SysNative\WindowsPowershell\v1.0\powershell.exe"
    If (!(Test-Path -Path $pshell)) {
        $pshell="${env:windir}\System32\WindowsPowershell\v1.0\powershell.exe"
        If ($Null -eq ([System.Management.Automation.PSTypeName]'Kernel32.Wow64').Type -or $Null -eq [Kernel32.Wow64].GetMethod('Wow64DisableWow64FsRedirection')) {
            New-LogMessage -Message 'Loading WOW64Redirection functions' -Severity Information

            Add-Type -Name Wow64 -Namespace Kernel32 -Debug:$False -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool Wow64DisableWow64FsRedirection(ref IntPtr ptr);

[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool Wow64RevertWow64FsRedirection(ref IntPtr ptr);
"@
        }
        New-LogMessage -Message 'System32 path is redirected. Disabling redirection.' -Severity Information
        [ref]$ptr = New-Object System.IntPtr
        $Result = [Kernel32.Wow64]::Wow64DisableWow64FsRedirection($ptr)
        $FSRedirectionDisabled=$True
    }#End If


    If ($myInvocation.Line) {
        &"$pshell" -NonInteractive -NoProfile $myInvocation.Line
    } Elseif ($myInvocation.InvocationName) {
        &"$pshell" -NonInteractive -NoProfile -File "$($myInvocation.InvocationName)" $args
    } Else {
        &"$pshell" -NonInteractive -NoProfile $myInvocation.MyCommand
    }#End If
    $ExitResult=$LASTEXITCODE

    If ($Null -ne ([System.Management.Automation.PSTypeName]'Kernel32.Wow64').Type -and $Null -ne [Kernel32.Wow64].GetMethod('Wow64DisableWow64FsRedirection') -and $FSRedirectionDisabled -eq $True) {
        [ref]$defaultptr = New-Object System.IntPtr
        $Result = [Kernel32.Wow64]::Wow64RevertWow64FsRedirection($defaultptr)
        New-LogMessage -Message 'System32 path redirection has been re-enabled.' -Severity Information
    }#End If
    New-LogMessage -Message 'Exiting 64-bit session. Module will only remain loaded in native 64-bit PowerShell environment.' -Severity Warning
    Exit $ExitResult
}#End If

#Ignore SSL errors
If ($Null -eq ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
    Add-Type -Debug:$False @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#Enable TLS, TLS1.1, TLS1.2, TLS1.3 in this session if they are available
IF([Net.SecurityProtocolType]::Tls) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls}
IF([Net.SecurityProtocolType]::Tls11) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls11}
IF([Net.SecurityProtocolType]::Tls12) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12}
IF([Net.SecurityProtocolType]::Tls13) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13}


# region Functions------------------------------------------------------------------------------------

Function Get-DiskSpace{
<#
.SYNOPSIS
    This function will pull drive details for the system drive.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/15/2021
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>

[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
Param ()

    Begin{
        $SystemDrive = $ENV:SystemDrive

    }#End Begin

    Process{
        New-LogMessage -Message "Getting System Drive $($SystemDrive) information" -Severity Information
        $DriveInfo = get-WmiObject win32_logicaldisk -Filter "DeviceID='$($SystemDrive)'"
    }#End Process

    End{
        $FreeSpace = [Math]::Round($DriveInfo.FreeSpace / 1Gb)
        $DiskSpacePercent = [Math]::Round(($DriveInfo.FreeSPace / $DriveInfo.Size) * 100)
        New-LogMessage -Message "System drive currently has $($FreeSpace) GB free ($($DiskSpacePercent)%)" -Severity Information
        return $FreeSpace 
    }#End End
}#End Function Get-DiskSpace


Function Get-Windows10Info{
<#
.SYNOPSIS
    This function will build an object to store key information.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/15/2021
    Purpose/Change: Initial script development

.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>

[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
Param ()


    Begin{
        New-LogMessage -Message "Creating PS hash table to store system information" -Severity Information
    }#End Begin

    Process{

        New-LogMessage -Message "Getting system version information" -Severity Information
        Try{
            $SystemVerInfo = [System.Environment]::OSVersion.Version
            $MajorVersion = $SystemVerInfo.Major
            $MinorVersion = $SystemVerInfo.Minor
            $BuildNumber = $SystemVerInfo.Build     
        }#End Try
        
        Catch{
            New-LogMessage -Message "Failed to retrieve version information" -Severity Error
        }#End Catch

        Try{
            New-LogMessage -Message "Getting System Name and OS" -Severity Information
            $ComputerName = [System.Net.DNS]::GetHostName()
            $OperatingSystem = (Get-WmiObject Win32_OperatingSystem).Caption
        }#End Try

        Catch{
            New-LogMessage -Message "Failed to gather System name and OS" -Severity Error
        }#End Catch

    }#End Process

    End{
        $SystemHash = @{
            ComputerName = $ComputerName
            OperatingSystem = $OperatingSystem
            BuildNumber = $BuildNumber
            MajorVersion = $MajorVersion
            MinorVersion = $MinorVersion
            Revison = $Revison

        }
        return $SystemHash
    }#End End
}#End Function Get-Windows10Info


Function Backup-UserProfile{
<#
.SYNOPSIS
    This function will create a backup of all users profiles and settings.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/15/2021
    Purpose/Change: Initial script development
#>

[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
Param ()

    Begin{
        Write-Output "This Function is currently under Development."
    }

    Process{}

    End{}
}


Function Get-DownloadSpeed{
<#
.SYNOPSIS
    This function will preform a quick test to determine the systems download speed.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/15/2021
    Purpose/Change: Initial script development
#>

[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
Param ()    
Write-Output "This Function is currently under Development."
}


Function Update-Windows10Iso {
<#
.SYNOPSIS
    This function will preform the windows 10 update using a provided ISO.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  4/5/2021
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>

    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$ISOPath,
        [switch]$BackupUserProfile,
        [int]$FreeSpaceThreshold = 20,
        [string]$LogPath,
        [switch]$NoReboot
        )


        Begin{
            New-LogMessage -Message "Begining validation of machines eligibility to update." -Severity Information
            if ((Get-DiskSpace) -ge $FreeSpaceThreshold){
                New-LogMessage -Message "System disk check passed. Continuing with update" -Severity Information
            }Else{
               New-LogMessage -Message "ERROR: Line $($LINENUM): Not enough free disk space to continue." -Severity Error
            }
    
            if (-Not([string]::IsNullOrEmpty($LogPath))){
                New-LogMessage "New log path $($LogPath) defined. Using destination for logging" -Severity Information
                $CopyArg = [string]::Concat("/copylogs ", $LogPath)
                if(-Not(Test-Path $LogPath)){
                    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
                }   
            }
    
            if ($NoReboot){
                New-LogMessage -Message "No Reboot Argument set to True" -Severity Information
                $RebootArg = "/noreboot"
            }
    
            if ($BackupUserProfile){
                New-LogMessage -Message "User Profile Backup switch set to true. Starting backup of profile" -Severity Information
                Backup-UserProfile
            }Else{
                New-LogMessage -Message "User Profile Backup switch set to false. Skipping backup of profile" -Severity Information
            }

            if (-Not(Test-WindowsLicense)){
                New-LogMessage -Message "Stopping script due to missing licnese." -Severity Error -ErrorAction Stop
            }
            $OsInfo = Get-Windows10Info
            New-LogMessage -Message "Current Build $($OsInfo.BuildNumber)"
        }#End Begin

        Process{
            New-LogMessage -Message "Begining process of updating Windows 10." -Severity Information

            If (Test-Path -Path $ISOPath){
                If ((Get-ItemProperty $ISOPath).Extension -eq '.iso'){
                    New-LogMessage -Message "ISO file successfully detected" -Severity Information
                    $FileName = (Get-ItemProperty $ISOPath).Name
                } Else{
                    New-LogMessage -Message "File path $($ISOPath) is not using the correct file format. Looking for .iso" -Severity Error -ErrorAction Stop
                }
               
            } Else {
                New-LogMessage -Message "Failed to detect ISO file $($ISOPath). Ensure file exists" -Severity Error -ErrorAction Stop
            }

            Try{
                New-LogMessage -Message "Copying $($ISOPath) to $($ENV:Systemdrive)\Windows\Temp" -Severity Information
                Copy-Item -Path $ISOPath -Destination "$($ENV:Systemdrive)\Windows\Temp" -Force -ErrorAction Stop
            }

            Catch{
                New-LogMessage -Message "Failed to copy $($ISOPath)" -Severity Error -ErrorAction Stop
            }

            Try{
                New-LogMessage -Message "Mounting ISO imange." -Severity Information
                $mountResult = Mount-DiskImage -ImagePath "$($ENV:Systemdrive)\Windows\Temp\$($FileName)"  -Passthru
                $MountDriveLetter = ($mountResult | Get-Volume).DriveLetter
                New-LogMessage -Message "Successfully Mounted ISO to $($MountDriveLetter):\" -Severity Information
            }

            Catch{
                New-LogMessage -Message "Failed to mount ISO image" -Severity Error -ErrorAction Stop
            }

            New-LogMessage -Message "Creating temp directory $($ENV:Systemdrive)\Windows\Temp\Windows10Feature" -Severity Information
            New-Item -Path "$($ENV:Systemdrive)\Windows\Temp\Windows10Feature" -ItemType Directory -Force -ErrorAction Stop | Out-Null

            If (Test-Path -Path "$($ENV:Systemdrive)\Windows\Temp\Windows10Feature"){
                Try{
                    foreach ($file in (Get-ChildItem -Path "$($MountDriveLetter):\")){
                        New-LogMessage -Message "Copying file $($File.FullName)" -Severity Information
                        Copy-Item -Path $file.FullName -Destination "$($ENV:Systemdrive)\Windows\Temp\Windows10Feature" -Force -Recurse
                    }
                }

                Catch{
                    New-LogMessage -Message "Failed to copy ISO contents to Temp drive $($ENV:Systemdrive)\Windows\Temp\Windows10Feature $($Error[0])" -Severity Error -ErrorAction Stop
                }
            } Else{
                New-LogMessage -Message "Temp Directory not detected. Exiting script." -Severity Error -ErrorAction Stop
            }

            Try{
                New-LogMessage -Message "Dismounting Disk image." -Severity Information
                Dismount-DiskImage -ImagePath "$($ENV:Systemdrive)\Windows\Temp\$FileName" | Out-Null
            }
            
            Catch{
                New-LogMessage -Message "Failed to dismount disk image" -Severity Error
            }

            New-LogMessage -Message "Launching installer." -Severity Information

            Try{
                $Install = Start-Process -FilePath "$($ENV:Systemdrive)\Windows\Temp\Windows10Feature\Setup.exe" -ArgumentList "/auto upgrade $($RebootArg) /Compat IgnoreWarning /DynamicUpdate disable $($CopyArgs)" -Wait -PassThru
                $hex = "{0:x}" -f $install.ExitCode
                $exit_code = "0x$hex"


                $message = Switch ($exit_code) {
                    "0xC1900210" { "SUCCESS: No compatibility issues detected"; break } 
                    "0xC1900101" { "ERROR: Driver compatibility issue detected. https://docs.microsoft.com/en-us/windows/deployment/upgrade/resolution-procedures"; break }
                    "0xC1900208" { "ERROR: Compatibility issue detected, unsupported programs:`r`n$incompatible_programs`r`n"; break }
                    "0xC1900204" { "ERROR: Migration choice not available." ; break }
                    "0xC1900200" { "ERROR: System not compatible with upgrade." ; break }
                    "0xC190020E" { "ERROR: Insufficient disk space." ; break }
                    "0x80070490" { "ERROR: General Windows Update failure, try the following troubleshooting steps`r`n- Run update troubleshooter`r`n- sfc /scannow`r`n- DISM.exe /Online /Cleanup-image /Restorehealth`r`n - Reset windows update components.`r`n"; break }
                    "0xC1800118" { "ERROR: WSUS has downloaded content that it cannot use due to a missing decryption key."; break }
                    "0x80090011" { "ERROR: A device driver error occurred during user data migration."; break }
                    "0xC7700112" { "ERROR: Failure to complete writing data to the system drive, possibly due to write access failure on the hard disk."; break }
                    "0xC1900201" { "ERROR: The system did not pass the minimum requirements to install the update."; break }
                    "0x80240017" { "ERROR: The upgrade is unavailable for this edition of Windows."; break }
                    "0x80070020" { "ERROR: The existing process cannot access the file because it is being used by another process."; break }
                    "0xC1900107" { "ERROR: A cleanup operation from a previous installation attempt is still pending and a system reboot is required in order to continue the upgrade."; break }
                    "0x3" { "SUCCESS: The upgrade started, no compatibility issues."; break }
                    "0x5" { "ERROR: The compatibility check detected issues that require resolution before the upgrade can continue."; break }
                    "0x7" { "ERROR: The installation option (upgrade or data only) was not available."; break }
                    "0x0" { "SUCCESS: Upgrade started."; break }
                    default { "WARNING: Unknown exit code."; break }
                  }
                
                  if ($exit_code -eq "0xC1900210" -or $exit_code -eq "0x3" -or $exit_code -eq "0x0") {
                      New-LogMessage -Message $message -Severity Information
                      Start-Sleep -Seconds 300
                      Restart-Computer -Force
                    } else {
                        New-LogMessage -Message $message -Severity Error
                    }

            }

            Catch{
                New-LogMessage -Message "Failed to start process. Error $($Error[0])"
            }

            
        }#End Begin

        End{
            Get-UpgradeSoftwareCompatibility
            Get-UpgradeHardwareCompatibility
            New-LogMessage -Message "Reached finish" -Severity Information
        }#End End

}

Function Update-Windows10 {
    <#
.SYNOPSIS
    This function will update a Windows 10 system to the latest build.
.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/15/2021
    Purpose/Change: Initial script development
#>


[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
Param (
    [string]$UpdateTool = 'https://download.microsoft.com/download/2/b/b/2bba292a-21c3-42a6-8123-98265faff0b6/Windows10Upgrade9252.exe',
    [switch]$BackupUserProfile,
    [int]$FreeSpaceThreshold = 20,
    [string]$LogPath,
    [switch]$NoReboot
)

    Begin{
        if ((Get-DiskSpace) -ge $FreeSpaceThreshold){
            New-LogMessage -Message "System disk check passed. Continuing with update" -Severity Information
        }Else{
            New-LogMessage -Message "Not enough free disk space to continue." -Severity Error -ErrorAction Stop
        }

        if (-Not([string]::IsNullOrEmpty($LogPath))){
            New-LogMessage -Message "New log path $($LogPath) defined. Using destination for logging" -Severity Information
            $CopyArg = [string]::Concat("/copylogs ", $LogPath)
            if(-Not(Test-Path $LogPath)){
                New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            }   
        }

        if ($NoReboot){
            $RebootArg = "/noreboot"
        }

        if ($BackupUserProfile){
            New-LogMessage -Message "User Profile Backup switch set to true. Starting backup of profile" -Severity Information
            Backup-UserProfile
        }Else{
            New-LogMessage -Message "User Profile Backup switch set to false. Skipping backup of profile" -Severity Information
        }
        $OsInfo = Get-Windows10Info
        New-LogMessage -Message "Current Build $($OsInfo.BuildNumber)"
    }

    Process{
        Try{
            New-LogMessage -Message "Creating temp directory at $($ENV:TEMP)\Windows10Update" -Severity Information
            New-Item -Path $ENV:TEMP -Name "Windows10Update" -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        Catch{
            New-LogMessage -Message "Failed to create temp directory to store update data" -Severity Error -ErrorAction Stop
        }

        Try{
            (New-Object Net.Webclient).DownloadFile($UpdateTool,($ENV:TEMP + "\Windows10Update\updater.exe"))
        }

        Catch{
            New-LogMessage -Message "Failed to download file $($UpdateTool) $($Error[0])" -Severity Error -ErrorAction Stop
        }
        Try{
            if (Test-Path ($ENV:TEMP + "\Windows10Update\updater.exe")){
                New-LogMessage -Message "Update utility successfully downloaded" -Severity Information
                $InstallArg = "/quietinstall /skipeula /auto upgrade $($CopyArg) $($RebootArg)"
                New-LogMessage -Message "Issuing install command Update.exe $($InstallArg)" -Severity Information
                Try{
                    New-LogMessage -Message "Invoking install now. This process can take several hours to complete" -Severity Information
                    $install = Start-Process -FilePath ($ENV:TEMP + "\Windows10Update\updater.exe") -ArgumentList $InstallArg -Wait -PassThru
                    
                    $hex = "{0:x}" -f $install.ExitCode
                    $exit_code = "0x$hex"


                    $message = Switch ($exit_code) {
                        "0xC1900210" { "SUCCESS: No compatibility issues detected"; break } 
                        "0xC1900101" { "ERROR: Driver compatibility issue detected. https://docs.microsoft.com/en-us/windows/deployment/upgrade/resolution-procedures"; break }
                        "0xC1900208" { "ERROR: Compatibility issue detected, unsupported programs:`r`n$incompatible_programs`r`n"; break }
                        "0xC1900204" { "ERROR: Migration choice not available." ; break }
                        "0xC1900200" { "ERROR: System not compatible with upgrade." ; break }
                        "0xC190020E" { "ERROR: Insufficient disk space." ; break }
                        "0x80070490" { "ERROR: General Windows Update failure, try the following troubleshooting steps`r`n- Run update troubleshooter`r`n- sfc /scannow`r`n- DISM.exe /Online /Cleanup-image /Restorehealth`r`n - Reset windows update components.`r`n"; break }
                        "0xC1800118" { "ERROR: WSUS has downloaded content that it cannot use due to a missing decryption key."; break }
                        "0x80090011" { "ERROR: A device driver error occurred during user data migration."; break }
                        "0xC7700112" { "ERROR: Failure to complete writing data to the system drive, possibly due to write access failure on the hard disk."; break }
                        "0xC1900201" { "ERROR: The system did not pass the minimum requirements to install the update."; break }
                        "0x80240017" { "ERROR: The upgrade is unavailable for this edition of Windows."; break }
                        "0x80070020" { "ERROR: The existing process cannot access the file because it is being used by another process."; break }
                        "0xC1900107" { "ERROR: A cleanup operation from a previous installation attempt is still pending and a system reboot is required in order to continue the upgrade."; break }
                        "0x3" { "SUCCESS: The upgrade started, no compatibility issues."; break }
                        "0x5" { "ERROR: The compatibility check detected issues that require resolution before the upgrade can continue."; break }
                        "0x7" { "ERROR: The installation option (upgrade or data only) was not available."; break }
                        "0x0" { "SUCCESS: Upgrade started."; break }
                        default { "WARNING: Unknown exit code."; break }
                    }
                
                    if ($exit_code -eq "0xC1900210" -or $exit_code -eq "0x3" -or $exit_code -eq "0x0") {
                        New-LogMessage -Message $message -Severity Information
                        Start-Sleep -Seconds 300
                        } else {
                        New-LogMessage -Message $message -Severity Error
                        }

                }

                Catch{
                    New-LogMessage -Message "Failed to start install process. Error: $($Error[0])" -Severity Error
                }
            }else{
                New-LogMessage -Message "Failed to download Windows 10 Update Assistant. Error: $($Error[0])" -Severity Error
            }
        }
        
        Catch{
            New-LogMessage -Message "An error occured while attempting to setup installer. ERROR: $($Error[0])" -Severity Error
        }

    }

    End{
        Get-UpgradeSoftwareCompatibility
        Get-UpgradeHardwareCompatibility
    }
}


Function Get-Win10Logs {
<#
.SYNOPSIS
    This function will collect all Windows 10 update logs to a centralized location.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/15/2021
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>

    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
    Param (
        [string]$Path,
        [switch]$Zip
    )

    Begin{
        $UpdateLogs = @(
            'C:\Windows\Panther\Setupact.log',
            'C:\Windows\panther\setuperr.log',
            'C:\Windows\inf\setupapi.app.log',
            'C:\Windows\inf\setupapi.dev.log',
            'C:\Windows\panther\PreGatherPnPList.log',
            'C:\Windows\panther\PostApplyPnPList.log',
            'C:\Windows\panther\miglog.xml',
            'C:\$Windows.~BT\Sources\panther\setupact.log',
            'C:\$Windows.~BT\Sources\panther\miglog.xml',
            'C:\Windows\setupapi.log',
            'C:\Windows\Logs\MoSetup\BlueBox.log',
            'C:\Windows\panther\setupact.log',
            'C:\Windows\panther\miglog.xml',
            'C:\Windows\inf\setupapi.app.log',
            'C:\Windows\inf\setupapi.dev.log',
            'C:\Windows\panther\PreGatherPnPList.log',
            'C:\Windows\panther\PostApplyPnPList.log'
            'C:\Windows\memory.dmp',
            'C:\$Windows.~BT\Sources\panther\setupact.log',
            'C:\$Windows.~BT\Sources\panther\miglog.xml',
            'C:\$Windows.~BT\sources\panther\setupapi\setupapi.dev.log',
            'C:\$Windows.~BT\sources\panther\setupapi\setupapi.app.log',
            'C:\Windows\memory.dmp',
            'C:\$Windows.~BT\Sources\Rollback\setupact.log',
            'C:\$Windows.~BT\Sources\Rollback\setupact.err',
            'C:\Windows\Panther\UnattendGC\diagerr.xml',
            'C:\Windows\Panther\UnattendGC\diagwrn.xml',
            'C:\Windows\Panther\UnattendGC\setupact.log',
            'C:\Windows\Panther\UnattendGC\setuperr.log',
            'C:\Windows\Panther\setup.etl'
        )

        If ([string]::IsNullOrEmpty($Path)){
            New-LogMessage -Message "No path provided using current directory" -Severity Information
            $Path = (Get-Location).Path 
        }

        $Path = [string]::Concat($Path, '\Win10UpdateLogs')
        New-LogMessage -Message "Setting path equal to $($Path)" -Severity Information
    }

    Process{

        Try{
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        Catch{
            New-LogMessage -Message "Failed to create directory. $($Error[0])" -Severity Error
        }

        Try{
            foreach ($log in $UpdateLogs){
                If (Test-path $log){
                    New-LogMessage -Message "Copying file $($log)" -Severity Information
                    Copy-Item $log -Destination $Path -Force | Out-Null
                }
            }
        }

        Catch{
            New-LogMessage -Message "ERROR: Line $($LINENUM): Failed to copy all Success logs. $($Error[0])" -Severity Error
        }
    }

    End{
        New-LogMessage -Message "Finished copying all logs." -Severity Information

        If ($Zip){
            Compress-Archive -Path $Path -DestinationPath "$($Path)\Win10UpdateLogs.zip" -Force | Out-Null
        }
    }
}


Function Get-SetupDiag {
<#
.SYNOPSIS
    This function will attempt to download the Windows 10 setupdiag tool and scan for errors.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/16/2021
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>


    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
    Param ()

    Begin{
        Write-Output "This Function is currently under Development."
        Try{
            if ($true){}
        }
        Catch{}
    }

    Process{}

    End{}
}


Function Get-Windows10EventLogs {
<#
.SYNOPSIS
    This function will search through the event log for known upgrade events.
.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/31/2021
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
    Param ()

    Begin{
        New-LogMessage -Message "Starting search for upgrade event logs." -Severity Information
    }#End Begin

    Process{
        Try{
            $events = Get-WinEvent -FilterHashtable @{LogName="Application";ID="1001";Data="WinSetupDiag02"}
            $eventlogs = [xml]$events[0].ToXml()
        }

        Catch{
            New-LogMessage -Message "ERROR: Line $($LINEUM): Failed to retrieve event logs." -Severity Error
        }
    }#End Process

    End{
        $eventlogs.Event.EventData.Data
    }#End End
}

Function Get-UpgradeHardwareCompatibility {
<#
.SYNOPSIS
    This function will attempt to locate Hardware that may be incompatible with the upgrade.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/31/2021
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>

    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
    Param ()

    Begin{
        $ScanDir = "$($env:SystemDrive)\`$WINDOWS.~BT\Sources\panther\compat*"
    }#End Begin

    Process{
        New-LogMessage -Message "Gathering hardware compatibility information" -Severity Information

        Try{
            [xml]$compatreport = Get-ChildItem $ScanDir -ErrorAction Stop |
            Sort-Object LastWriteTime |
            Select-Object -Last 1 |
            Get-Content

            $hw_issues = @()

            $compatreport.Compatreport.Hardware.HardwareItem |
            ForEach-Object {
                If ($_.CompatibilityInfo.BlockingType -eq "Hard") {
                    $hw_issues += $_.HartwareType
                }
            }
        }

        Catch{
            New-LogMessage -Message "Unable to identify any incompatible hardware" -Severity Information
            break
        }
    }#End Process

    End{
        If ($hw_issues.count -gt 0) {
            New-LogMessage -Message "Incompatable Hardware found: $([string]::Join(", ", $hw_issues))" -Severity Error
        } Else {
            New-LogMessage -Message "No hardware compatibility issues found" -Severity Information
        }
    }#End End

}#End Function Get-UpgradeHardwareCompatibility


Function Get-UpgradeSoftwareCompatibility {
<#
.SYNOPSIS
    This function will attempt to locate Software that may be incompatible with the upgrade.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/30/2021
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>

    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
    Param ()

    Begin{
        $ScanDir = "$($env:SystemDrive)\`$WINDOWS.~BT\Sources\panther\compat*"
    }#End Begin

    Process{
        New-LogMessage -Message "Gathering incompatible software" -Severity Information

        Try {
            [xml]$CompatReport = Get-ChildItem -Path $ScanDir -ErrorAction Stop |
            Sort-Object LastWriteTime |
            Select-Object -Last 1 |
            Get-Content

            $IncompatibleSoftware = $CompatReport.Compatreport.Programs | ForEach-Object {$_.Program.Name}
        }

        Catch{
            New-LogMessage -Message "Unable to identify any incompatible software" -Severity Information
            break
        }
    }#End Process

    End{
        If ($IncompatibleSoftware.count -gt 0) {
            New-LogMessage -Message "Incompatable Software found: $([string]::Join(", ", $IncompatibleSoftware))" -Severity Error
        } Else {
            New-LogMessage -Message "No incompatible software found" -Severity Information
        }
    }#End End

}#End Function Get-UpgradeSoftwareCompatibility
Function Test-WindowsLicense{
<#
.SYNOPSIS
    This function will use the slmgr.vbs to determine if the system is licensed.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/30/2021
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>

    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
    Param ()

    Begin{
        $LicenseStatus = $false
        $SlmgrPath = $ENV:SystemDrive + "\Windows\System32\slmgr.vbs"
    }#End Begin

    Process{
        New-LogMessage -Message "Determining if Windows is licensed" -Severity Information
        if ((Cscript "$($SlmgrPath) "/dli ) -match "Licensed"){
            $LicenseStatus = $true
            New-LogMessage -Message "Windows is Activly Licensed. Continuing with installation." -Severity Information
        } Else{
            New-LogMessage -Message "Windows is not currently licnesed. License is required to continue." -Severity Error
        }
    }#End Process

    End{
        Return $LicenseStatus
    }#End End

}#End Funciton Test-WindowsLicense

Function Get-CurrentLineNumber {
    $MyInvocation.ScriptLineNumber
}
Set-Alias -name LINENUM -value Get-CurrentLineNumber -WhatIf:$False -Confirm:$False -Scope Script

Function New-LogMessage{
<#
.SYNOPSIS
    This function will record all log messages.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  3/30/2021
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
 
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Information'
    )

    Begin{
        
        $LogPath = $ENV:SystemDrive + "\Windows\Temp\Windows10FeatureUpdate.log"

        if (-NOT(Test-Path -Path $LogPath)){
            New-Item -Path $LogPath -Force | Out-Null
        }
    }#End Begin

    Process{
        $date = Get-Date -Format "dd-MM-yyyy HH:mm"
        $LogFormat = "$($date)  $($Severity)  $($message)"
    
    }#End Process

    End{
        Out-File -FilePath $LogPath -InputObject $LogFormat -Append

        Switch($Severity)
            {
                "Information"{Write-Verbose $LogFormat; Break}
                "Warning"{Write-Verbose $LogFormat; Break}
                "Error"{Write-Error $LogFormat; Break}

            }
    }#End End
}#End Function New-LogMessage



function Get-MissingUpdates{
<#
.SYNOPSIS
    This function will gather all availible updates and write them to file.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  2/22/2022
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>
    [CmdletBinding()]
    Param(
        [string]$Path = "$ENV:SystemDrive:\Windows\Temp\Missingpatches.txt"
    )

    Begin{
        New-LogMessage -Message "Gathering missing Updates"
    }
    Process{
        $UpdateObject = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateObject.CreateupdateSearcher()
        $Updates = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0").Updates)
        $Updates | Select-Object Title,RebootRequired,SupportURL | Format-List > $Path
    }
    End{
        New-LogMessage -Message "Missing Updates list: $Path" -Severity Information
    }

}
Function Import-WindowsUpdateModule {
<#
.SYNOPSIS
    This function will install the Windows Update module.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  2/22/2022
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>
    [CmdletBinding()]
    Param()
    

    Begin{
        New-LogMessage -Message "Installing Package Provider NuGet" -Severity Information

    }
    Process{
        New-LogMessage -Message "Testing if NuGet Package provider is installed. If missing it will be installed" -Severity Information
        Get-PackageProvider -Name Nuget -ForceBootstrap | Out-Null

        New-LogMessage -Message "Setting PSGallery as a trusted source" -Severity Information
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

        New-LogMessage -Message "Installing PSWindowsUpdate Module" -Severity Information
        Install-Module -Name PSWindowsUpdate
    }
    End{
        New-LogMessage -Message "PSWindowsUpdate is now installed" -Severity Information
    }
}

Function Remove-WindowsUpdateModule{
<#
.SYNOPSIS
    This function will Remove the Windows Update module.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  2/22/2022
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>    

    [CmdletBinding()]
    Param()

    Begin{
        New-LogMessage -Message "Begining removal of PSWindowsUpdate Module" -Severity Information
    }
    Process{
        Remove-Module -Name PSWindowsUpdate
        Uninstall-Module -Name PSWindowsUpdate -Force -ErrorAction SilentlyContinue
        
        New-LogMessage -Message "Reverting PSRepository settings" -Severity Information
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Untrusted

    }
    End{
        New-LogMessage -Message "PSWindows Update Module has been removed."
    }

}


Function Invoke-WindowsUpdates{
<#
.SYNOPSIS
    This function will install all availible Windows Updates.

.NOTES
    Version:        1.0
    Author:         Jason Connell
    Creation Date:  2/22/2022
    Purpose/Change: Initial script development
    
.LINK
    https://github.com/jasonconnell/WindowsUpdate/blob/main/README.md
#>
    [CmdletBinding()]

    Param(
        [switch]$reboot
    )

    Begin{
        # Setup Directory to store update history
        New-LogMessage -Message "Creating folder directory $ENV:SystemDrive\AutoUpdates\History" -Severity Information
        New-Item -Path "$ENV:SystemDrive\AutoUpdates\History" -ItemType Directory -Force | Out-Null

        New-LogMessage -Message "Importing Udate module" -Severity Information
        Import-WindowsUpdateModule
    }

    Process{
        New-LogMessage -Message "Querying all availible upates and storing in $ENV:SystemDrive\AutoUpdates\History\" -Severity Information
        Get-WindowsUpdate | Out-File $ENV:SystemDrive:\AutoUpdates\History\Updates_"$((Get-Date).ToString('dd-MM-yyyy_HH.mm.ss'))".txt
        if ($reboot){
            Install-WindowsUpdate -Install -AcceptAll -AutoReboot
        }else{
            Install-WindowsUpdate -Install -AcceptAll 
        }
    }

    End{
        New-LogMessage -Message "Finished installing all availible updates" -Severity Information
        New-LogMessage -Message "Removing PSWindowsUpdate Module"
        Remove-WindowsUpdateModule
    }


}


$PublicFunctions=@(((@"
Get-SetupDiag
Get-Win10Logs
Update-Windows10
Get-DownloadSpeed
Backup-UserProfile
Get-SystemHashTable
Get-DiskSpace
Invoke-WindowsUpdate
Import-WindowsUpdateModule
Remove-WindowsUpdateModule
Get-MissingUpdates
"@) -replace "[`r`n,\s]+",',') -split ',')
