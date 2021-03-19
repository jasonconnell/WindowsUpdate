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

If (-not ($PSVersionTable)) {Write-Warning 'PS1 Detected. PowerShell Version 2.0 or higher is required.';return}
ElseIf ($PSVersionTable.PSVersion.Major -lt 3 ) {Write-Verbose 'PS2 Detected. PowerShell Version 3.0 or higher may be required for full functionality.'}


#Module Version
$ModuleVersion = "1.0.0"
$ModuleGuid='084a979b-91fd-45d9-b214-149bdfc168c7'

If ($env:PROCESSOR_ARCHITEW6432 -match '64' -and [IntPtr]::Size -ne 8 -and $env:PROCESSOR_ARCHITEW6432 -ne 'ARM64') {
    Write-Warning '32-bit PowerShell session detected on 64-bit OS. Attempting to launch 64-Bit session to process commands.'
    $pshell="${env:windir}\SysNative\WindowsPowershell\v1.0\powershell.exe"
    If (!(Test-Path -Path $pshell)) {
        $pshell="${env:windir}\System32\WindowsPowershell\v1.0\powershell.exe"
        If ($Null -eq ([System.Management.Automation.PSTypeName]'Kernel32.Wow64').Type -or $Null -eq [Kernel32.Wow64].GetMethod('Wow64DisableWow64FsRedirection')) {
            Write-Debug 'Loading WOW64Redirection functions'

            Add-Type -Name Wow64 -Namespace Kernel32 -Debug:$False -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool Wow64DisableWow64FsRedirection(ref IntPtr ptr);

[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool Wow64RevertWow64FsRedirection(ref IntPtr ptr);
"@
        }
        Write-Verbose 'System32 path is redirected. Disabling redirection.'
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
        Write-Verbose 'System32 path redirection has been re-enabled.'
    }#End If
    Write-Warning 'Exiting 64-bit session. Module will only remain loaded in native 64-bit PowerShell environment.'
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
        Write-Debug "Getting System Drive $($SystemDrive) information"
        $DriveInfo = get-WmiObject win32_logicaldisk -Filter "DeviceID='$($SystemDrive)'"
    }#End Process

    End{
        $FreeSpace = [Math]::Round($DriveInfo.FreeSpace / 1Gb)
        $DiskSpacePercent = [Math]::Round(($DriveInfo.FreeSPace / $DriveInfo.Size) * 100)
        Write-Verbose "System drive currently has $($FreeSpace) GB free ($($DiskSpacePercent)%)"     
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
        Write-Debug "Creating PS hash table to store system information"
    }#End Begin

    Process{

        Write-Debug "Getting system version information"
        Try{
            $SystemVerInfo = [System.Environment]::OSVersion.Version
            $MajorVersion = $SystemVerInfo.Major
            $MinorVersion = $SystemVerInfo.Minor
            $BuildNumber = $SystemVerInfo.Build     
        }#End Try
        
        Catch{
            Write-Error "ERROR: Line ($($LINENUM): Failed to retrieve version information"
        }#End Catch

        Try{
            Write-Debug "Getting System Name and OS"
            $ComputerName = [System.Net.DNS]::GetHostName()
            $OperatingSystem = (Get-WmiObject Win32_OperatingSystem).Caption
        }#End Try

        Catch{
            Write-Error "ERROR: Line $($LINENUM): Failed to gather System name and OS"
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

    Begin{}

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
    [switch]$ISO,
    [string]$LogPath,
    [switch]$NoReboot
)

    Begin{
        if ((Get-DiskSpace) -ge $FreeSpaceThreshold){
            Write-Verbose "System disk check passed. Continuing with update"
        }Else{
            Write-Error "ERROR: Line $($LINENUM): Not enough free disk space to continue." -ErrorAction Stop
        }

        if (-Not([string]::IsNullOrEmpty($LogPath))){
            Write-Verbose "New log path $($LogPath) defined. Using destination for logging"
            $CopyArg = [string]::Concat("/copylogs ", $LogPath)
            if(-Not(Test-Path $LogPath)){
                New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            }   
        }

        if ($NoReboot){
            $RebootArg = "/noreboot"
        }

        if ($BackupUserProfile){
            Write-Verbose "User Profile Backup switch set to true. Starting backup of profile"
            Backup-UserProfile
        }Else{
            Write-Verbose "User Profile Backup switch set to false. Skipping backup of profile"
        }
    }

    Process{
        Try{
            Write-Verbose "Creating temp directory at $($ENV:TEMP)\Windows10Update"
            New-Item -Path $ENV:TEMP -Name "Windows10Update" -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        Catch{
            Write-Error "Failed to create temp directory to store update data" -ErrorAction Stop
        }

        Try{
            (New-Object Net.Webclient).DownloadFile($UpdateTool,($ENV:TEMP + "\Windows10Update\updater.exe"))
        }

        Catch{
            Write-Error "ERROR: Line ($($LINENUM): Failed to download file $($UpdateTool) $($Error[0])" -ErrorAction Stop
        }
        Try{
            if (Test-Path ($ENV:TEMP + "\Windows10Update\updater.exe")){
                Write-Verbose "Update utility successfully downloaded"
                $InstallArg = "/quietinstall /skipeula /auto upgrade $($CopyArg) $($RebootArg)"
                Write-Verbose "Issuing install command Update.exe $($InstallArg)"
                Try{
                    Write-Verbose "Invoking install now. This process can take several hours to complete"
                    Start-Process -FilePath ($ENV:TEMP + "\Windows10Update\updater.exe") -ArgumentList $InstallArg
                }

                Catch{
                    Write-Error "ERROR: Line $($LINENUM): Failed to start install process. Error: $($Error[0])"
                }
            }else{
                Write-Error "ERROR: Line $($LINENUM): Failed to download Windows 10 Update Assistant"
            }
        }
        
        Catch{
            Write-Error "ERROR: Line $($LINENUM): An error occured while attempting to setup installer. ERROR: $($Error[0])"
        }

    }

    End{}
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
            Write-Verbose "No path provided using current directory"
            $Path = (Get-Location).Path 
        }

        $Path = [string]::Concat($Path, '\Win10UpdateLogs')
        Write-Verbose "Setting path equal to $($Path)"
    }

    Process{

        Try{
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        Catch{
            Write-Error "ERROR: Line $($LINENUMB): Failed to create directory. $($Error[0])"
        }

        Try{
            foreach ($log in $UpdateLogs){
                If (Test-path $log){
                    Write-Verbose "Copying file $($log)"
                    Copy-Item $log -Destination $Path -Force | Out-Null
                }
            }
        }

        Catch{
            Write-Error "ERROR: Line $($LINENUM): Failed to copy all Success logs. $($Error[0])"
        }
    }

    End{
        Write-Verbose "Finished copying all logs."

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
    #https://go.microsoft.com/fwlink/?linkid=870142

    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
    Param ()

    Begin{
        Try{
            if ($true){}
        }
        Catch{}
    }

    Process{}

    End{}
}


Function Get-Windows10EventLogs {
    $events = Get-WinEvent -FilterHashtable @{LogName="Application";ID="1001";Data="WinSetupDiag02"}
$event = [xml]$events[0].ToXml()
$event.Event.EventData.Data
}

Function Get-CurrentLineNumber {
    $MyInvocation.ScriptLineNumber
}
Set-Alias -name LINENUM -value Get-CurrentLineNumber -WhatIf:$False -Confirm:$False -Scope Script


$PublicFunctions=@(((@"
Get-SetupDiag
Get-Win10Logs
Update-Windows10
Get-DownloadSpeed
Backup-UserProfile
Get-SystemHashTable
Get-DiskSpace
"@) -replace "[`r`n,\s]+",',') -split ',')