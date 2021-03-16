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
}




Function Get-CurrentLineNumber {
    $MyInvocation.ScriptLineNumber
}
Set-Alias -name LINENUM -value Get-CurrentLineNumber -WhatIf:$False -Confirm:$False -Scope Script
