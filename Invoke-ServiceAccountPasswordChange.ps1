<#
.SYNOPSIS
    This runbook can be used to manage service accounts and service account passwords.

.DESCRIPTION
    This runbook can be used to manage service accounts and service account passwords. 
    This can be used with SMA or Azure Automation as a PowerShell Runbook.
    It will randomly generate a 24-character password, update the account in Active Directory, Update the service account password & restart the service.
    This requires the Active Directory PowerShell Module.
    The account used to run this will need appropriate permissions to set account passwords and modify the service settings on the target computer.

.PARAMETER ServiceName
    The name of the service to target. This must be the service name shown in the service properties, not the display name of the service.
    This parameter is mandatory.
    Example: -ServiceName ServiceName

.PARAMETER ComputerName
    The name of the service to target. This must be the service name shown in the service properties, not the display name of the service.
    This parameter is mandatory.
    Example: -ComputerName 'servername.contoso.com'

.PARAMETER ServiceAccountLoginName
    The name of the service to target. This must be the service name shown in the service properties, not the display name of the service.
    This parameter is not mandatory and should only be used with the ChangeServiceAccountUser switch set to $True.
    Use of this parameter will change the password for the specified account and update the service to use this new account.
    If no account is specified the Runbook will read the current user account from the service to perform password maintenance.
    Example: -ServiceAccountLoginName 'Contoso\BackupServiceAccount'

.PARAMETER PasswordLength
    The desired password length of the new randomly generated password.
    This parameter is not mandatory and the default is set to 24 characters.
    Example: -PasswordLength '24'

.PARAMETER ChangeServiceAccountUser
    This is a switch that will activate the account change process.
    The default is set to $false.
    Setting this to true will change the service account to the new account specified with the ServiceAccountLoginName parameter.
    Example: -ChangeServiceAccountUser

.EXAMPLE
    As a Standalone Script
    .\Invoke-ServiceAccountPasswordChange.ps1 -ComputerName server1.contoso.local -PasswordLength '36' -ServiceName 'SQLAgent$SQLINST01' -ServiceAccountLoginName 'Contoso\NewSvcAcct' -ChangeServiceAccountUser

    As a Azure Automation Runbook
    $Parameters = @{'ComputerName'='server1.contoso.local';'PasswordLength'='36';'ServiceName'='SQLAgent$SQLINST01';'ServiceAccountLoginName'='Contoso\NewSvcAcct';'ChangeServiceAccountUser'="$True"}
    Start-AzureRmAutomationRunbook –AutomationAccountName $AutomationAccount –Name 'Invoke-ServiceAccountPasswordChange' -ResourceGroupName $AutomationResourceGroup –Parameters $Parameters -RunOn $AzureAutomationWorkers

    As a SMA Runbook
    $Parameters = @{'ComputerName'='server1.contoso.local';'PasswordLength'='36';'ServiceName'='SQLAgent$SQLINST01';'ServiceAccountLoginName'='Contoso\NewSvcAcct';'ChangeServiceAccountUser'="$True"}
    Start-SmaRunbook -WebServiceEndpoint 'https://localhost' -Name 'Invoke-ServiceAccountPasswordChange' -Parameters $Parameters
#>
param
(
    [parameter(Mandatory=$true)]
    [String]$ServiceName,

    [parameter(Mandatory=$true)]
    [String]$ComputerName,

    [parameter()]
    [String]$ServiceAccountLoginName,

    [parameter()]
    [Int]$PasswordLength,

    [parameter()]
    [Bool]$ChangeServiceAccountUser = $false
)

$Service = Get-CimInstance Win32_Service -ComputerName $ComputerName | Where-Object Name -eq $ServiceName

#region Set variable defaults if not defined.
if ([String]::IsNullOrEmpty($PasswordLength))
{
    [Int]$PasswordLength = '24'
}

if ([String]::IsNullOrEmpty($ServiceAccountLoginName))
{
    $ServiceAccountLoginName = $Service.StartName
    $ActiveDirectoryAccount = $ServiceAccountLoginName.Split("\")[1]
}
#endregion

#region Test for Active Directory Module
Import-Module ActiveDirectory

$ModuleTest = Get-Module ActiveDirectory

if ([String]::IsNullOrEmpty($ModuleTest))
{
    Write-Output 'The Active Directory Module was not found! Please install the module and try again.'
    break
}
#endregion

#region Generate Complex Password for New Local Admin
$ascii = $NULL;For ($a=33;$a –le 126;$a++) {$ascii+=,[char][byte]$a}
Function Get-Password()
{
    Param
    (
        [int]$length=10,
        [string[]]$Sourcedata
    )
    For ($loop=1; $loop –le $length; $loop++)
    {
        $Password += ($sourcedata | Get-Random)
    }
    return $Password
}
$Password = (Get-Password –length $PasswordLength –sourcedata $ascii) | ConvertTo-SecureString -AsPlainText -Force
#endregion

#region Change Active Directory Account Password
try
{
    Set-ADAccountPassword -NewPassword $Password -Identity $ActiveDirectoryAccount -PassThru -ErrorAction Stop
}
catch
{
    $Message = "$_"
    Write-Output "$Message"
    Break
}
#endregion

#region Change Service Properties
try
{
    if ($ChangeServiceAccountUser)
    {
        $ServiceAccountChangeResults = Invoke-CimMethod -InputObject $Service -ComputerName $ComputerName -MethodName Change -Arguments @{StartName="$ServiceAccountLoginName";StartPassword="$Password"} -ErrorAction Stop
    }
    else
    {
        $ServiceAccountChangeResults = Invoke-CimMethod -InputObject $Service -ComputerName $ComputerName -MethodName Change -Arguments @{StartPassword="$Password"} -ErrorAction Stop
    }

    if ($ServiceAccountChangeResults.ReturnValue -eq '0')
    {
        Write-Output "Service Account Password for $ServiceAccountLoginName has been changed. Restarting Service..."
    }

    if ($Service.State -eq 'Running' -or $Service.State -eq 'Stop Pending')
    {
        $StopServiceResults = Invoke-CimMethod -InputObject $Service -ComputerName $ComputerName -MethodName StopService -ErrorAction Stop

        if ($StopServiceResults.ReturnValue -eq '0')
        {
            Write-Output "The Service $ServiceName on $ComputerName has accepted the stop request."
            do
            {
                $Service = Get-CimInstance Win32_Service -ComputerName $ComputerName | Where-Object Name -eq $ServiceName
            }
            until ($Service.State -eq 'Stopped')
            Write-Output "The Service $ServiceName on $ComputerName has been stopped."
        }
    }

    $StartServiceResults = Invoke-CimMethod -InputObject $Service -ComputerName $ComputerName -MethodName StartService -ErrorAction Stop

    if ($StartServiceResults.ReturnValue -eq '0')
    {
        Write-Output "The Service $ServiceName on $ComputerName has accepted the start request."
        do
        {
            $Service = Get-CimInstance Win32_Service -ComputerName $ComputerName | Where-Object Name -eq $ServiceName
        }
        until ($Service.State -eq 'Running')
        Write-Output "The Service $ServiceName on $ComputerName has been started."
    }
    Write-Output "The service account information for $ServiceName has been updated on $ComputerName."
}
catch
{
    $Message = "$_"
    Write-Output "$Message"
    Break
}
#endregion