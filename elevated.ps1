##############################
# Script Written By Spectrum #
##############################

Param
(
	[Parameter(Mandatory=$True)]
	[ValidateScript({ Test-Path -Path $_ })]
	[string]
	$Path
)

# Track execution time of the script
$StopWatchElevated = [System.Diagnostics.StopWatch]::StartNew()

# Detect Windows version
$WindowsBuild  = [System.Environment]::OSVersion.Version.Build
$Win10MinBuild = 10240

# Crash dumps to collect per minidump folder
$CrashesToCollect = 5

# This is set because $PSScriptRoot is not available on stock Windows 7 SP1
$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent

# Module path
$LoggerModule = Join-Path -Path $PSScriptRoot -ChildPath "logger-module.psm1"

# Log file
$Transcript = Join-Path -Path $env:TEMP -ChildPath "transcript-elevated.txt"

# Output folders
$CrashDumps   = Join-Path -Path $Path -ChildPath "Crash Dumps"
$PowerReports = Join-Path -Path $Path -ChildPath "Power Reports"
$WER          = Join-Path -Path $Path -ChildPath "Error Reports"

# Output files
$AutorunsReport    = Join-Path -Path $Path -ChildPath "autorun.txt"
$CrashDumpSettings = Join-Path -Path $CrashDumps -ChildPath "crash-dump-settings.txt"
$CrashLiveReports  = Join-Path -Path $CrashDumps -ChildPath "live-kernel-reports.txt"
$Disks             = Join-Path -Path $Path -ChildPath "disks.txt"
$OSDetails         = Join-Path -Path $Path -ChildPath "os-details.txt"
$Partitions        = Join-Path -Path $Path -ChildPath "partitions.txt"
$PnPDevices        = Join-Path -Path $Path -ChildPath "pnp-devices.txt"
$Processes         = Join-Path -Path $Path -ChildPath "processes.txt"
$RestorePoints	   = Join-Path -Path $Path -ChildPath "restore-points.txt"
$Services          = Join-Path -Path $Path -ChildPath "services.txt"
$SleepDiagnostics  = Join-Path -Path $PowerReports -ChildPath "sleep-diagnostics.html"
$SleepStudy        = Join-Path -Path $PowerReports -ChildPath "power-report.html"
$DriverVerifier    = Join-Path -Path $CrashDumps -ChildPath "driver-verifier.txt"

# Native file and folder locations
$KernelReportsPath = Join-Path -Path $env:SystemRoot -ChildPath "LiveKernelReports"
$LocalUserWER      = Join-Path -Path $home -ChildPath "AppData\Local\Microsoft\Windows\WER\ReportArchive" 
$ProgramDataWER    = Join-Path -Path $env:ALLUSERSPROFILE -ChildPath "Microsoft\Windows\WER\ReportArchive"
$System32          = Join-Path -Path $env:SystemRoot -ChildPath "System32"

# Full paths of executables used in this script, in case the system's path environment variables have been messed with
$AutoRunsPath = Join-Path -Path $PSScriptRoot -ChildPath "autorunsc.exe"
$PowerCfgPath = Join-Path -Path $System32 -ChildPath "powercfg.exe"
$VerifierPath = Join-Path -Path $System32 -ChildPath "verifier.exe"

# https://support.microsoft.com/en-us/help/310123/error-codes-in-device-manager-in-windows
$DeviceManagerErrorTable =
@{
    1  = "There is no driver installed or the driver is configured incorrectly."
    3  = "The driver for this device is corrupted or the system is out of resources."
    9  = "Windows cannot identify this hardware - invalid hardware ID."
    10 = "The device cannot start."
    12 = "The device cannot find enough free resources to use"
    14 = "The device cannot work properly until the system restarts."
    16 = "Windows cannot identify all the resources this device uses."
    18 = "Reinstall the drivers for this device."
    19 = "The device cannot start because its configuration information in the registry is incomplete or damaged."
    21 = "Windows is in the process of removing the device."
    22 = "The device was disabled by the user in Device Manager."
    24 = "This device is not present, is not working properly, or does not have all its drivers installed."
    28 = "Drivers for this device are not installed."
    29 = "The device is disabled because the firmware of the device did not give it the required resources."
    31 = "Windows cannot load the drivers required for this device."
    32 = "The start type for this driver is set to disabled in the registry."
    33 = "Cannot determine which resources are required for this device."
    34 = "Windows cannot determine the settings for this device - manual configuration is required."
    35 = "The system firmware does not include enough information to properly configure and use this device."
    36 = "The device is requesting a PCI interrupt but is configured for an ISA interrupt or vice versa."
    37 = "The driver returned a failure when it executed the DriverEntry routine."
    38 = "A previous instance of the device driver is still in memory."
    39 = "The driver for this device is corrupt or missing."
    40 = "The device's service key information is missing or is incorrect."
    42 = "A duplicate device was detected."
    43 = "One of the drivers controlling this device notified Windows that the device failed in some manner."
    44 = "An application or service has shut down this device."
    45 = "The device is no longer connected to the computer."
    46 = "The device is not available because Windows is shutting down."
    47 = "Windows cannot use this device because it has been prepared for safe removal, but has not been removed."
    48 = "The driver for this device has been blocked from starting because it is known to have problems with Windows."
    49 = "The System hive has exceeded the registry size limit - cannot initialize new hardware."
    50 = "Windows cannot apply all of the properties for this device."
    51 = "The device is waiting on another device to initialize."
    52 = "Windows cannot verify the driver's digital signature"
    53 = "The device has been reserved by the Windows kernel debugger."
    54 = "The device has failed and is undergoing a reset."
}

# Begin logging
Start-Transcript -Path $Transcript -Force | Out-Null

# Create folders, power reports has already been created by main.ps1
New-Item -ItemType Directory $CrashDumps -Force -ErrorAction Stop | Out-Null
New-Item -ItemType Directory $WER -Force -ErrorAction Stop | Out-Null

# Import custom module containing support functions
Try
{
    Import-Module $LoggerModule
}

Catch
{
	Write-Warning "Failed to import $LoggerModule."
	Write-Output $error[0]
    Return "Script cannot continue."
}

# Check that this script is being run with elevated credentials, e.g. Administrator, SYSTEM, or TrustedInstaller
$ElevatedCheck = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

If ( $ElevatedCheck -ne "True" )
{
	Write-Warning "Administrator rights are required for this script to work properly."
	Return "Script cannot continue."
}

# Set window size to 1000 by 1000 to avoid truncation when sending output to files
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(1000,1000)

# Get crash dump settings and append crash dump type matrix
Get-CrashDumpSettings -DestinationPath $CrashDumpSettings

# Copy mini crash dumps
Copy-MiniCrashDumps -DestinationPath $CrashDumps -CrashesToCollect $CrashesToCollect

# Check if a full/kernel/active memory dump exists in the default location and the one specified in the registry
Get-FullCrashDumpInfo -DestinationPath $CrashDumps

# Obtain status of driver verifier
Write-Output "Getting driver verifier settings..."
&$VerifierPath /query | Out-File -Append -FilePath $DriverVerifier
&$VerifierPath /querysettings | Out-File -Append -FilePath $DriverVerifier

# List contents of LiveKernelReports directory if it exists and is not empty
If ( $(Test-Path -Path $KernelReportsPath) -eq $True -and $(Get-ChildItem -Path $KernelReportsPath ) -ne $null )
{
	$LengthMB = @{Name="Size (MB)";Expression={[math]::Round($_.Length / 1MB, 2)}}
	Get-ChildItem -Filter "*.dmp" -Path $KernelReportsPath -Recurse | Select-Object Name,LastWriteTime,$LengthMB | Out-File -FilePath $CrashLiveReports
}

# Gather a power report
Write-Output "Running system power report..."
&$PowerCfgPath /sleepstudy /output $SleepStudy 2> $null| Out-Null

# Run a sleep diagnostics report
Write-Output "Running sleep diagnostics..."
&$PowerCfgPath /systemsleepdiagnostics /output $SleepDiagnostics 2> $null | Out-Null

# Disk and partition information
Import-DriveInformation

$SizeGB     = @{Name="Size (GB)";Expression={[math]::Round($_.Capacity / 1GB, 2)}}
$FreeGB     = @{Name="Free (GB)";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}
$DevicePath = @{Name="Device Path";Expression={[diskinfo]::GetDeviceName($_.DriveLetter)}}

Get-CimInstance -ClassName Win32_Volume | Where-Object { $_.DriveLetter -ne $null } | Select-Object -Property DriveLetter, $SizeGB, $FreeGB, $DevicePath | Sort-Object DriveLetter | Format-Table -AutoSize | Out-File -FilePath $Partitions
Get-Partition | Format-List | Out-File -Append -FilePath $Partitions
Get-DiskInformation | Out-File -FilePath $Disks

# List PnP devices and associated information
Write-Output "Listing PnP devices..."
$ErrorCode = @{Name="ErrorCode";Expression={ $_.ConfigManagerErrorCode }}
$ErrorText = @{Name="ErrorText";Expression={ $DeviceManagerErrorTable.($_.ConfigManagerErrorCode -as [int]) }}
$DriverAttributes = "Name", "Status", $ErrorCode, $ErrorText, "Description", "Manufacturer", "DeviceID"
Get-CimInstance -ClassName Win32_PNPEntity | Select-Object $DriverAttributes | Sort-Object Name | Format-Table -AutoSize | Out-File -Append -FilePath $PnPDevices

# List all processes
Write-Output "Enumerating running processes..."
$ProcessAttributes = "ProcessName", "ProcessID", "SessionId", "Priority", "CommandLine"
Get-CimInstance -ClassName Win32_Process | Select-Object $ProcessAttributes | Sort-Object ProcessName,ProcessId | Format-Table -AutoSize | Out-File -FilePath $Processes

# List all services including status, pid, only Windows 10 has support for listing service StartType via Get-Service
Write-Output "Identifying running services..."
If ( $WindowsBuild -ge $Win10MinBuild )
{
	$StartType = @{Name="StartType";Expression={(Get-Service $_.Name).StartType}}
	Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, State, ProcessID, $StartType | Sort-Object State, Name | Format-Table -AutoSize | Out-File -FilePath $Services	
}

Else
{
	Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, State, ProcessID | Sort-Object State, Name | Format-Table -AutoSize | Out-File -FilePath $Services
}

# List available Restore Points
Write-Output "Finding restore points..."
Get-ComputerRestorePoint | Format-Table -AutoSize | Out-File -FilePath $RestorePoints

# Get information on the OS and its boot/firmware settings
Write-Output "Checking OS details..."
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Name, Version, BuildNumber, OSArchitecture, LocalDateTime, LastBootUpTime, InstallDate, BootDevice, SystemDevice | Out-File -Append -FilePath $OSDetails

Write-Output "Getting boot information..."
Get-BootInfo | Format-List | Out-File -Append -FilePath $OSDetails

# Copy Windows Error Reports
Write-Output "Copying Windows error reports..."
If ( Test-Path -Path $LocalUserWER )
{
	Copy-Item "$LocalUserWER\*" -Destination $WER -Recurse -Container 2> $null | Out-Null
}

If ( Test-Path -Path $ProgramDataWER )
{
	Copy-Item "$ProgramDataWER\*" -Destination $WER -Recurse -Container 2> $null | Out-Null
}

# Find autostart entries, scheduled tasks etc. with Autorunsc.exe
If ( Test-Path -Path $AutoRunsPath )
{
	Write-Output "Finding auto-start entries..."
	# -s = Verify digital signatures, -m = List all autostart entries that are not cryptographically signed by Microsoft, -a = specify autostart selection, 
	# b = boot execute, d = Appinit DLLs, e = explorer add-ons, h = image hijacks, l = logon, t = scheduled tasks, w = winlogon

	Start-Process -FilePath $AutoRunsPath -ArgumentList "-accepteula","-nobanner","-s","-m","-a","bdehtw" -NoNewWindow -Wait -RedirectStandardOutput $AutoRunsReport
	Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location | Format-List | Out-File -Append -FilePath $AutoRunsReport
	Remove-Item -Path $AutoRunsPath -Force | Out-Null
}

Else
{
	Write-Warning "$AutoRunsPath not found."
}

# Record execution time
If ( $StopWatchElevated.IsRunning )
{
	$StopWatchElevated.Stop()
	Write-Information -MessageData "elevated.ps1 execution time was $($StopWatchElevated.Elapsed.TotalSeconds) seconds."
}

Else
{
	Write-Information -MessageData "StopWatch instance for elevated.ps1 was not running."
}

# Stop transcript and move it into $Path
If ( Test-Path -Path $Transcript )
{
	Stop-Transcript | Out-Null

	# Allow transcript to be moved and read by standard users, otherwise hashing and compression may fail 
	$TranscriptACL = Get-ACL -Path $Transcript
	$TranscriptACL.SetAccessRuleProtection(1,0)
	$NewAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","full","none","none","Allow")
	$TranscriptACL.AddAccessRule($NewAccessRule)
	Set-Acl -Path $Transcript -AclObject $TranscriptACL

	# Move transcript into $Path
	Move-Item -Path $Transcript -Destination $Path -Force
}

# Stop script, it was launched with -NoExit so we must actually stop the process to close the Window
Stop-Process -ID $PID | Out-Null