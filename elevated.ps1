##############################
# Script Written By Spectrum #
##############################

#Requires -Version 4.0
#Requires -RunAsAdministrator

Param
(
	[Parameter(Mandatory=$True)]
	[ValidateScript({ Test-Path -Path $_ })]
	[string]
	$Path
)

# Any errors at the start should be treated as fatal
$ErrorActionPreference = 'Stop'

# Track execution time of the script
$StopWatchElevated = [System.Diagnostics.StopWatch]::StartNew()

# Default to UTF-8 output
$PSDefaultParameterValues['*:Encoding'] = 'UTF8'

# Log file
$Guid = [System.Guid]::NewGuid().ToString()
$TranscriptFile  = "transcript-elevated-" + $Guid + ".txt"
$TranscriptFinal = "transcript-elevated.txt"
$TranscriptPath  = Join-Path -Path $env:TEMP -ChildPath $TranscriptFile

# Begin logging
Start-Transcript -Path $TranscriptPath -Force | Out-Null

# Detect Windows version
$WindowsBuild  = [System.Environment]::OSVersion.Version.Build
$Win10MinBuild = 10240

# Crash dumps to collect per minidump folder
$CrashesToCollect = 5

# Module path
$LoggerModule = Join-Path -Path $PSScriptRoot -ChildPath "logger-module.psm1"

# Output folders
$CrashDumps   = Join-Path -Path $Path -ChildPath "Crash Dumps"
$PowerReports = Join-Path -Path $Path -ChildPath "Power Reports"
$WER          = Join-Path -Path $Path -ChildPath "Error Reports"

# Output files
$AutorunsReport    = Join-Path -Path $Path -ChildPath "autorun.txt"
$CrashDumpSettings = Join-Path -Path $CrashDumps -ChildPath "crash-dump-settings.txt"
$FullDumpReport    = Join-Path -Path $CrashDumps -ChildPath "memory-dumps.txt"
$CrashLiveReports  = Join-Path -Path $CrashDumps -ChildPath "live-kernel-reports.txt"
$Disks             = Join-Path -Path $Path -ChildPath "disks.txt"
$DriverVerifier    = Join-Path -Path $CrashDumps -ChildPath "driver-verifier.txt"
$OSDetails         = Join-Path -Path $Path -ChildPath "os-details.txt"
$Partitions        = Join-Path -Path $Path -ChildPath "partitions.txt"
$PnpDevices        = Join-Path -Path $Path -ChildPath "pnp-devices.txt"
$Processes         = Join-Path -Path $Path -ChildPath "processes.txt"
$RestorePoints	   = Join-Path -Path $Path -ChildPath "restore-points.txt"
$Services          = Join-Path -Path $Path -ChildPath "services.txt"
$SleepDiagnostics  = Join-Path -Path $PowerReports -ChildPath "sleep-diagnostics.html"
$SleepStudy        = Join-Path -Path $PowerReports -ChildPath "power-report.html"
$TranscriptDest    = Join-Path -Path $Path -ChildPath $TranscriptFinal

# Native file and folder locations
$LocalUserWER      = Join-Path -Path $home -ChildPath "AppData\Local\Microsoft\Windows\WER\ReportArchive"
$ProgramDataWER    = Join-Path -Path $env:ALLUSERSPROFILE -ChildPath "Microsoft\Windows\WER\ReportArchive"
$System32          = Join-Path -Path $env:SystemRoot -ChildPath "System32"

# Full paths of executables used in this script, in case the system's path environment variables have been messed with
$AutoRunsPath = Join-Path -Path $PSScriptRoot -ChildPath "autorunsc.exe"
$PowerCfgPath = Join-Path -Path $System32 -ChildPath "powercfg.exe"
$VerifierPath = Join-Path -Path $System32 -ChildPath "verifier.exe"

# Import custom module containing support functions
Import-Module $LoggerModule

# Create folders, power reports has already been created by main.ps1
New-Item -ItemType Directory $CrashDumps -Force | Out-Null
New-Item -ItemType Directory $WER -Force | Out-Null

# End of "critical" area, errors will now default to being non-fatal
$ErrorActionPreference = 'Continue'

# Set window size to 1000 by 1000 to avoid truncation when sending output to files
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(1000,1000)

# Get crash dump settings and append crash dump type matrix
Get-CrashDumpSetting -DestinationPath $CrashDumpSettings

# Copy mini crash dumps
Copy-MiniCrashDump -DestinationPath $CrashDumps -CrashesToCollect $CrashesToCollect

# Check if a full/kernel/active memory dump exists in the default location and the one specified in the registry
Get-FullCrashDumpInfo -DestinationPath $FullDumpReport

# Obtain status of driver verifier
Write-Output "Getting driver verifier settings..."
&$VerifierPath /query | Out-File -Append -FilePath $DriverVerifier
&$VerifierPath /querysettings | Out-File -Append -FilePath $DriverVerifier

# List contents of LiveKernelReports directory if it exists and is not empty
Get-LiveKernelReport -DestinationPath $CrashLiveReports

# Gather a power report
Write-Output "Running system power report..."
&$PowerCfgPath /sleepstudy /output $SleepStudy 2> $null| Out-Null

# Run a sleep diagnostics report
Write-Output "Running sleep diagnostics..."
&$PowerCfgPath /systemsleepdiagnostics /output $SleepDiagnostics 2> $null | Out-Null

# Disk and partition information
Get-VolumeInfo | Format-Table -AutoSize | Out-File -Append -FilePath $Partitions
Get-Partition | Format-List | Out-File -Append -FilePath $Partitions
Get-DiskInfo | Out-File -FilePath $Disks

# List PnP devices and associated information
Write-Output "Listing PnP devices..."
Get-PnPDeviceInfo | Format-Table -AutoSize | Out-File -Append -FilePath $PnpDevices

# List all processes
Write-Output "Enumerating running processes..."
$ProcessAttributes = "ProcessName", "ProcessID", "SessionId", "Priority", "CommandLine"
Get-CimInstance -ClassName Win32_Process | Select-Object -Property $ProcessAttributes | Sort-Object ProcessName,ProcessId | Format-Table -AutoSize | Out-File -FilePath $Processes

# List all services including status, pid, only Windows 10 has support for listing service StartType via Get-Service
Write-Output "Identifying running services..."
If ( $WindowsBuild -ge $Win10MinBuild )
{
	$StartType = @{Name="StartType";Expression={ (Get-Service -Name $_.Name).StartType }}
	Get-CimInstance -ClassName Win32_Service | Select-Object -Property Name,DisplayName,State,ProcessID,$StartType | Sort-Object State, Name | Format-Table -AutoSize | Out-File -FilePath $Services
}

Else
{
	Get-CimInstance -ClassName Win32_Service | Select-Object -Property Name,DisplayName,State,ProcessID | Sort-Object State, Name | Format-Table -AutoSize | Out-File -FilePath $Services
}

# Get information about the OS and its boot/firmware settings
Write-Output "Checking OS details..."
$Properties = "Name", "Version", "BuildNumber", "OSArchitecture", "LocalDateTime", "LastBootUpTime", "InstallDate", "BootDevice", "SystemDevice"
$OsInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$OsInfo | Select-Object -Property $Properties | Out-File -Append -FilePath $OSDetails

# List available Restore Points if on a client SKU
If ( $OsInfo.ProductType -eq 1 -and $PSVersionTable.PSEdition -ne "core" )
{
	Write-Output "Finding restore points..."
	Get-ComputerRestorePoint | Format-Table -AutoSize | Out-File -FilePath $RestorePoints
}

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

# Convert WER files to UTF-8 for consistency with the other output
If ( Test-Path -Path $WER )
{
	Convert-UTF8 -Path $WER
}

# Find autostart entries, scheduled tasks etc. with Autorunsc.exe
If ( Test-Path -Path $AutoRunsPath )
{
	Write-Output "Finding auto-start entries..."

	# -s = Verify digital signatures, -m = List all autostart entries that are not cryptographically signed by Microsoft, -a = specify autostart selection,
	# b = boot execute, d = Appinit DLLs, e = explorer add-ons, h = image hijacks, l = logon, t = scheduled tasks, w = winlogon
	Start-Process -FilePath $AutoRunsPath -ArgumentList "-accepteula","-nobanner","-s","-m","-a","bdehtw" -NoNewWindow -Wait -RedirectStandardOutput $AutoRunsReport
	Convert-UTF8 -Path $AutoRunsReport
	Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Name,Command,Location | Format-List | Out-File -Append -FilePath $AutoRunsReport
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
If ( Test-Path -Path $TranscriptPath )
{
	Stop-Transcript | Out-Null

	# Allow transcript to be moved and read by standard users, otherwise hashing and compression may fail
	$PathACL = Get-ACL -Path $Path
	Set-Acl -Path $TranscriptPath -AclObject $PathACL -ErrorVariable $SetAclErr

	# Move transcript into $Path
	Move-Item -Path $TranscriptPath -Destination $TranscriptDest -Force

	If ( $SetAclErr )
	{
		Write-Output "Failed to set ACL for $TranscriptPath." | Out-File -Append -FilePath $TranscriptDest
		Write-Output $SetAclErr | Out-File -Append -FilePath $TranscriptDest
	}
}

Else
{
	Write-Output "$TranscriptPath not found." | Out-File -Append -FilePath $TranscriptDest
}

# Stop script, it was launched with -NoExit so we must actually stop the process to close the Window
Stop-Process -ID $PID | Out-Null