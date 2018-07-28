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

# Detect Windows version
$WindowsBuild  = [System.Environment]::OSVersion.Version.Build
$Win10MinBuild = 10240

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
$Partitions        = Join-Path -Path $Path -ChildPath "partitions.txt"
$PnPDevices        = Join-Path -Path $Path -ChildPath "pnp-devices.txt"
$Processes         = Join-Path -Path $Path -ChildPath "processes.txt"
$Services          = Join-Path -Path $Path -ChildPath "services.txt"
$SleepDiagnostics  = Join-Path -Path $PowerReports -ChildPath "sleep-diagnostics.html"
$SleepStudy        = Join-Path -Path $PowerReports -ChildPath "power-report.html"

# Native file and folder locations
$KernelReportsPath = Join-Path -Path $env:SystemRoot -ChildPath "LiveKernelReports"
$LocalUserWER      = Join-Path -Path $home -ChildPath "AppData\Local\Microsoft\Windows\WER\ReportArchive" 
$ProgramDataWER    = Join-Path -Path $env:ALLUSERSPROFILE -ChildPath "Microsoft\Windows\WER\ReportArchive"
$System32          = Join-Path -Path $env:SystemRoot -ChildPath "System32"

# Full paths of executables used in this script, in case the system's path environment variables have been messed with
$AutoRunsPath = Join-Path -Path $PSScriptRoot -ChildPath "autorunsc.exe"
$PowerCfgPath = Join-Path -Path $System32 -ChildPath "powercfg.exe"

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
Copy-CrashDumps -DestinationPath $CrashDumps

# Check if a full/kernel/active memory dump exists in the default location and the one specified in the registry
Get-FullCrashDumps -DestinationPath $CrashDumps

# List contents of LiveKernelReports directory if it exists and is not empty
If ( $(Test-Path -Path $KernelReportsPath) -eq $True -and $(Get-ChildItem -Path $KernelReportsPath ) -ne $null )
{
	$LengthMB = @{Name="Size (MB)";Expression={[math]::Round($_.Length / 1MB, 2)}}
	Get-ChildItem -Filter "*.dmp" -Path $KernelReportsPath -Recurse | Select-Object Name,LastWriteTime,$LengthMB | Out-File -FilePath $CrashLiveReports
}

# Gather a System Power Report, only supported on 8.1 and newer
Write-Host "Running system power report..."
&$PowerCfgPath /sleepstudy /output $SleepStudy 2> $null| Out-Null

# Run a sleep diagnostics report
Write-Host "Running sleep diagostics..."
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
Write-Host "Listing PnP devices..."
$DriverAttributes = "Name", "Status", "ConfigManagerErrorCode", "Description", "Manufacturer", "DeviceID"
Get-CimInstance -ClassName Win32_PNPEntity | Select-Object $DriverAttributes | Sort-Object Name | Format-Table -AutoSize | Out-File -Append -FilePath $PnPDevices

# List all processes
Write-Host "Enumerating running processes..."
$ProcessAttributes = "ProcessName", "ProcessID", "SessionId", "Priority", "CommandLine"
Get-CimInstance -ClassName Win32_Process | Select-Object $ProcessAttributes | Sort-Object ProcessName,ProcessId | Format-Table -AutoSize | Out-File -FilePath $Processes

# List all services including status, pid, only Windows 10 has support for listing service StartType via Get-Service
Write-Host "Identifying running services..."
If ( $WindowsBuild -ge $Win10MinBuild )
{
	$StartType = @{Name="StartType";Expression={(Get-Service $_.Name).StartType}}
	Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, State, ProcessID, $StartType | Sort-Object State, Name | Format-Table -AutoSize | Out-File -FilePath $Services	
}

Else
{
	Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, State, ProcessID | Sort-Object State, Name | Format-Table -AutoSize | Out-File -FilePath $Services
}

# Copy Windows Error Reports
Write-Host "Copying Windows error reports..."
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
	Write-Host "Finding auto-start entries..."
	# -s -m List all autostart entries that are not cryptographically signed by Microsoft, -a = specify autostart selection, b = boot execute, d = Appinit DLLs, w = winlogon, h = image hijacks, e = explorer add-ons, l = logon, t = scheduled tasks
	Start-Process -FilePath $AutoRunsPath -ArgumentList "-accepteula","-nobanner","-s","-m","-a","bdwhelt" -NoNewWindow -Wait -RedirectStandardOutput $AutorunsReport
}

Else
{
	Write-Warning "$AutoRunsPath not found."
}

If ( Test-Path -Path $AutoRunsPath )
{
	Remove-Item -Path $AutoRunsPath -Force | Out-Null
}

# Stop transcript and move it into $Path
If ( Test-Path -Path $Transcript )
{
	Stop-Transcript | Out-Null

	# Allow transcript to be moved and read by standard users, otherwise hashing and compression may fail 
	$TranscriptACL = Get-ACL -Path $Transcript
	$TranscriptACL.SetAccessRuleProtection(1,0)
	$NewAccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","full","none","none","Allow")
	$TranscriptACL.AddAccessRule($NewAccessRule)
	Set-Acl -Path $Transcript -AclObject $TranscriptACL

	# Move log into $Path
	Move-Item -Path $Transcript -Destination $Path -Force
}