﻿##############################
# Script Written By Spectrum #
##############################

#Requires -Version 4.0

# Any errors at the start should be treated as fatal
$ErrorActionPreference = 'Stop'

# Version String
$ScriptVersion = "V2 Log Collector 1.10 - 5/15/20"

# Default to UTF-8 output
$PSDefaultParameterValues['*:Encoding'] = 'UTF8'

# If we are running PowerShell Core, ensure that it is running Windows
If ( ($PSVersionTable.PSEdition -eq "core") -and (!$IsWindows) )
{
	Write-Warning "This script is for triaging Windows kernel panics, and does not work on non-Windows systems."
	Write-Warning "Detected OS: $env:OS"
	Return
}

# Check if constrained language mode is enabled, this may impact the execution of this script.
If ( $ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage" )
{
	Write-Warning "Constrained language mode is enabled, this prevents the script from running properly."
	Return
}

# Detect Windows version
$WindowsBuild = [System.Environment]::OSVersion.Version.Build
$Win1709Build = 16299
$Win81Build   = 9600

# Check if we are running PowerShell Core 6
# This is needed as some cmdlets and variables only work with legacy PowerShell or PowerShell 7+ (Get-Disk, Get-PhysicalDisk, Get-MpPreference, etc.)
If ( ($PSVersionTable.PSEdition -eq "core") -and ($Host.Version.Major -eq 6) )
{
	Return "This script does not work with PowerShell 6, please use 5.1 or 7+"
}

# Abort if Controlled Folder Access is enabled, as it prevents log files from being placed on the desktop
If ( $WindowsBuild -ge $Win1709Build )
{
	If ( (Get-MpPreference).EnableControlledFolderAccess -eq 1 )
	{
		Write-Warning "Controlled Folder Access is enabled in Windows Defender, this prevents the script from placing log files on your Desktop."
		Write-Output "`n"
		Write-Warning "If you would like allow this script to run, please temporarily disable Controlled Folder Access in Windows Defender Security Center and then re-launch this script."
		Write-Output "`n"
		Read-Host -Prompt "Press Enter to close this window"
		Stop-Process -ID $PID | Out-Null
	}
}

# If the OS is 64-bit and this script was launched with 32-bit PowerShell, relaunch with 64-bit PowerShell and exit the current instance
If ( [Environment]::Is64BitOperatingSystem -eq $True -and [Environment]::Is64BitProcess -eq $False )
{
	&"$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -NoExit -File $myInvocation.InvocationName
	Stop-Process -ID $PID | Out-Null
}

# Startup Banner
Clear-Host
Write-Output "
  ______              ______                          _
 /_  __/__  ____     / ____/___  _______  __________ ( )_____
  / / / _ \/ __ \   / /_  / __ \/ ___/ / / / __  __ \|// ___/
 / / /  __/ / / /  / __/ / /_/ / /  / /_/ / / / / / / (__  )
/_/  \___/_/ /_/  /_/    \____/_/   \__,_/_/ /_/ /_/ /____/
    __                   ______      ____          __
   / /   ____  ______   / ____/___  / / /__  _____/ /_____  _____
  / /   / __ \/ __ ` /  / /   / __ \/ / / _ \/ ___/ __/ __ \/ ___/
 / /___/ /_/ / /_/ /  / /___/ /_/ / / /  __/ /__/ /_/ /_/ / /
/_____/\____/\__, /   \____/\____/_/_/\___/\___/\__/\____/_/
            /____/
"

"`n" * 3
Write-Output $ScriptVersion
"`n"
Write-Output "Script written by Spectrum"
"`n"

Read-Host -Prompt "Press Enter to continue"
Clear-Host

# Track execution time of the script
$StopWatchMain = [System.Diagnostics.StopWatch]::StartNew()

# Log file
$Guid = [System.Guid]::NewGuid().ToString()
$TranscriptFile = "transcript-main.txt"
$TempFolderPath = Join-Path -Path $env:TEMP -ChildPath $Guid
$TranscriptPath = Join-Path -Path $TempFolderPath -ChildPath $TranscriptFile

New-Item -ItemType Directory -Path $TempFolderPath | Out-Null

# Begin logging
Start-Transcript -Path $TranscriptPath -Force | Out-Null
Write-Information -MessageData $ScriptVersion
Write-Information -MessageData $Guid

# Create folder name
$Time       = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$FolderName = "$env:COMPUTERNAME-($Time)"

# Define paths to other script files
$ElevatedScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "elevated.ps1"
$LoggerModule       = Join-Path -Path $PSScriptRoot -ChildPath "logger-module.psm1"

# Output folders
$Desktop      = [Environment]::GetFolderPath("Desktop")
$Path         = Join-Path -Path $Desktop -ChildPath $FolderName
$EventLogs    = Join-Path -Path $Path -ChildPath "Event Logs"
$PowerReports = Join-Path -Path $Path -ChildPath "Power Reports"

# Output files
$CPU               = Join-Path -Path $Path -ChildPath "cpu.txt"
$DriverTable       = Join-Path -Path $Path -ChildPath "driver-table.txt"
$DriverVersions    = Join-Path -Path $Path -ChildPath "driver-versions.txt"
$DxDiagFile        = Join-Path -Path $Path -ChildPath "dxdiag.txt"
$FileHashes        = Join-Path -Path $env:LOCALAPPDATA -ChildPath "hashes.txt"
$GPU               = Join-Path -Path $Path -ChildPath "gpu.txt"
$HostsReport       = Join-Path -Path $Path -ChildPath "hosts.txt"
$InstalledSoftware = Join-Path -Path $Path -ChildPath "installed-software.txt"
$DiagLogTemp       = "licensingdiag-log.txt"
$LicenseDiagLog    = Join-Path -Path $TempFolderPath -ChildPath $DiagLogTemp
$LicenseFile       = Join-Path -Path $Path -ChildPath "genuine.txt"
$LicneseXmlName    = "genuine.xml"
$LicenseXmlTemp    = Join-Path -Path $TempFolderPath -ChildPath $LicneseXmlName
$Motherboard       = Join-Path -Path $Path -ChildPath "motherboard.txt"
$NetworkInfo       = Join-Path -Path $Path -ChildPath "network-info.txt"
$PowerPlan         = Join-Path -Path $PowerReports -ChildPath "power-plan.txt"
$RAM               = Join-Path -Path $Path -ChildPath "ram.txt"
$SleepStates       = Join-Path -Path $PowerReports -ChildPath "sleep-states.txt"
$SystemInfo        = Join-Path -Path $Path -ChildPath "msinfo32.nfo"
$TranscriptDest    = Join-Path -Path $Path -ChildPath $TranscriptFile
$WindowsUpdates    = Join-Path -Path $Path -ChildPath "windows-updates.txt"
$Zip               = $Path + ".zip"

# Where to download autoruns from and where to place the executable
$AutorunsURL  = "https://live.sysinternals.com/autorunsc.exe"
$AutorunsPath = Join-Path -Path $PSScriptRoot -ChildPath "autorunsc.exe"

# Native file and folder locations
$HostsFile = Join-Path $env:SystemRoot -ChildPath "System32\drivers\etc\hosts"
$System32  = Join-Path -Path $env:SystemRoot -ChildPath "System32"

# Full paths of executables used in this script, in case the system's environment variables have been messed with
$DriverQueryPath = Join-Path -Path $System32 -ChildPath "driverquery.exe"
$DXDiagPath      = Join-Path -Path $System32 -ChildPath "dxdiag.exe"
$IpconfigPath    = Join-Path -Path $System32 -ChildPath "ipconfig.exe"
$LicenseDiagPath = Join-Path -Path $System32 -ChildPath "licensingdiag.exe"
$MsInfo32Path    = Join-Path -Path $System32 -ChildPath "msinfo32.exe"
$PowerCfgPath    = Join-Path -Path $System32 -ChildPath "powercfg.exe"
$PowerShellPath  = Get-Process -PID $PID | Select-Object -ExpandProperty "Path"
$RoutePath       = Join-Path -Path $System32 -ChildPath "route.exe"

# Timeouts for asynchronous processes to complete, in seconds
$DriverQueryTimeout    = 120
$DxDiagTimeout         = 60
$ElevatedScriptTimeout = 150
$LicenseTimeout        = 120
$MsInfo32Timeout       = 420

# Import custom module containing support functions
Import-Module $LoggerModule

# Set window size to 1000 by 1000 to avoid truncation when sending output to files
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(1000,1000)

# Check for pre-existing files and folders, and remove them if they exist
If ( Test-Path -Path $Path )
{
	Remove-Item -Path $Path -Recurse -Force | Out-Null
}

If ( Test-Path -Path $Zip )
{
	Remove-Item -Path $Zip -Force | Out-Null
}

# Create directories and files
New-Item -ItemType Directory -Path $Path -Force | Out-Null
New-Item -ItemType Directory -Path $EventLogs | Out-Null
New-Item -ItemType Directory -Path $PowerReports | Out-Null

# End of "critical" area, errors will now default to being non-fatal
$ErrorActionPreference = 'Continue'

# Check that the OS is supported, warn if it is not
If ( $WindowsBuild -lt $Win81Build )
{
	Write-Warning "Unsupported version of Windows detected.  Minimum build supported: $Win81Build, your build is: $WindowsBuild."
}

# Generate System Information Report
Write-Output "Generating system information report, this may take a while..."

Try
{
	$MsInfo32 = Start-Process -FilePath $MsInfo32Path -ArgumentList """/nfo"" ""$SystemInfo""" -PassThru
}

Catch
{
    Write-Warning "Failed to launch $MsInfo32Path"
    Write-Output $error[0]
}

# Download autorunsc.exe, this will later be run in elevated.ps1
Get-RemoteFile -URL $AutorunsURL -FileName "autorunsc" -DestinationPath $AutorunsPath

# Start elevated.ps1
If ( Test-Path -Path $ElevatedScriptPath )
{
	Write-Output "Launching elevated script..."

	Try
	{
		$ElevatedScript = Start-Process -FilePath $PowerShellPath `
										-ArgumentList """-ExecutionPolicy"" ""Bypass"" ""-NonInteractive"" ""-NoProfile"" ""-NoExit"" ""-File"" ""$ElevatedScriptPath"" ""$Path"" ""$Guid"" ""$TempFolderPath""" `
										-Verb RunAs `
										-PassThru
	}

	Catch
	{
		Write-Warning "Failed to launch elevated script!"
        Write-Output $error[0]
	}
}

Else
{
	Write-Warning "$ElevatedScriptPath not found!"
}

# Start DirectX Diagnostics Report
Write-Output "Running DirectX diagnostics..."

Try
{
	$DxDiag = Start-Process -FilePath $DXDiagPath -ArgumentList "/dontskip","/whql:off","/t","$DxDiagFile" -WindowStyle Hidden -PassThru
}

Catch
{
	Write-Warning "Failed to run DirectX diagnostics!"
    Write-Output $error[0]
}

# Start Driver Query
Try
{
	$DriverQuery = Start-Process -FilePath $DriverQueryPath -ArgumentList "/v","/fo table" -WindowStyle Hidden -RedirectStandardOutput $DriverTable -PassThru
}

Catch
{
	Write-Warning "Failed to run Driver Query!"
    Write-Output $error[0]
}

# Start License Diagnostics
Try
{
	# licensingdiag.exe outputs error messages to standardoutput, which is why we are not using -RedirectStandardError
	$LicenseDiag = Start-Process -FilePath $LicenseDiagPath -ArgumentList "/report","$LicenseXmlTemp" -RedirectStandardOutput $LicenseDiagLog -WindowStyle Hidden -PassThru
}

Catch
{
	Write-Warning "Failed to run licensing diagnostics!"
    Write-Output $error[0]
}

# Export System, Application, and PnP Event Logs
Export-EventLog -DestinationPath $EventLogs

# Driver information
Write-Output "Gathering device driver information..."
$DriverInfoAttributes = "DeviceName", "FriendlyName", "InfName", "DriverVersion", "DeviceID", "IsSigned", "DriverDate"
Get-CimInstance -ClassName Win32_PnPSignedDriver | Select-Object -Property $DriverInfoAttributes | Sort-Object -Property DeviceName | Format-Table -AutoSize | Out-File -FilePath $DriverVersions

# Get default power plan
Write-Output "Checking power settings..."
&$PowerCfgPath /list 2> $null | Out-File -FilePath $PowerPlan

# List available sleep states
&$PowerCfgPath /availablesleepstates 2> $null | Out-File -FilePath $SleepStates

# RAM info
Write-Output "Getting hardware information..."
Get-MemoryInfo | Format-List | Out-File -FilePath $RAM

# Processor information
$ProcessorAttributes = "Name", "Description", "Manufacturer", "DeviceID", "SocketDesignation", "CurrentClockSpeed", "CPUStatus", `
					   "LastErrorCode", "ErrorDescription", "PartNumber", "Revision", "SerialNumber", "ProcessorId", "Status", `
					   "StatusInfo", "Stepping", "CurrentVoltage", "VoltageCaps"
Get-CimInstance -ClassName Win32_Processor | Select-Object -Property $ProcessorAttributes | Format-List | Out-File -FilePath $CPU

# System Board information
Write-Output "Motherboard Details" | Out-File -Append -FilePath $Motherboard
$BaseBoardAttributes = "Product", "Model", "Version", "Manufacturer", "Description", "Name", "SKU"
Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -Property $BaseBoardAttributes | Format-List | Out-File -Append -FilePath $Motherboard

# UEFI/BIOS properties
Write-Output "UEFI/BIOS Details" | Out-File -Append -FilePath $Motherboard
$BiosAttributes = "SMBIOSBIOSVersion", "Manufacturer", "Name", "Version", "BIOSVersion", "ReleaseDate"
Get-CimInstance -ClassName Win32_Bios | Select-Object -Property $BiosAttributes | Format-List | Out-File -Append -FilePath $Motherboard

# GPU information
$GpuAttributes = "Name", "DeviceID", "PNPDeviceID", "VideoProcessor", "CurrentRefreshRate", "VideoModeDescription", "AdapterRAM", `
				 "DriverVersion", "InfFilename", "InstalledDisplayDrivers", "InstallDate", "DriverDate", "Status", "StatusInfo", `
				 "LastErrorCode", "ErrorDescription"
Get-CimInstance -ClassName Win32_VideoController | Select-Object -Property $GpuAttributes | Format-List | Out-File -FilePath $GPU

# Installed software information
Write-Output "Listing installed software..."
Get-InstalledSoftware -DestinationPath $InstalledSoftware

# Installed Windows Updates
Write-Output "Listing installed Windows updates..."
Get-CimInstance -ClassName Win32_QuickFixEngineering | Select-Object -Property HotFixID,Description,InstalledOn | Sort-Object -Property InstalledOn,HotFixID | Format-Table -AutoSize | Out-File -FilePath $WindowsUpdates

# Basic networking information
Write-Output "Finding network information..."
&$IpconfigPath /allcompartments /all 2> $null | Select-Object -Skip 1 | Out-File -FilePath $NetworkInfo
&$RoutePath print | Out-File -Append -FilePath $NetworkInfo 2> $null

# Copy relevant entries from the hosts file
Write-Output "Examining hosts file..."

If ( Test-Path -Path $HostsFile )
{
	Get-Content -Path $HostsFile | Select-String '(127.0.0.1)|(0.0.0.0)' | Out-File -FilePath $HostsReport
}

Else
{
	Write-Warning "Hosts file not found."
}

# Wait for licensingdiag.exe to finish
If ( $LicenseDiag )
{
	Wait-ProcessCustom -ProcessObject $LicenseDiag -ProcessName "licensingdiag.exe" -TimeoutSeconds $LicenseTimeout
}

# Now that licensingdiag.exe has finished, attempt to process the xml file, redact the license key, and export from xml to flat text
Write-Output "Creating Windows license report..."
If ( Test-Path -Path $LicenseXmlTemp )
{
	[xml] $LicenseXml = Get-Content -Path $LicenseXmlTemp

	# Cleanup other files generated by licensingdiag.exe
	Remove-Item -Path $LicenseXmlTemp -Force | Out-Null
	Remove-Item -Path "$TempFolderPath\$env:COMPUTERNAME*.cab" -Force | Out-Null

	# Redact potentially sensitive information that is not useful for troubleshooting before exporting as plaintext
	$LicenseXml.DiagReport.LicensingData.OA3ProductKey = "Redacted"
	$LicenseXml.DiagReport.GenuineAuthz.ServerProps    = "Redacted"
	$LicenseXml.DiagReport.ChildNodes | Out-File -FilePath $LicenseFile
}

Else
{
	Write-Warning "$LicenseFileTemp does not exist."
}

# Send all output of licensingdiag.exe to $LicenseFile
If ( Test-Path -Path $LicenseDiagLog )
{
	Get-Content -Encoding Unicode -Path $LicenseDiagLog | Out-File -Append -FilePath $LicenseFile
	Remove-Item -Path $LicenseDiagLog -Force | Out-Null
}

Else
{
	Write-Information -MessageData "$LicenseDiagLog does not exist."
}

# Wait for dxdiag.exe to finish
If ( $DxDiag )
{
	Wait-ProcessCustom -ProcessObject $DxDiag -ProcessName "dxdiag.exe" -TimeoutSeconds $DxDiagTimeout
}

# Wait for driverquery.exe to finish
If ( $DriverQuery )
{
	Wait-ProcessCustom -ProcessObject $DriverQuery -ProcessName "driverquery.exe" -TimeoutSeconds $DriverQueryTimeout
}

# Wait for msinfo32.exe to finish
If ( $MsInfo32 )
{
	Wait-ProcessCustom -ProcessObject $MsInfo32 -ProcessName "msinfo32.exe" -TimeoutSeconds $MsInfo32Timeout
}

# Check that the msinfo32.nfo file was created, msinfo32.exe returns an exit code of 0 regardless of whether or not it ran into an error, so this check is necessary.
$SystemInfoExists = Test-Path -Path $SystemInfo

If ( !$SystemInfoExists )
{
	Write-Warning "$SystemInfo not found, msinfo32.exe may have crashed or was canceled by the user."
}

# Wait for elevated.ps1 to finish
If ( $ElevatedScript )
{
	Wait-ProcessCustom -ProcessObject $ElevatedScript -ProcessName "elevated script" -TimeoutSeconds $ElevatedScriptTimeout
}

If ( $StopWatchMain.IsRunning )
{
	$StopWatchMain.Stop()
	Write-Information -MessageData "main.ps1 execution time (before file hashing and compression) was $($StopWatchMain.Elapsed.TotalSeconds) seconds."
}

Else
{
	Write-Information -MessageData "StopWatch instance for main.ps1 was not running."
}

# Stop transcript since the file will need to be moved into the output folder
Stop-Transcript | Out-Null

# Move transcript to $Path
If ( Test-Path -Path $TranscriptPath )
{
    Move-Item -Path $TranscriptPath -Destination $TranscriptDest -Force
}

Else
{
	Write-Output "$TranscriptPath not found." | Out-File -Append -FilePath $TranscriptDest
}

If ( Test-Path -path $TempFolderPath )
{
	Remove-Item -Path $TempFolderPath -Force
}

# Get hash of files to later check for corruption, we skip .wer files as there can be hundreds of them which can take an excessive amount of time to hash
$FileName = @{Name="FileName";Expression={Split-Path $_.Path -Leaf}}
$FilesToHash = Get-ChildItem -Path $Path -Recurse -Exclude "*.wer" -File
$Hashes = $FilesToHash | Get-FileHash -Algorithm SHA256
$Hashes | Select-Object -Property $FileName,Hash,Algorithm | Sort-Object -Property FileName | Format-Table -AutoSize | Out-File -FilePath $FileHashes

If ( Test-Path -Path $FileHashes )
{
    Move-Item -Path $FileHashes -Destination $Path
}

# Compress output folder
Write-Output "Compressing folder..."
$CompressionResult = Compress-Folder -Path $Path -DestinationPath $Zip

# Check that the .zip file was created and the compression operation completed successfully before removing the uncompressed directory
Write-Output "`n"

$ZipExists = Test-Path -Path $Zip

If ( $ZipExists -eq "True" -and $CompressionResult -eq "True" )
{
	# Check that $Zip is not empty before declaring compression succeeded
	$ZipSize = (Get-Item -Path $Zip).Length

	If ( $ZipSize -gt 1 )
	{
		Remove-Item -Path $Path -Recurse -Force | Out-Null
		Write-Output "Output location: $Zip"
	}

	Else
	{
	    Write-Warning "Compression failed, $Zip is empty."
		Write-Output "`n"
		Write-Output "Output location: $Path"
	}
}

Else
{
    Write-Warning "Compression failed!"
    Write-Output "`n"
    Write-Output "Output location: $Path"
}

Write-Output "`n"
Read-Host -Prompt "Press Enter to exit"

# Stop script, it was launched with -NoExit so we must actually stop the process to close the window
Stop-Process -ID $PID | Out-Null