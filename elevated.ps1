##############################
# Script Written By Spectrum #
##############################

Param(
	[Parameter(Mandatory=$True)]
	[ValidateScript({ Test-Path -Path $_ })]
	[string]
	$Path
)

# Detect Windows version, convert the value from a string to a decimal
$MajorVer = [System.Environment]::OSVersion.Version.Major
$MinorVer = [System.Environment]::OSVersion.Version.Minor
$WindowsVersion = "$MajorVer" + "." + "$MinorVer" -as [decimal]

# This is set because $PSScriptRoot is not available on stock Windows 7 SP1
$ScriptPath = Split-Path $MyInvocation.MyCommand.Path -Parent

# Set output files for logging
$Log = Join-Path -Path $env:TEMP -ChildPath "script-log-elevated.csv"
$ErrorFile = Join-Path -Path $env:TEMP -ChildPath "error-temp-elevated.txt"
$CrashDumps = Join-Path -Path $Path -ChildPath "Crash Dumps"
$PowerReports = Join-Path -Path $Path -ChildPath "Power Reports"
$WER = Join-Path -Path $Path -ChildPath "Error Reports"
$LoggerModule = Join-Path -Path $ScriptPath -ChildPath "logger-module.psm1"

# Create folders
New-Item -ItemType Directory $CrashDumps -Force -ErrorAction Stop | Out-Null
New-Item -ItemType Directory $WER -Force -ErrorAction Stop | Out-Null

# Create file for temporarily storing errors
New-Item -ItemType File -Path $ErrorFile -Force -ErrorAction Stop | Out-Null

If ( Test-Path -Path $Log ) {

	Remove-Item -Path $Log -Force | Out-Null
}

# Import custom module containing support functions
Try {

    Import-Module $LoggerModule
}

Catch {

	Write-Warning "Could not import $LoggerModule, exiting script."
	$TimeStamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $ImportError =  $TimeStamp + "," + "Failed to import $LoggerModule, exiting script."
    Write-Output $ImportError | Out-File -Append -FilePath $Log
    Exit
}

# Check that this script is being run with elevated credentials, e.g. Administrator, SYSTEM, or TrustedInstaller
$ElevatedCheck = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

If ( $ElevatedCheck -ne "True" ) {

	Write-Warning "ERROR: Administrator rights are required for this script to work properly!"
	Write-Warning "Aborting script!"
	Write-Log -Message "Administrator rights are required for this script to work properly, exiting script." -LogPath $Log
	Exit
}

# Set window size to 1000 by 1000 to avoid truncation when sending output to files
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (1000,1000)

# Get crash dump settings and append crash dump type matrix
Write-Host "Getting crash dump settings..."
Write-Output "########################## Crash Dump Settings #########################" | Out-File -FilePath "$CrashDumps\crash-dump-settings.txt"
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" | Out-File -Append -FilePath "$CrashDumps\crash-dump-settings.txt" -ErrorAction SilentlyContinue -ErrorVariable ScriptError
Write-Log -Message $ScriptError -LogPath $Log

Write-Output "######################## Crash Dump Type Matrix ########################


		CrashDumpEnabled			FilterPages
Disabled	0					<does not exist>
Complete	1					<does not exist>
Active		1					1
Kernel		2					<does not exist>
Small		3					<does not exist>
Automatic	7					<does not exist>" | Out-File -Append -FilePath "$CrashDumps\crash-dump-settings.txt"

# Copy mini crash dumps
$MinidumpPath = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl").MinidumpDir
$DefaultPath = "$env:SystemRoot\Minidump"

If ( $DefaultPath -eq $MinidumpPath ) {

	If ( Test-Path -Path $MinidumpPath ) {

		Get-ChildItem $MinidumpPath | Sort-Object LastWriteTime -Descending | Out-File -Append -FilePath "$CrashDumps\mini-crash-dumps.txt"

		If ( $(Get-ChildItem -Filter "*.dmp" -Path $MinidumpPath) -ne $null ) {

			Write-Host "Copying crash dumps from $MinidumpPath..."
			Get-ChildItem -Filter "*.dmp" -Path $MinidumpPath | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First 5 | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$Path\Crash Dumps" } -ErrorAction SilentlyContinue -ErrorVariable ScriptError
			Write-Log -Message $ScriptError -LogPath $Log
		}

		Else {

			Write-Host "No crash dumps to copy from $MinidumpPath"
			Write-Output "$MinidumpPath contains no dump files." Out-File -Append -FilePath "$CrashDumps\mini-crash-dumps.txt"
		}
	}

	Else {

		Write-Host "No crash dumps to copy from $MinidumpPath"
		Write-Output "$MinidumpPath does not exist." | Out-File -Append -FilePath "$CrashDumps\mini-crash-dumps.txt"
	}
}

# If they paths in the registry and the default minidump path differ, check both paths for crash dumps and copy the 5 newest
Else {

	# Check that the registry path exists and is not empty, copy the 5 newest crash dumps
	If ( Test-Path -Path $MinidumpPath ) {

		Get-ChildItem $MinidumpPath | Sort-Object LastWriteTime -Descending | Out-File -Append -FilePath "$CrashDumps\mini-crash-dumps.txt"

		If ( $(Get-ChildItem -Filter "*.dmp" -Path $MinidumpPath) -ne $null ) {

			Write-Host "Copying crash dumps from $MinidumpPath..."
			Get-ChildItem -Filter "*.dmp" -Path $MinidumpPath | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First 5 | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$Path\Crash Dumps" } -ErrorAction SilentlyContinue -ErrorVariable ScriptError
			Write-Log -Message $ScriptError -LogPath $Log
		}

		Else {

			Write-Host "No crash dumps to copy from $MinidumpPath"
			Write-Output "$MinidumpPath contains no dump files." | Out-File -Append -FilePath "$CrashDumps\mini-crash-dumps.txt"
		}
	}

	Else {

		Write-Host "No crash dumps to copy from $MinidumpPath"
		Write-Output "$MinidumpPath does not exist." | Out-File -Append -FilePath "$CrashDumps\mini-crash-dumps.txt"
	}

	If ( Test-Path -Path $DefaultPath ) {

		Get-ChildItem $DefaultPath | Sort-Object LastWriteTime -Descending | Out-File -Append -FilePath "$CrashDumps\mini-crash-dumps.txt"

		If ( $(Get-ChildItem -Filter "*.dmp" -Path $DefaultPath) -ne $null ) {

			Write-Host "Copying crash dumps from $DefaultPath..."
			Get-ChildItem -Filter "*.dmp" -Path $DefaultPath | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First 5 | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$Path\Crash Dumps" } -ErrorAction SilentlyContinue -ErrorVariable ScriptError
			Write-Log -Message $ScriptError -LogPath $Log
		}

		Else {
		
			Write-Host "No crash dumps to copy from $DefaultPath"
			Write-Output "$DefaultPath contains no dump files." | Out-File -Append -FilePath "$CrashDumps\mini-crash-dumps.txt"
		}
	}

	Else {

		Write-Host "No crash dumps to copy from $DefaultPath"
		Write-Output "$DefaultPath does not exist." | Out-File -Append -FilePath "$CrashDumps\mini-crash-dumps.txt"
	}
}

# Check if a full/kernel/active memory dump exists in the default location and the one specified in the registry
$DumpPath = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl").DumpFile

If ( $DumpPath -eq "$env:SystemRoot\Memory.dmp" ) {

	If ( Test-Path $DumpPath ) {

		Write-Output "Crash dump found at $DumpPath" | Out-File -FilePath "$CrashDumps\memory-dumps.txt"
		Write-Output "Creation date: $((Get-Item $DumpPath).LastWriteTime)" | Out-File -Append -FilePath "$CrashDumps\memory-dumps.txt"
		Write-Output "Size on disk: $([math]::truncate((Get-Item $DumpPath).Length / 1MB)) MB" | Out-File -Append -FilePath "$CrashDumps\memory-dumps.txt"
	}

	Else {

		Write-Output "$DumpPath was not found" | Out-File -Append -FilePath "$CrashDumps\memory-dumps.txt"
	}
}

Else {

	If ( Test-Path $DumpPath ) {

		Write-Output "Crash dump found at $DumpPath" | Out-File -FilePath "$CrashDumps\memory-dumps.txt"
		Write-Output "Creation date: $((Get-Item $DumpPath).LastWriteTime)" | Out-File -Append -FilePath "$CrashDumps\memory-dumps.txt"
		Write-Output "Size on disk: $([math]::truncate((Get-Item $DumpPath).Length / 1MB)) MB" | Out-File -Append -FilePath "$CrashDumps\memory-dumps.txt"
	}

	Else {

		Write-Output "$DumpPath was not found" | Out-File -Append -FilePath "$CrashDumps\memory-dumps.txt"
	}

	If ( Test-Path "$env:SystemRoot\Memory.dmp" ) {

		Write-Output "Crash dump found at $env:SystemRoot\Memory.dmp" | Out-File -Append -FilePath "$CrashDumps\memory-dumps.txt"
		Write-Output "Creation date: $((Get-Item $env:SystemRoot\MEMORY.DMP).LastWriteTime)" | Out-File -Append -FilePath "$CrashDumps\memory-dumps.txt"
		Write-Output "Size on disk: $([math]::truncate((Get-Item "$env:SystemRoot\Memory.dmp").Length / 1MB)) MB" | Out-File -Append -FilePath "$CrashDumps\memory-dumps.txt"
	}

	Else {

		Write-Output "$env:SystemRoot\Memory.dmp was not found" | Out-File -Append -FilePath "$CrashDumps\memory-dumps.txt"
	}
}

# List contents of LiveKernelReports directory if it exists and is not empty
If ( $(Test-Path -Path "$env:SystemRoot\LiveKernelReports") -eq $True -and $(Get-ChildItem -Path "$env:SystemRoot\LiveKernelReports" ) -ne $null ) {

	$LengthMB = @{Name="Size (MB)";Expression={[math]::Round($_.Length / 1MB, 2)}}
	Get-ChildItem -Filter "*.dmp" -Path "$env:SystemRoot\LiveKernelReports" -Recurse -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object Name,LastWriteTime,$LengthMB | Out-File -FilePath "$CrashDumps\live-kernel-reports.txt"
	Write-Log -Message $ScriptError -LogPath $Log
}

# Gather a System Power Report, only supported on 8.1 and newer
If ( $WindowsVersion -ge "6.3" ) {

	Write-Host "Running system power report..."
	&"$env:SystemRoot\System32\powercfg.exe" /sleepstudy /output "$PowerReports\power-report.html" 2> $ErrorFile | Out-Null
	Write-CommandError -ErrorFile $ErrorFile -LogPath $Log
}

# Run a sleep diagnostics report
Write-Host "Running sleep diagostics..."
&"$env:SystemRoot\System32\powercfg.exe" /systemsleepdiagnostics /output "$PowerReports\sleep-diagnostics.html" 2> $ErrorFile | Out-Null
Write-CommandError -ErrorFile $ErrorFile -LogPath $Log

# Disk and partition information, 8.1 requires admin rights unlike 10
If ( $WindowsVersion -eq "6.3" ) {

	Get-Partition -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Format-List | Out-File -Append -FilePath "$Path\partitions.txt"
	Write-Log -Message $ScriptError -LogPath $Log
	
	$DiskAttributes = "FriendlyName", "Model", "Manufacturer", "Number", "IsBoot", "AllocatedSize", "HealthStatus", "OperationalStatus", "BusType", "FirmwareVersion", "PartitionStyle", "Path"
	Get-Disk -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $DiskAttributes | Format-List | Out-File -Append -FilePath "$Path\disks.txt"
	Write-Log -Message $ScriptError -LogPath $Log
}

# List PnP devices and associated information
Write-Host "Listing PnP devices..."

$DriverAttributes = "Name", "Status", "ConfigManagerErrorCode", "Description", "Manufacturer", "DeviceID"
Get-WmiObject Win32_PNPEntity -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $DriverAttributes | Sort-Object Name | Format-Table -AutoSize | Out-File -Append -FilePath "$Path\pnp-devices.txt"
Write-Log -Message $ScriptError -LogPath $Log

# List all processes
Write-Host "Enumerating running processes..."

$ProcessAttributes = "ProcessName", "ProcessID", "SessionId", "Priority", "CommandLine"
Get-WmiObject Win32_Process -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $ProcessAttributes | Sort-Object ProcessName,ProcessId | Format-Table -AutoSize | Out-File -FilePath "$Path\processes.txt"
Write-Log -Message $ScriptError -LogPath $Log

# List all services including status, pid, only Windows 10 has support for listing service StartType via Get-Service
Write-Host "Identifying running services..."

If ( $WindowsVersion -ge "10.0" ) {

	$StartType = @{Name="StartType";Expression={(Get-Service $_.Name).StartType}}
	
	Get-WmiObject Win32_Service -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object Name, DisplayName, State, ProcessID, $StartType | Sort-Object State, Name | Format-Table -AutoSize | Out-File -FilePath "$Path\services.txt"
	Write-Log -Message $ScriptError -LogPath $Log	
}

Else {

	Get-WmiObject Win32_Service -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object Name, DisplayName, State, ProcessID | Sort-Object State, Name | Format-Table -AutoSize | Out-File -FilePath "$Path\services.txt"
	Write-Log -Message $ScriptError -LogPath $Log
}

# Copy Windows Error Reports
Write-Host "Copying Windows error reports..."

If ( Test-Path -Path "$home\AppData\Local\Microsoft\Windows\WER\ReportArchive" ) {

	Copy-Item "$home\AppData\Local\Microsoft\Windows\WER\ReportArchive\*" -Destination $WER -Recurse -Container 2> $null | Out-Null
	Write-Log -Message $ScriptError -LogPath $Log
}

If ( Test-Path -Path "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive" ) {

	Copy-Item "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive\*" -Destination $WER -Recurse -Container 2> $null | Out-Null
	Write-Log -Message $ScriptError -LogPath $Log
}

# Find autostart entries, scheduled tasks etc. with Autorunsc.exe
If ( Test-Path -Path "$ScriptPath\autorunsc.exe" ) {

	Write-Host "Finding auto-start entries..."

	# -s -m List all autostart entries that are not cryptographically signed by Microsoft, -a = specify autostart selection, b = boot execute, d = Appinit DLLs, w = winlogon, h = image hijacks, e = explorer add-ons, l = logon, t = scheduled tasks
	Start-Process -FilePath "$ScriptPath\autorunsc.exe" -ArgumentList "-accepteula","-nobanner","-s","-m","-a","bdwhelt" -NoNewWindow -Wait -RedirectStandardOutput "$Path\autorun.txt" -RedirectStandardError $ErrorFile
	Write-CommandError -ErrorFile $ErrorFile -LogPath $Log
}

Else {

	Write-Log "$ScriptPath\autorunsc.exe not found." -LogPath $Log
}

If ( Test-Path -Path "$ScriptPath\autorunsc.exe" ) {

	Remove-Item -Path "$ScriptPath\autorunsc.exe" -Force | Out-Null
}

If ( $(Test-Path -Path $Log) -eq "True" -and (Get-Item $Log).Length -gt 0 ) {

	# Allow log file to be modified by standard users, otherwise hashing and compression may fail 
	$LogACL = Get-ACL -Path $Log
	$LogACL.SetAccessRuleProtection(1,0)
	$NewAccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","full","none","none","Allow")
	$LogACL.AddAccessRule($NewAccessRule)
	Set-Acl -Path $Log -AclObject $LogACL

	# Move log into $Path
	Move-Item -Path $Log -Destination $Path
}

If ( Test-Path -Path $ErrorFile ) {

	Remove-Item -Path $ErrorFile -Force | Out-Null
}