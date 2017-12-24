##############################
# Script Written By Spectrum #
##############################

Param(
	[Parameter(Mandatory=$True)]
	[string]
	$Path
)

# This is set because $PSScriptRoot is not available on stock Windows 7 SP1
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent

# Set output files for logging
$Log = "$env:TEMP\script-log-elevated.csv"
$ErrorFile = "$env:TEMP\error-temp-elevated.txt"
New-Item -ItemType File -Path $ErrorFile -Force -ErrorAction Stop > $null

If ( Test-Path -Path $Log ) {

	Remove-Item -Force $Log
}

# Import custom module containing support functions
Try {

    Import-Module "$ScriptDir\logger-module.psm1"
}

Catch {

	Write-Warning "Could not import $ScriptDir\test-module.psm1, exiting script."
	$TimeStamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $ImportError =  $TimeStamp + "," + "Failed to import $ScriptDir\test-module.psm1, exiting script."
    Write-Output $ImportError >> $Log
    Exit
}

# Check that this script is being run with elevated credentials, e.g. Administrator, SYSTEM, or TrustedInstaller
$ElevatedCheck = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

If ( $ElevatedCheck -ne "True" ) {

	Write-Warning "ERROR: Administrator rights are required for this script to work properly!"
	Write-Warning "Aborting script!"
	Write-Log "Administrator rights are required for this script to work properly, exiting script." $Log
	Exit
}

# Verify path is valid before continuing
Try {

	If ( !(Test-Path -Path $Path) ) {

		Write-Warning "Invalid path specified!"
		Write-Warning "Aborting script!"
		Write-Log "Path is invalid. Script aborted! Path variable is $Path" $Log
		Exit
	}
}

Catch {

	Write-Warning "Invalid path specified!"
	Write-Warning "Aborting script!"
	Write-Log "Path is invalid. Script aborted! Path variable is $Path" $Log
	Exit
}

# Detect Windows version, convert the value from a string to a decimal
$MajorVer=[System.Environment]::OSVersion.Version.Major
$MinorVer=[System.Environment]::OSVersion.Version.Minor
$VerNum = "$MajorVer" + "." + "$MinorVer" -as [decimal]

# Set window size to 1000 by 1000 to avoid truncation when sending output to files
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (1000,1000)

# Get crash dump settings and append crash dump type matrix
Write-Host "Getting Crash Dump Settings..."
Write-Output "########################## Crash Dump Settings #########################" > "$Path\Crash Dumps\crash-dump-settings.txt"
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" >> "$Path\Crash Dumps\crash-dump-settings.txt" -ErrorAction SilentlyContinue -ErrorVariable ScriptError
Write-Log $ScriptError $Log

Write-Output "######################## Crash Dump Type Matrix ########################


		CrashDumpEnabled			FilterPages
Disabled	0					<does not exist>
Complete	1					<does not exist>
Active		1					1
Kernel		2					<does not exist>
Small		3					<does not exist>
Automatic	7					<does not exist>" >> "$Path\Crash Dumps\crash-dump-settings.txt"

# Copy mini crash dumps
$MinidumpPath = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl").MinidumpDir
$DefaultPath = "$env:SystemRoot\Minidump"

If ( $DefaultPath -eq $MinidumpPath ) {

	If ( Test-Path -Path $MinidumpPath ) {

		Get-ChildItem $MinidumpPath | Sort-Object LastWriteTime -Descending >> "$Path\Crash Dumps\mini-crash-dumps.txt"

		If ( $(Get-ChildItem -Filter "*.dmp" -Path "$MinidumpPath") -ne $null ) {

			Write-Host "Copying Crash Dumps from $MinidumpPath..."

			Get-ChildItem -Filter "*.dmp" -Path "$MinidumpPath" | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First 5 | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$Path\Crash Dumps" } -ErrorAction SilentlyContinue -ErrorVariable ScriptError
			Write-Log $ScriptError $Log
		}

		Else {

			Write-Host "No Crash Dumps To Copy From $MinidumpPath"

			Write-Output "No Crash Dumps To Copy From $MinidumpPath." >> "$Path\Crash Dumps\mini-crash-dumps.txt"
		}
	}

	Else {

		Write-Host "No Crash Dumps To Copy From $MinidumpPath"

		Write-Output "$MinidumpPath does not exist." >> "$Path\Crash Dumps\mini-crash-dumps.txt"
	}
}

# If they paths in the registry and the default minidump path differ, check both paths for crash dumps and copy the 5 newest
Else {

	# Check that the registry path exists and is not empty, copy the 5 newest crash dumps
	If ( Test-Path -Path $MinidumpPath ) {

		Get-ChildItem $MinidumpPath | Sort-Object LastWriteTime -Descending >> "$Path\Crash Dumps\mini-crash-dumps.txt"

		If ( $(Get-ChildItem -Filter "*.dmp" -Path "$MinidumpPath") -ne $null ) {

			Write-Host "Copying Crash Dumps from $MinidumpPath..."
			Get-ChildItem -Filter "*.dmp" -Path "$MinidumpPath" | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First 5 | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$Path\Crash Dumps" } -ErrorAction SilentlyContinue -ErrorVariable ScriptError
			Write-Log $ScriptError $Log
		}

		Else {

			Write-Host "No Crash Dumps To Copy From $MinidumpPath"
			Write-Output "No Crash Dumps To Copy From $MinidumpPath." >> "$Path\Crash Dumps\mini-crash-dumps.txt"
		}
	}

	Else {

		Write-Host "No Crash Dumps To Copy From $MinidumpPath"
		Write-Output "$MinidumpPath does not exist." >> "$Path\Crash Dumps\mini-crash-dumps.txt"
	}

	If ( Test-Path -Path $DefaultPath ) {

		Get-ChildItem $DefaultPath | Sort-Object LastWriteTime -Descending >> "$Path\Crash Dumps\mini-crash-dumps.txt"

		If ( $(Get-ChildItem -Filter "*.dmp" -Path "$DefaultPath") -ne $null ) {

			Write-Host "Copying Crash Dumps from $DefaultPath..."
			Get-ChildItem -Filter "*.dmp" -Path "$DefaultPath"  | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First 5 | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$Path\Crash Dumps" } -ErrorAction SilentlyContinue -ErrorVariable ScriptError
			Write-Log $ScriptError $Log
		}

		Else {
		
			Write-Host "No Crash Dumps To Copy From $DefaultPath"
			Write-Output "No Crash Dumps To Copy From $DefaultPath." >> "$Path\Crash Dumps\mini-crash-dumps.txt"
		}
	}

	Else {

		Write-Host "No Crash Dumps To Copy From $DefaultPath"
		Write-Output "$DefaultPath does not exist." >> "$Path\Crash Dumps\mini-crash-dumps.txt"
	}
}

# Check if a full/kernel/active memory dump exists in the default location and the one specified in the registry
$DumpPath = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl").DumpFile

If ( $DumpPath -eq "$env:SystemRoot\Memory.dmp" ) {

	If ( Test-Path $DumpPath ) {

		Write-Output "Crash dump found at $DumpPath" > "$Path\Crash Dumps\memory-dumps.txt"
		Write-Output "Creation date: $((Get-Item "$DumpPath").LastWriteTime)" >> "$Path\Crash Dumps\memory-dumps.txt"
		Write-Output "Size on disk: $([math]::truncate((Get-Item $DumpPath).Length / 1MB)) MB" >> "$Path\Crash Dumps\memory-dumps.txt"
	}

	Else {

		Write-Output "$DumpPath was not found" >> "$Path\Crash Dumps\memory-dumps.txt"
	}
}

Else {

	If ( Test-Path $DumpPath ) {

		Write-Output "Crash dump found at $DumpPath" > "$Path\Crash Dumps\memory-dumps.txt"
		Write-Output "Creation date: $((Get-Item "$DumpPath").LastWriteTime)" >> "$Path\Crash Dumps\memory-dumps.txt"
		Write-Output "Size on disk: $([math]::truncate((Get-Item $DumpPath).Length / 1MB)) MB" >> "$Path\Crash Dumps\memory-dumps.txt"
	}

	Else {

		Write-Output "$DumpPath was not found" >> "$Path\Crash Dumps\memory-dumps.txt"
	}

	If ( Test-Path "$env:SystemRoot\Memory.dmp" ) {

		Write-Output "Crash dump found at $env:SystemRoot\Memory.dmp" >> "$Path\Crash Dumps\memory-dumps.txt"
		Write-Output "Creation date: $((Get-Item $env:SystemRoot\MEMORY.DMP).LastWriteTime)" >> "$Path\Crash Dumps\memory-dumps.txt"
		Write-Output "Size on disk: $([math]::truncate((Get-Item "$env:SystemRoot\Memory.dmp").Length / 1MB)) MB" >> "$Path\Crash Dumps\memory-dumps.txt"
	}

	Else {

		Write-Output "$env:SystemRoot\Memory.dmp was not found" >> "$Path\Crash Dumps\memory-dumps.txt"
	}
}

# List contents of LiveKernelReports directory if it exists and is not empty
If ( $(Test-Path -Path "$env:SystemRoot\LiveKernelReports") -eq $True -and $(Get-ChildItem -Path "$env:SystemRoot\LiveKernelReports" ) -ne $null ) {

	$LengthMB = @{Name="Size (MB)";Expression={[math]::Round($_.Length / 1MB, 2)}}
	Get-ChildItem -Path "$env:SystemRoot\LiveKernelReports" -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object Name,LastWriteTime,$LengthMB > "$Path\Crash Dumps\live-kernel-reports.txt"
	Write-Log $ScriptError $Log
}

# Gather a System Power Report, only supported on 8.1 and newer
If ( $VerNum -ge "6.3" ) {

	Write-Host "Running System Power Report..."
	&"$env:SystemRoot\System32\powercfg.exe" /sleepstudy /output "$Path\power-report.html" > $null 2> $ErrorFile
	Write-CommandError $ErrorFile $Log
}

# Disk and partition information, 8.1 requires admin rights unlike 10
If ( $VerNum -eq "6.3" ) {

	Get-Partition -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Format-List >> "$Path\partitions.txt"
	Write-Log $ScriptError $Log
	
	$DiskAttributes = "FriendlyName", "Model", "Manufacturer", "Number", "IsBoot", "AllocatedSize", "HealthStatus", "OperationalStatus", "BusType", "FirmwareVersion", "PartitionStyle", "Path"
	Get-Disk -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $DiskAttributes | Format-List >> "$Path\disks.txt"
	Write-Log $ScriptError $Log
}

# List PnP devices and associated information
Write-Host "Listing PnP Devices..."

$DriverAttributes = "Name", "Status", "ConfigManagerErrorCode", "Description", "Manufacturer", "DeviceID"
Get-WmiObject Win32_PNPEntity -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $DriverAttributes | Sort-Object Name | Format-Table -AutoSize >> "$Path\pnp-devices.txt"
Write-Log $ScriptError $Log

# List all processes
Write-Host "Enumerating Running Processes..."

$ProcessAttributes = "ProcessName", "ProcessID", "SessionId", "Priority", "CommandLine"
Get-WmiObject Win32_Process -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $ProcessAttributes | Sort-Object ProcessName,ProcessId | Format-Table -AutoSize > "$Path\processes.txt"
Write-Log $ScriptError $Log

# List all services including status, pid, only Windows 10 has support for listing service StartType via Get-Service
Write-Host "Identifying Running Services..."

If ( $VerNum -ge "10.0" ) {

	$StartType = @{Name="StartType";Expression={(Get-Service $_.Name).StartType}}
	
	Get-WmiObject Win32_Service -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object Name, DisplayName, State, ProcessID, $StartType | Sort-Object State, Name | Format-Table -AutoSize > "$Path\services.txt"
	Write-Log $ScriptError $Log	
}

Else {

	Get-WmiObject Win32_Service -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object Name, DisplayName, State, ProcessID | Sort-Object State, Name | Format-Table -AutoSize > "$Path\services.txt"
	Write-Log $ScriptError $Log
}

# Copy Windows Error Reports
Write-Host "Copying Windows Error Reports..."

If ( Test-Path -Path "$home\AppData\Local\Microsoft\Windows\WER\ReportArchive" ) {

	Copy-Item -Recurse "$home\AppData\Local\Microsoft\Windows\WER\ReportArchive\*" -Destination "$Path\Error Reports" > $null -ErrorAction SilentlyContinue -ErrorVariable ScriptError
	Write-Log $ScriptError $Log
}

If ( Test-Path -Path "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive" ) {

	Copy-Item -Recurse "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive\*" -Destination "$Path\Error Reports" > $null -ErrorAction SilentlyContinue -ErrorVariable ScriptError
	Write-Log $ScriptError $Log
}

# Download and run autorunsc.exe
Write-Host "Downloading autorunsc..."
$AutorunsUrl = "http://live.sysinternals.com/autorunsc.exe"

If ( $VerNum -ge "6.3" ) {

	Try {

		# This remove the progress bar, which slows the download to a crawl if enabled
		$ProgressPreference = 'SilentlyContinue'
		Invoke-WebRequest -Uri $AutorunsUrl -OutFile "$ScriptDir\autorunsc.exe" -TimeoutSec 10 -ErrorAction SilentlyContinue -ErrorVariable ScriptError
		Write-Log $ScriptError $Log
	}

	Catch {

		Write-Warning "Failed To Download autorunsc. Skipping..."
		Write-Log "Failed to download autrunsc." $Log
		Write-Log $error[0] $Log

		# Cleanup if the download fails
		If ( Test-Path -Path "$ScriptDir\autorunsc.exe" ) {
		
			Remove-Item -Force "$ScriptDir\autorunsc.exe"
		}
	}
}

Else {

	Try {

		$AutorunsUrl = "http://live.sysinternals.com/autorunsc.exe"
		$WebClient = New-Object System.Net.WebClient
		$WebClient.DownloadFile($AutorunsUrl,"$ScriptDir\autorunsc.exe")
	}

	Catch {

		Write-Warning "Failed To Download autorunsc. Skipping..."
		Write-Log "Failed to download autorunsc." $Log
		Write-Log $error[0] $Log

		# Cleanup if the download fails
		If ( Test-Path -Path "$ScriptDir\autorunsc.exe" ) {
		
			Remove-Item -Force "$ScriptDir\autorunsc.exe"
		}
	}
}

If ( Test-Path -Path "$ScriptDir\autorunsc.exe" ) {

	Write-Host "Finding Auto-Start Entries..."

	# -s -m List all autostart entries that are not cryptographically signed by Microsoft, -a = specify autostart selection, b = boot execute, d = Appinit DLLs, w = winlogon, h = image hijacks, e = explorer add-ons, l = logon, t = scheduled tasks
	Start-Process -FilePath "$ScriptDir\autorunsc.exe" -ArgumentList "-accepteula","-nobanner","-s","-m","-a","bdwhelt" -NoNewWindow -Wait -RedirectStandardOutput "$Path\autorun.txt" -RedirectStandardError $ErrorFile
	Write-CommandError $ErrorFile $Log
}

Else {

	Write-Log "$ScriptDir\autorunsc.exe not found." $Log
}

If ( Test-Path -Path "$ScriptDir\autorunsc.exe" ) {

	Remove-Item -Force "$ScriptDir\autorunsc.exe"
}

# Move log into $Path if it is non-empty
If ( $(Test-Path -Path $Log) -eq "True" -and (Get-Item $Log).Length -gt 0 ) {

	Move-Item -Path $Log -Destination $Path
}

If ( Test-Path -Path $ErrorFile ) { Remove-Item -Force $ErrorFile 2> $null }