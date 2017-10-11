##############################
# Script Written By Spectrum #
##############################

Param($path)

# Set output file for logging

$elevatedlog = "$env:TEMP\script-log-elevated.log"

# Check that this script is being run with elevated credentials, e.g. Administrator, SYSTEM, or TrustedInstaller

$elevatedcheck = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

If ( "$elevatedcheck" -ne "True" ) {

	Write-Warning "ERROR: Administrator rights are required for this script to work properly!"
	Write-Warning "Aborting script!"
	echo "ERROR: Administrator rights are required for this script to work properly!" >> $elevatedlog
	exit
}

# Verify path is valid before continuing

Try {

	If ( !(Test-Path "$path") ) {

		Write-Warning "Invalid path specified!"
		Write-Warning "Aborting script!"
		echo "path is invalid. Script aborted!" >> $elevatedlog
		echo "path variable is $path" >> $elevatedlog
		exit
	}
}

Catch {

	Write-Warning "Invalid path specified!"
	Write-Warning "Aborting script!"
	echo "path is invalid. Script aborted!" >> $elevatedlog
	echo "path variable is $path" >> $elevatedlog
	exit
}

# Detect Windows version, convert the value from a string to a decimal

$majorver=[System.Environment]::OSVersion.Version.Major
$minorver=[System.Environment]::OSVersion.Version.Minor
$ver = "$majorver" + "." + "$minorver"

$vernum=$ver -as [decimal]

# This is set because $PSScriptRoot is not available on stock Windows 7 SP1

$scriptdir = Split-Path $MyInvocation.MyCommand.Path -Parent

# Set window size to 1000 by 1000 to avoid truncation when sending output to files

$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (1000,1000)

# Get crash dump settings and append crash dump type matrix

Write-Host "Getting Crash Dump Settings..."

echo "########################## Crash Dump Settings #########################" > "$path\Crash Dumps\crash-dump-settings.txt"

Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" >> "$path\Crash Dumps\crash-dump-settings.txt" 2>> $elevatedlog

echo "######################## Crash Dump Type Matrix ########################


		CrashDumpEnabled			FilterPages
Disabled	0					<does not exist>
Complete	1					<does not exist>
Active		1					1
Kernel		2					<does not exist>
Small		3					<does not exist>
Automatic	7					<does not exist>" >> "$path\Crash Dumps\crash-dump-settings.txt"

# Copy mini crash dumps

$minidump_path = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl").MinidumpDir

$default_path = "$env:SystemRoot\Minidump"

If ( $default_path -eq $minidump_path ) {

	If ( Test-Path "$minidump_path" ) {

		Get-ChildItem $minidump_path | Sort-Object LastWriteTime -Descending >> "$path\Crash Dumps\mini-crash-dumps.txt"

		If ( $(Get-ChildItem -Filter "*.dmp" -Path "$minidump_path") -ne $null ) {

			Write-Host "Copying Crash Dumps from $minidump_path..."

			Get-ChildItem -Filter "*.dmp" -Path "$minidump_path" | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First 5 | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$path\Crash Dumps" } 2>> $elevatedlog
		}

		Else {

			Write-Host "No Crash Dumps To Copy From $minidump_path"

			echo "No Crash Dumps To Copy From $minidump_path." >> "$path\Crash Dumps\mini-crash-dumps.txt"
		}
	}

	Else {

		Write-Host "No Crash Dumps To Copy From $minidump_path"

		echo "$minidump_path does not exist." >> "$path\Crash Dumps\mini-crash-dumps.txt"
	}
}

# If they paths in the registry and the default minidump path differ, check both paths for crash dumps and copy the 5 newest

Else {

	# If the registry path exists and is not empty, copy the 5 newest crash dumps

	If ( Test-Path "$minidump_path" ) {

		Get-ChildItem $minidump_path | Sort-Object LastWriteTime -Descending >> "$path\Crash Dumps\mini-crash-dumps.txt"

		If ( $(Get-ChildItem -Filter "*.dmp" -Path "$minidump_path") -ne $null ) {

			Write-Host "Copying Crash Dumps from $minidump_path..."

			Get-ChildItem -Filter "*.dmp" -Path "$minidump_path" | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First 5 | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$path\Crash Dumps" } 2>> $elevatedlog
		}

		Else {

			Write-Host "No Crash Dumps To Copy From $minidump_path"

			echo "No Crash Dumps To Copy From $minidump_path." >> "$path\Crash Dumps\mini-crash-dumps.txt"
		}
	}

	Else {

		Write-Host "No Crash Dumps To Copy From $minidump_path"

		echo "$minidump_path does not exist." >> "$path\Crash Dumps\mini-crash-dumps.txt"
	}

	If ( Test-Path "$default_path" ) {

		Get-ChildItem $default_path | Sort-Object LastWriteTime -Descending >> "$path\Crash Dumps\mini-crash-dumps.txt"

		If ( $(Get-ChildItem -Filter "*.dmp" -Path "$default_path") -ne $null ) {

			Write-Host "Copying Crash Dumps from $default_path..."

			Get-ChildItem -Filter "*.dmp" -Path "$default_path"  | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First 5 | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$path\Crash Dumps" } 2>> $elevatedlog
		}

		Else {
		
			Write-Host "No Crash Dumps To Copy From $default_path"

			echo "No Crash Dumps To Copy From $default_path." >> "$path\Crash Dumps\mini-crash-dumps.txt"
		}
	}

	Else {

		Write-Host "No Crash Dumps To Copy From $default_path"

		echo "$default_path does not exist." >> "$path\Crash Dumps\mini-crash-dumps.txt"
	}
}

# Check if a full/kernel/active memory dump exists in the default location and the one specified in the registry

$dump_path = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl").DumpFile

If ( $dump_path -eq "$env:SystemRoot\Memory.dmp" ) {

	If ( Test-Path "$dump_path" ) {

		echo "Crash dump found at $dump_path" > "$path\Crash Dumps\memory-dumps.txt"
		echo "Creation date: $((Get-Item "$dump_path").LastWriteTime)" >> "$path\Crash Dumps\memory-dumps.txt"
		echo "Size on disk: $([math]::truncate((Get-Item $dump_path).Length / 1MB)) MB" >> "$path\Crash Dumps\memory-dumps.txt"
	}

	Else {

		echo "$dump_path was not found" >> "$path\Crash Dumps\memory-dumps.txt"
	}
}

Else {

	If ( Test-Path "$dump_path" ) {

		echo "Crash dump found at $dump_path" > "$path\Crash Dumps\memory-dumps.txt"
		echo "Creation date: $((Get-Item "$dump_path").LastWriteTime)" >> "$path\Crash Dumps\memory-dumps.txt"
		echo "Size on disk: $([math]::truncate((Get-Item $dump_path).Length / 1MB)) MB" >> "$path\Crash Dumps\memory-dumps.txt"
	}

	Else {

		echo "$dump_path was not found" >> "$path\Crash Dumps\memory-dumps.txt"
	}

	If ( Test-Path "$env:SystemRoot\Memory.dmp" ) {

		echo "Crash dump found at $env:SystemRoot\Memory.dmp" >> "$path\Crash Dumps\memory-dumps.txt"
		echo "Creation date: $((Get-Item $env:SystemRoot\MEMORY.DMP).LastWriteTime)" >> "$path\Crash Dumps\memory-dumps.txt"
		echo "Size on disk: $([math]::truncate((Get-Item "$env:SystemRoot\Memory.dmp").Length / 1MB)) MB" >> "$path\Crash Dumps\memory-dumps.txt"
	}

	Else {

		echo "$env:SystemRoot\Memory.dmp was not found" >> "$path\Crash Dumps\memory-dumps.txt"
	}
}

# List contents of LiveKernelReports directory if it exists and is not empty

If ( $(Test-Path "$env:SystemRoot\LiveKernelReports") -eq $True -and $(Get-ChildItem -Path "$env:SystemRoot\LiveKernelReports" ) -ne $null ) {

	$LengthMB = @{Name="Size (MB)";Expression={[math]::Round($_.Length / 1MB, 2)}}

	Get-ChildItem -Path "$env:SystemRoot\LiveKernelReports" 2>> $elevatedlog | Select-Object Name,LastWriteTime,$LengthMB > "$path\Crash Dumps\live-kernel-reports.txt"
}

# Gather a System Power Report, only supported on 8.1 and newer

If ( $vernum -ge "6.3" ) {

	Write-Host "Running System Power Report..."

	powercfg.exe /sleepstudy /output "$path\power-report.html" > $null 2>> $elevatedlog
}

# Disk and partition information, 8.1 requires admin rights unlike 10

If ( $vernum -eq "6.3" ) {

	Get-Partition 2>> $elevatedlog | Format-List >> "$path\partitions.txt"

	Get-Disk 2>> $elevatedlog | Select-Object FriendlyName, Model, Manufacturer, Number, IsBoot, AllocatedSize, HealthStatus, OperationalStatus, BusType, FirmwareVersion, PartitionStyle, Path | Format-List >> "$path\disks.txt"																	 "$path\disks.txt"
}

# List all processes

Write-Host "Enumerating Running Processes..."

Get-WmiObject Win32_Process 2>> $elevatedlog | Select-Object ProcessName, ProcessID, SessionId, Priority, CommandLine | Sort-Object ProcessName,ProcessId | Format-Table -AutoSize > "$path\processes.txt"

# List all services including status, pid, only Windows 10 has support for listing service StartType via Get-Service

Write-Host "Identifying Running Services..."

If ( $vernum -ge "10.0" ) {

	$StartType = @{Name="StartType";Expression={(Get-Service $_.Name).StartType}}

	Get-WmiObject Win32_Service 2>> $elevatedlog | Select-Object Name, DisplayName, State, ProcessID, $StartType | Sort-Object State, Name | Format-Table -AutoSize > "$path\services.txt"	
}

Else {

	Get-WmiObject Win32_Service 2>> $elevatedlog | Select-Object Name, DisplayName, State, ProcessID | Sort-Object State, Name | Format-Table -AutoSize > "$path\services.txt"
}

# Copy Windows Error Reports

Write-Host "Copying Windows Error Reports..."

If ( Test-Path "$home\AppData\Local\Microsoft\Windows\WER\ReportArchive" ) {

	Copy-Item -Recurse "$home\AppData\Local\Microsoft\Windows\WER\ReportArchive\*" -Destination "$path\Error Reports" > $null 2>> $elevatedlog
}

If ( Test-Path "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive" ) {

	Copy-Item -Recurse "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive\*" -Destination "$path\Error Reports" > $null 2>> $elevatedlog
}

# Download and run autorunsc.exe

$autorunsurl = "http://live.sysinternals.com/autorunsc.exe"

Write-Host "Downloading autorunsc..."

If ( $vernum -ge "6.3" ) {

	Try {

		$ProgressPreference = 'SilentlyContinue'

		Invoke-WebRequest -Uri "$autorunsurl" -OutFile "$scriptdir\autorunsc.exe" -TimeoutSec 10 2>> $elevatedlog
	}

	Catch {

		Write-Warning "Failed To Download autorunsc. Skipping..."

		echo "Failed to download autrunsc." >> $elevatedlog

		echo $error[0] >> $elevatedlog

		If ( Test-Path "$scriptdir\autorunsc.exe" ) { Remove-Item -Force "$scriptdir\autorunsc.exe" }
	}
}

Else {

	Try {

		$autorunsurl = "http://live.sysinternals.com/autorunsc.exe"

		$WebClient = New-Object System.Net.WebClient

		$WebClient.DownloadFile($autorunsurl,"$scriptdir\autorunsc.exe") 2>> $elevatedlog
	}

	Catch {

		Write-Warning "Failed To Download autorunsc. Skipping..."

		echo "Failed to download autrunsc." >> $elevatedlog

		echo $error[0] >> $elevatedlog

		If ( Test-Path "$scriptdir\autorunsc.exe" ) { Remove-Item -Force "$scriptdir\autorunsc.exe" }
	}
}

If ( Test-Path "$scriptdir\autorunsc.exe" ) {

	Write-Host "Finding Auto-Start Entries..."

	# -s -m List all autostart entries that are not cryptographically signed by Microsoft, -a = specify autostart selection, b = boot execute, d = Appinit DLLs, w = winlogon, h = image hijacks, e = explorer add-ons, l = logon, t = scheduled tasks

	Start-Process -FilePath "$scriptdir\autorunsc.exe" -ArgumentList "-accepteula","-nobanner","-s","-m","-a","bdwhelt" -NoNewWindow -Wait -RedirectStandardOutput "$path\autorun.txt" 2>> $elevatedlog
}

Else {

	echo "$scriptdir\autorunsc.exe not found." >> $elevatedlog
}

If ( Test-Path "$scriptdir\autorunsc.exe" ) {

	Remove-Item -Force "$scriptdir\autorunsc.exe"
}