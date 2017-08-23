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

# Detect Windows version, convert the value from a string to a decimal

	$majorver=[System.Environment]::OSVersion.Version.Major
	$minorver=[System.Environment]::OSVersion.Version.Minor
	$ver = "$majorver" + "." + "$minorver"

	$vernum=$ver -as [decimal]

# This is set because $PSScriptRoot is not available on stock Windows 7 SP1

	$scriptdir = Split-Path $MyInvocation.MyCommand.Path -Parent

# Set window size to 1000 by 1000 to avoid truncation when sending output to files

	$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (1000,1000)

# Get output path from main.ps1, verify it is a valid path before continuing

	If ( !(Test-Path "$env:SystemRoot\Temp\path.txt") ) { 

		Write-Warning "$env:SystemRoot\Temp\path.txt does not exist! Exiting..."
		echo "$env:SystemRoot\Temp\path.txt does not exist. Script aborted!" >> $elevatedlog
		exit
	}

	$path = Get-Content "$env:SystemRoot\Temp\path.txt"
	
	If ( !(Test-Path "$path") ) {
	
		Write-Warning "$env:SystemRoot\Temp\path.txt does not contain a valid file path!"
		Write-Warning "Aborting script!"
		
		echo "$env:SystemRoot\Temp\path.txt does not contain a valid filepath! Script aborted!" >> $elevatedlog
		echo "$path" >> $elevatedlog
		Remove-Item "$env:SystemRoot\Temp\path.txt" > $null 2>> $elevatedlog

		exit
	}

	Remove-Item "$env:SystemRoot\Temp\path.txt" > $null 2>> $elevatedlog

# Copy Crash Dumps

	If ( Test-Path "$env:SystemRoot\Minidump" ) {

		If ( $(Get-ChildItem "$env:SystemRoot\Minidump") -ne $null ) {

			Write-Host "Copying Crash Dumps..."

			Get-ChildItem -Path "$env:SystemRoot\Minidump" | Sort-Object $_.LastWriteTime | Select-Object -First 5 | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$path\Crash Dumps" } 2>> $elevatedlog
		}

		Else {

			 Write-Host "No Crash Dumps To Copy"

			 echo "$env:SystemRoot\Minidump is empty." >> "$path\Crash Dumps\no-mini-crash-dumps.txt"
		}
	} 

	Else {

		 Write-Host "No Crash Dumps To Copy"

		 echo "The folder $env:SystemRoot\Minidump does not exist." >> "$path\Crash Dumps\no-mini-crash-dumps.txt"
	}

# Check if a full/kernel/active memory dump exists

	If ( Test-Path "$env:SystemRoot\MEMORY.DMP" ) {

		echo "Crash dump found at $env:SystemRoot\MEMORY.DMP" > "$path\Crash Dumps\memory.dmp-exists.txt"
		echo "Creation date: $((Get-Item $env:SystemRoot\MEMORY.DMP).LastWriteTime)" >> "$path\Crash Dumps\memory.dmp-exists.txt"
		echo "Size on disk: $([math]::truncate((Get-Item $env:SystemRoot\MEMORY.DMP).Length / 1MB)) MB" >> "$path\Crash Dumps\memory.dmp-exists.txt"
	}

	Else {

		echo "MEMORY.DMP was not found in $env:SystemRoot" > "$path\Crash Dumps\no-memory.dmp.txt"
	}

# Gather a System Power Report, only supported on 8.1 and newer

	If ($vernum -ge "6.3") {

		Write-Host "Running System Power Report..."

		powercfg.exe /sleepstudy /output "$path\power-report.html" > $null 2>> $elevatedlog
	}

# Disk and Partition Information, 8.1 requires admin rights unlike 10

	If ( $vernum -eq "6.3" ) {

		Get-Partition 2>> $elevatedlog | Format-List > "$path\partitions.txt"

		Get-Disk 2>> $elevatedlog | Select-Object FriendlyName, Model, Manufacturer, IsBoot, AllocatedSize, HealthStatus, OperationalStatus, FirmwareVersion, PartitionStyle, Path | Format-List >> "$path\disks.txt"																	 "$path\disks.txt"
	}

# List all processes

	Write-Host "Enumerating Running Processes..."

	Get-WmiObject Win32_Process 2>> $elevatedlog | Select-Object ProcessId,ProcessName,SessionId,Priority,CommandLine | Sort-Object ProcessName,ProcessId | Format-Table -AutoSize > "$path\processes.txt"

# List all services including status and startup type, only Windows 10 has support for listing service StartType via Get-Service

	Write-Host "Identifying Running Services..."

	If ( $vernum -ge "10.0" ) {

		Get-Service 2>> $elevatedlog | Select-Object Status,StartType,Name,DisplayName | Sort-Object -Property @{Expression = "Status"; Descending = $True}, @{Expression = "Name"; Descending = $False} | Format-Table -Autosize > "$path\services.txt"	
	}

	Else { Get-Service 2>> $elevatedlog | Select-Object Status,Name,DisplayName | Sort-Object -Property @{Expression = "Status"; Descending = $True}, @{Expression = "Name"; Descending = $False} | Format-Table -Autosize > "$path\services.txt" }

# Copy Windows Error Reports

	Write-Host "Copying Windows Error Reports..."

	If ( Test-Path "$home\AppData\Local\Microsoft\Windows\WER\ReportArchive" ) {

		Copy-Item -Recurse "$home\AppData\Local\Microsoft\Windows\WER\ReportArchive\*" -Destination "$path\Error Reports" > $null 2>> $elevatedlog
	}

	If ( Test-Path "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive" ) {

		Copy-Item -Recurse "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive\*" -Destination "$path\Error Reports" > $null 2>> $elevatedlog
	}

# List all autostart entries that are not cryptographically signed by Microsoft (-s -m)

	If ( Test-Path "$scriptdir\autorunsc.exe" ) {

		Write-Host "Finding Auto-Start Entries..."

		# -a = specify autostart selection, b = boot execute, d = Appinit DLLs, w = winlogon, h = image hijacks, e = explorer add-ons, l = logon, t = scheduled tasks
	
		Start-Process -FilePath "$scriptdir\autorunsc.exe" -ArgumentList "-accepteula","-nobanner","-s","-m","-a","bdwhelt" -NoNewWindow -Wait -RedirectStandardOutput "$path\autorun.txt" 2>> $elevatedlog
	}
	
	Else {
	
		Write-Warning "$scriptdir\autorunsc.exe not found"
		echo "$scriptdir\autorunsc.exe not found" >> $elevatedlog
	}
