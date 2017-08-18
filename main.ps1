# If the OS is 64-bit and this script was launched with 32-bit PowerShell, relaunch with 64-bit PowerShell and exit the current instance

	If ( [Environment]::Is64BitOperatingSystem -eq $True -and [Environment]::Is64BitProcess -eq $False ) {

		&"$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe" -NoProfile $myInvocation.InvocationName

		exit
	}

# Define wait loop function with timeout

	function waitloop ( $process, $name, $timeoutseconds, $outputfilepath ){

		$startDate = Get-Date

		If ( !$process.HasExited ) {

			Write-Host "Waiting For $name To Finish..."
		}

		While ( !$process.HasExited -and $startDate.AddSeconds($timeoutseconds) -gt (Get-Date) ) {

			Start-Sleep -Milliseconds 500
		}

		If ( !$process.HasExited -and $startDate.AddSeconds($timeoutseconds) -le (Get-Date) ) { 

			Stop-Process -Force -Id $process.Id 2>> $log

			If ( "$outputfilepath" -ne $null ) {

				Remove-Item "$outputfilepath" 2>> $log
			}

			echo "Killed $name due to timeout." >> $log

			Write-Warning "Killed $name due to timeout."

		}
	}

# This is set because $PSScriptRoot is not available on stock Windows 7 SP1

	$scriptdir = Split-Path $MyInvocation.MyCommand.Path -Parent

# Set window size to 1000 by 1000 to avoid truncation when sending output to files

	$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (1000,1000)

# Detect Windows version, convert the value from a string to a decimal

	$majorver=[System.Environment]::OSVersion.Version.Major
	$minorver=[System.Environment]::OSVersion.Version.Minor
	$ver = "$majorver" + "." + "$minorver"

	$vernum=$ver -as [decimal]

	If ( $vernum -lt 6.1 ) {

		echo "UNSUPPORTED VERSION OF WINDOWS DETECTED - KERNEL VERSION LESS THAN 6.1" >> $log
		Write-Host "`n"
		Write-Warning "Windows Version Is Unsupported!"
		Write-Warning "This Script Has Not Been Tested On Anything Before Windows 7!"
		exit
	}

	If ( $vernum -eq 6.2 ) {

		echo "UNSUPPORTED VERSION OF WINDOWS DETECTED - WINDOWS 8" >> $log
		Write-Host "`n"
		Write-Warning "Windows Version Is Unsupported!"
		Write-Warning "This Script Has Not Been Tested On Windows 8, Please Upgrade!"
	}

# Set variables

	$scriptver = "Version alpha002 - 8/18/17"
	$time = Get-Date -format M-d-yyyy
	$name = "$env:computername ($time)"
	$path = "$home\Desktop\Logs-$name"
	$log = "$env:TEMP\script-log.log"
	$elevatedlog = "$env:TEMP\script-log-elevated.log"
	$zip = "$path" + ".zip"

# User Banner

	clear
	Write-Host "
  ______              ______                          _              
 /_  __/__  ____     / ____/___  _______  ______ ___ ( )_____        
  / / / _ \/ __ \   / /_  / __ \/ ___/ / / / __ `__ \|// ___/        
 / / /  __/ / / /  / __/ / /_/ / /  / /_/ / / / / / / (__  )         
/_/  \___/_/ /_/  /_/    \____/_/   \__,_/_/ /_/ /_/ /____/          
    __                   ______      ____          __                
   / /   ____  ____ _   / ____/___  / / /__  _____/ /_____  _____    
  / /   / __ \/ __ `/   / /   / __ \/ / / _ \/ ___/ __/ __ \/ ___/    
 / /___/ /_/ / /_/ /  / /___/ /_/ / / /  __/ /__/ /_/ /_/ / /        
/_____/\____/\__, /   \____/\____/_/_/\___/\___/\__/\____/_/         
            /____/                                                      
"
	"`n" * 3
	
	Write-Host $scriptver
	
	"`n" * 3

	Read-Host -Prompt "Press Enter To Continue"

	clear

# Store the home of the current user so elevated.ps1 can retrieve it, elevated.ps1 may run under a different account

	echo "$home" > "$env:SystemRoot\Temp\home.txt"
	
# Check for pre-existing files and folders, and remove them if they exist

	If ( Test-Path "$path" ) { Remove-Item "$path" -Recurse }

	If ( Test-Path "$zip" ) { Remove-Item "$zip" }

	If ( Test-Path $log ) { Remove-Item $log }

	If ( Test-path "$elevatedlog" ) { Remove-Item "$elevatedlog" }

# Create Directories

	New-Item -ItemType Directory "$path" -Force -ErrorAction Stop > $null 2>> $log

	New-Item -ItemType Directory "$path\Events" -Force -ErrorAction Stop > $null 2>> $log
	
	New-Item -ItemType Directory "$path\Crash Dumps" -Force -ErrorAction Stop > $null 2>> $log

	New-Item -ItemType Directory "$path\Error Reports" -Force -ErrorAction Stop > $null 2>> $log

# Generate System Information Report

	Write-Host "Generating System Information Report, this may take a while..."

	Try { $msinfo32 = Start-Process msinfo32.exe -ArgumentList """/nfo"" ""$path\info.nfo""" -PassThru }

	Catch {

		Write-Warning "Failed To Launch msinfo32.exe!"
		echo "Failed to launch msinfo32.exe!" >> $log
		echo $error[0] >> $log
	}

# Start Elevated Script

	If ( Test-Path "$scriptdir\elevated.ps1" ) {

		Write-Host "Launching Elevated Script..."

		Try { $elevated_script = Start-Process Powershell.exe -ArgumentList """-ExecutionPolicy"" ""Bypass"" ""-NonInteractive"" ""-File"" ""$scriptdir\elevated.ps1""" -Verb RunAs -PassThru }

		Catch {

			Write-Warning "Failed To Launch Elevated Script!" 
			echo "Failed To Launch Elevated Script!" >> $log
			$elevatedscriptfailed = "1"
			echo $error[0] >> $log
		}
	}

	Else {
		
		Write-Warning "$scriptdir\elevated.ps1 not found!"
		echo "$scriptdir\elevated.ps1 not found!" >> $log
		$elevatedscriptfailed = "1"
	}

# DirectX Diagnostics Report

	Write-Host "Running DirectX Diagnostics..."

	Try { $dxdiag = Start-Process dxdiag.exe -ArgumentList "/dontskip","/whql:off","/t","$path\dxdiag.txt" -NoNewWindow -PassThru }

	Catch {

		Write-Warning "Failed To Run DirectX Diagnostics!"
		echo "Failed to run dxdiag.exe" >> $log
		echo $error[0] >> $log
	}

# Get crash dump settings and append crash dump type matrix

	echo "########################## Crash Dump Settings #########################" > "$path\Crash Dumps\crash-dump-settings.txt"

	Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl >> "$path\Crash Dumps\crash-dump-settings.txt" 2>> $log

echo "######################## Crash Dump Type Matrix ########################


		CrashDumpEnabled			FilterPages
Disabled	0					<does not exist>
Complete	1					<does not exist>
Active		1					1
Kernel		2					<does not exist>
Small		3					<does not exist>
Automatic	7					<does not exist>" >> "$path\Crash Dumps\crash-dump-settings.txt"

# Export Event Logs (1209600000ms = 14 days, 604800000ms = 7 days)

	Write-Host "Exporting Application Event Log..."

	wevtutil.exe query-events Application /q:"*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]" /f:text > $path\Events\application-events.txt 2>> $log

#	wevtutil.exe export-log Application $path\Events\application-events.evtx /q:"*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]" 2>> $log

	Write-Host "Exporting System Event Log..."

	wevtutil.exe query-events System /q:"*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]" /f:text > $path\Events\system-events.txt 2>> $log

#	wevtutil.exe export-log System $path\Events\system-events.evtx /q:"*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]" 2>> $log

	Write-Host "Exporting WHEA Event Log..."

	wevtutil.exe query-events Microsoft-Windows-Kernel-WHEA/Errors /q:"*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]" /f:text > $path\Events\whea-events.txt 2>> $log

#	wevtutil.exe export-log Microsoft-Windows-Kernel-WHEA/Errors $path\Events\whea-events.evtx /q:"*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]" 2>> $log

# Driver information

	Write-Host "Gathering Driver Information..."

	driverquery.exe /v /fo table 2>> $log | Select-Object -Skip 1 > "$path\driver-list.txt"

	Get-WmiObject Win32_PnPSignedDriver 2>> $log | Select-Object DeviceName,FriendlyName,DriverVersion,DriverDate | Sort-Object DeviceName | Format-Table -AutoSize > "$path\driver-versions.txt"

# Get Default Power Plan

	Write-Host "Checking Power Settings..."

	powercfg.exe /list > "$path\power-plan.txt" 2>> $log

# System serial/product number

	Write-Host "Looking Up Serial Number..."

	(Get-WmiObject Win32_Bios).SerialNumber > "$path\serial.txt" 2>> $log

# RAM info

	Write-Host "Getting Hardware Information..."
	
	Get-WmiObject Win32_PhysicalMemory 2>> $log | Select banklabel, devicelocator, capacity, manufacturer, configuredclockspeed, configuredvoltage | Format-List > "$path\ram.txt"

# Processor Information

	Get-WmiObject Win32_Processor 2>> $log | Select Name, Description, CurrentClockSpeed, CPUStatus, LastErrorCode, ErrorDescription, PartNumber, Revision, SerialNumber, ProcessorId, Status, StatusInfo, Stepping, CurrentVoltage, VoltageCaps | Format-List > "$path\cpu.txt"

# Disk and Partition Information

	Get-Partition 2>> $log | Format-List > "$path\partitions.txt"

	Get-Disk 2>> $log | Select FriendlyName, Model, IsBoot, AllocatedSize, HealthStatus, OperationalStatus, FirmwareVersion, PartitionStyle, Path | Format-List > "$path\disks.txt"

	Get-WmiObject Win32_LogicalDisk 2>> $log | ForEach-Object {write " $($_.caption) $('{0:N2}' -f ($_.Size/1gb)) GB total, $('{0:N2}' -f ($_.FreeSpace/1gb)) GB free "} >> "$path\disks.txt"
	
# System Board Information

	Get-WmiObject Win32_BaseBoard 2>> $log | Select Product, Model, Version, Manufacturer, Description > "$path\motherboard.txt"

# GPU Information

	Get-WmiObject Win32_VideoController 2>> $log | Select Name, DeviceID, PNPDeviceID, VideoProcessor, CurrentRefreshRate, VideoModeDescription, AdapterRAM, DriverVersion, InfFilename, InstalledDisplayDrivers, InstallDate, DriverDate, Status, StatusInfo, LastErrorCode, ErrorDescription | Format-List > "$path\gpu.txt"
	
# Windows license information

	Write-Host "Finding Windows License Information..."

	cscript.exe $env:SystemRoot\System32\slmgr.vbs /dlv | Select-Object -Skip 4 > "$path\windows-license-info.txt" 2>> $log

# Installed Software, first check native and then 32-bit (if it exists)

	Write-Host "Listing Installed Software..."

	Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>> $log | Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName | Format-Table -AutoSize > "$path\installed-software.txt"

	If ( Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" ) {

		echo "`n" >> "$path\installed-software.txt"
		echo "32-bit Software" >> "$path\installed-software.txt"

		Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>> $log | Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName | Format-Table -AutoSize >> "$path\installed-software.txt"
	}

# Installed Windows Updates

	Write-Host "Listing Installed Windows Updates..."

	Get-WmiObject Win32_QuickFixEngineering 2>> $log | Select-Object HotFixID,Description,InstalledOn | Sort-Object InstalledOn,HotFixID | Format-Table -AutoSize > "$path\windows-updates.txt"

# Basic networking information

	Write-Host "Finding Network Information..."

	ipconfig.exe /allcompartments /all 2>> $log | Select-Object -Skip 1 > "$path\network-info.txt"

	route.exe print >> "$path\network-info.txt" 2>> $log

# Copy hosts file

	Write-Host "Copying Hosts File..."

	If ( Test-Path "$env:SystemRoot\System32\drivers\etc\hosts" ) {

		Copy-Item -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Destination "$path\hosts.txt"
	}

# Wait if dxdiag.exe has not finished, kill process if timeout is reached

	If ( $dxdiag -ne $null ) {

		waitloop $dxdiag dxdiag.exe 30
	}

	Else {

		echo "dxdiag.exe crashed or was closed by the user!" >> $log
	}
# Wait if msinfo32.exe has not finished, kill process if timeout is reached

	If ( $msinfo32 -ne $null ) {

		waitloop $msinfo32 msinfo32.exe 120 "$path\info.nfo"
	}

	Else {

		echo "msinfo32.exe crashed or was closed by the user!" >> $log
	}

# Wait if the elevated script has not finished, include timeout and kill process if timeout is reached, .HasExited on a PowerShell script appears to be broken on PowerShell v2

	If ( $elevated_script -ne $null ) {

		waitloop $elevated_script "Elevated Script" 120
	}

	ElseIf ( $elevatedscriptfailed -ne "1" ) {

		echo "elevated.ps1 crashed or was closed by the user!" >> $log
	}

# Move logs into $path if they exist and are not empty

	If ( $(Test-Path "$elevatedlog") -eq "True" -and (Get-Item "$elevatedlog").Length -gt 0 ) {

		Move-Item "$elevatedlog" -Destination "$path"
	}

	If ( $(Test-Path "$log") -eq "True" -and (Get-Item "$log").Length -gt 0 ) {

		Move-Item "$log" -Destination "$path"
	}

# Compress folder, use native cmdlet or native function if PowerShell supports it

	If ( $vernum -ge "10.0" ) {

		Try {

			Write-Host "Compressing folder..."

			Compress-Archive -Path "$path\*" -DestinationPath "$zip"

			$compression = $?
		}

		Catch {

			Write-Warning "Failed to compress the folder with native cmdlet!"

		 	If ( Test-Path "$zip" ) { Remove-Item "$zip" }
			
			If ( Test-Path "$scriptdir\7za.exe" ) {

				Write-Host "Compressing folder with 7-Zip (Licensed under the LGPL - www.7-zip.org)..."

				Start-Process -FilePath "$scriptdir\7za.exe" -ArgumentList """a"" ""-tzip"" ""$zip"" ""$path\*""" -NoNewWindow -Wait -RedirectStandardOutput NUL

				$compression = $?
			}
			
			Else {
			
				Write-Warning "$scriptdir\7za.exe not found"
				Write-Warning "Skipping Compression..."

				$compression = "False"
			}
		}

	}

	ElseIf ( $PSVersionTable.PSVersion.Major -ge "3" -and $PSVersionTable.CLRVersion.Major -ge "4" ) {

		Try {

			Write-Host "Compressing folder with system.io.compression..."

			Add-Type -assembly "system.io.compression.filesystem"

			[io.compression.zipfile]::CreateFromDirectory("$path","$zip")

			$compression = $?
		}

		Catch {

			Write-Warning "Failed to compress the folder with native cmdlet!"

		 	If ( Test-Path "$zip" ) { Remove-Item "$zip" }
			
			If ( Test-Path "$scriptdir\7za.exe" ) {

				Write-Host "Compressing folder with 7-Zip (Licensed under the LGPL - www.7-zip.org)..."

				Start-Process -FilePath "$scriptdir\7za.exe" -ArgumentList """a"" ""-tzip"" ""$zip"" ""$path\*""" -NoNewWindow -Wait -RedirectStandardOutput NUL

				$compression = $?
			}
			
			Else {
			
				Write-Warning "$scriptdir\7za.exe not found"
				Write-Warning "Skipping Compression..."

				$compression = "False"
			}
		}
	}

	ElseIf ( Test-Path "$scriptdir\7za.exe" ) {

			Write-Host "Compressing folder with 7-Zip (Licensed under the LGPL - www.7-zip.org)..."

			Start-Process -FilePath "$scriptdir\7za.exe" -ArgumentList """a"" ""-tzip"" ""$zip"" ""$path\*""" -NoNewWindow -Wait -RedirectStandardOutput NUL

			$compression = $?
		}
		
	Else {
			
		Write-Warning "$scriptdir\7za.exe not found"
		Write-Warning "Skipping Compression..."

		$compression = "False"
	}

	Write-Host "`n"

# Check that the .zip file was created and the compression operation completed successfully before removing the uncompressed directory

	If ( "$(Test-Path "$zip")" -eq "True" -and "$compression" -eq "True" ) {

		Remove-Item "$path" -Recurse

		Write-Host "Output location: $zip" 
	}

	Else {

		Write-Host "Compression failed!"
		Write-Host "`n"
		Write-Host "Output location: $path"
	}

Write-Host "`n"
Read-Host -Prompt "Press Enter To Exit"
