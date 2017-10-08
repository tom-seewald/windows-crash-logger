##############################
# Script Written By Spectrum #
##############################

# If the OS is 64-bit and this script was launched with 32-bit PowerShell, relaunch with 64-bit PowerShell and exit the current instance

If ( [Environment]::Is64BitOperatingSystem -eq $True -and [Environment]::Is64BitProcess -eq $False ) {

	&"$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe" -NoProfile $myInvocation.InvocationName

	exit
}

# Define wait loop function with timeout

function waitloop ( $process, $name, $timeoutseconds, $outputfilepath ) {

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

# Define compression function

function compression ( $inputpath, $outputpath ) {

	If ( $PSVersionTable.PSVersion.Major -ge "3" -and $PSVersionTable.CLRVersion.Major -ge "4" ) {

		Try {

			Write-Host "Compressing Folder..."

			Add-Type -Assembly "system.io.compression.filesystem"

			[io.compression.zipfile]::CreateFromDirectory("$inputpath","$outputpath")

			$compression = $?
			
			Return $?
		}

		Catch {

			Write-Warning "Failed to compress the folder with io.compression!"

			If ( Test-Path "$outputpath" ) { Remove-Item "$outputpath" }
			
			$compression = "False"
			
			Return "False"
		}
	}

	If ( $(Test-Path "$scriptdir\compression.vbs") -eq $True -and $compression -ne "True" ) {

		Try {
		
			Write-Host "Compressing Folder..."
			
			cscript.exe "$scriptdir\compression.vbs" "$inputpath" "$outputpath" > $null 2>> $log
			
			Return $?
		}
		
		Catch {
		
			Write-Warning "Failed to compress the folder with vbscript!"

			If ( Test-Path "$outputpath" ) { Remove-Item "$outputpath" }
			
			Return "False"
		}
	}
	
	Else {
	
		Write-Warning "Could not find compression.vbs"
	
		Return "False"
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

# Version String

$scriptver = "Version alpha012 - 10/7/17"

# Startup Banner

clear

Write-Host "
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

Write-Host $scriptver

"`n" * 3

Read-Host -Prompt "Press Enter To Continue"

clear

# Set variables for output folders

$time = Get-Date
$time = $time.ToShortDateString() + " " + $time.ToShortTimeString()
$time = $time -Replace ":"," "
$time = $time -Replace "/","-"

$name = "$env:computername ($time)"
$path = "$home\Desktop\$name"
$overflow = "$home\Desktop\overflow-$env:computername"
$log = "$env:TEMP\script-log.log"
$elevatedlog = "$env:TEMP\script-log-elevated.log"
$zip = "$path" + ".zip"
$overflowzip = "$overflow" + ".zip"

# Store the path so elevated.ps1 can retrieve it, elevated.ps1 may run under a different account or during a time change

echo "$path" > "$env:SystemRoot\Temp\path.txt"

# Check for pre-existing files and folders, and remove them if they exist

If ( Test-Path "$path" ) { Remove-Item -Recurse -Force "$path" }

If ( Test-Path "$zip" ) { Remove-Item -Force "$zip" }

If ( Test-Path "$overflow" ) { Remove-Item -Force "$overflow" }

If ( Test-Path "$overflowzip" ) { Remove-Item -Force "$overflowzip" }

If ( Test-Path $log ) { Remove-Item -Force $log }

If ( Test-path $elevatedlog ) { Remove-Item -Force $elevatedlog }

# Create directories

New-Item -ItemType Directory "$path" -Force -ErrorAction Stop > $null 2>> $log

New-Item -ItemType Directory "$path\Events" -Force -ErrorAction Stop > $null 2>> $log

New-Item -ItemType Directory "$path\Crash Dumps" -Force -ErrorAction Stop > $null 2>> $log

New-Item -ItemType Directory "$path\Error Reports" -Force -ErrorAction Stop > $null 2>> $log

# Generate System Information Report

Write-Host "Generating System Information Report, this may take a while..."

Try { $msinfo32 = Start-Process msinfo32.exe -ArgumentList """/nfo"" ""$path\msinfo32.nfo""" -PassThru }

Catch {

	Write-Warning "Failed To Launch msinfo32.exe!"
	echo "Failed to launch msinfo32.exe!" >> $log
	echo $error[0] >> $log
}

# Start elevated.ps1

If ( Test-Path "$scriptdir\elevated.ps1" ) {

	Write-Host "Launching Elevated Script..."

	Try { $elevated_script = Start-Process Powershell.exe -ArgumentList """-ExecutionPolicy"" ""Bypass"" ""-NonInteractive"" ""-NoProfile"" ""-File"" ""$scriptdir\elevated.ps1""" -Verb RunAs -PassThru }

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
	
	If ( Test-Path "$env:SystemRoot\Temp\path.txt" ) { Remove-Item -Force "$env:SystemRoot\Temp\path.txt" }
}

# Start DirectX Diagnostics Report

Write-Host "Running DirectX Diagnostics..."

Try { $dxdiag = Start-Process dxdiag.exe -ArgumentList "/dontskip","/whql:off","/t","$path\dxdiag.txt" -NoNewWindow -PassThru }

Catch {

	Write-Warning "Failed To Run DirectX Diagnostics!"
	echo "Failed to run dxdiag.exe" >> $log
	echo $error[0] >> $log
}

# Export Event Logs (2592000000 ms = 30 days)

Write-Host "Exporting Application Event Log..."

wevtutil.exe query-events Application /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $path\Events\application-events.txt 2>> $log

Write-Host "Exporting System Event Log..."

wevtutil.exe query-events System /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $path\Events\system-events.txt 2>> $log

Write-Host "Exporting WHEA Event Log..."

wevtutil.exe query-events Microsoft-Windows-Kernel-WHEA/Errors /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $path\Events\whea-events.txt 2>> $log

If ( $vernum -ge "6.3" ) {

	Write-Host "Exporting Kernel PnP Log..."

	wevtutil.exe query-events Microsoft-Windows-Kernel-PnP/Configuration /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $path\Events\pnp-events.txt 2>> $log
}

# Driver information

Write-Host "Gathering Driver Information..."

driverquery.exe /v /fo table 2>> $log | Select-Object -Skip 1 > "$path\driver-list.txt"

Get-WmiObject Win32_PnPSignedDriver 2>> $log | Select-Object DeviceName, FriendlyName, InfName, DriverVersion, IsSigned, DriverDate | Where-Object {$_.DeviceName -ne $null -or $_.FriendlyName -ne $null -or $_.InfName -ne $null } | Sort-Object DeviceName | Format-Table -AutoSize > "$path\driver-versions.txt"

# Get Default Power Plan

Write-Host "Checking Power Settings..."

powercfg.exe /list > "$path\power-plan.txt" 2>> $log

# RAM info

Write-Host "Getting Hardware Information..."

Get-WmiObject Win32_PhysicalMemory 2>> $log | Select-Object BankLabel, DeviceLocator, Manufacturer, Capacity, ConfiguredClockspeed, ConfiguredVoltage, SerialNumber, PartNumber | Sort-Object BankLabel, DeviceLocator | Format-List > "$path\ram.txt"

# Processor information

Get-WmiObject Win32_Processor 2>> $log | Select-Object Name, Description, Manufacturer, DeviceID, SocketDesignation, CurrentClockSpeed, CPUStatus, LastErrorCode, ErrorDescription, PartNumber, Revision, SerialNumber, ProcessorId, Status, StatusInfo, Stepping, CurrentVoltage, VoltageCaps | Format-List > "$path\cpu.txt"

# Disk and partition information

$DiskInfoCode=@'

Public Class DiskInfo
	Private Declare Function QueryDosDevice Lib "kernel32" Alias "QueryDosDeviceA" (ByVal lpDeviceName As String, ByVal lpTargetPath As String, ByVal ucchMax As Long) As Long
		
	Shared Function GetDeviceName(sDisk As String) As String
		
		Dim sDevice As String = New String(" ",50)
			
		If QueryDosDevice(sDisk, sDevice, sDevice.Length) Then
			Return sDevice
				
		Else
			Throw New System.Exception("sDisk value not found - not a disk.")
				
		End If	
	End Function
End Class

'@

Add-Type $DiskInfoCode -Language VisualBasic

$SizeGB = @{Name="Size (GB)";Expression={[math]::Round($_.Capacity / 1GB, 2)}}

$FreeGB = @{Name="Free (GB)";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}

$DevicePath = @{Name="Device Path";Expression={[diskinfo]::GetDeviceName($_.DriveLetter)}}

Get-WmiObject Win32_Volume 2>> $log | Where-Object { $_.DriveLetter -ne $null } | Select-Object DriveLetter, $SizeGB, $FreeGB, $DevicePath | Sort-Object DriveLetter | Format-Table -AutoSize > "$path\partitions.txt"

If ( $vernum -ge "10.0" ) {

	Get-Partition 2>> $log | Format-List >> "$path\partitions.txt"

	$disknumbers = (Get-Disk).Number

	ForEach ( $number in $disknumbers ) { Get-Disk -Number $number | Select-Object FriendlyName, Model, Manufacturer, Number, IsBoot, AllocatedSize, HealthStatus, OperationalStatus, BusType, FirmwareVersion, PartitionStyle, Path | Format-List }

}

# System Board information

Get-WmiObject Win32_BaseBoard 2>> $log | Select-Object Product, Model, Version, Manufacturer, Description | Format-List > "$path\motherboard.txt"

Get-WmiObject Win32_Bios 2>> $log | Select-Object SMBIOSBIOSVersion, Manufacturer, Name, Version, BIOSVersion, ReleaseDate | Format-List >> "$path\motherboard.txt"

# GPU information

Get-WmiObject Win32_VideoController 2>> $log | Select-Object Name, DeviceID, PNPDeviceID, VideoProcessor, CurrentRefreshRate, VideoModeDescription, AdapterRAM, DriverVersion, InfFilename, InstalledDisplayDrivers, InstallDate, DriverDate, Status, StatusInfo, LastErrorCode, ErrorDescription | Format-List > "$path\gpu.txt"

# Windows license information

Write-Host "Finding Windows License Information..."

cscript.exe $env:SystemRoot\System32\slmgr.vbs /dlv 2>> $log | Select-Object -Skip 4 > "$path\windows-license-info.txt"

# Installed software, first check native and then 32-bit (if it exists).

Write-Host "Listing Installed Software..."

Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>> $log | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object {$_.DisplayName -ne $null -or $_.DisplayVersion -ne $null -or $_.Publisher -ne $null -or $_.InstallDate -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize > "$path\installed-software.txt"

If ( Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" ) {

	echo "32-bit Software" >> "$path\installed-software.txt"

	Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>> $log | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object {$_.DisplayName -ne $null -or $_.DisplayVersion -ne $null -or $_.Publisher -ne $null -or $_.InstallDate -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize | Format-Table -AutoSize >> "$path\installed-software.txt"
}

echo "User-specific Software" >> "$path\installed-software.txt"

Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>> $log | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object {$_.DisplayName -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize >> "$path\installed-software.txt"

echo "Installed Windows Components" >> "$path\installed-software.txt"

Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\*" 2>> $log | Select-Object "(Default)", ComponentID, Version, Enabled | Where-Object {$_."(Default)" -ne $null -or $_.ComponentID -ne $null} | Sort-Object @{Expression = "Enabled"; Descending = $True}, "(default)" | Format-Table -AutoSize >> "$path\installed-software.txt"

# Installed Windows Updates

Write-Host "Listing Installed Windows Updates..."

Get-WmiObject Win32_QuickFixEngineering 2>> $log | Select-Object HotFixID,Description,InstalledOn | Sort-Object InstalledOn,HotFixID | Format-Table -AutoSize > "$path\windows-updates.txt"

# Basic networking information

Write-Host "Finding Network Information..."

ipconfig.exe /allcompartments /all 2>> $log | Select-Object -Skip 1 > "$path\network-info.txt"

route.exe print >> "$path\network-info.txt" 2>> $log

# Copy relevant entries from the hosts file

Write-Host "Examining Hosts File..."

If ( Test-Path "$env:SystemRoot\System32\drivers\etc\hosts" ) {

	Get-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" 2>> $log | Select-String '(127.0.0.1)|(0.0.0.0)' > "$path\hosts.txt"
}

Else { echo "Hosts file not found." >> $log }

# Wait if dxdiag.exe has not finished, kill process if timeout is reached

If ( $dxdiag -ne $null ) {

	waitloop $dxdiag dxdiag.exe 30
}

# Wait if msinfo32.exe has not finished, kill process if timeout is reached

If ( $msinfo32 -ne $null ) {

	waitloop $msinfo32 msinfo32.exe 120 "$path\msinfo32.nfo"
}

# Wait if the elevated script has not finished, kill process if timeout is reached

If ( $elevated_script -ne $null ) {

	waitloop $elevated_script "Elevated Script" 120
}

# Move logs into $path if they exist and are not empty

If ( $(Test-Path $elevatedlog) -eq "True" -and (Get-Item $elevatedlog).Length -gt 0 ) {

	Move-Item $elevatedlog -Destination "$path"
}

If ( $(Test-Path "$log") -eq "True" -and (Get-Item "$log").Length -gt 0 ) {

	Move-Item "$log" -Destination "$path"
}

# Get hash of files to later check for corruption

$FileName = @{Name="FileName";Expression={Split-Path $_.Path -Leaf}}

If ( $vernum -ge "6.3" ) {

	Get-ChildItem -Path "$path" -Recurse -Exclude "*.wer" | Get-FileHash -Algorithm SHA256 | Select-Object $FileName, Hash, Algorithm | Sort-Object FileName | Format-Table -AutoSize > "$env:LOCALAPPDATA\hashes.txt"
}

If ( Test-Path "$env:LOCALAPPDATA\hashes.txt" ) {

	Move-Item -Path "$env:LOCALAPPDATA\hashes.txt" -Destination "$path"
}

# Compress output folder	

$compressionresult = compression "$path" "$zip"

# Check that $zip does not exceed 8MB, try to reduce filesize by removing the largest file then compressing, give up after 4 iterations.

$count = 0

While ( $((Get-Item $zip).Length -ge 8MB) -eq $True -and $count -lt 4 ) {

	If ( !(Test-Path $overflow) ) {
	
		New-Item -ItemType Directory "$overflow" -Force 2>> "$path\script-log.log" > $null
	}

	Remove-Item -Force $zip

	Write-Warning "Size of $zip met or exceeded 8MB limit!"
	echo "Size of $zip met or exceeded 8MB limit!" >> "$path\script-log.log"
	
	$trimmedfile = (Get-ChildItem -Recurse -File -Exclude script-log.log, script-log-elevated.log -Path $path | Sort-Object Length -Descending | Select-Object -First 1).FullName
	
	echo "Moving the following file to $overflow  to lower the .zip size:" >> "$path\script-log.log"
	echo $trimmedfile >> "$path\script-log.log"

	Move-Item -Force -Path $trimmedfile -Destination $overflow
	
	Write-Host "Retrying compression..."
	echo "Retrying compression." >> "$path\script-log.log"
	
	$compressionresult = compression "$path" "$zip"
	
	$count++
}

If ( $count -ge 4 ) {

	Write-Warning "Unable to shrink .zip below 8MB"
	echo "Unable to shrink .zip below 8MB" >> "$path\script-log.log"
}

# Compress overflow directory if it exists

If ( Test-Path $overflow ) {

	$overflowcompression = compression "$overflow" "$overflowzip"
}

# Check that the .zip file was created and the compression operation completed successfully before removing the uncompressed directory

Write-Host "`n"

If ( $(Test-Path "$zip") -eq "True" -and "$compressionresult" -eq "True" ) {

	Remove-Item -Recurse -Force "$path"
	Write-Host "Output location: $zip" 
}

Else {

	Write-Host "Compression Failed!"
	Write-Host "`n"
	Write-Host "Output location: $path"
}

If ( $(Test-Path $overflowzip) -eq "True" -and $overflowcompression -eq "True" ) {

	Remove-Item -Recurse -Force "$overflow"
	Write-Host "Second Output Location: $overflowzip"
}

ElseIf ( $(Test-Path $overflowzip) -eq "True" -and $overflowcompression -ne "True" ) {

	Write-Host "Second Output Location: $overflow"
}

Write-Host "`n"
Read-Host -Prompt "Press Enter To Exit"
