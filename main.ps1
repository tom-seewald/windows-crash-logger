##############################
# Script Written By Spectrum #
##############################

# Loops until a process exits for a specified number of seconds, kills the process if the timeout is reached
Function WaitFor-Process ( $Process, $Name, $TimeoutSeconds, $OutputFilePath ) {

	$StartTime = Get-Date

	If ( !$Process.HasExited ) {

		Write-Host "Waiting For $name To Finish..."
	}

	While ( !$Process.HasExited -and $StartTime.AddSeconds($TimeoutSeconds) -gt (Get-Date) ) {

		Start-Sleep -Milliseconds 500
	}

	If ( !$Process.HasExited -and $StartTime.AddSeconds($TimeoutSeconds) -le (Get-Date) ) {

		Stop-Process -Force -Id $Process.Id 2>> $Log

		If ( $OutputFilePath -ne $null ) {

			If ( Test-Path -Path $OutputFilePath ) {

				Remove-Item "$OutputFilePath" 2>> $Log
			}
		}

		Write-Output "Killed $name due to timeout." >> $Log
		Write-Warning "Killed $name due to timeout."
	}
}

# Compresses specified folder, attempts to use built-in compression (PowerShell 3+) and falls back to using compression.vbs
Function Compress-Folder ( $InputPath, $OutputPath ) {

	If ( $PSVersionTable.PSVersion.Major -ge "3" -and $PSVersionTable.CLRVersion.Major -ge "4" ) {

		Try {

			Write-Host "Compressing Folder..."
			Add-Type -Assembly "system.io.compression.filesystem"
			[io.compression.zipfile]::CreateFromDirectory("$inputpath","$OutputPath")
			$Compression = $?
			Return $?
		}

		Catch {

			Write-Warning "Failed to compress the folder with io.compression!"
			Write-Output "Failed to compress the folder with io.compression!" >> "$Path\script-log.log"
			Write-Output $error[0] >> "$Path\script-log.log"

			If ( Test-Path -Path $OutputPath ) {
			
				Remove-Item $OutputPath
			}
			
			$Compression = "False"
			Return "False"
		}
	}

	If ( $(Test-Path -Path "$ScriptDir\compression.vbs") -eq $True -and $Compression -ne "True" ) {

		Try {

			Write-Host "Compressing Folder..."
			&"$env:SystemRoot\System32\cscript.exe" "$ScriptDir\compression.vbs" "$inputpath" "$OutputPath" > $null
			Return $?
		}

		Catch {

			Write-Warning "Failed to compress the folder with vbscript!"
			Write-Output "Failed to compress the folder with vbscript!" >> "$Path\script-log.log"
			Write-Output $error[0] >> "$Path\script-log.log"

			If ( Test-Path -Path $OutputPath ) {
			
				Remove-Item $OutputPath
			}
			
			Return "False"
		}
	}

	Else {

		Write-Output "Could not find $ScriptDir\compression.vbs" >> "$Path\script-log.log"
		Write-Warning "Could not find compression.vbs"
		Return "False"
	}
}

# Detect Windows version, convert the value from a string to a decimal
$MajorVer=[System.Environment]::OSVersion.Version.Major
$MinorVer=[System.Environment]::OSVersion.Version.Minor
$VerNum = "$MajorVer" + "." + "$MinorVer" -as [decimal]

# Check that the OS is supported
If ( $VerNum -lt 6.1 ) {

	Write-Output "UNSUPPORTED VERSION OF WINDOWS DETECTED - KERNEL VERSION LESS THAN 6.1" >> $Log
	Write-Host "`n"
	Write-Warning "Windows Version Is Unsupported!"
	Write-Warning "This Script Has Not Been Tested On Anything Before Windows 7!"
	Exit
}

If ( $VerNum -eq 6.2 ) {

	Write-Output "UNSUPPORTED VERSION OF WINDOWS DETECTED - WINDOWS 8" >> $Log
	Write-Host "`n"
	Write-Warning "Windows Version Is Unsupported!"
	Write-Warning "This Script Has Not Been Tested On Windows 8, Please Upgrade!"
}

# Abort if Controlled Folder Access is enabled, as it prevents log files from being placed on the desktop
If ( $VerNum -ge 10 ) {

	If ( (Get-MpPreference).EnableControlledFolderAccess -eq 1 ) {

		Write-Warning "Controlled Folder Access is enabled in Windows Defender, this prevents the script from placing log files on your Desktop."
		Write-Host "`n"
		Write-Warning "If you would like allow this script to run, please temporarily disable Controlled Folder Access in Windows Defender Security Center and then re-launch this script."
		Write-Host "`n"
		Read-Host -Prompt "Press Enter to close this window"
		Exit
	}
}

# If the OS is 64-bit and this script was launched with 32-bit PowerShell, relaunch with 64-bit PowerShell and Exit the current instance
If ( [Environment]::Is64BitOperatingSystem -eq $True -and [Environment]::Is64BitProcess -eq $False ) {

	&"$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe" -NoProfile $myInvocation.InvocationName
	Write-Output "The OS is 64-bit but powershell.exe is 32-bit, relaunching script with 64-bit PowerShell." >> $Log
	Exit
}

# This is set because $PSScriptRoot is not available on stock Windows 7 SP1
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent

# Set window size to 1000 by 1000 to avoid truncation when sending output to files
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (1000,1000)

# Version String
$ScriptVer = "Beta07 - 12/11/17"

# Startup Banner
Clear-Host

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
Write-Host $ScriptVer
"`n" * 3

Read-Host -Prompt "Press Enter To Continue"
Clear-Host

# Set variables for output folders
$Time = Get-Date -Format "M-d-yyyy HH mm tt"
$Name = "$env:computername ($Time)"
$Path = "$home\Desktop\$Name"
$Overflow = "$home\Desktop\Overflow-$env:computername"
$Log = "$env:TEMP\script-log.log"
$Zip = "$Path" + ".zip"
$Overflowzip = "$Overflow" + ".zip"

# Check for pre-existing files and folders, and remove them if they exist
If ( Test-Path -Path $Path ) { Remove-Item -Recurse -Force $Path }
If ( Test-Path -Path $Zip ) { Remove-Item -Force $Zip }
If ( Test-Path -Path $Overflow ) { Remove-Item -Force $Overflow }
If ( Test-Path -Path $Overflowzip ) { Remove-Item -Force $Overflowzip }
If ( Test-Path -Path $Log ) { Remove-Item -Force $Log }

# Create directories
New-Item -ItemType Directory $Path -Force -ErrorAction Stop > $null 2>> $Log
New-Item -ItemType Directory "$Path\Events" -Force -ErrorAction Stop > $null 2>> $Log
New-Item -ItemType Directory "$Path\Crash Dumps" -Force -ErrorAction Stop > $null 2>> $Log
New-Item -ItemType Directory "$Path\Error Reports" -Force -ErrorAction Stop > $null 2>> $Log

# Generate System Information Report
Write-Host "Generating System Information Report, this may take a while..."

Try {

	$MsInfo32 = Start-Process -FilePath "$env:SystemRoot\System32\msinfo32.exe" -ArgumentList """/nfo"" ""$Path\msinfo32.nfo""" -PassThru
}

Catch {

	Write-Warning "Failed To Launch msinfo32.exe!"
	Write-Output "Failed to launch msinfo32.exe!" >> $Log
	Write-Output $error[0] >> $Log
}

# Start elevated.ps1
If ( Test-Path -Path "$ScriptDir\elevated.ps1" ) {

	Write-Host "Launching Elevated Script..."

	Try {
	
		$ElevatedScript = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
										-ArgumentList """-ExecutionPolicy"" ""Bypass"" ""-NonInteractive"" ""-NoProfile"" ""-File"" ""$ScriptDir\elevated.ps1"" ""$Path""" `
										-Verb RunAs -PassThru
	}

	Catch {

		Write-Warning "Failed To Launch Elevated Script!" 
		Write-Output "Failed To Launch Elevated Script!" >> $Log
		Write-Output $error[0] >> $Log
	}
}

Else {

	Write-Warning "$ScriptDir\elevated.ps1 not found!"
	Write-Output "$ScriptDir\elevated.ps1 not found!" >> $Log
}

# Start DirectX Diagnostics Report
Write-Host "Running DirectX Diagnostics..."

Try {

	$DxDiag = Start-Process -FilePath "$env:SystemRoot\System32\dxdiag.exe" -ArgumentList "/dontskip","/whql:off","/t","$Path\dxdiag.txt" -NoNewWindow -PassThru
}

Catch {

	Write-Warning "Failed To Run DirectX Diagnostics!"
	Write-Output "Failed to run dxdiag.exe" >> $Log
	Write-Output $error[0] >> $Log
}

# Export Event Logs (2592000000 ms = 30 days)
Write-Host "Exporting Application Event Log..."
&"$env:SystemRoot\System32\wevtutil.exe" query-events Application /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $Path\Events\application-events.txt 2>> $Log

Write-Host "Exporting System Event Log..."
&"$env:SystemRoot\System32\wevtutil.exe" query-events System /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $Path\Events\system-events.txt 2>> $Log

Write-Host "Exporting WHEA Event Log..."
&"$env:SystemRoot\System32\wevtutil.exe" query-events Microsoft-Windows-Kernel-WHEA/Errors /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $Path\Events\whea-events.txt 2>> $Log

If ( $VerNum -ge "6.3" ) {

	Write-Host "Exporting Kernel PnP Log..."
	&"$env:SystemRoot\System32\wevtutil.exe" query-events Microsoft-Windows-Kernel-PnP/Configuration /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $Path\Events\pnp-events.txt 2>> $Log
}

# Driver information
Write-Host "Gathering Driver Information..."
&"$env:SystemRoot\System32\driverquery.exe" /v /fo table 2>> $Log | Select-Object -Skip 1 > "$Path\driver-table.txt"

$DriverInfoAttributes = "DeviceName", "FriendlyName", "InfName", "DriverVersion", "IsSigned", "DriverDate"
Get-WmiObject Win32_PnPSignedDriver 2>> $Log | Select-Object -Property $DriverInfoAttributes | Where-Object {$_.DeviceName -ne $null -or $_.FriendlyName -ne $null -or $_.InfName -ne $null } | Sort-Object DeviceName | Format-Table -AutoSize > "$Path\driver-versions.txt"

# Get Default Power Plan
Write-Host "Checking Power Settings..."
&"$env:SystemRoot\System32\powercfg.exe" /list > "$Path\power-plan.txt" 2>> $Log

# RAM info
Write-Host "Getting Hardware Information..."

$MemoryAttributes = "BankLabel", "DeviceLocator", "Manufacturer", "Capacity", "ConfiguredClockspeed", "ConfiguredVoltage", "SerialNumber", "PartNumber"
Get-WmiObject Win32_PhysicalMemory 2>> $Log | Select-Object $MemoryAttributes | Sort-Object BankLabel, DeviceLocator | Format-List > "$Path\ram.txt"

# Processor information
$ProcessorAttributes = "Name", "Description", "Manufacturer", "DeviceID", "SocketDesignation", "CurrentClockSpeed", "CPUStatus", `
					   "LastErrorCode", "ErrorDescription", "PartNumber", "Revision", "SerialNumber", "ProcessorId", "Status", `
					   "StatusInfo", "Stepping", "CurrentVoltage", "VoltageCaps"
Get-WmiObject Win32_Processor 2>> $Log | Select-Object $ProcessorAttributes | Format-List > "$Path\cpu.txt"

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

Get-WmiObject Win32_Volume 2>> $Log | Where-Object { $_.DriveLetter -ne $null } | Select-Object DriveLetter, $SizeGB, $FreeGB, $DevicePath | Sort-Object DriveLetter | Format-Table -AutoSize > "$Path\partitions.txt"

If ( $VerNum -ge "10.0" ) {

	Get-Partition 2>> $Log | Format-List >> "$Path\partitions.txt"

	$DiskNumbers = (Get-Disk).Number
	$DiskAttributes = "FriendlyName", "Model", "SerialNumber", "Manufacturer", "Number", "IsBoot", "AllocatedSize", `
					  "HealthStatus", "OperationalStatus", "BusType", "FirmwareVersion", "PartitionStyle", "Path"
	ForEach ( $DiskNumber in $DiskNumbers ) {

		Get-Disk -Number $DiskNumber 2>> $Log | Select-Object $DiskAttributes | Format-List >> "$Path\disks.txt"
	}
}

# System Board information
$BaseBoarAttributes = "Product", "Model", "Version", "Manufacturer", "Description"
Get-WmiObject Win32_BaseBoard 2>> $Log | Select-Object $BaseBoarAttributes | Format-List > "$Path\motherboard.txt"

$BiosAttributes = "SMBIOSBIOSVersion", "Manufacturer", "Name", "Version", "BIOSVersion", "ReleaseDate"
Get-WmiObject Win32_Bios 2>> $Log | Select-Object $BiosAttributes | Format-List >> "$Path\motherboard.txt"

# GPU information
$GpuAttributes = "Name", "DeviceID", "PNPDeviceID", "VideoProcessor", "CurrentRefreshRate", "VideoModeDescription", "AdapterRAM", `
				 "DriverVersion", "InfFilename", "InstalledDisplayDrivers", "InstallDate", "DriverDate", "Status", "StatusInfo", `
				 "LastErrorCode", "ErrorDescription"
Get-WmiObject Win32_VideoController 2>> $Log | Select-Object $GpuAttributes | Format-List > "$Path\gpu.txt"

# Windows license information
Write-Host "Finding Windows License Information..."
&"$env:SystemRoot\System32\cscript.exe" $env:SystemRoot\System32\slmgr.vbs /dlv 2>> $Log | Select-Object -Skip 4 > "$Path\windows-license-info.txt"

# Installed software, first check native and then 32-bit (if it exists).
Write-Host "Listing Installed Software..."

$SoftwareAttributes = "DisplayName", "DisplayVersion", "Publisher", "InstallDate"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>> $Log | Select-Object $SoftwareAttributes | `
Where-Object {$_.DisplayName -ne $null -or $_.DisplayVersion -ne $null -or $_.Publisher -ne $null -or $_.InstallDate -ne $null} | `
Sort-Object DisplayName | Format-Table -AutoSize > "$Path\installed-software.txt"

If ( Test-Path -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" ) {

	Write-Output "32-bit Software" >> "$Path\installed-software.txt"

	Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>> $Log | Select-Object $SoftwareAttributes | Where-Object {$_.DisplayName -ne $null -or $_.DisplayVersion -ne $null -or $_.Publisher -ne $null -or $_.InstallDate -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize | Format-Table -AutoSize >> "$Path\installed-software.txt"
}

Write-Output "User-specific Software" >> "$Path\installed-software.txt"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>> $Log | Select-Object $SoftwareAttributes | Where-Object {$_.DisplayName -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize >> "$Path\installed-software.txt"

Write-Output "Installed Windows Components" >> "$Path\installed-software.txt"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\*" 2>> $Log | Select-Object "(Default)", ComponentID, Version, Enabled | Where-Object {$_."(Default)" -ne $null -or $_.ComponentID -ne $null} | Sort-Object "(default)" | Format-Table -AutoSize >> "$Path\installed-software.txt"

# Installed Windows Updates
Write-Host "Listing Installed Windows Updates..."
Get-WmiObject Win32_QuickFixEngineering 2>> $Log | Select-Object HotFixID,Description,InstalledOn | Sort-Object InstalledOn,HotFixID | Format-Table -AutoSize > "$Path\windows-updates.txt"

# Basic networking information
Write-Host "Finding Network Information..."
&"$env:SystemRoot\System32\ipconfig.exe" /allcompartments /all 2>> $Log | Select-Object -Skip 1 > "$Path\network-info.txt"
&"$env:SystemRoot\System32\route.exe" print >> "$Path\network-info.txt" 2>> $Log

# Copy relevant entries from the hosts file
Write-Host "Examining Hosts File..."

If ( Test-Path -Path "$env:SystemRoot\System32\drivers\etc\hosts" ) {

	Get-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" 2>> $Log | Select-String '(127.0.0.1)|(0.0.0.0)' > "$Path\hosts.txt"
}

Else {

	Write-Output "Hosts file not found." >> $Log
}

# Wait if dxdiag.exe has not finished, kill process if timeout is reached
If ( $DxDiag -ne $null ) {

	WaitFor-Process $DxDiag dxdiag.exe 30 "$Path\dxdiag.txt"
}

# Wait if msinfo32.exe has not finished, kill process if timeout is reached
If ( $MsInfo32 -ne $null ) {

	WaitFor-Process $MsInfo32 msinfo32.exe 120 "$Path\msinfo32.nfo"
}

# Wait if elevated.ps1 has not finished, kill the script if timeout is reached
If ( $ElevatedScript -ne $null ) {

	WaitFor-Process $ElevatedScript "Elevated Script" 120
}

# Move log into $Path if it is non-empty
If ( $(Test-Path -Path $Log) -eq "True" -and (Get-Item $Log).Length -gt 0 ) {

	Move-Item -Path $Log -Destination $Path
}

# Get hash of files to later check for corruption
$FileName = @{Name="FileName";Expression={Split-Path $_.Path -Leaf}}

If ( $VerNum -ge "6.3" ) {

	Get-ChildItem -Path "$Path" -Recurse -Exclude "*.wer" | Get-FileHash -Algorithm SHA256 | Select-Object $FileName, Hash, Algorithm | Sort-Object FileName | Format-Table -AutoSize > "$env:LOCALAPPDATA\hashes.txt"
}

If ( Test-Path -Path "$env:LOCALAPPDATA\hashes.txt" ) {

	Move-Item -Path "$env:LOCALAPPDATA\hashes.txt" -Destination $Path
}

# Compress output folder
$CompressionResult = Compress-Folder $Path $Zip

# Check that $Zip does not exceed 8MB, try to reduce filesize by removing the largest file then compressing, give up after 4 iterations.
$Count = 0

While ( $((Get-Item $Zip).Length -ge 8MB) -eq $True -and $Count -lt 4 ) {

	If ( !(Test-Path -Path $Overflow) ) {

		New-Item -ItemType Directory "$Overflow" -Force 2>> "$Path\script-log.log" > $null
	}

	Remove-Item -Force $Zip

	Write-Warning "Size of $Zip met or exceeded 8MB limit!"
	Write-Output "Size of $Zip met or exceeded 8MB limit!" >> "$Path\script-log.log"

	$TrimmedFile = (Get-ChildItem -Recurse -File -Exclude script-log.log, script-log-elevated.log -Path $Path | Sort-Object Length -Descending | Select-Object -First 1).FullName

	Write-Output "Moving the following file to $Overflow  to lower the .zip size:" >> "$Path\script-log.log"
	Write-Output $TrimmedFile >> "$Path\script-log.log"

	Move-Item -Force -Path $TrimmedFile -Destination $Overflow

	Write-Host "Retrying compression..."
	Write-Output "Retrying compression." >> "$Path\script-log.log"

	$CompressionResult = compression $Path $Zip

	$Count++
}

If ( $Count -ge 4 ) {

	Write-Warning "Unable to shrink .zip below 8MB"
	Write-Output "Unable to shrink .zip below 8MB" >> "$Path\script-log.log"
}

# Compress Overflow directory if it exists
If ( Test-Path -Path $Overflow ) {

	$OverflowCompression = compression $Overflow $Overflowzip
}

# Check that the .zip file was created and the compression operation completed successfully before removing the uncompressed directory
Write-Host "`n"

If ( $(Test-Path -Path $Zip) -eq "True" -and $CompressionResult -eq "True" ) {

	Remove-Item -Recurse -Force "$Path"
	Write-Host "Output location: $Zip" 
}

Else {

	Write-Host "Compression Failed!"
	Write-Host "`n"
	Write-Host "Output location: $Path"
}

If ( $(Test-Path -Path $Overflowzip) -eq "True" -and $OverflowCompression -eq "True" ) {

	Remove-Item -Recurse -Force "$Overflow"
	Write-Host "Second Output Location: $Overflowzip"
}

ElseIf ( $(Test-Path -Path $Overflowzip) -eq "True" -and $OverflowCompression -ne "True" ) {

	Write-Host "Second Output Location: $Overflow"
}

Write-Host "`n"
Read-Host -Prompt "Press Enter To Exit"
