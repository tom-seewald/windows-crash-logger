##############################
# Script Written By Spectrum #
##############################

# Version String
$ScriptVer = "Beta08 - 12/28/17"

# Detect Windows version, convert the value from a string to a decimal
$MajorVer=[System.Environment]::OSVersion.Version.Major
$MinorVer=[System.Environment]::OSVersion.Version.Minor
$VerNum = "$MajorVer" + "." + "$MinorVer" -as [decimal]

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
	Exit
}

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

Read-Host -Prompt "Press Enter to continue"
Clear-Host

# Set variables for output folders
$Time = (Get-Date).ToString("yyyy-MM-dd HH mm")
$Name = "$env:computername ($Time)"
$Path = "$home\Desktop\$Name"
$Log = "$env:TEMP\script-log.csv"
$Zip = "$Path" + ".zip"
$ErrorFile = "$env:TEMP\error-temp.txt"

# Check for pre-existing files and folders, and remove them if they exist
If ( Test-Path -Path $Path ) { Remove-Item -Recurse -Force $Path }
If ( Test-Path -Path $Zip ) { Remove-Item -Force $Zip }
If ( Test-Path -Path $Log ) { Remove-Item -Force $Log }
If ( Test-Path -Path $ErrorFile ) { Remove-Item -Force $ErrorFile }

# Create directories and files
New-Item -ItemType Directory $Path -Force -ErrorAction Stop > $null
New-Item -ItemType Directory "$Path\Events" -Force -ErrorAction Stop > $null
New-Item -ItemType Directory "$Path\Crash Dumps" -Force -ErrorAction Stop > $null
New-Item -ItemType Directory "$Path\Error Reports" -Force -ErrorAction Stop > $null
New-Item -ItemType File -Path $ErrorFile -Force -ErrorAction Stop > $null

# Parent directory of this script, used instead of $PSScriptRoot as that is not available on stock Windows 7 SP1
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent

# Import custom module containing support functions
Try {

    Import-Module "$ScriptDir\logger-module.psm1"
}

Catch {

	Write-Warning "Could not import $ScriptDir\test-module.psm1, exiting script."
	$TimeStamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $ImportError =   $TimeStamp + "," + "Failed to import $ScriptDir\test-module.psm1, exiting script."
    Write-Ouptut $ImportError >> $Log
    Exit
}

# Set window size to 1000 by 1000 to avoid truncation when sending output to files
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(1000,1000)

# Check that the OS is supported
If ( $VerNum -lt 6.1 ) {

	Write-Log "Unsupported version of Windows, kernel version less than 6.1" $Log
	Write-Warning "Unsupported version of Windows detected!"
	Write-Warning "This script has not been tested on any release prior to Windows 7!"
}

If ( $VerNum -eq 6.2 ) {

	Write-Log "Unsupported version of Windows detected, Windows 8" $Log
	Write-Warning "Unsupported version of Windows detected!"
	Write-Warning "This script has not been tested on Windows 8, please upgrade!"
}

# Generate System Information Report
Write-Host "Generating system information report, this may take a while..."

Try {

	$MsInfo32 = Start-Process -FilePath "$env:SystemRoot\System32\msinfo32.exe" -ArgumentList """/nfo"" ""$Path\msinfo32.nfo""" -PassThru
}

Catch {

    Write-Warning "Failed to launch msinfo32.exe!"
    Write-Log "Failed to launch msinfo32.exe!" $Log
    Write-Log $error[0] $Log
}

# Download autorunsc
Get-RemoteFile "http://live.sysinternals.com/autorunsc.exe" "autorunsc" "$ScriptDir\autorunsc.exe" $Log

# Start elevated.ps1
If ( Test-Path -Path "$ScriptDir\elevated.ps1" ) {

	Write-Host "Launching elevated script..."

	Try {
	
		$ElevatedScript = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
										-ArgumentList """-ExecutionPolicy"" ""Bypass"" ""-NonInteractive"" ""-NoProfile"" ""-File"" ""$ScriptDir\elevated.ps1"" ""$Path""" `
										-Verb RunAs -PassThru
	}

	Catch {

		Write-Warning "Failed to launch elevated script!" 
        Write-Log "Failed to launch elevated script" $Log
        Write-Log $error[0] $Log
	}
}

Else {

	Write-Warning "$ScriptDir\elevated.ps1 not found!"
	Write-Log "$ScriptDir\elevated.ps1 not found!" $Log
}

# Start DirectX Diagnostics Report
Write-Host "Running DirectX diagnostics..."

Try {

	$DxDiag = Start-Process -FilePath "$env:SystemRoot\System32\dxdiag.exe" -ArgumentList "/dontskip","/whql:off","/t","$Path\dxdiag.txt" -NoNewWindow -PassThru
}

Catch {

	Write-Warning "Failed to run DirectX diagnostics!"
    Write-Log "Failed to run dxdiag.exe" $Log
    Write-Log $error[0] $Log
}

# Export Event Logs (2592000000 ms = 30 days)
Write-Host "Exporting Application event Log..."
&"$env:SystemRoot\System32\wevtutil.exe" query-events Application /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $Path\Events\application-events.txt
Write-CommandError $ErrorFile $Log

Write-Host "Exporting System event log..."

&"$env:SystemRoot\System32\wevtutil.exe" query-events System /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $Path\Events\system-events.txt 2> $ErrorFile
Write-CommandError $ErrorFile $Log


# Kernel PnP Event log only exists on Windows 8.1 and newer
If ( $VerNum -ge "6.3" ) {

	Write-Host "Exporting Kernel PnP log..."
	&"$env:SystemRoot\System32\wevtutil.exe" query-events Microsoft-Windows-Kernel-PnP/Configuration /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text > $Path\Events\pnp-events.txt 2> $ErrorFile
	Write-CommandError $ErrorFile $Log

}

# Driver information
Write-Host "Gathering driver information..."
&"$env:SystemRoot\System32\driverquery.exe" /v /fo table 2> $ErrorFile | Select-Object -Skip 1 > "$Path\driver-table.txt"
Write-CommandError $ErrorFile $Log

$DriverInfoAttributes = "DeviceName", "FriendlyName", "InfName", "DriverVersion", "IsSigned", "DriverDate"
Get-WmiObject Win32_PnPSignedDriver -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object -Property $DriverInfoAttributes | Where-Object {$_.DeviceName -ne $null -or $_.FriendlyName -ne $null -or $_.InfName -ne $null } | Sort-Object DeviceName | Format-Table -AutoSize > "$Path\driver-versions.txt"
Write-Log $ScriptError $Log

# Get Default Power Plan
Write-Host "Checking power settings..."
&"$env:SystemRoot\System32\powercfg.exe" /list > "$Path\power-plan.txt" 2> $ErrorFile
Write-CommandError $ErrorFile $Log

# RAM info
Write-Host "Getting hardware information..."
$MemoryAttributes = "BankLabel", "DeviceLocator", "Manufacturer", "Capacity", "ConfiguredClockspeed", "ConfiguredVoltage", "SerialNumber", "PartNumber"
Get-WmiObject Win32_PhysicalMemory -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $MemoryAttributes | Sort-Object BankLabel, DeviceLocator | Format-List > "$Path\ram.txt"
Write-Log $ScriptError $Log

# Processor information
$ProcessorAttributes = "Name", "Description", "Manufacturer", "DeviceID", "SocketDesignation", "CurrentClockSpeed", "CPUStatus", `
					   "LastErrorCode", "ErrorDescription", "PartNumber", "Revision", "SerialNumber", "ProcessorId", "Status", `
					   "StatusInfo", "Stepping", "CurrentVoltage", "VoltageCaps"
Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $ProcessorAttributes | Format-List > "$Path\cpu.txt"
Write-Log $ScriptError $Log

# Disk and partition information
Get-DiskInformation

$SizeGB = @{Name="Size (GB)";Expression={[math]::Round($_.Capacity / 1GB, 2)}}
$FreeGB = @{Name="Free (GB)";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}
$DevicePath = @{Name="Device Path";Expression={[diskinfo]::GetDeviceName($_.DriveLetter)}}

Get-WmiObject Win32_Volume -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Where-Object { $_.DriveLetter -ne $null } | Select-Object DriveLetter, $SizeGB, $FreeGB, $DevicePath | Sort-Object DriveLetter | Format-Table -AutoSize > "$Path\partitions.txt"
Write-Log $ScriptError $Log

If ( $VerNum -ge "10.0" ) {

	Get-Partition -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Format-List >> "$Path\partitions.txt"
	Write-Log $ScriptError $Log

	$DiskNumbers = (Get-Disk).Number
	$DiskAttributes = "FriendlyName", "Model", "SerialNumber", "Manufacturer", "Number", "IsBoot", "AllocatedSize", `
					  "HealthStatus", "OperationalStatus", "BusType", "FirmwareVersion", "PartitionStyle", "Path"
	ForEach ( $DiskNumber in $DiskNumbers ) {

		Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $DiskAttributes | Format-List >> "$Path\disks.txt"
		Write-Log $ScriptError $Log
	}
}

# System Board information
$BaseBoarAttributes = "Product", "Model", "Version", "Manufacturer", "Description"
Get-WmiObject Win32_BaseBoard -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $BaseBoarAttributes | Format-List > "$Path\motherboard.txt"
Write-Log $ScriptError $Log

$BiosAttributes = "SMBIOSBIOSVersion", "Manufacturer", "Name", "Version", "BIOSVersion", "ReleaseDate"
Get-WmiObject Win32_Bios -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $BiosAttributes | Format-List >> "$Path\motherboard.txt"
Write-Log $ScriptError $Log

# GPU information
$GpuAttributes = "Name", "DeviceID", "PNPDeviceID", "VideoProcessor", "CurrentRefreshRate", "VideoModeDescription", "AdapterRAM", `
				 "DriverVersion", "InfFilename", "InstalledDisplayDrivers", "InstallDate", "DriverDate", "Status", "StatusInfo", `
				 "LastErrorCode", "ErrorDescription"
Get-WmiObject Win32_VideoController -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $GpuAttributes | Format-List > "$Path\gpu.txt"
Write-Log $ScriptError $Log

# Windows license information
Write-Host "Finding Windows license information..."
&"$env:SystemRoot\System32\cscript.exe" $env:SystemRoot\System32\slmgr.vbs /dlv -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object -Skip 4 > "$Path\windows-license-info.txt"
Write-Log $ScriptError $Log

# Installed software, first check native and then 32-bit (if it exists).
Write-Host "Listing installed software..."

$SoftwareAttributes = "DisplayName", "DisplayVersion", "Publisher", "InstallDate"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $SoftwareAttributes | `
Where-Object {$_.DisplayName -ne $null -or $_.DisplayVersion -ne $null -or $_.Publisher -ne $null -or $_.InstallDate -ne $null} | `
Sort-Object DisplayName | Format-Table -AutoSize > "$Path\installed-software.txt"
Write-Log $ScriptError $Log

If ( Test-Path -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" ) {

	Write-Output "32-bit Software" >> "$Path\installed-software.txt"

	Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $SoftwareAttributes | Where-Object {$_.DisplayName -ne $null -or $_.DisplayVersion -ne $null -or $_.Publisher -ne $null -or $_.InstallDate -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize | Format-Table -AutoSize >> "$Path\installed-software.txt"
	Write-Log $ScriptError $Log
}

Write-Output "User-specific Software" >> "$Path\installed-software.txt"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $SoftwareAttributes | Where-Object {$_.DisplayName -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize >> "$Path\installed-software.txt"
Write-Log $ScriptError $Log

Write-Output "Installed Windows Components" >> "$Path\installed-software.txt"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\*" -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object "(Default)", ComponentID, Version, Enabled | Where-Object {$_."(Default)" -ne $null -or $_.ComponentID -ne $null} | Sort-Object "(default)" | Format-Table -AutoSize >> "$Path\installed-software.txt"
Write-Log $ScriptError $Log

# Installed Windows Updates
Write-Host "Listing installed Windows updates..."
Get-WmiObject Win32_QuickFixEngineering -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object HotFixID,Description,InstalledOn | Sort-Object InstalledOn,HotFixID | Format-Table -AutoSize > "$Path\windows-updates.txt"
Write-Log $ScriptError $Log

# Basic networking information
Write-Host "Finding network information..."
&"$env:SystemRoot\System32\ipconfig.exe" /allcompartments /all 2> $ErrorFile | Select-Object -Skip 1 > "$Path\network-info.txt"
Write-CommandError $ErrorFile $Log

&"$env:SystemRoot\System32\route.exe" print >> "$Path\network-info.txt" 2> $ErrorFile
Write-CommandError $ErrorFile $Log

# Copy relevant entries from the hosts file
Write-Host "Examining hosts file..."

If ( Test-Path -Path "$env:SystemRoot\System32\drivers\etc\hosts" ) {

	Get-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue -ErrorVariable ScriptError| Select-String '(127.0.0.1)|(0.0.0.0)' > "$Path\hosts.txt"
	Write-Log $ScriptError $Log
}

Else {

	Write-Log "Hosts file not found." $Log
}

# Wait if dxdiag.exe has not finished, kill process if timeout is reached
If ( $DxDiag -ne $null ) {

	Wait-Process $DxDiag dxdiag.exe 5 $Log "$Path\dxdiag.txt"
}

# Wait if msinfo32.exe has not finished, kill process if timeout is reached
If ( $MsInfo32 -ne $null ) {

	Wait-Process $MsInfo32 msinfo32.exe 120 $Log "$Path\msinfo32.nfo"
}

# Wait if elevated.ps1 has not finished, kill the script if timeout is reached
If ( $ElevatedScript -ne $null ) {

	Wait-Process $ElevatedScript "elevated script" 120 $Log
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
$CompressionResult = Compress-Folder $Path $Zip "$ScriptDir\compression.vbs" $Log

# Check that the .zip file was created and the compression operation completed successfully before removing the uncompressed directory
Write-Host "`n"

If ( $(Test-Path -Path $Zip) -eq "True" -and $CompressionResult -eq "True" ) {

    Remove-Item -Recurse -Force "$Path"
    Write-Host "Output location: $Zip" 
}

Else {

    Write-Host "Compression failed!"
    Write-Host "`n"
    Write-Host "Output location: $Path"
}

If ( Test-Path -Path $ErrorFile ) { 

	Remove-Item -Force $ErrorFile 2> $null
}

Write-Host "`n"
Read-Host -Prompt "Press Enter to exit"