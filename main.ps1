##############################
# Script Written By Spectrum #
##############################

# Version String
$ScriptVersion = "Beta09 - 3/17/18"

# Detect Windows version, convert the value from a string to a decimal
$MajorVer = [System.Environment]::OSVersion.Version.Major
$MinorVer = [System.Environment]::OSVersion.Version.Minor
$WindowsVersion = "$MajorVer" + "." + "$MinorVer" -as [decimal]

# Abort if Controlled Folder Access is enabled, as it prevents log files from being placed on the desktop
If ( $WindowsVersion -ge 10 ) {

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
Write-Host $ScriptVersion
"`n" * 3

Read-Host -Prompt "Press Enter to continue"
Clear-Host

# Parent directory of this script, used instead of $PSScriptRoot as that is not available on stock Windows 7 SP1
$ScriptPath = Split-Path $MyInvocation.MyCommand.Path -Parent

# Set variables for output folders
$Time = (Get-Date).ToString("yyyy-MM-dd HH mm")
$Name = "$env:computername ($Time)"
$Path = Join-Path -Path "$home\Desktop" -ChildPath $Name
$Log = Join-Path -Path "$env:TEMP" -ChildPath "script-log.csv"
$ErrorFile = Join-Path -Path "$env:TEMP" -ChildPath "error-temp.txt"
$EventLogs = Join-Path -Path $Path -ChildPath "Event Logs"
$PowerReports = Join-Path -Path $Path -ChildPath "Power Reports"
$LoggerModule = Join-Path -Path $ScriptPath -ChildPath "logger-module.psm1"
$ElevatedScriptPath = Join-Path -Path $ScriptPath -ChildPath "elevated.ps1"
$Zip = "$Path" + ".zip"

# Check for pre-existing files and folders, and remove them if they exist
If ( Test-Path -Path $Path ) { Remove-Item -Recurse -Force $Path }
If ( Test-Path -Path $Zip ) { Remove-Item -Force $Zip }
If ( Test-Path -Path $Log ) { Remove-Item -Force $Log }
If ( Test-Path -Path $ErrorFile ) { Remove-Item -Force $ErrorFile }

# Create directories and files
New-Item -ItemType Directory $Path -Force -ErrorAction Stop | Out-Null
New-Item -ItemType Directory $EventLogs -Force -ErrorAction Stop | Out-Null
New-Item -ItemType Directory $PowerReports -Force -ErrorAction Stop | Out-Null
New-Item -ItemType File -Path $ErrorFile -Force -ErrorAction Stop | Out-Null

# Import custom module containing support functions
Try {

    Import-Module $LoggerModule
}

Catch {

	Write-Warning "Could not import $LoggerModule, exiting script."
	$TimeStamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $ImportError = $TimeStamp + "," + "Failed to import $LoggerModule, exiting script."
    Write-Ouptut $ImportError | Out-File -Append -FilePath $Log
    Exit
}

# Set window size to 1000 by 1000 to avoid truncation when sending output to files
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(1000,1000)

# Check that the OS is supported
If ( $WindowsVersion -lt 6.1 ) {

	Write-Log -Message "Unsupported version of Windows, kernel version less than 6.1" -LogPath $Log
	Write-Warning "Unsupported version of Windows detected!"
	Write-Warning "This script has not been tested on any release prior to Windows 7!"
}

If ( $WindowsVersion -eq 6.2 ) {

	Write-Log -Message "Unsupported version of Windows detected, Windows 8" -LogPath $Log
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
    Write-Log -Message "Failed to launch msinfo32.exe!" -LogPath $Log
    Write-Log -Message $error[0] -LogPath $Log
}

# Download autorunsc.exe, this will later be run in elevated.ps1
$AutorunsURL = "https://live.sysinternals.com/autorunsc.exe"
Get-RemoteFile -URL $AutorunsURL -FileName "autorunsc" -OutputPath "$ScriptPath\autorunsc.exe" -LogPath $Log

# Start elevated.ps1
If ( Test-Path -Path $ElevatedScriptPath ) {

	Write-Host "Launching elevated script..."

	Try {
	
		$ElevatedScript = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
										-ArgumentList """-ExecutionPolicy"" ""Bypass"" ""-NonInteractive"" ""-NoProfile"" ""-File"" ""$ElevatedScriptPath"" ""$Path""" `
										-Verb RunAs -PassThru
	}

	Catch {

		Write-Warning "Failed to launch elevated script!" 
        Write-Log -Message "Failed to launch elevated script!" -LogPath $Log
        Write-Log -Message $error[0] -LogPath $Log
	}
}

Else {

	Write-Warning "$ElevatedScriptPath not found!"
	Write-Log -Message "$ElevatedScriptPath not found!" -LogPath $Log
}

# Start DirectX Diagnostics Report
Write-Host "Running DirectX diagnostics..."

Try {

	$DxDiag = Start-Process -FilePath "$env:SystemRoot\System32\dxdiag.exe" -ArgumentList "/dontskip","/whql:off","/t","$Path\dxdiag.txt" -NoNewWindow -PassThru
}

Catch {

	Write-Warning "Failed to run DirectX diagnostics!"
    Write-Log -Message "Failed to run dxdiag.exe" -LogPath $Log
    Write-Log -Message $error[0] -LogPath $Log
}

# Export Event Logs (2592000000 ms = 30 days)
Write-Host "Exporting Application event Log..."
&"$env:SystemRoot\System32\wevtutil.exe" query-events Application /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text | Out-File -FilePath "$EventLogs\application-events.txt" 2> $ErrorFile
Write-CommandError -ErrorFile $ErrorFile -LogPath $Log

Write-Host "Exporting System event log..."
&"$env:SystemRoot\System32\wevtutil.exe" query-events System /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text | Out-File -FilePath "$EventLogs\system-events.txt" 2> $ErrorFile
Write-CommandError -ErrorFile $ErrorFile -LogPath $Log

# Kernel PnP Event log only exists on Windows 8.1 and newer
If ( $WindowsVersion -ge "6.3" ) {

	Write-Host "Exporting Kernel PnP event log..."
	&"$env:SystemRoot\System32\wevtutil.exe" query-events Microsoft-Windows-Kernel-PnP/Configuration /q:"*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text | Out-File -FilePath "$EventLogs\pnp-events.txt" 2> $ErrorFile
	Write-CommandError -ErrorFile $ErrorFile -LogPath $Log
}

# Driver information
Write-Host "Gathering driver information..."
&"$env:SystemRoot\System32\driverquery.exe" /v /fo table 2> $ErrorFile | Select-Object -Skip 1 | Out-File -FilePath "$Path\driver-table.txt"
Write-CommandError -ErrorFile $ErrorFile -LogPath $Log

$DriverInfoAttributes = "DeviceName", "FriendlyName", "InfName", "DriverVersion", "IsSigned", "DriverDate"
Get-WmiObject Win32_PnPSignedDriver -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object -Property $DriverInfoAttributes | Where-Object {$_.DeviceName -ne $null -or $_.FriendlyName -ne $null -or $_.InfName -ne $null } | Sort-Object DeviceName | Format-Table -AutoSize | Out-File -FilePath "$Path\driver-versions.txt"
Write-Log -Message $ScriptError -LogPath $Log

# Get Default Power Plan
Write-Host "Checking power settings..."
&"$env:SystemRoot\System32\powercfg.exe" /list | Out-File -FilePath "$PowerReports\power-plan.txt" 2> $ErrorFile
Write-CommandError -ErrorFile $ErrorFile -LogPath $Log

# RAM info
Write-Host "Getting hardware information..."
$MemoryAttributes = "BankLabel", "DeviceLocator", "Manufacturer", "Capacity", "ConfiguredClockspeed", "ConfiguredVoltage", "SerialNumber", "PartNumber"
Get-WmiObject Win32_PhysicalMemory -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $MemoryAttributes | Sort-Object BankLabel, DeviceLocator | Format-List | Out-File -FilePath "$Path\ram.txt"
Write-Log -Message $ScriptError -LogPath $Log

# Processor information
$ProcessorAttributes = "Name", "Description", "Manufacturer", "DeviceID", "SocketDesignation", "CurrentClockSpeed", "CPUStatus", `
					   "LastErrorCode", "ErrorDescription", "PartNumber", "Revision", "SerialNumber", "ProcessorId", "Status", `
					   "StatusInfo", "Stepping", "CurrentVoltage", "VoltageCaps"
Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $ProcessorAttributes | Format-List | Out-File -FilePath "$Path\cpu.txt"
Write-Log -Message $ScriptError -LogPath $Log

# Disk and partition information
Get-DiskInformation

$SizeGB = @{Name="Size (GB)";Expression={[math]::Round($_.Capacity / 1GB, 2)}}
$FreeGB = @{Name="Free (GB)";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}
$DevicePath = @{Name="Device Path";Expression={[diskinfo]::GetDeviceName($_.DriveLetter)}}

Get-WmiObject Win32_Volume -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Where-Object { $_.DriveLetter -ne $null } | Select-Object DriveLetter, $SizeGB, $FreeGB, $DevicePath | Sort-Object DriveLetter | Format-Table -AutoSize > "$Path\partitions.txt"
Write-Log -Message $ScriptError -LogPath $Log

If ( $WindowsVersion -ge "10.0" ) {

	Get-Partition -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Format-List >> "$Path\partitions.txt"
	Write-Log -Message $ScriptError -LogPath $Log

	$DiskNumbers = (Get-Disk).Number
	$DiskAttributes = "FriendlyName", "Model", "SerialNumber", "Manufacturer", "Number", "IsBoot", "AllocatedSize", `
					  "HealthStatus", "OperationalStatus", "BusType", "FirmwareVersion", "PartitionStyle", "Path"
	ForEach ( $DiskNumber in $DiskNumbers ) {

		Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $DiskAttributes | Format-List | Out-File -Append -FilePath "$Path\disks.txt"
		Write-Log -Message $ScriptError -LogPath $Log
	}
}

# System Board information
$BaseBoardAttributes = "Product", "Model", "Version", "Manufacturer", "Description"
Get-WmiObject Win32_BaseBoard -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $BaseBoardAttributes | Format-List | Out-File -FilePath "$Path\motherboard.txt"
Write-Log -Message $ScriptError -LogPath $Log

# UEFI/BIOS properties
$BiosAttributes = "SMBIOSBIOSVersion", "Manufacturer", "Name", "Version", "BIOSVersion", "ReleaseDate"
Get-WmiObject Win32_Bios -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $BiosAttributes | Format-List | Out-File -Append -FilePath "$Path\bios.txt"
Write-Log -Message $ScriptError -LogPath $Log

# GPU information
$GpuAttributes = "Name", "DeviceID", "PNPDeviceID", "VideoProcessor", "CurrentRefreshRate", "VideoModeDescription", "AdapterRAM", `
				 "DriverVersion", "InfFilename", "InstalledDisplayDrivers", "InstallDate", "DriverDate", "Status", "StatusInfo", `
				 "LastErrorCode", "ErrorDescription"
Get-WmiObject Win32_VideoController -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $GpuAttributes | Format-List | Out-File -FilePath "$Path\gpu.txt"
Write-Log -Message $ScriptError -LogPath $Log

# Windows license information
Write-Host "Finding Windows license information..."
&"$env:SystemRoot\System32\cscript.exe" $env:SystemRoot\System32\slmgr.vbs /dlv -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object -Skip 4 | Out-File -FilePath "$Path\windows-license-info.txt"
Write-Log -Message $ScriptError -LogPath $Log

# Installed software, first check native and then 32-bit (if it exists).
Write-Host "Listing installed software..."

$SoftwareAttributes = "DisplayName", "DisplayVersion", "Publisher", "InstallDate"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $SoftwareAttributes | `
Where-Object {$_.DisplayName -ne $null -or $_.DisplayVersion -ne $null -or $_.Publisher -ne $null -or $_.InstallDate -ne $null} | `
Sort-Object DisplayName | Format-Table -AutoSize | Out-File -FilePath "$Path\installed-software.txt"
Write-Log -Message $ScriptError -LogPath $Log

If ( Test-Path -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" ) {

	Write-Output "32-bit Software" >> "$Path\installed-software.txt"

	Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $SoftwareAttributes | Where-Object {$_.DisplayName -ne $null -or $_.DisplayVersion -ne $null -or $_.Publisher -ne $null -or $_.InstallDate -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize | Format-Table -AutoSize | Out-File -Append -FilePath "$Path\installed-software.txt"
	Write-Log -Message $ScriptError -LogPath $Log
}

Write-Output "User-specific Software" >> "$Path\installed-software.txt"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object $SoftwareAttributes | Where-Object {$_.DisplayName -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize | Out-File -Append -FilePath "$Path\installed-software.txt"
Write-Log -Message $ScriptError -LogPath $Log

Write-Output "Installed Windows Components" >> "$Path\installed-software.txt"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\*" -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object "(Default)", ComponentID, Version, Enabled | Where-Object {$_."(Default)" -ne $null -or $_.ComponentID -ne $null} | Sort-Object "(default)" | Format-Table -AutoSize | Out-File -Append -FilePath "$Path\installed-software.txt"
Write-Log -Message $ScriptError -LogPath $Log

# Installed Windows Updates
Write-Host "Listing installed Windows updates..."
Get-WmiObject Win32_QuickFixEngineering -ErrorAction SilentlyContinue -ErrorVariable ScriptError | Select-Object HotFixID,Description,InstalledOn | Sort-Object InstalledOn,HotFixID | Format-Table -AutoSize | Out-File -FilePath "$Path\windows-updates.txt"
Write-Log -Message $ScriptError -LogPath $Log

# Basic networking information
Write-Host "Finding network information..."
&"$env:SystemRoot\System32\ipconfig.exe" /allcompartments /all 2> $ErrorFile | Select-Object -Skip 1 | Out-File -FilePath "$Path\network-info.txt"
Write-CommandError -ErrorFile $ErrorFile -LogPath $Log

&"$env:SystemRoot\System32\route.exe" print | Out-File -Append -FilePath "$Path\network-info.txt" 2> $ErrorFile
Write-CommandError -ErrorFile $ErrorFile -LogPath $Log

# Copy relevant entries from the hosts file
Write-Host "Examining hosts file..."

If ( Test-Path -Path "$env:SystemRoot\System32\drivers\etc\hosts" ) {

	Get-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue -ErrorVariable ScriptError| Select-String '(127.0.0.1)|(0.0.0.0)' | Out-File -FilePath "$Path\hosts.txt"
	Write-Log -Message $ScriptError -LogPath $Log
}

Else {

	Write-Log -Message "Hosts file not found." -LogPath $Log
}

# Wait if dxdiag.exe has not finished, kill process if timeout is reached
If ( $DxDiag -ne $null ) {

	Wait-Process -ProcessObject $DxDiag -ProcessName "dxdiag.exe" -TimeoutSeconds 10 -LogPath $Log -OutputFilePath "$Path\dxdiag.txt"
}

# Wait if msinfo32.exe has not finished, kill process if timeout is reached
If ( $MsInfo32 -ne $null ) {

	Wait-Process -ProcessObject $MsInfo32 -ProcessName "msinfo32.exe" -TimeoutSeconds 300 -LogPath $Log -OutputFilePath "$Path\msinfo32.nfo"
}

# Wait if elevated.ps1 has not finished, kill the script if timeout is reached
If ( $ElevatedScript -ne $null ) {

	Wait-Process -ProcessObject $ElevatedScript -ProcessName "elevated script" -TimeoutSeconds 120 -LogPath $Log
}

# Move log into $Path if it is non-empty
If ( $(Test-Path -Path $Log) -eq "True" -and (Get-Item $Log).Length -gt 0 ) {

    Move-Item -Path $Log -Destination $Path
}

# Get hash of files to later check for corruption
$FileName = @{Name="FileName";Expression={Split-Path $_.Path -Leaf}}

If ( $WindowsVersion -ge "6.3" ) {

    Get-ChildItem -Path "$Path" -Recurse -Exclude "*.wer" | Get-FileHash -Algorithm SHA256 | Select-Object $FileName, Hash, Algorithm | Sort-Object FileName | Format-Table -AutoSize | Out-File -FilePath "$env:LOCALAPPDATA\hashes.txt"
}

If ( Test-Path -Path "$env:LOCALAPPDATA\hashes.txt" ) {

    Move-Item -Path "$env:LOCALAPPDATA\hashes.txt" -Destination $Path
}

# Compress output folder
$CompressionResult = Compress-Folder -InputPath $Path -OutputPath $Zip -CompressionScriptPath "$ScriptPath\compression.vbs" -LogPath $Log

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