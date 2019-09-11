# Default to UTF-8 output
$PSDefaultParameterValues['*:Encoding'] = 'UTF8'

# This is used instead of the built-in "Compress-Archive" cmdlet for serveral reasons
# 1. Using .NET directly results in faster compression
# 2. Windows 8.1/Server 2012R2 does not have that cmdlet by default, since they ship with PowerShell 4.0
Function Compress-Folder
{
	Param
	(
		[Parameter(Mandatory=$True)]
		[string]
		[ValidateScript({ Test-Path -Path $_ })]
		$Path,
		[Parameter(Mandatory=$True)]
		[string]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
		$DestinationPath
	)

	Try
	{
		Add-Type -Assembly "System.IO.Compression.Filesystem"
		Write-Output "Compressing folder..."
		[IO.Compression.ZipFile]::CreateFromDirectory("$Path","$DestinationPath")
		Return $?
	}

	Catch
	{
		Write-Warning "Failed to compress the folder."

		If ( Test-Path -Path $DestinationPath )
		{
			Remove-Item $DestinationPath -Force
		}
	}
}

# Converts all text files in a specified directory to UTF-8
Function Convert-UTF8
{
	Param
	(
		[Parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path $_ })]
		[string]
		$Path
	)

	$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($False)
	$Files = Get-ChildItem -Path $Path -Recurse -File -Include "*.txt", "*.wer"

	ForEach ( $File in $Files ) {

		$FilePath = $File.FullName

		$Content = Get-Content -Path $FilePath

		If ( $Content -ne $null )
		{
			[System.IO.File]::WriteAllLines($FilePath, $Content, $Utf8NoBomEncoding)
		}

		Else
		{
			# Do nothing as the file is empty
		}
	}
}

# Checks both the standard path and the registry to see if there was an alternate path specified
# $CrashesToCollect is a per-folder value
# In the event both $MinidumpPath and $DefaultPath are not the same folder, and both have $CrashesToCollect or more dump files, it will collect 2 * $CrashesToCollect dumps.
Function Copy-MiniCrashDumps
{
	Param
	(
		[Parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path $_ -PathType Container })]
		[string]
		$DestinationPath,
		[Parameter(Mandatory=$False)]
		[ValidateRange(1,100)] 
		[int]
		$CrashesToCollect = 5
	)

	$SizeMB = @{Name="Size (MB)";Expression={[math]::Round($_.Length / 1MB, 4)}}
	$CrashSettings  = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
	
	If ( Test-Path -Path $CrashSettings )
	{
		$MinidumpPath = (Get-ItemProperty -Path $CrashSettings).MinidumpDir
	}

	$DefaultPath    = Join-Path -Path $env:SystemRoot -ChildPath "Minidump"
	$MiniDumpReport = Join-Path -Path $DestinationPath -ChildPath "mini-crash-dumps.txt"

	# Always look where the registry points to for minidumps
	If ( $MinidumpPath -and (Test-Path -Path $MinidumpPath) )
	{
		$Report = Get-ChildItem -Path $MinidumpPath | Sort-Object LastWriteTime -Descending | Select-Object Mode,LastWriteTime,$SizeMB,Name
		$Report | Out-File -Append -FilePath $MiniDumpReport

		$MiniDumpPathContents = Get-ChildItem -Filter "*.dmp" -Path $MinidumpPath

		If ( $MiniDumpPathContents -ne $null )
		{
			Write-Output "Copying crash dumps from $MinidumpPath..."
			$CrashDumps = Get-ChildItem -Filter "*.dmp" -Path $MinidumpPath | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First $CrashesToCollect
			$CrashDumps	| ForEach-Object { Copy-Item -Path $_.FullName -Destination "$CrashDumps" }
		}

		Else
		{
			Write-Output "No crash dumps to copy from $MinidumpPath"
			Write-Output "$MinidumpPath contains no dump files." | Out-File -Append -FilePath $MiniDumpReport
		}
	}

	Else
	{
		Write-Output "No crash dumps to copy from $MinidumpPath"
		Write-Output "$MinidumpPath does not exist." | Out-File -Append -FilePath $MiniDumpReport
	}

	# If the path in the registry and the default minidump path differ, also check the default path for crash dumps.
	If ( $DefaultPath -ne $MinidumpPath )
	{
		If ( Test-Path -Path $DefaultPath )
		{
			$Report = Get-ChildItem -Path $DefaultPath | Sort-Object LastWriteTime -Descending | Select-Object Mode,LastWriteTime,$SizeMB,Name
			$Report	| Out-File -Append -FilePath $MiniDumpReport

			$DefaultPathContents = Get-ChildItem -Filter "*.dmp" -Path $DefaultPath

			If ( $DefaultPathContents -ne $null )
			{
				Write-Output "Copying crash dumps from $DefaultPath..."
				$CrashDumps = Get-ChildItem -Filter "*.dmp" -Path $DefaultPath  | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First $CrashesToCollect
				$CrashDumps | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$CrashDumps" }
			}

			Else
			{
				Write-Output "No crash dumps to copy from $DefaultPath"
				Write-Output "$DefaultPath contains no dump files." | Out-File -Append -FilePath $MiniDumpReport
			}
		}

		Else
		{
			Write-Output "No crash dumps to copy from $DefaultPath"
			Write-Output "$DefaultPath does not exist." | Out-File -Append -FilePath $MiniDumpReport
		}
	}
}

Function Export-Events
{
	Param
	(
		[Parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
		[string]
		$DestinationPath
	)
	
	$EventExportStart = $StopWatchMain.Elapsed.TotalSeconds
	
	$System32     = Join-Path -Path $env:SystemRoot -ChildPath "System32"
	$WevtUtilPath = Join-Path -Path $System32 -ChildPath "wevtutil.exe"
	$AppEvents    = Join-Path -Path $DestinationPath -ChildPath "application-events.txt"
	$SystemEvents = Join-Path -Path $DestinationPath -ChildPath "system-events.txt"
	$PnPEvents    = Join-Path -Path $DestinationPath -ChildPath "pnp-events.txt"
	
	If ( Test-Path -Path $WevtUtilPath )
	{
		# 2592000000 ms = 30 days
		$TimeLimit  = "2592000000"
		$TimeString = "*[System[TimeCreated[timediff(@SystemTime) <= " + $TimeLimit + "]]]"

		# Export Event Logs 
		Write-Output "Exporting Application event Log..."
		&$WevtUtilPath query-events Application /q:"$TimeString" /f:text | Out-File -FilePath $AppEvents 2> $null

		Write-Output "Exporting System event log..."
		&$WevtUtilPath query-events System /q:"$TimeString" /f:text | Out-File -FilePath $SystemEvents 2> $null

		Write-Output "Exporting Kernel PnP event log..."
		&$WevtUtilPath query-events Microsoft-Windows-Kernel-PnP/Configuration /q:"$TimeString" /f:text | Out-File -FilePath $PnPEvents 2> $null
	}
	
	Else
	{
		Write-Warning "$WevtUtilPath does not exist, cannot export event logs."
	}
	
	$EventExportEnd = $StopWatchMain.Elapsed.TotalSeconds
	$EventExportSec = $EventExportEnd - $EventExportStart
	Write-Information -MessageData "Event Log export took $EventExportSec seconds."
}

Function Get-BootInfo
{
	$PowerRegPath =  "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power\"

	# Check if the machine was booted into safe mode
	$SafeMode = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty BootupState

	# Fastboot status
	If ( Test-Path -Path $PowerRegPath ) {
		$FastStartupVal = Get-ItemProperty -Path $PowerRegPath -Name "HiberbootEnabled" | Select-Object -ExpandProperty HiberbootEnabled

		If ( $FastStartupVal -eq 1 )
		{
			$FastStartup = "Enabled"
		}

		ElseIf ( $FastStartupVal -eq 0 )
		{
			$FastStartup = "Disabled"
		}

		Else
		{
			$FastStartUp = "Unknown value $FastStartupVal"
		}
	}
	Else
	{
		$FastStartup = "Reg key not found."
	}

	# Confirm if UEFI is enabled and if SecureBoot is enabled
	$FirmwareType = Get-FirmwareType
	
	# If the system is not using UEFI secureboot is not enabled as it is a UEFI-specific feature
	If ( $FirmwareType -ne "UEFI" )
	{
		$SecureBoot = "Not Enabled"
	}

	Else
	{
		$ErrorActionPreference = 'SilentlyContinue'
		$SecureBoot = Confirm-SecureBootUEFI | Out-Null
		$ErrorActionPreference = 'Continue'

		If ( $SecureBoot -eq $True )
		{
			$SecureBootStatus = "Enabled"
		}
		Else
		{
			$SecureBootStatus = "Not Enabled"
		}
	}

	$FirmwareInfo =
	[PSCustomObject]@{
		"Safe Mode"    = $SafeMode
		"FastStartup"  = $FastStartup
		"FirmwareType" = $FirmwareType
		"SecureBoot"   = $SecureBootStatus
	}

	Return $FirmwareInfo
}

Function Get-CrashDumpSettings
{
	Param
	(
		[Parameter(Mandatory=$True)]
		[string]
		$DestinationPath
	)
	
	$CrashSettings = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"

	Write-Output "Getting crash dump settings..."
	Write-Output "########################## Crash Dump Settings #########################" | Out-File -FilePath $DestinationPath
	
	If ( Test-Path -Path $CrashSettings )
	{
		Get-ItemProperty -Path $CrashSettings | Out-File -Append -FilePath $DestinationPath
	}
	
	Else
	{
		Write-Output "$CrashSettings does not exist." | Out-File -Append -FilePath $DestinationPath
	}

	$CrashDumpMatrix =
"
######################## Crash Dump Type Matrix ########################`r`n`r`n`r`n
`t`tCrashDumpEnabled`t`t`tFilterPages`r`n
Disabled`t0`t`t`t`t`t<does not exist>`r`n
Complete`t1`t`t`t`t`t<does not exist>`r`n
Active`t`t1`t`t`t`t`t1`r`n
Kernel`t`t2`t`t`t`t`t<does not exist>`r`n
Small`t`t3`t`t`t`t`t<does not exist>`r`n
Automatic`t7`t`t`t`t`t<does not exist>
"

	Write-Output $CrashDumpMatrix | Out-File -Append -FilePath $DestinationPath
}

# Combines information from Get-Disk and Get-PhysicalDisk for each disk and outputs it into an array
Function Get-DiskInformation
{
	$DiskInfoArray = New-Object System.Collections.ArrayList
	$Disks         = Get-Disk
	$PhysicalDisks = Get-PhysicalDisk

	ForEach ( $Disk in $Disks )
	{

		# Attempt to match based on Windows uniqueID assigned to each disk
		If ( $Disk.UniqueId -ne $null )
		{
			$PhysicalDisk = $PhysicalDisks | Where-Object { $_.UniqueId -eq $Disk.UniqueId }
		}
		
		# If a disk has a null uniqueID, fallback to using the serialnumber as a unique identifier
		ElseIf ( $Disk.SerialNumber -ne $null )
		{
			Write-Warning "Disk has null UniqueId - attempting to match based on SerialNumber"
			$PhysicalDisk = $PhysicalDisks | Where-Object { $_.SerialNumber -eq $Disk.SerialNumber }
		}
		
		# Both the uniqueID and SerialNumber fields are null, inform user
		Else
		{
			Write-Warning "Disk has null UniqueId and null SerialNumber - cannot find matched physical disk."
		}
		
		# If multiple disks have the same uniqueID or SerialNumber create an array of their sizes
		If ( $PhysicalDisk.Count -ge 1 )
		{
			Write-Information -MessageData "Multiple physical disks matched uniqueID $Disk.UniqueId or SerialNumber $Disk.SerialNumber."
			$SizeGB = @()
			ForEach ( $PhysDisk in $PhysicalDisk )
			{
				$SizeGB += [math]::Round($PhysicalDisk.Size / 1GB, 2)
			}
		}
		
		Else
		{
			$SizeGB = [math]::Round($PhysicalDisk.Size / 1GB, 2)
		}
		
		If ( $Disk.SerialNumber )
		{
			$Serial = $Disk.SerialNumber.Trim()
		}
		
		# Obtain disk reliability statistics
		If ( $PhysicalDisk )
		{
			$ReliabilityCounter = $PhysicalDisk | Get-StorageReliabilityCounter
		}
		
		Else
		{
			Write-Information -MessageData "Did not obtain disk reliability counters for disk $($Disk.FriendlyName) as PhysicalDisk was null."
		}
		
		$DiskInformation =
		[PSCustomObject]@{
			"Name"                   = $Disk.FriendlyName;
			"Model"			         = $Disk.Model;
			"Manufacturer"	         = $Disk.Manufacturer;
			"PartNumber"             = $PhysicalDisk.PartNumber;
			"SerialNumber"	         = $Serial;
			"MediaType"		         = $PhysicalDisk.MediaType;
			"BusType"		         = $PhysicalDisk.BusType;
			"BootDrive"		         = $Disk.IsBoot;
			"PartitionStyle"         = $Disk.PartitionStyle;
			"FirmwareVersion"        = $Disk.FirmwareVersion;
			"Size(GB)"		         = $SizeGB;
			"GUID"                   = $Disk.Guid;
			"Temperature"            = $ReliabilityCounter.Temperature;
			"TemperatureMax"         = $ReliabilityCounter.TemperatureMax;
			"Wear"                   = $ReliabilityCounter.Wear;
			"PowerOnHours"           = $ReliabilityCounter.PowerOnHours;
			"ReadErrorsUncorrected"  = $ReliabilityCounter.ReadErrorsUncorrected;
			"ReadErrorsCorrected"    = $ReliabilityCounter.ReadErrorsCorrected;
			"WriteErrorsUncorrected" = $ReliabilityCounter.WriteErrorsUncorrected;
			"WriteErrorsCorrected"   = $ReliabilityCounter.WriteErrorsCorrected;
		}

		$DiskInfoArray.Add($DiskInformation) | Out-Null
	}

	Return $DiskInfoArray
}

# This script is a modified version of Chris Warwick's original
Function Get-FirmwareType
{
	Add-Type -Language CSharp -TypeDefinition @'
	using System;
	using System.Runtime.InteropServices;

	public class FirmwareType
    {
        [DllImport("kernel32.dll")]
        static extern bool GetFirmwareType(ref uint FirmwareType);

        public static uint GetFirmwareType()
        {
            uint firmwaretype = 0;
            if (GetFirmwareType(ref firmwaretype))
                return firmwaretype;
            else
                return 0;   // API call failed, just return 'unknown'
        }
    }
'@

    $Result = [FirmwareType]::GetFirmwareType()

	Switch ($Result)
	{
		1		{ Return "BIOS" }
		2   	{ Return "UEFI" }
		Default { Return "Unknown - $Result" }
	}
}

# Gather information about full memory dumps that exist on the system
Function Get-FullCrashDumpInfo
{
	Param
	(
		[Parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path $_ })]
		[string]
		$DestinationPath
	)
	
	$CrashSettings = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
	
	If ( Test-Path -Path $CrashSettings )
	{
		$DumpPath = (Get-ItemProperty -Path $CrashSettings).DumpFile
	}
	
	$DefaultPath      = Join-Path -Path $env:SystemRoot -ChildPath "Memory.dmp"
	$MemoryDumpReport = Join-Path -Path $DestinationPath -ChildPath "memory-dumps.txt"
	
	If ( $DumpPath -and (Test-Path -Path $DumpPath) )
	{
		$DumpPathProperties = Get-Item -Path $DumpPath
		
		Write-Output "Crash dump found at $DumpPath" | Out-File -Append -FilePath $MemoryDumpReport
		Write-Output "Creation date: $($DumpPathProperties.LastWriteTime)" | Out-File -Append -FilePath $MemoryDumpReport
		Write-Output "Size on disk: $([math]::round($DumpPathProperties.Length / 1MB)) MB" | Out-File -Append -FilePath $MemoryDumpReport
	}

	Else
	{
		Write-Output "$DumpPath was not found" | Out-File -Append -FilePath $MemoryDumpReport
	}

	If ( $DumpPath -ne $DefaultPath )
	{
		If ( Test-Path -Path $DefaultPath )
		{
			$DefaultPathProperties = Get-Item -Path $DefaultPath
			
			Write-Output "Crash dump found at $DefaultPath" | Out-File -Append -FilePath $MemoryDumpReport
			Write-Output "Creation date: $($DefaultPathProperties.LastWriteTime)" | Out-File -Append -FilePath $MemoryDumpReport
			Write-Output "Size on disk: $([math]::round($DefaultPathProperties.Length / 1MB)) MB" | Out-File -Append -FilePath $MemoryDumpReport
		}

		Else
		{
			Write-Output "$DefaultPath was not found" | Out-File -Append -FilePath $MemoryDumpReport
		}
	}
}

# Get information about installed software by looking at the registry
Function Get-InstalledSoftwareKeys
{
    Param
	(
		[Parameter(Mandatory=$True)]
		[string]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
		$DestinationPath
	)
    
    # Registry locations that contain installed software information
    $NativeSoftware      = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $Wow6432Software     = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    $InstalledComponents = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components"
    $UserSoftware        = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"

    $SoftwareAttributes = "DisplayName", "DisplayVersion", "Publisher", "InstallDate"

	# Native software
	Write-Output "Native Software" | Out-File -FilePath $DestinationPath

	$NativeKeyProps = Get-RegKeyProps -Path $NativeSoftware
	
	$NativeKeyProps = $NativeKeyProps | Select-Object $SoftwareAttributes
	$NativeKeyProps = $NativeKeyProps | Where-Object { $_.DisplayName -ne $null -or $_.DisplayVersion -ne $null -or $_.Publisher -ne $null -or $_.InstallDate -ne $null }
	$NativeKeyProps = $NativeKeyProps | Sort-Object DisplayName | Format-Table -AutoSize

	$NativeKeyProps | Out-File -Append -FilePath $DestinationPath

	# This only exists if 32-bit software is installed on a 64-bit OS
    If ( Test-Path -Path $Wow6432Software )
    {
		Write-Output "32-bit Software" | Out-File -Append -FilePath $DestinationPath

		$Wow6432KeyProps = Get-RegKeyProps -Path $Wow6432Software

		$Wow6432KeyProps = $Wow6432KeyProps | Select-Object $SoftwareAttributes
		$Wow6432KeyProps = $Wow6432KeyProps | Where-Object {$_.DisplayName -ne $null -or $_.DisplayVersion -ne $null -or $_.Publisher -ne $null -or $_.InstallDate -ne $null}
		$Wow6432KeyProps = $Wow6432KeyProps | Sort-Object DisplayName | Format-Table -AutoSize

		$Wow6432KeyProps | Out-File -Append -FilePath $DestinationPath
    }

	# Per-user software for the current user
	Write-Output "User-specific Software" | Out-File -Append -FilePath $DestinationPath

	$UserSoftKeyProps = Get-RegKeyProps -Path $UserSoftware

	$UserSoftKeyProps = $UserSoftKeyProps | Select-Object $SoftwareAttributes 
	$UserSoftKeyProps = $UserSoftKeyProps | Where-Object {$_.DisplayName -ne $null} 
	$UserSoftKeyProps = $UserSoftKeyProps | Sort-Object DisplayName | Format-Table -AutoSize

	$UserSoftKeyProps | Out-File -Append -FilePath $DestinationPath

	# Windows components
	Write-Output "Installed Windows Components" | Out-File -Append -FilePath $DestinationPath

	$ComponentKeyProps = Get-RegKeyProps -Path $InstalledComponents
	
	$ComponentKeyProps = $ComponentKeyProps | Select-Object "(Default)", ComponentID, Version, Enabled 
	$ComponentKeyProps = $ComponentKeyProps | Where-Object {$_."(Default)" -ne $null -or $_.ComponentID -ne $null} 
	$ComponentKeyProps = $ComponentKeyProps | Sort-Object "(default)" | Format-Table -AutoSize

	$ComponentKeyProps | Out-File -Append -FilePath $DestinationPath
}

# List contents of LiveKernelReports directory if it exists and is not empty
Function Get-LiveKernelReports
{
	Param
	(
		[Parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
		[string]
		$DestinationPath
	)
	
	$LiveReportPath = Join-Path -Path $env:SystemRoot -ChildPath "LiveKernelReports"
	
	If ( Test-Path -Path $LiveReportPath )
	{
		$LengthMB  = @{Name="Size (MB)";Expression={[math]::Round($_.Length / 1MB, 2)}}
		$LiveDumps = Get-ChildItem -Filter "*.dmp" -Path $LiveReportPath -Recurse
		
		If ( $LiveDumps )
		{
			$LiveDumps | Select-Object Name,LastWriteTime,$LengthMB | Out-File -FilePath $DestinationPath
		}
		
		Else
		{
			Write-Output "No LiveDumps found in $LiveReportPath." | Out-File -FilePath $DestinationPath
		}
	}

	Else
	{
		Write-Output "$LiveReportPath does not exist" | Out-File -FilePath $DestinationPath
	}
}

# Get RAM information, decode SMBIOS values into human-readable output
Function Get-MemoryInfo
{
	# Official SMBIOS documentation: https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.0.0.pdf (page 93)
	# Official MS documentation for Win32_PhysicalMemory: https://msdn.microsoft.com/en-us/library/aa394347(v=vs.85).aspx

	# Hash table for translating numeric value of FormFactor to a human-readable result
	$FormFactorHashTable =
	@{
		0  = "Unknown"
		1  = "Other"
		2  = "SIP"
		3  = "DIP"
		4  = "ZIP"
		5  = "SOJ"
		6  = "Proprietary"
		7  = "SIMM"
		8  = "DIMM"
		9  = "TSOP"
		10 = "PGA"
		11 = "RIMM"
		12 = "SODIMM"
		13 = "SRIMM"
		14 = "SMD"
		15 = "SSMP"
		16 = "QFP"
		17 = "TQFP"
		18 = "SOIC"
		19 = "LCC"
		20 = "PLCC"
		21 = "BGA"
		22 = "FPBGA" 
		23 = "LGA"
	}

	# Hash table for translating numeric value of TypeDetail to a human readable string
	$TypeDetailHashTable =
	@{
		0  = "Reserved"
		1  = "Other"
		2  = "Unknown"
		3  = "Fast-Paged"
		4  = "Static column"
		5  = "Pseudo-static"
		6  = "RAMBUS"
		7  = "Synchronous"
		8  = "CMOS"
		9  = "EDO"
		10 = "Window DRAM"
		11 = "Cache DRAM"
		12 = "Non-volatile"
		13 = "Registered (Buffered)"
		14 = "Unbuffered (Unregistered)"
		15 = "LRDIMM"
	}

	# Hash table for translating numeric value of MemoryType to a human-readable result
	$TypeHashTable = 
	@{
		1  = "Other"
		2  = "Unknown"
		3  = "DRAM"
		4  = "EDRAM"
		5  = "VRAM"
		6  = "SRAM"
		7  = "RAM"
		8  = "ROM"
		9  = "Flash"
		10 = "EEPROM"
		11 = "FEPROM"
		12 = "EPROM"
		13 = "CDRAM"
		14 = "EPROM"
		15 = "SDRAM"
		16 = "SGRAM"
		17 = "RDRAM"
		18 = "DDR"
		19 = "DDR2"
		20 = "DDR2 FB-DIMM"
		21 = "Reserved"
		22 = "Reserved"
		23 = "Reserved"
		24 = "DDR3"
		25 = "FBD2"
		26 = "DDR4"
		27 = "LPDDR"
		28 = "LPDDR2"
		29 = "LPDDR3"
		30 = "LPDDR4"
	}

	$PhysicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory
	$DIMMArray = New-Object System.Collections.ArrayList

	# Loop through each DIMM
	ForEach ( $DIMM in $PhysicalMemory )
	{
		# Translate the capacity from Bytes to Gigabytes
		$SizeGB   = [System.Math]::Round($DIMM.Capacity / 1GB)
		$Capacity = "$SizeGB" + "GB"

		# Translate DIMM formfactor
		$FormFactorRaw = $DIMM.FormFactor -as [int]
		$FormFactor    = $FormFactorHashTable.$FormFactorRaw

		# If the lookup in the hashtable fails, report the raw value
		If ( !$FormFactor )
		{
			$FormFactor = $FormFactorRaw
		}

		# Translate memory type as reported by the system firmware
		$SMBIOSMemoryTypeRaw = $DIMM.SMBIOSMemoryType -as [int]
		$SMBIOSType          = $TypeHashTable.$SMBIOSMemoryTypeRaw

		# If the lookup in the hashtable fails, report the raw value
		If ( !$SMBIOSType )
		{
			$SMBIOSType = $SMBIOSMemoryTypeRaw
		}

		# If the total bits are greater than just the data bits, we assume that the difference is due to error correcting check bits
		If ( $DIMM.TotalWidth -gt $DIMM.DataWidth )
		{
			$ECC = "True"
		}

		Else
		{
			$ECC = "False"
		}

		# Get TypeDetail and convert it
		If ( $DIMM.TypeDetail )
		{
			$TypeDetailBitField = [Convert]::ToString($DIMM.TypeDetail,2)
			$BitFieldLength     = $TypeDetailBitField | Measure-Object -Character | Select-Object -ExpandProperty Characters

			# Reverse bitfield, as PowerShell defaults to left to right for significant digits in binary
			$TypeDetailBitField = ([regex]::Matches($TypeDetailBitField,'.','RightToLeft') | ForEach-Object {$_.value}) -join ''

			$TypeDetailArray = @()

			# Loop through each bit in $TypeDetailBitField, convert every matching entry to a human-readable label
			for ( $i=0; $i -le ($BitFieldLength - 1); $i++ )
			{
				If ( $TypeDetailBitField[$i] -eq "1" )
				{
					$TypeDetailArray += $TypeDetailHashTable.$i
				}
			}

			If ( !$TypeDetailArray )
			{
				$TypeDetailArray += $TypeDetailBitField
			}
		}

		Else
		{
			$TypeDetailArray = "Dimm.TypeDetail field was null."
		}

		# Construct object containing gathered information
		$DIMMInfo = [PSCustomObject]@{
			"Location"	   = $DIMM.DeviceLocator
			"BankLabel"	   = $DIMM.BankLabel
			"Manufacturer" = $DIMM.Manufacturer
			"MemoryType"   = $SMBIOSType
			"FormFactor"   = $FormFactor
			"Capacity"     = $Capacity
			"Speed"		   = $DIMM.Speed
			"Serial"	   = $DIMM.SerialNumber
			"PartNumber"   = $DIMM.PartNumber
			"ECC"		   = $ECC
			"TypeDetail"   = $TypeDetailArray
		}

		$DIMMArray.Add($DIMMInfo) | Out-Null
	}
	
	Return $DIMMArray
}

# Retrieve and translate information about all detected PnP devices
Function Get-PnpDeviceInfo
{
	# Translation of Device Manager error codes - for reference see: https://support.microsoft.com/en-us/help/310123/error-codes-in-device-manager-in-windows
	$DeviceManagerErrorTable =
	@{
		1  = "There is no driver installed or the driver is configured incorrectly."
		3  = "The driver for this device is corrupted or the system is out of resources."
		9  = "Windows cannot identify this hardware - invalid hardware ID."
		10 = "The device cannot start."
		12 = "The device cannot find enough free resources to use"
		14 = "The device cannot work properly until the system restarts."
		16 = "Windows cannot identify all the resources this device uses."
		18 = "Reinstall the drivers for this device."
		19 = "The device cannot start because its configuration information in the registry is incomplete or damaged."
		21 = "Windows is in the process of removing the device."
		22 = "The device was disabled by the user in Device Manager."
		24 = "This device is not present, is not working properly, or does not have all its drivers installed."
		28 = "Drivers for this device are not installed."
		29 = "The device is disabled because the firmware of the device did not give it the required resources."
		31 = "Windows cannot load the drivers required for this device."
		32 = "The start type for this driver is set to disabled in the registry."
		33 = "Cannot determine which resources are required for this device."
		34 = "Windows cannot determine the settings for this device - manual configuration is required."
		35 = "The system firmware does not include enough information to properly configure and use this device."
		36 = "The device is requesting a PCI interrupt but is configured for an ISA interrupt or vice versa."
		37 = "The driver returned a failure when it executed the DriverEntry routine."
		38 = "A previous instance of the device driver is still in memory."
		39 = "The driver for this device is corrupt or missing."
		40 = "The device's service key information is missing or is incorrect."
		42 = "A duplicate device was detected."
		43 = "One of the drivers controlling this device notified Windows that the device failed in some manner."
		44 = "An application or service has shut down this device."
		45 = "The device is no longer connected to the computer."
		46 = "The device is not available because Windows is shutting down."
		47 = "Windows cannot use this device because it has been prepared for safe removal, but has not been removed."
		48 = "The driver for this device has been blocked from starting because it is known to have problems with Windows."
		49 = "The System hive has exceeded the registry size limit - cannot initialize new hardware."
		50 = "Windows cannot apply all of the properties for this device."
		51 = "The device is waiting on another device to initialize."
		52 = "Windows cannot verify the driver's digital signature"
		53 = "The device has been reserved by the Windows kernel debugger."
		54 = "The device has failed and is undergoing a reset."
	}

	# List PnP devices and associated information
	$ErrorCode = @{Name="ErrorCode";Expression={ $_.ConfigManagerErrorCode }}
	$ErrorText = @{Name="ErrorText";Expression={ $DeviceManagerErrorTable.($_.ConfigManagerErrorCode -as [int]) }}
	$Attributes = "Name", "Status", $ErrorCode, $ErrorText, "Description", "Manufacturer", "DeviceID"
	
	$PnpDevices = Get-CimInstance -ClassName Win32_PNPEntity | Select-Object $Attributes | Sort-Object Name
	Return $PnpDevices
}

# We have to implement error handling when using Get-ItemProperty when getting registry key properties , as it can fail if a key is corrupted or was otherwise improperly written.
# For further information, see this bug report: https://github.com/PowerShell/PowerShell/issues/9552
Function Get-RegKeyProps
{
	Param
	(
		[Parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path $_ })]
		[string]
		$Path
	)

	$RegKeys = Get-ChildItem -Path $Path
	
	# The absolute worst-case is that every key in the path is bad, so limit our attempts to that count.
	$TryLimit = $RegKeys.Count
	$TryCount = 1

	While ( $TryCount -le $TryLimit )
	{
		$RegKeyPaths = $RegKeys | Select-Object -ExpandProperty PSPath

		Try
		{
			$RegKeyProps = Get-ItemProperty -LiteralPath $RegKeyPaths
			Return $RegKeyProps
		}

		Catch
		{
			Write-Information -MessageData "Bad registry key encountered when enumerating registry keys in $Path, attempting to identify the bad key..."

			# Identify the first key encountered that results in an error
			ForEach ( $Key in $RegKeys )
			{
				Try
				{
					Get-ItemProperty -LiteralPath $Key.PSPath | Out-Null 
				}
				Catch
				{
					$BadKey = $Key.PSPath
					break;
				}
			}

			Write-Information -MessageData "Bad registry key found: $BadKey"
			
			# Remove $BadKey from the list of registry keys to look at in the next loop
			$RegKeys = $RegKeys | Where-Object { $BadKey -NotContains $_.PSPath }

			$TryCount++
		}
	}

	# If we get here then we were unable to find *any* valid registry keys in the given path, so report the problem and return nothing
	Write-Warning "Could not find valid registry keys in $Path"
	Write-Information -MessageData "Looped through $Path $TryLimit times and found no valid registry keys."

	Return $null
}

# Download specified remote file with timeout and error handling
Function Get-RemoteFile
{
    Param
	(
        [Parameter(Mandatory=$True)]
        [string]
		$URL,
		[Parameter(Mandatory=$True)]
        [string]
		$FileName,
		[Parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
        [string]
		$DestinationPath,
		[Parameter(Mandatory=$False)]
		[ValidateRange(1,120)]
		$TimeoutSeconds = 30
	)

    Write-Output "Downloading $FileName..."

	Try
	{
		# This removes the progress bar, which slows the download to a crawl if enabled
		$ProgressPreference = "SilentlyContinue"
		Invoke-WebRequest -Uri $URL -OutFile $DestinationPath -TimeoutSec $TimeoutSeconds
	}

	Catch
	{
		Write-Warning "Failed to download $FileName. Skipping..."
		Write-Output $error[0]

		# Cleanup if the download fails
		If ( Test-Path -Path $DestinationPath )
		{
			Remove-Item -Path $DestinationPath -Force | Out-Null
		}
	}
}

# Originally from: phant0m - https://superuser.com/questions/1058217/list-every-device-harddiskvolume
# Returns Volume information, including the actual device path of the volume in the object manager along with the associated drive letter
Function Get-VolumeInfo
{
$Signature = @'
	[DllImport("kernel32.dll", SetLastError=true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool GetVolumePathNamesForVolumeNameW([MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
			[MarshalAs(UnmanagedType.LPWStr)] [Out] StringBuilder lpszVolumeNamePaths, uint cchBuferLength, 
			ref UInt32 lpcchReturnLength);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr FindFirstVolume([Out] StringBuilder lpszVolumeName,
	   uint cchBufferLength);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool FindNextVolume(IntPtr hFindVolume, [Out] StringBuilder lpszVolumeName, uint cchBufferLength);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
'@

	Add-Type -MemberDefinition $Signature -Name Win32Utils -Namespace PInvoke -Using PInvoke,System.Text;

	$lpcchReturnLength = 0;
	$Max = 65535

	$VolumeName   = New-Object System.Text.StringBuilder($Max, $Max)
	$PathName     = New-Object System.Text.StringBuilder($Max, $Max)
	$MountPoint   = New-Object System.Text.StringBuilder($Max, $Max)
	$VolumeHandle = [PInvoke.Win32Utils]::FindFirstVolume($VolumeName, $Max)

	$VolumeArray = New-Object System.Collections.ArrayList

	$VolumeWMI = Get-CimInstance -ClassName Win32_Volume

	Do
	{
		$Volume = $VolumeName.ToString()
		$Unused = [PInvoke.Win32Utils]::GetVolumePathNamesForVolumeNameW($Volume, $MountPoint, $Max, [Ref] $lpcchReturnLength);
		$ReturnLength = [PInvoke.Win32Utils]::QueryDosDevice($Volume.Substring(4, $Volume.Length - 1 - 4), $PathName, [UInt32] $Max);
		
		If ( $ReturnLength )
		{
			$VolumeInstance = $VolumeWMI | Where-Object { $_.DeviceID -eq $Volume }
			
			$VolumeInformation = [PSCustomObject]@{
				DriveLetter = $MountPoint.ToString()
				DevicePath  = $PathName.ToString()
				VolumeGUID  = $Volume
				"Size (GB)"  = [math]::Round($VolumeInstance.Capacity / 1GB, 2)
				"Free (GB)"  = [math]::Round($VolumeInstance.FreeSpace / 1GB, 2)
			}

			$VolumeArray.Add($VolumeInformation) | Out-Null
		}
		
		Else
		{
			Write-Output "No mountpoint found for: " + $volume
		}
	} While ( [PInvoke.Win32Utils]::FindNextVolume([IntPtr] $VolumeHandle, $VolumeName, $Max) )

	Return $VolumeArray
}

# Loop until a process exits for a specified number of seconds, kills the process if the timeout is reached
Function Wait-Process
{
	Param
	(
		[Parameter(Mandatory=$True)]
		$ProcessObject,
		[Parameter(Mandatory=$True)]
		[string]
        $ProcessName,
        [Parameter(Mandatory=$True)]
        [int]
        $TimeoutSeconds
	)

	$StartTime = Get-Date

	If ( !$ProcessObject.HasExited )
	{
		$StopWatchLoop = [System.Diagnostics.StopWatch]::StartNew()
		Write-Output "Waiting for $ProcessName to finish..."
	}

	While ( !$ProcessObject.HasExited -and $StartTime.AddSeconds($TimeoutSeconds) -gt (Get-Date) )
	{
		Start-Sleep -Milliseconds 500
		$LoopWaitSec += .5
	}

	If ( !$ProcessObject.HasExited -and $StartTime.AddSeconds($TimeoutSeconds) -le (Get-Date) )
	{
		Stop-Process -Force -Id $ProcessObject.Id 2> $null
		Write-Output "Killed $ProcessName due to $TimeoutSeconds second timeout."
		Exit
	}

	If ( $StopWatchLoop.IsRunning )
	{
		$StopWatchLoop.Stop()
		Write-Information -MessageData "Waited for $ProcessName for $($StopWatchLoop.Elapsed.TotalSeconds) seconds."
	}
}