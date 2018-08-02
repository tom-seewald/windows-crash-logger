# This is used instead of the built-in "Compress-Archive" cmdlet for serveral reasons
# 1. Using .NET results in faster compression
# 2. Windows 8.1/Server 2012R2 does not have that cmdlet by default, since they ship with PowerShell 4.0
Function Compress-Folder
{
	Param
	(
		[parameter(Mandatory=$True)]
		[string]
		[ValidateScript({ Test-Path -Path $_ })]
		$Path,
		[parameter(Mandatory=$True)]
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

# Allows us to map drive letters to disk paths in the NT Object Manager namespace
Function Import-DriveInformation
{
$DiskInfoCode =
@'

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
}

# Combines information from Get-Disk and Get-PhysicalDisk for each disk and outputs it into an array
Function Get-DiskInformation
{
	$DiskInfoArray = New-Object System.Collections.ArrayList
	$PhysicalDisks = Get-PhysicalDisk
	$Disks         = Get-Disk

	ForEach ( $SerialNumber in $Disks.SerialNumber )
	{
		$MatchedPhysicalDisk = $PhysicalDisks | Where-Object { $_.SerialNumber.Trim() -eq $SerialNumber.Trim() }
		$MatchedDisk         = $Disks | Where-Object { $_.SerialNumber.Trim() -eq $SerialNumber.Trim() }
		$SizeGB              = [math]::Round($MatchedDisk.Size / 1GB,2)

		$DiskInformation =
		[PSCustomObject]@{
			"Model"			  = $MatchedDisk.Model;
			"Manufacturer"	  = $MatchedDisk.Manufacturer;
			"SerialNumber"	  = $SerialNumber.Trim();
			"MediaType"		  = $MatchedPhysicalDisk.MediaType;
			"BusType"		  = $MatchedPhysicalDisk.BusType;
			"BootDrive"		  = $MatchedDisk.IsBoot;
			"PartitionStyle"  = $MatchedDisk.PartitionStyle;
			"FirmwareVersion" = $MatchedDisk.FirmwareVersion;
			"Size(GB)"		  = $SizeGB;
		}

		$DiskInfoArray.Add($DiskInformation) | Out-Null
	}

	$DiskInfoArray
}

# Loop until a process exits for a specified number of seconds, kills the process if the timeout is reached
Function Wait-Process
{
	Param
	(
		[parameter(Mandatory=$True)]
		$ProcessObject,
		[parameter(Mandatory=$True)]
		[string]
        $ProcessName,
        [parameter(Mandatory=$True)]
        [int]
        $TimeoutSeconds,
		[parameter(Mandatory=$False)]
		[string]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
        $DestinationPath
	)

	$StartTime = Get-Date

	If ( !$ProcessObject.HasExited )
	{
		Write-Output "Waiting for $ProcessName to finish..."
	}

	While ( !$ProcessObject.HasExited -and $StartTime.AddSeconds($TimeoutSeconds) -gt (Get-Date) )
	{
		Start-Sleep -Milliseconds 500
	}

	If ( !$ProcessObject.HasExited -and $StartTime.AddSeconds($TimeoutSeconds) -le (Get-Date) )
	{
		Stop-Process -Force -Id $ProcessObject.Id 2> $null

		If ( $DestinationPath )
		{
			If ( Test-Path -Path $DestinationPath )
			{
				Remove-Item $DestinationPath 2> $null
			}
		}

		Write-Output "Killed $ProcessName due to $TimeoutSeconds second timeout."
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
		0  = "Unknown"
		1  = "Other"
		2  = "DRAM"
		3  = "Synchronous DRAM"
		4  = "Cache DRAM"
		5  = "EDO"
		6  = "EDRAM"
		7  = "VRAM"
		8  = "SRAM"
		9  = "RAM"
		10 = "ROM"
		11 = "Flash"
		12 = "SODIMM"
		13 = "FEPROM"
		14 = "EPROM"
		15 = "CDRAM"
		16 = "Q3DRAM"
		17 = "SDRAM"
		18 = "RDRAM"
		19 = "LCC"
		20 = "DDR"
		21 = "DDR2"
		22 = "DDR2 FB-DIMM" 
		24 = "DDR3"
		25 = "FBD2"
		26 = "DDR4"
		27 = "LPDDR"
		28 = "LPDDR2"
		29 = "LPDDR3"
		30 = "LPDDR4"
	}

	$PhysicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory

	# Loop through each DIMM
	ForEach ( $DIMM in $PhysicalMemory )
	{
		# Translate the capacity from Bytes to Gigabytes
		$SizeGB = [System.Math]::Round($DIMM.Capacity / 1GB)
		$Capacity = "$SizeGB" + "GB"

		# Translate DIMM formfactor
		$FormFactorRaw = $DIMM.FormFactor -as [int]
		$FormFactor = $FormFactorHashTable.$FormFactorRaw

		# If the lookup in the hashtable fails, report the raw value
		If ( !$FormFactor )
		{
			$FormFactor = $FormFactorRaw
		}

		# Translate memory type as reported by the system firmware
		$SMBIOSMemoryTypeRaw = $DIMM.SMBIOSMemoryType -as [int]
		$SMBIOSType = $TypeHashTable.$SMBIOSMemoryTypeRaw

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
		$TypeDetail = $DIMM.TypeDetail
		$TypeDetailBitField = [Convert]::ToString($TypeDetail,2)
		$BitFieldLength = $TypeDetailBitField | Measure-Object -Character | Select-Object -ExpandProperty Characters

		# Reverse bitfield, as PowerShell defaults to left to right for significant digits in binary (little endian)
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

		# Construct object containing gathered information
		$DIMMInfo =
		[PSCustomObject]@{
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

		$DIMMInfo
	}
}

# Copy the last N mini crash dumps, check both the standard path and the registry to see if there was an alternate path specified
Function Copy-MiniCrashDumps
{
	Param
	(
		[Parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path $_ -PathType Container })]
		[string]
		$DestinationPath
	)
	
	# Only copy at most the 10 most recent minidumps, in the event both $MinidumpPath and $DefaultPath have 5 minidumps.
	$CrashesToCollect = 5

	$CrashSettings  = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
	$MinidumpPath   = (Get-ItemProperty -Path $CrashSettings).MinidumpDir
	$DefaultPath    = Join-Path -Path $env:SystemRoot -ChildPath "Minidump"
	$MiniDumpReport = Join-Path -Path $DestinationPath -ChildPath "mini-crash-dumps.txt"

	# Always look where the registry points to for minidumps
	If ( Test-Path -Path $MinidumpPath )
	{
		Get-ChildItem -Path $MinidumpPath | Sort-Object LastWriteTime -Descending | Out-File -Append -FilePath $MiniDumpReport

		$MiniDumpPathContents = Get-ChildItem -Filter "*.dmp" -Path $MinidumpPath

		If ( $MiniDumpPathContents -ne $null )
		{
			Write-Output "Copying crash dumps from $MinidumpPath..."
			Get-ChildItem -Filter "*.dmp" -Path $MinidumpPath | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First $CrashesToCollect | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$CrashDumps" } -ErrorAction SilentlyContinue
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

	# If they path in the registry and the default minidump path differ, also check the default path for crash dumps.
	If ( $DefaultPath -ne $MinidumpPath )
	{
		If ( Test-Path -Path $DefaultPath )
		{
			Get-ChildItem -Path $DefaultPath | Sort-Object LastWriteTime -Descending | Out-File -Append -FilePath $MiniDumpReport

			$DefaultPathContents = Get-ChildItem -Filter "*.dmp" -Path $DefaultPath

			If ( $DefaultPathContents -ne $null )
			{
				Write-Output "Copying crash dumps from $DefaultPath..."
				Get-ChildItem -Filter "*.dmp" -Path $DefaultPath  | Where-Object { $_.Length -gt 0 } | Sort-Object -Descending LastWriteTime | Select-Object -First $CrashesToCollect | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$CrashDumps" }
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
	
	$CrashSettings    = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
	$DumpPath         = (Get-ItemProperty -Path $CrashSettings).DumpFile
	$DefaultPath      = Join-Path -Path $env:SystemRoot -ChildPath "Memory.dmp"
	$MemoryDumpReport = Join-Path -Path $DestinationPath -ChildPath "memory-dumps.txt"
	
	If ( Test-Path -Path $DumpPath )
	{
		$DumpPathProperties = $(Get-Item -Path $DumpPath)
		
		Write-Output "Crash dump found at $DumpPath" | Out-File -Append -FilePath $MemoryDumpReport
		Write-Output "Creation date: $((Get-Item -Path $DumpPath).LastWriteTime)" | Out-File -Append -FilePath $MemoryDumpReport
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
			Write-Output "Creation date: $((Get-Item -Path $DefaultPath).LastWriteTime)" | Out-File -Append -FilePath $MemoryDumpReport
			Write-Output "Size on disk: $([math]::round($DefaultPathProperties.Length / 1MB)) MB" | Out-File -Append -FilePath $MemoryDumpReport
		}

		Else
		{
			Write-Output "$DefaultPath was not found" | Out-File -Append -FilePath $MemoryDumpReport
		}
	}
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
	Get-ItemProperty -Path $CrashSettings | Out-File -Append -FilePath $DestinationPath

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

# Download specified remote file with timeout and error handling
Function Get-RemoteFile
{
    Param
	(
        [parameter(Mandatory=$True)]
        [string]
		$URL,
		[parameter(Mandatory=$True)]
        [string]
		$FileName,
		[parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
        [string]
		$DestinationPath
	)

	$TimeoutSec = 10

    Write-Output "Downloading $FileName..."

	Try
	{
		# This removes the progress bar, which slows the download to a crawl if enabled
		$ProgressPreference = "SilentlyContinue"
		Invoke-WebRequest -Uri $URL -OutFile $DestinationPath -TimeoutSec $TimeoutSec
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