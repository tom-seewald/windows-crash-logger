# This is used instead of the built-in "Compress-Archive" cmdlet for serveral reasons
# 1. Using .NET directly results in faster compression
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
		
		$DiskInformation =
		[PSCustomObject]@{
			"Model"			  = $Disk.Model;
			"Manufacturer"	  = $Disk.Manufacturer;
			"SerialNumber"	  = $Disk.SerialNumber;
			"MediaType"		  = $PhysicalDisk.MediaType;
			"BusType"		  = $PhysicalDisk.BusType;
			"BootDrive"		  = $Disk.IsBoot;
			"PartitionStyle"  = $Disk.PartitionStyle;
			"FirmwareVersion" = $Disk.FirmwareVersion;
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
		$TypeDetail         = $DIMM.TypeDetail
		$TypeDetailBitField = [Convert]::ToString($TypeDetail,2)
		$BitFieldLength     = $TypeDetailBitField | Measure-Object -Character | Select-Object -ExpandProperty Characters

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

# Checks both the standard path and the registry to see if there was an alternate path specified
# $CrashesToCollect is a per folder value
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

	# If the path in the registry and the default minidump path differ, also check the default path for crash dumps.
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
		1		{Return "BIOS"}
		2   	{Return "UEFI"}
		Default {Return "Unknown - $Result"}
	}
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

	$FirmwareInfo
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
		$DestinationPath,
		[parameter(Mandatory=$False)]
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

			Write-Information -MessageData  "Bad registry key found: $BadKey"
			
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

# Get information about installed software by looking at the registry
Function Get-InstalledSoftwareKeys
{
    Param
	(
		[parameter(Mandatory=$True)]
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
