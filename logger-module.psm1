# Compress specified folder, attempts to use built-in compression (PowerShell 3+ and .NET 4+) and falls back to using compression.vbs
Function Compress-Folder {

    Param(
		[parameter(Mandatory=$True,position=0)]
		[string]
		$InputPath,
		[parameter(Mandatory=$True,position=1)]
		[string]
		$OutputPath,
		[parameter(Mandatory=$True,position=2)]
		[string]
		$CompressionScriptPath,
		[parameter(Mandatory=$True,position=3)]
		[string]
		$Log
    )

	$ErrorFile = $ErrorFile = "$env:TEMP\error-temp.txt"

	If ( $PSVersionTable.PSVersion.Major -ge "3" -and $PSVersionTable.CLRVersion.Major -ge "4" ) {

		Try {

			Write-Host "Compressing folder..."
			Add-Type -Assembly "system.io.compression.filesystem"
			[io.compression.zipfile]::CreateFromDirectory("$Inputpath","$OutputPath")
			$Compression = $?
			Return $?
		}

		Catch {

			Write-Warning "Failed to compress the folder with io.compression!"

			If ( Test-Path -Path $OutputPath ) {
			
				Remove-Item $OutputPath
			}
			
			$Compression = "False"
			Return "False"
		}
	}

	If ( $(Test-Path -Path $CompressionScriptPath) -eq $True -and $Compression -ne "True" ) {


		Write-Host "Compressing folder..."
		&"$env:SystemRoot\System32\cscript.exe" $CompressionScriptPath "$Inputpath" "$OutputPath" > $null 2> $ErrorFile
		$Result = $?
		Write-CommandError $ErrorFile $Log
		Return $Result
	}

	Else {

		Write-Output "Could not find $CompressionScriptPath" >> "$Path\script-log.log"
		Write-Warning "Could not find $CompressionScriptPath"
		Return "False"
	}
}

Function Get-DiskInformation {

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
}

# Download specified remote file
Function Get-RemoteFile {

    Param(
        [parameter(Mandatory=$True,position=0)]
        [string]
		$URL,
		[parameter(Mandatory=$True,position=1)]
        [string]
		$FileName,
        [parameter(Mandatory=$True,position=2)]
        [string]
		$OutputPath,
        [parameter(Mandatory=$True,position=3)]
        [string]
		$LogPath
	)

    $MajorVer=[System.Environment]::OSVersion.Version.Major
    $MinorVer=[System.Environment]::OSVersion.Version.Minor
    $KernelVersion = "$MajorVer" + "." + "$MinorVer" -as [decimal]

    Write-Host "Downloading $FileName..."

    If ( $KernelVersion -ge "6.3" ) {

        Try {

            # This remove the progress bar, which slows the download to a crawl if enabled
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $URL -OutFile $OutputPath -TimeoutSec 10 -ErrorAction SilentlyContinue -ErrorVariable ScriptError
            Write-Log $ScriptError $LogPath
        }

        Catch {

            Write-Warning "Failed to download $FileName. Skipping..."
            Write-Log "Failed to download $FileName." $LogPath
            Write-Log $error[0] $LogPath

            # Cleanup if the download fails
            If ( Test-Path -Path $OutputPath ) {
            
                Remove-Item -Force $OutputPath
            }
        }
    }

    Else {

        Try {

            $WebClient = New-Object System.Net.WebClient
            $WebClient.DownloadFile($URL,$OutputPath)
        }

        Catch {

            Write-Warning "Failed To Download $FileName. Skipping..."
            Write-Log "Failed to download $FileName." $LogPath
            Write-Log $error[0] $LogPath

            # Cleanup if the download fails
            If ( Test-Path -Path $OutputPath ) {
            
                Remove-Item -Force $OutputPath
            }
        }
    }
}

# Loop until a process exits for a specified number of seconds, kills the process if the timeout is reached
Function Wait-Process {

    Param(
		[parameter(Mandatory=$True,position=0)]
		$Process,
		[parameter(Mandatory=$True,position=1)]
		[string]
        $ProcessName,
        [parameter(Mandatory=$True,position=2)]
        [int16]
        $TimeoutSeconds,
        [parameter(Mandatory=$True,position=3)]
        [string]
		$LogPath,
		[parameter(Mandatory=$False,position=4)]
        [string]
        $OutputFilePath
	)

	$StartTime = Get-Date

	If ( !$Process.HasExited ) {

		Write-Host "Waiting for $ProcessName to finish..."
	}

	While ( !$Process.HasExited -and $StartTime.AddSeconds($TimeoutSeconds) -gt (Get-Date) ) {

		Start-Sleep -Milliseconds 500
	}

	If ( !$Process.HasExited -and $StartTime.AddSeconds($TimeoutSeconds) -le (Get-Date) ) {

		Stop-Process -Force -Id $Process.Id 2> $ScriptError
		Write-Log $ScriptError $LogPath

		If ( $OutputFilePath -ne $null ) {

			If ( Test-Path -Path $OutputFilePath ) {

				Remove-Item "$OutputFilePath" 2> $ScriptError
				Write-Log $ScriptError $LogPath
			}
		}

		Write-Log "Killed $ProcessName due to timeout." $LogPath
		Write-Warning "Killed $ProcessName due to timeout."
	}
}

# Wrapper around Write-Log, this is used as a hack to allow logging for non-powershell commands.  They cannot redirect stderr to a variable, and instead have to be sent to a file temporarily.
Function Write-CommandError {

	Param(
        [parameter(Mandatory=$True,position=0)]
        [string]
		$ErrorFile,
		[parameter(Mandatory=$True,position=1)]
        [string]
		$LogPath
	)

	[string]$ErrorMessage = Get-Content -Path $ErrorFile
	Set-Content -Path $ErrorFile $null
	Write-Log $ErrorMessage $LogPath
}

# Send specified message along with a timestamp to a specified .csv file
Function Write-Log {

    Param(
        [parameter(Mandatory=$False,position=0)]
        [string]
		$Message,
		[parameter(Mandatory=$True,position=1)]
        [string]
		$LogPath
	)
	
	# Do not log empty messages
	If ( !([string]::IsNullOrEmpty($Message)) ) {

		$TimeStamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
		[PSCustomObject]@{ TimeStamp =  $TimeStamp; Message = $Message} | Export-Csv -Path $LogPath -Append -NoTypeInformation
	}
}

Export-ModuleMember -Function Compress-Folder, Get-DiskInformation, Get-RemoteFile, Wait-Process, Write-CommandError, Write-Log 