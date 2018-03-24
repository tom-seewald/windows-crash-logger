# Compress specified folder, attempts to use built-in compression (PowerShell 3+ and .NET 4+) and falls back to using compression.vbs
Function Compress-Folder {

    Param(
		[parameter(Mandatory=$True)]
		[string]
		[ValidateScript({ Test-Path -Path $_ })]
		$InputPath,
		[parameter(Mandatory=$True)]
		[string]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
		$OutputPath,
		[parameter(Mandatory=$False)]
		[string]
		$CompressionScriptPath,
		[parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
		[string]
		$LogPath
    )

	$ErrorFile = "$env:TEMP\error-temp-compression.txt"

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
			
				Remove-Item -Path $OutputPath -Force | Out-Null
			}
			
			$Compression = "False"
			Return "False"
		}
	}

	If ( $(Test-Path -Path $CompressionScriptPath) -eq $True -and $Compression -ne "True" ) {

		Write-Host "Compressing folder..."
		&"$env:SystemRoot\System32\cscript.exe" $CompressionScriptPath $InputPath $OutputPath 2> $ErrorFile | Out-Null
		$Result = $?
		Write-CommandError $ErrorFile $LogPath
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
        [parameter(Mandatory=$True)]
        [string]
		$URL,
		[parameter(Mandatory=$True)]
        [string]
		$FileName,
		[parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
        [string]
		$OutputPath,
		[parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
        [string]
		$LogPath
	)

    $MajorVer=[System.Environment]::OSVersion.Version.Major
    $MinorVer=[System.Environment]::OSVersion.Version.Minor
    $WindowsVersion = "$MajorVer" + "." + "$MinorVer" -as [decimal]

    Write-Host "Downloading $FileName..."

    If ( $WindowsVersion -ge "6.3" ) {

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
            
                Remove-Item -Path $OutputPath -Force | Out-Null
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
            
                Remove-Item -Path $OutputPath -Force | Out-Null
            }
        }
    }
}

# Loop until a process exits for a specified number of seconds, kills the process if the timeout is reached
Function Wait-Process {

    Param(
		[parameter(Mandatory=$True)]
		$ProcessObject,
		[parameter(Mandatory=$True)]
		[string]
        $ProcessName,
        [parameter(Mandatory=$True)]
        [int]
        $TimeoutSeconds,
        [parameter(Mandatory=$True)]
		[string]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
		$LogPath,
		[parameter(Mandatory=$False)]
		[string]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
        $OutputFilePath
	)

	$StartTime = Get-Date

	If ( !$ProcessObject.HasExited ) {

		Write-Host "Waiting for $ProcessName to finish..."
	}

	While ( !$ProcessObject.HasExited -and $StartTime.AddSeconds($TimeoutSeconds) -gt (Get-Date) ) {

		Start-Sleep -Milliseconds 500
	}

	If ( !$ProcessObject.HasExited -and $StartTime.AddSeconds($TimeoutSeconds) -le (Get-Date) ) {

		Stop-Process -Force -Id $ProcessObject.Id 2> $ScriptError
		Write-Log -Message $ScriptError -LogPath $LogPath

		If ( $OutputFilePath -ne $null ) {

			If ( Test-Path -Path $OutputFilePath ) {

				Remove-Item -Path $OutputFilePath -Force 2> $ScriptError
				Write-Log $ScriptError $LogPath
			}
		}

		Write-Log -Message "Killed $ProcessName due to $TimeoutSeconds second timeout." -LogPath $LogPath
		Write-Warning "Killed $ProcessName due to timeout."
	}
}

# Wrapper around Write-Log, this is used as a hack to allow logging for non-powershell commands.  They cannot redirect stderr to a variable, and instead have to be sent to a file temporarily.
Function Write-CommandError {

	Param(
		[parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path $_ })]
        [string]
		$ErrorFile,
		[parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
        [string]
		$LogPath
	)

	[string]$Message = Get-Content -Path $ErrorFile
	Set-Content -Path $ErrorFile $null
	Write-Log -Message $Message -LogPath $LogPath
}

# Send specified message along with a timestamp to a .csv file
Function Write-Log {

    Param(
        [parameter(Mandatory=$False)]
        [string]
		$Message,
		[parameter(Mandatory=$True)]
		[ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) })]
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