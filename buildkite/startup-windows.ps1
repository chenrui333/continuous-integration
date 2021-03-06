## Stop on action error.
$ErrorActionPreference = "Stop"
$ConfirmPreference = "None"

## Use TLS1.2 for HTTPS (fixes an issue where later steps can't connect to github.com)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

## Initialize, partition and format the local SSD.
Write-Host "Initializing local SSD..."
if ((Get-Disk -Number 1).PartitionStyle -ne "RAW") {
  Clear-Disk -Number 1 -RemoveData -RemoveOEM
}
Initialize-Disk -Number 1
New-Partition -DiskNumber 1 -UseMaximumSize -DriveLetter D
Format-Volume -DriveLetter D -ShortFileNameSupport $true
Add-NTFSAccess "D:\" -Account "b" -AccessRights FullControl

## Load PowerShell support for ZIP files.
Write-Host "Loading support for ZIP files..."
Add-Type -AssemblyName "System.IO.Compression.FileSystem"

## Create temporary folder (D:\temp).
Write-Host "Creating temporary folder on local SSD..."
New-Item "D:\temp" -ItemType "directory"

## Redirect MSYS2's tmp folder to D:\temp
Write-Host "Redirecting MSYS2's tmp folder to D:\temp..."
Remove-Item -Recurse -Force C:\tools\msys64\tmp
New-Item -ItemType Junction -Path "C:\tools\msys64\tmp" -Value "D:\temp"

## Create Buildkite agent working directory (D:\b).
Write-Host "Creating build folder on local SSD..."
Remove-Item "D:\b" -Recurse -Force -ErrorAction Ignore
New-Item "D:\b" -ItemType "directory"

## Setup the TEMP and TMP environment variables.
Write-Host "Setting environment variables..."
[Environment]::SetEnvironmentVariable("TEMP", "D:\temp", "Machine")
[Environment]::SetEnvironmentVariable("TMP", "D:\temp", "Machine")
$env:TEMP = [Environment]::GetEnvironmentVariable("TEMP", "Machine")
$env:TMP = [Environment]::GetEnvironmentVariable("TMP", "Machine")

## Enable support for symlinks.
Write-Host "Enabling SECreateSymbolicLinkPrivilege permission..."
$ntprincipal = New-Object System.Security.Principal.NTAccount "b"
$sid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
$sidstr = $sid.Value.ToString()

$tmp = [System.IO.Path]::GetTempFileName()
& secedit.exe /export /cfg "$($tmp)"
$currentConfig = Get-Content -Path "$tmp"
$currentSetting = ""
foreach ($s in $currentConfig) {
    if ($s -like "SECreateSymbolicLinkPrivilege*") {
        $x = $s.split("=",[System.StringSplitOptions]::RemoveEmptyEntries)
        $currentSetting = $x[1].Trim()
    }
}

if ([string]::IsNullOrEmpty($currentSetting)) {
    $currentSetting = "*$($sidstr)"
} else {
    $currentSetting = "*$($sidstr),$($currentSetting)"
}
$outfile = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SECreateSymbolicLinkPrivilege = $($currentSetting)
"@
$outfile | Set-Content -Path $tmp -Encoding Unicode -Force
& secedit.exe /configure /db "secedit.sdb" /cfg "$($tmp)" /areas USER_RIGHTS
Remove-Item -Path "$tmp"

## Write encrypted buildkite agent token into a file.
$myhostname = [System.Net.Dns]::GetHostName()
if ($myhostname -like "*trusted*") {
  $buildkite_agent_token_url = "https://storage.googleapis.com/bazel-trusted-encrypted-secrets/buildkite-trusted-agent-token.enc"
  $project = "bazel-public"
  $key = "buildkite-trusted-agent-token"
} elseif ($myhostname -like "*testing*") {
  $buildkite_agent_token_url = "https://storage.googleapis.com/bazel-testing-encrypted-secrets/buildkite-testing-agent-token.enc"
  $project = "bazel-untrusted"
  $key = "buildkite-testing-agent-token"
} else {
  $buildkite_agent_token_url = "https://storage.googleapis.com/bazel-untrusted-encrypted-secrets/buildkite-untrusted-agent-token.enc"
  $project = "bazel-untrusted"
  $key = "buildkite-untrusted-agent-token"
}
$buildkite_agent_token_file = "d:\buildkite_agent_token.enc"
Write-Host "Getting Buildkite Agent token from GCS..."
while ($true) {
  try {
    (New-Object Net.WebClient).DownloadFile($buildkite_agent_token_url, $buildkite_agent_token_file)
    break
  } catch {
    $msg = $_.Exception.Message
    Write-Host "Failed to download token: $msg"
    Start-Sleep -Seconds 10
  }
}

## Decrypt the Buildkite agent token.
Write-Host "Decrypting Buildkite Agent token using KMS..."
$buildkite_agent_token = & gcloud kms decrypt --project $project --location global --keyring buildkite --key $key --ciphertext-file $buildkite_agent_token_file --plaintext-file -
Remove-Item $buildkite_agent_token_file

## Configure the Buildkite agent.
Write-Host "Configuring Buildkite Agent..."
$buildkite_agent_root = "c:\buildkite"
$buildkite_agent_config = @"
token="${buildkite_agent_token}"
name="%hostname"
tags="queue=windows,kind=worker,os=windows"
experiment="git-mirrors"
build-path="d:\b"
hooks-path="c:\buildkite\hooks"
plugins-path="c:\buildkite\plugins"
git-mirrors-path="c:\buildkite\bazelbuild"
disconnect-after-job=true
health-check-addr=0.0.0.0:8080
"@
[System.IO.File]::WriteAllLines("${buildkite_agent_root}\buildkite-agent.cfg", $buildkite_agent_config)

## Download our custom Buildkite Agent binary with the health check patch.
Write-Host "Downloading Buildkite Agent..."
$buildkite_agent_url = "https://storage.googleapis.com/bazel-ci/buildkite-agent/v3.14.0.bazel1/buildkite-agent-windows-amd64.exe"
$buildkite_agent_exe = "c:\buildkite\buildkite-agent.exe"
while ($true) {
  try {
    (New-Object Net.WebClient).DownloadFile($buildkite_agent_url, $buildkite_agent_exe)
    break
  } catch {
    $msg = $_.Exception.Message
    Write-Host "Failed to download agent: $msg"
    Start-Sleep -Seconds 10
  }
}

## Start the Buildkite agent service.
try {
  Write-Host "Starting Buildkite agent..."
  Start-Service -Name "buildkite-agent"

  Write-Host "Waiting for Buildkite agent to start..."
  (Get-Service -Name "buildkite-agent").WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running)
  Write-Host "Waiting for Buildkite agent to exit..."
  (Get-Service -Name "buildkite-agent").WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped)
  Write-Host "Buildkite agent has exited."
} finally {
  Write-Host "Waiting for at least one minute of uptime..."
  ## Wait until the machine has been running for at least one minute, in order to
  ## prevent exponential backoff from happening when it terminates too early.
  $up = (Get-CimInstance -ClassName win32_operatingsystem).LastBootUpTime
  $uptime = ((Get-Date) - $up).TotalSeconds
  $timetosleep = 60 - $uptime
  if ($timetosleep -gt 0) {
    Start-Sleep -Seconds $timetosleep
  }

  Write-Host "Shutting down..."
  Stop-Computer
}
