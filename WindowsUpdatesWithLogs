# Define log file location
$logFile = "$env:SystemDrive\WindowsUpdateLog.txt"

# Function to log messages
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Host $logMessage
}

# Function to log Windows version and build number
function Log-WindowsVersion {
    $windowsVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
    $buildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    $releaseId = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    Log-Message "Windows Version: $windowsVersion, Build Number: $buildNumber, Release ID: $releaseId"
}

# Check if the script is running with administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Message "Not running as administrator. Restarting with elevated privileges."
    $arguments = "-ExecutionPolicy Bypass -File """ + $MyInvocation.MyCommand.Path + """"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    exit
}

# Log the Windows version before checking for updates
Log-Message "Logging current Windows version and build number."
Log-WindowsVersion

# Log and Check for PSWindowsUpdate module
Log-Message "Checking for PSWindowsUpdate module..."
function Check-PSWindowsUpdateModule {
    $moduleName = "PSWindowsUpdate"

    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Log-Message "PSWindowsUpdate module not found. Installing..."
        try {
            Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Log-Message "PSWindowsUpdate module installed successfully."
        } catch {
            Log-Message "Failed to install PSWindowsUpdate module: $_"
            exit 1
        }
    } else {
        Log-Message "PSWindowsUpdate module is already installed."
    }
}

Check-PSWindowsUpdateModule

# Log and import the module
Log-Message "Importing PSWindowsUpdate module..."
try {
    Import-Module PSWindowsUpdate -ErrorAction Stop
    Log-Message "PSWindowsUpdate module imported successfully."
} catch {
    Log-Message "Failed to import PSWindowsUpdate module: $_"
    exit 1
}

# Log and check for updates
Log-Message "Checking for Windows Updates..."
try {
    Get-WindowsUpdate -AcceptAll -Install -AutoReboot | ForEach-Object {
        Log-Message "Installed: $_"
    }
} catch {
    Log-Message "Failed to check for Windows updates: $_"
    exit 1
}

# Log the Windows version after updates (in case of a reboot, this won't run until manually triggered again)
Log-Message "Logging Windows version and build number after updates."
Log-WindowsVersion

Log-Message "Windows Updates check completed."

# Keep the PowerShell window open
Read-Host -Prompt "Press Enter to exit"
