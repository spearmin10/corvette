Param(
  [parameter(mandatory=$true)][string]$SyslogHost,
  [int]$SyslogPort = 514,
  [string]$SyslogProtocol = "UDP",
  [int]$SyslogFacility = 16,
  [int]$SyslogSeverity = 6,
  [string]$SyslogFormat = "RFC-5424",
  [bool]$ShowLogs = $false,
  [parameter(mandatory=$true)][string]$CEFVendor,
  [parameter(mandatory=$true)][string]$CEFDeviceProduct,
  [parameter(mandatory=$true)][string]$CEFDeviceVersion,
  [parameter(mandatory=$true)][string]$CEFEventClassID,
  [parameter(mandatory=$true)][string]$CEFName,
  [parameter(mandatory=$true)][string]$CEFSeverity,
  [parameter(mandatory=$true)][string]$CEFExtension
)

class Syslog {
    [string]$format
    [int]$pri

    Syslog([string]$format, [int]$facility, [int]$severity) {
        $severity = [Math]::Min($severity, 7)
        $facility = [Math]::Min($facility, 124)
        $this.format = $format
        $this.pri = [string](($facility * 8) + $severity)
    }

    [void]Send([byte[]]$log) {
        
    }

    [string]Build5424([string]$message, [string]$hostname, [string]$appname, [string]$procid) {
        [string]$timestamp = $(Get-Date $(Get-Date).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ssK")
        if ([string]::IsNullOrEmpty($hostname)) {
            $hostname = $Env:Computername
            if ([string]::IsNullOrEmpty($hostname)) {
                $hostname = "-"
            }
        }
        if ([string]::IsNullOrEmpty($appname)) {
            $appname = "-"
        }
        if ([string]::IsNullOrEmpty($procid)) {
            $procid = "-"
        }
        return "<" + $this.pri + ">1 ${timestamp} ${hostname} ${appname} ${procid} - - ${message}"
    }

    [string]Build3164([string]$message, [string]$hostname, [string]$appname, [string]$procid) {
        [string]$payload = "<" + $this.pri + ">"
        $payload += $(Get-Date).ToString("MMM dd HH:mm:ss", [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US"))
        
        if ([string]::IsNullOrEmpty($hostname)) {
            $hostname = $Env:Computername
            if ([string]::IsNullOrEmpty($hostname)) {
                $hostname = "localhost"
            }
        }
        $payload += " ${hostname}"
        
        if (![string]::IsNullOrEmpty($appname)) {
            if (![string]::IsNullOrEmpty($procid)) {
                $payload += " ${appname}[${procid}]:"
            } else {
                $payload += " ${appname}:"
            }
        }
        return $payload + " " + $message
    }

    [string]Build([string]$message) {
        return $this.Build($message, $null, $null, $null)
    }

    [string]Build([string]$message, [string]$hostname, [string]$appname, [string]$procid) {
        switch ($this.format) {
            "RFC-3164" {
                return $this.Build3164($message, $hostname, $appname, $procid)
            }
            "RFC-5424" {
                return $this.Build5424($message, $hostname, $appname, $procid)
            }
        }
        throw "Unknown syslog format: " + $this.format
    }
}

class UdpSyslog : Syslog {
    [System.Net.Sockets.UdpClient]$socket
    
    UdpSyslog([string]$sylog_host, [int]$syslog_port,
              [string]$syslog_format, [int]$syslog_facility, [int]$syslog_severity)
        : base($syslog_format, $syslog_facility, $syslog_severity) {
        $this.socket = New-Object System.Net.Sockets.UdpClient($sylog_host, $syslog_port)
        $this.socket.DontFragment = $true
    }

    [void]Send([string]$log) {
        $payload = [System.Text.Encoding]::UTF8.GetBytes($log)
        [void]$this.socket.Send($payload, $payload.Length)
    }

    [void]Close() {
        $this.socket.Close()
    }
}

class TcpSyslog : Syslog {
    [System.Net.Sockets.TcpClient]$socket
    [System.Net.Sockets.NetworkStream]$stream
    
    TcpSyslog([string]$sylog_host, [int]$syslog_port,
              [string]$syslog_format, [int]$syslog_facility, [int]$syslog_severity)
        : base($syslog_format, $syslog_facility, $syslog_severity) {
        $this.socket = New-Object System.Net.Sockets.TcpClient
        $this.socket.SendTimeout = 10 * 1000
        $this.socket.Connect($sylog_host, $syslog_port)
        $this.stream = $this.socket.GetStream()
    }

    [void]Send([string]$log) {
        $payload = [System.Text.Encoding]::UTF8.GetBytes($log)
        $header = [System.Text.Encoding]::UTF8.GetBytes([string]$payload.Length + " ")
        $record = $header + $payload
        [void]$this.stream.Write($record, 0, $record.Length)
    }

    [void]Close() {
        $this.socket.Close()
    }
}

class Main {
    [Syslog]$syslog
    
    Main([string]$syslog_protocol, [string]$sylog_host, [int]$syslog_port,
         [string]$syslog_format, [int]$syslog_facility, [int]$syslog_severity) {
        switch ($syslog_protocol) {
            "UDP" {
                $this.syslog = [UdpSyslog]::New($sylog_host, $syslog_port, $syslog_format, $syslog_facility, $syslog_severity)
            }
            "TCP" {
                $this.syslog = [TcpSyslog]::New($sylog_host, $syslog_port, $syslog_format, $syslog_facility, $syslog_severity)
            }
            default {
                throw "Unknown syslog protocol: " + $syslog_protocol
            }
        }
    }

    hidden [string]EncodeCEFHeader([object]$val) {
        if ([string]::IsNullOrEmpty($val)) {
            return ""
        } elseif ($val -isnot [string]) {
            $val = ConvertTo-Json -Compress $val
        }
        $m = @{
            "|" = '\|'
            "\" = '\\'
        }
        return [regex]::Replace($val, '[|\\]', { $m[$args.groups[0].value] })
    }

    hidden [string]EncodeCEFValue([object]$val) {
        if ([string]::IsNullOrEmpty($val)) {
            return ""
        } elseif ($val -isnot [string]) {
            $val = ConvertTo-Json -Compress $val
        }
        $m = @{
            "`n" = '\n'
            "`r" = '\r'
            "`t" = '\t'
            "="  = '\='
            "\" = '\\'
        }
        return [regex]::Replace($val, '[=\\\r\n]', { $m[$args.groups[0].value] })
    }

    [void]Run(
        [string]$cef_vendor,
        [string]$cef_device_product,
        [string]$cef_device_version,
        [string]$cef_event_class_id,
        [string]$cef_name,
        [string]$cef_severity,
        [hashtable]$cef_extension,
        [bool]$verbose
    ){
        $exts = @()
        foreach ($ext in $cef_extension.GetEnumerator()) {
            $ext_key = $this.EncodeCEFValue($ext.Key)
            $ext_val = $this.EncodeCEFValue($ext.Value)
            $exts += "$ext_key=$ext_val"
        }
        $log = "CEF:" + $(
            @(
                "0",
                $this.EncodeCEFHeader($cef_vendor),
                $this.EncodeCEFHeader($cef_device_product),
                $this.EncodeCEFHeader($cef_device_version),
                $this.EncodeCEFHeader($cef_event_class_id),
                $this.EncodeCEFHeader($cef_name),
                $this.EncodeCEFHeader($cef_severity),
                ($exts -join " ")
            ) -join "|"
        )

        $this.syslog.Send($this.syslog.Build($log))
        if ($verbose) {
            Write-Host $log
        }
        $this.syslog.Close()
    }
}

$cef_extension_obj = ConvertFrom-Json $([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CEFExtension)))
$cef_extension = @{}
foreach ($key in $cef_extension_obj.PSObject.Properties.Name) {
    $cef_extension[$key] = $cef_extension_obj.$key
}

$main = [Main]::New($SyslogProtocol, $SyslogHost, $SyslogPort, $SyslogFormat, $SyslogFacility, $SyslogSeverity)
$main.Run(
    $CEFVendor,
    $CEFDeviceProduct,
    $CEFDeviceVersion,
    $CEFEventClassID,
    $CEFName,
    $CEFSeverity,
    $cef_extension,
    $ShowLogs
)
