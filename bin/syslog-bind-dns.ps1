Param(
  [parameter(mandatory=$true)][string]$SyslogHost,
  [int]$SyslogPort = 514,
  [string]$SyslogProtocol = "UDP",
  [int]$SyslogFacility = 16,
  [int]$SyslogSeverity = 6,
  [string]$SyslogFormat = "RFC-3164",
  [bool]$ShowLogs = $false,
  [parameter(mandatory=$true)][string]$DNSClientIP,
  [parameter(mandatory=$true)][string]$DNSServerIP,
  [parameter(mandatory=$true)][string]$QueryNamePattern,
  [string]$QueryErrors = "",
  [int]$Count = 1
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
    
    Main(
        [string]$syslog_protocol, [string]$sylog_host, [int]$syslog_port,
        [string]$syslog_format, [int]$syslog_facility, [int]$syslog_severity
    ) {
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

    hidden [string]MakeQueryName(
        [string]$pattern,
        [int]$mcw_min,
        [int]$mcw_max
    ) {
        while ($pattern -match "\?\{(\d+)(?:,(\d+))?\}") {
            $min = [int]$matches[1]
            $max = if ($matches[2]) { [int]$matches[2] } else { $min }
            $len = Get-Random -Minimum $min -Maximum ($max + 1)
            $expanded = "?" * $len
            $pattern = [regex]::Replace(
                $pattern,
                "\?\{\d+(?:,\d+)?\}",
                $expanded,
                1
            )
        }
        while ($pattern -match "\(([^()]+)\)") {
            $options = $matches[1] -split '\|'
            $choice  = $options | Get-Random
            $pattern = [regex]::Replace(
                $pattern,
                "\([^()]+\)",
                $choice,
                1
            )
        }
        $qname = ""
        foreach ($c in $pattern.ToCharArray()) {
            switch ($c) {
                "*" {
                    $mcw_len = Get-Random -Minimum $mcw_min -Maximum ($mcw_max + 1)
                    $qname = -Join (Get-Random -Count $mcw_len -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)
                }
                "?" {
                    $qname += (Get-Random -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)
                }
                default {
                    $qname += $c
                }
            }
        }
        return $qname
    }

    [void]Run(
        [string]$client_ip,
        [string]$server_ip,
        [string]$pattern,
        [string]$query_errors,
        [int]$count,
        [bool]$verbose
    ) {
        
        $utf8 = [System.Text.UTF8Encoding]::New()
        $md5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::New()
        $client_id = ([System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($client_ip))).ToLower() -replace '-', '').Substring(0, 12)

        1..$count | %{
            $query_name = $this.MakeQueryName($pattern, 1, 12)
            [int]$client_port = $(Get-Random -Minimum 1025 -Maximum 65534)
            [string]$log_time = $(Get-Date).ToUniversalTime().ToString("dd-MMM-yyyy HH:mm:ss.fff", [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US"))

            $logs = @(
@"
$log_time queries: info: client @0x${client_id} ${client_ip}#${client_port} (${query_name}): query: ${query_name} IN A +E(0) (${server_ip})
"@
            )
            switch ($query_errors) {
                "NXDOMAIN" {
                    $logs += @"
$log_time query-errors: info: client @0x${client_id} ${client_ip}#${client_port} (${query_name}): query failed (NXDOMAIN) for ${query_name}/IN/A at ../../../bin/named/query.c:1234
"@
                }
            }

            foreach ($log in $logs) {
                $this.syslog.Send($this.syslog.Build($log, "dns", "named", "1234"))
                if ($verbose) {
                    Write-Host $log
                } else {
                    Write-Host "DNS: ${client_ip} > ${server_ip} : ${query_name}"
                }
            }
        }
    }

    [void]Close() {
        $this.syslog.Close()
    }
}

$main = [Main]::New($SyslogProtocol, $SyslogHost, $SyslogPort, $SyslogFormat, $SyslogFacility, $SyslogSeverity)
$main.Run($DNSClientIP, $DNSServerIP, $QueryNamePattern, $QueryErrors, $Count, $ShowLogs)
$main.Close()
