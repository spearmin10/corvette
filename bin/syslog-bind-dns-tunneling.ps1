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
  [parameter(mandatory=$true)][string]$QueryDomain,
  [int]$Count = 1
)

class Syslog {
    [int]$pri
    [string]$format

    Syslog([string]$format, [int]$facility, [int]$severity) {
        $severity = [Math]::Min($severity, 7)
        $facility = [Math]::Min($facility, 124)
        $this.format = $format
        $this.pri = [string](($facility * 8) + $severity)
    }

    [void]Send([byte[]]$log) {
        
    }

    [string]Build5424([string]$hostname, [string]$appname, [string]$procid, [string]$message) {
        [string]$timestamp = $(Get-Date $(Get-Date).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ssK")
        if ([string]::IsNullOrEmpty($hostname)) {
            $hostname = "-"
        }
        if ([string]::IsNullOrEmpty($appname)) {
            $appname = "-"
        }
        if ([string]::IsNullOrEmpty($procid)) {
            $procid = "-"
        }
        return "<" + $this.pri + ">1 ${timestamp} ${hostname} ${appname} ${procid} - - ${message}"
    }

    [string]Build3164([string]$hostname, [string]$appname, [string]$procid, [string]$message) {
        [string]$timestamp =  $(Get-Date).ToString("MMM dd HH:mm:ss", [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US"))
        if ([string]::IsNullOrEmpty($hostname)) {
            $hostname = "-"
        }
        if ([string]::IsNullOrEmpty($appname)) {
            $appname = "-"
        }
        if ([string]::IsNullOrEmpty($procid)) {
            $procid = "-"
        }
        return "<" + $this.pri + ">${timestamp} ${hostname} ${appname}[${procid}]: ${message}"
    }

    [string]Build([string]$hostname, [string]$appname, [string]$procid, [string]$message) {
        switch ($this.format) {
            "RFC-3164" {
                return $this.Build3164($hostname, $appname, $procid, $message)
            }
            "RFC-5424" {
                return $this.Build5424($hostname, $appname, $procid, $message)
            }
        }
        return $this.Build3164($hostname, $appname, $procid, $message)
    }
}

class UdpSyslog : Syslog {
    [System.Net.Sockets.UdpClient]$socket
    
    UdpSyslog([string]$sylog_host, [int]$syslog_port, [string]$format, [int]$facility, [int]$severity) : base($syslog_format, $facility, $severity) {
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
    
    TcpSyslog([string]$sylog_host, [int]$syslog_port, [string]$format, [int]$facility, [int]$severity) : base($format, $facility, $severity) {
        $this.socket = New-Object System.Net.Sockets.TcpClient
        $this.socket.SendTimeout = 10 * 1000
        $this.socket.Connect($sylog_host, $syslog_port)
        $this.stream = $this.socket.GetStream()
    }

    [void]Send([string]$log) {
        $payload = [System.Text.Encoding]::UTF8.GetBytes($log + "`r`n")
        [void]$this.stream.Write($payload, 0, $payload.Length)
    }

    [void]Close() {
        $this.socket.Close()
    }
}

class Main {
    [Syslog]$syslog
    
    Main([string]$syslog_protocol, [string]$sylog_host, [int]$syslog_port,
         [string]$syslog_format, [int]$facility, [int]$severity) {
        switch ($syslog_protocol) {
            "UDP" {
                $this.syslog = [UdpSyslog]::New($sylog_host, $syslog_port, $syslog_format, $facility, $severity)
            }
            "TCP" {
                $this.syslog = [TcpSyslog]::New($sylog_host, $syslog_port, $syslog_format, $facility, $severity)
            }
            default {
                throw "Unknown syslog protocol: " + $syslog_protocol
            }
        }
    }

    [void]Run([string]$client_ip,
              [string]$server_ip,
              [string]$domain,
              [int]$count,
              [bool]$verbose) {
        
        $utf8 = [System.Text.UTF8Encoding]::New()
        $md5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::New()
        $client_id = ([System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($client_ip))).ToLower() -replace '-', '').Substring(0, 12)

        1..$count | %{
            [string]$hostname = -Join (Get-Random -Count 12 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)
            [int]$client_port = $(Get-Random -Minimum 1025 -Maximum 65534)
            [string]$log_time = $(Get-Date).ToUniversalTime().ToString("dd-MMM-yyyy HH:mm:ss.fff", [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US"))
            [string]$query_name = "${hostname}.${domain}"
            
            $log = @"
$log_time queries: info: client @0x${client_id} ${client_ip}#${client_port} (${query_name}): query: ${query_name} IN A +E(0) (${server_ip})
"@

            $this.syslog.Send($this.syslog.Build("dns", "named", "1234", $log))
            if ($verbose) {
                Write-Host $log
            } else {
                Write-Host "DNS: ${client_ip} > ${server_ip} : ${query_name}"
            }
        }
    }
}

$main = [Main]::New($SyslogProtocol, $SyslogHost, $SyslogPort, $SyslogFormat, $SyslogFacility, $SyslogSeverity)
$main.Run($DNSClientIP, $DNSServerIP, $QueryDomain, $Count, $ShowLogs)
