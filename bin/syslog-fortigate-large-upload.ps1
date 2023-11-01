Param(
  [parameter(mandatory=$true)][string]$SyslogHost,
  [int]$SyslogPort = 514,
  [string]$SyslogProtocol = "UDP",
  [int]$SyslogFacility = 16,
  [int]$SyslogSeverity = 6,
  [string]$SyslogFormat = "RFC-5424",
  [bool]$ShowLogs = $false,
  [int64]$TotalUploadSize = 1 * 1024 * 1024 * 1024,
  [int]$NumberOfRecords = 1,
  [parameter(mandatory=$true)][string]$SourceIP,
  [parameter(mandatory=$true)][string]$DestinationIP,
  [parameter(mandatory=$true)][string]$SessionType
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

    [string]Build3164([string]$message, [string]$hostname, [string]$appname, [string]$procid) {
        [string]$payload = "<" + $this.pri + ">"
        $payload += $(Get-Date).ToString("MMM dd HH:mm:ss", [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US"))
        
        if (![string]::IsNullOrEmpty($hostname)) {
            $payload += " $hostname"
        }
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

    [void]Run([string]$client_ip,
              [string]$target_ip,
              [string]$session_type,
              [int64]$upload_size,
              [int]$num_records,
              [bool]$verbose) {
        
        if ($num_records -le 0) {
            throw "The number of records must be grater than 0."
        }
        [int64]$session_size = $upload_size / $num_records
        1..$num_records | %{
            [int64]$timestamp = ($(Get-Date).ToUniversalTime().ToFileTime() - 116444736000000000) * 100
            [int64]$session_kb = $session_size / 1024
            [int64]$session_mb = $session_size / (1024 * 1024)
            [int]$sess_id = $(Get-Random)
            [int]$client_port = $(Get-Random -Minimum 1025 -Maximum 65534)
            [int]$duration_secs = [int]($session_mb / 1024)
            
            switch ($session_type) {
                "http" {
                    $target_port = 80
                    $log = @"
CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|deviceExternalId=FGT5HD0000000000 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=notice FTNTFGTvd=vdom1 FTNTFGTeventtime=${timestamp} src=$client_ip spt=$client_port deviceInboundInterface=port12 FTNTFGTsrcintfrole=undefined dst=$target_ip dpt=$target_port deviceOutboundInterface=port11 FTNTFGTdstintfrole=undefined FTNTFGTpoluuid=c2d460aa-fe6f-51e8-9505-41b5117dfdd4 externalId=402 proto=6 act=close FTNTFGTpolicyid=1 FTNTFGTpolicytype=policy app=HTTP FTNTFGTdstcountry=United States FTNTFGTsrccountry=Reserved FTNTFGTappid=40568 FTNTFGTapp=HTTP.BROWSER FTNTFGTappcat=Web.Client FTNTFGTapprisk=medium FTNTFGTapplist=g-default FTNTFGTduration=$duration_secs out=$session_kb in=1024000 FTNTFGTcountapp=2
"@
                }
                "https" {
                    $target_port = 443
                    $log = @"
CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|deviceExternalId=FGT5HD0000000000 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=notice FTNTFGTvd=vdom1 FTNTFGTeventtime=${timestamp} src=$client_ip spt=$client_port deviceInboundInterface=port12 FTNTFGTsrcintfrole=undefined dst=$target_ip dpt=$target_port deviceOutboundInterface=port11 FTNTFGTdstintfrole=undefined FTNTFGTpoluuid=c2d460aa-fe6f-51e8-9505-41b5117dfdd4 externalId=402 proto=6 act=close FTNTFGTpolicyid=1 FTNTFGTpolicytype=policy app=HTTPS FTNTFGTdstcountry=United States FTNTFGTsrccountry=Reserved FTNTFGTappid=40568 FTNTFGTapp=HTTPS.BROWSER FTNTFGTappcat=Web.Client FTNTFGTapprisk=medium FTNTFGTapplist=g-default FTNTFGTduration=$duration_secs out=$session_kb in=1024000 FTNTFGTcountapp=2
"@
                }
                "ssh" {
                    $target_port = 22
                    $log = @"
CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|deviceExternalId=FGT5HD0000000000 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=notice FTNTFGTvd=vdom1 FTNTFGTeventtime=${timestamp} src=$client_ip spt=$client_port deviceInboundInterface=port12 FTNTFGTsrcintfrole=undefined dst=$target_ip dpt=$target_port deviceOutboundInterface=port11 FTNTFGTdstintfrole=undefined FTNTFGTpoluuid=c2d460aa-fe6f-51e8-9505-41b5117dfdd4 externalId=402 proto=6 act=close FTNTFGTpolicyid=1 FTNTFGTpolicytype=policy app=ssh FTNTFGTdstcountry=United States FTNTFGTsrccountry=Reserved FTNTFGTappid=40568 FTNTFGTapp=ssh FTNTFGTappcat=unscanned FTNTFGTapprisk=medium FTNTFGTapplist=g-default FTNTFGTduration=$duration_secs out=$session_kb in=1024000 FTNTFGTcountapp=2
"@
                }
                default {
                    throw "Unknown session type: " + $session_type
                }
            }
            $this.syslog.Send($this.syslog.Build($log))
            if ($verbose) {
                Write-Host $log
            } else {
                Write-Host "log: ${client_ip} > ${target_ip}:${target_port} - size: ${session_mb} MB"
            }
        }
    }
}

$main = [Main]::New($SyslogProtocol, $SyslogHost, $SyslogPort, $SyslogFormat, $SyslogFacility, $SyslogSeverity)
$main.Run($SourceIP, $DestinationIP, $SessionType, $TotalUploadSize, $NumberOfRecords, $ShowLogs)
