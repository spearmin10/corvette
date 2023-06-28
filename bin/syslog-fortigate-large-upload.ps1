Param(
  [parameter(mandatory=$true)][string]$SyslogHost,
  [int]$SyslogPort = 514,
  [string]$SyslogProtocol = "UDP",
  [int]$SyslogFacility = 16,
  [int]$SyslogSeverity = 6,
  [bool]$ShowLogs = $false,
  [parameter(mandatory=$true)][string]$SourceIP,
  [parameter(mandatory=$true)][string]$DestinationIP,
  [parameter(mandatory=$true)][int]$DestinationPort
)

class Syslog {
    [int]$pri

    Syslog([int]$facility, [int]$severity) {
        $severity = [Math]::Min($severity, 7)
        $facility = [Math]::Min($facility, 124)
        $this.pri = [string](($facility * 8) + $severity)
    }

    [void]Send([byte[]]$log) {
        
    }

    [string]Build([string]$message) {
        return "<" + $this.pri +">1 " + $(Get-Date $(Get-Date).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ssK") + " - - - - - " + $message
    }
}

class UdpSyslog : Syslog {
    [System.Net.Sockets.UdpClient]$socket
    
    UdpSyslog([string]$sylog_host, [int]$syslog_port, [int]$facility, [int]$severity) : base($facility, $severity) {
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
    
    TcpSyslog([string]$sylog_host, [int]$syslog_port, [int]$facility, [int]$severity) : base($facility, $severity) {
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
    
    Main([string]$syslog_protocol, [string]$sylog_host,
         [int]$syslog_port, [int]$facility, [int]$severity) {
        switch ($syslog_protocol) {
            "UDP" {
                $this.syslog = [UdpSyslog]::New($sylog_host, $syslog_port, $facility, $severity)
            }
            "TCP" {
                $this.syslog = [TcpSyslog]::New($sylog_host, $syslog_port, $facility, $severity)
            }
            default {
                throw "Unknown syslog protocol: " + $syslog_protocol
            }
        }
    }

    [void]Run([string]$client_ip,
              [string]$target_ip,
              [int]$target_port,
              [bool]$verbose) {
        [int]$limit = 10000
        1..$limit | %{
            [int]$timestamp = $(Get-Date $(Get-Date).ToUniversalTime() -UFormat "%s")
            [int]$sess_id = $(Get-Random)
            [int]$client_port = $(Get-Random -Minimum 1025 -Maximum 65534)
            [int]$session_kb = $(Get-Random -Minimum 1024000 -Maximum 1024000000)
            $log = @"
CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|deviceExternalId=FGT5HD0000000000 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=notice FTNTFGTvd=vdom1 FTNTFGTeventtime=${timestamp}000000000 src=$client_ip spt=$client_port deviceInboundInterface=port12 FTNTFGTsrcintfrole=undefined dst=$target_ip dpt=$target_port deviceOutboundInterface=port11 FTNTFGTdstintfrole=undefined FTNTFGTpoluuid=c2d460aa-fe6f-51e8-9505-41b5117dfdd4 externalId=402 proto=6 act=close FTNTFGTpolicyid=1 FTNTFGTpolicytype=policy app=tcp/$target_port FTNTFGTdstcountry=United States FTNTFGTsrccountry=Reserved FTNTFGTappid=40568 FTNTFGTapp=tcp/$target_port FTNTFGTappcat=Web.Client FTNTFGTapprisk=medium FTNTFGTapplist=g-default FTNTFGTduration=2 out=$session_kb in=1024000 FTNTFGTcountapp=2
"@
            $this.syslog.Send($this.syslog.Build($log))
            if ($verbose) {
                Write-Host $log
            } else {
                Write-Host "log: "$client_ip" > "$target_ip":"$target_port" - size: "$session_kb" KB"
            }
        }
    }
}

$main = [Main]::New($SyslogProtocol, $SyslogHost, $SyslogPort, $SyslogFacility, $SyslogSeverity)
$main.Run($SourceIP, $DestinationIP, $DestinationPort, $ShowLogs)
