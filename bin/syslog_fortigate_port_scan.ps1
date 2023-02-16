Param(
  [parameter(mandatory=$true)][string]$SyslogHost,
  [int]$SyslogPort = 514,
  [string]$SyslogProtocol = "UDP",
  [int]$SyslogFacility = 16,
  [int]$SyslogSeverity = 6,
  [bool]$Silent = $false,
  [parameter(mandatory=$true)][string]$SourceIP,
  [parameter(mandatory=$true)][string]$DestinationIP
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
        return "<" + $this.pri +">1 " + $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssK") + " - - - - - " + $message
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

    [void]Run([string]$client_ip, [string]$target_ip, [bool]$silent){
        [int]$timestamp = $(Get-Date -UFormat "%s")
        for ($target_port = 1; $target_port -lt 65536; $target_port++){
          $log = @"
CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward server-rst|3|deviceExternalId=FGT5HD0000000000 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=notice FTNTFGTvd=vdom1 FTNTFGTeventtime=$($timestamp)000000000 src=$client_ip spt=54190 deviceInboundInterface=port12 FTNTFGTsrcintfrole=undefined dst=$target_ip dpt=$target_port deviceOutboundInterface=port11 FTNTFGTdstintfrole=undefined FTNTFGTpoluuid=c2d460aa-fe6f-51e8-9505-41b5117dfdd4 externalId=402 proto=6 act=server-rst FTNTFGTpolicyid=1 FTNTFGTpolicytype=policy app=tcp/$target_port FTNTFGTdstcountry=United States FTNTFGTsrccountry=Reserved FTNTFGTtrandisp=snat FTNTFGTappid=40568 FTNTFGTapp=tcp/$target_port FTNTFGTappcat=Web.Client FTNTFGTapprisk=medium FTNTFGTapplist=g-default FTNTFGTduration=2 out=1024 in=1024 FTNTFGTsentpkt=58 FTNTFGTrcvdpkt=105 FTNTFGTutmaction=allow FTNTFGTcountapp=2
"@
          $this.syslog.Send($this.syslog.Build($log))
          if (!$silent) {
              Write-Host $log
          }
        }
    }
}

$main = [Main]::New($SyslogProtocol, $SyslogHost, $SyslogPort, $SyslogFacility, $SyslogSeverity)
$main.Run($SourceIP, $DestinationIP, $Silent)
