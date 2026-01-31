Param(
  [parameter(mandatory=$true)][string]$SyslogHost,
  [int]$SyslogPort = 514,
  [string]$SyslogProtocol = "UDP",
  [int]$SyslogFacility = 16,
  [int]$SyslogSeverity = 6,
  [string]$SyslogFormat = "RFC-5424",
  [switch]$ShowLogs,
  [parameter(mandatory=$true)][string]$SourceIP,
  [parameter(mandatory=$true)][string]$DestinationIP,
  [string]$UserID,
  [parameter(mandatory=$true)][string]$Domain,
  [parameter(mandatory=$true)][string]$LogType,
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
              [string]$user_id,
              [string]$domain,
              [string]$log_type,
              [int]$count,
              [bool]$verbose) {
        1..$count | %{
            [int64]$timestamp = ($(Get-Date).ToUniversalTime().ToFileTime() - 116444736000000000) * 100
            
            $new_user_id = $user_id
            if ([string]::IsNullOrEmpty($new_user_id)) {
                $new_user_id = -Join (Get-Random -Count 8 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)
            }
            switch ($log_type) {
                "NTLM-auth:success" {
                    $log = @"
CEF:0|Fortinet|Fortigate|v6.0.3|43016|event:user NTLM-auth success|7|deviceExternalId=FGT5HD0000000000 FTNTFGTlogid=0102043016 cat=event:user FTNTFGTsubtype=user FTNTFGTlevel=alert FTNTFGTvd=vdom1 FTNTFGTeventtime=$timestamp FTNTFGTlogdesc=NTLM authentication successful duser=$new_user_id FTNTFGTgroup=N/A FTNTFGTauthproto=https($client_ip) src=$client_ip dst=$target_ip FTNTFGTpolicyid=3 FTNTFGTadgroup=$domain act=NTLM-auth outcome=success reason=reason msg=AD group user succeeded in authentication
"@
                }
                "NTLM-auth:failure" {
                    $log = @"
CEF:0|Fortinet|Fortigate|v6.0.3|43017|event:user NTLM-auth failure|7|deviceExternalId=FGT5HD0000000000 FTNTFGTlogid=0102043017 cat=event:user FTNTFGTsubtype=user FTNTFGTlevel=alert FTNTFGTvd=vdom1 FTNTFGTeventtime=$timestamp FTNTFGTlogdesc=NTLM authentication failed duser=$new_user_id FTNTFGTgroup=N/A FTNTFGTauthproto=https($client_ip) src=$client_ip dst=$target_ip FTNTFGTpolicyid=3 FTNTFGTadgroup=$domain act=NTLM-auth outcome=failure reason=reason msg=AD group user failed in authentication
"@
                }
                default {
                    throw "Unknown log type: " + $log_type
                }
            }

            $this.syslog.Send($this.syslog.Build($log))
            if ($verbose) {
                Write-Host $log
            } else {
                Write-Host "log: ${client_ip} > ${target_ip}"
            }
        }
    }

    [void]Close() {
        $this.syslog.Close()
    }
}

$main = [Main]::New($SyslogProtocol, $SyslogHost, $SyslogPort, $SyslogFormat, $SyslogFacility, $SyslogSeverity)
$main.Run($SourceIP, $DestinationIP, $UserID, $Domain, $LogType, $Count, $ShowLogs)
$main.Close()

