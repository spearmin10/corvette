Param(
  [parameter(mandatory=$true)][string]$SyslogHost,
  [int]$SyslogPort = 514,
  [string]$SyslogProtocol = "UDP",
  [int]$SyslogFacility = 16,
  [int]$SyslogSeverity = 6,
  [string]$SyslogFormat = "RFC-5424",
  [bool]$ShowLogs = $false,
  [parameter(mandatory=$true)][string]$UserIP,
  [string]$UserID,
  [parameter(mandatory=$true)][string]$UserGroup,
  [string]$LogType = "all",
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

    [void]Run([string]$user_ip,
              [string]$user_id,
              [string]$user_group,
              [string]$log_type,
              [int]$count,
              [bool]$verbose) {
        $cul = New-Object system.globalization.cultureinfo("en-US")
        $orig_user_id = $user_id
        $public_ip = "1.2.3.4"
        $assigned_ip4 = "5.6.7.8"
        $assigned_ip6 = "2001:db8:3333:4444:5555:6666:7777:8888"
        
        1..$count | %{
            $user_id = $orig_user_id
            if ([string]::IsNullOrEmpty($user_id)) {
                $user_id = -Join (Get-Random -Count 8 -input a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z)
            }
            $timestamp = (get-date).ToUniversalTime().ToString("MMM dd yyyy HH:mm:ss", $cul)
            
            if ($log_type -eq "all") {
                $log_ids = @("ASA-6-113039",
                             "ASA-6-716001",
                             "ASA-6-722022",
                             "ASA-5-722033",
                             "ASA-5-722034",
                             "ASA-6-722051",
                             "ASA-6-722055",
                             "ASA-6-722053",
                             "ASA-4-113019",
                             "ASA-6-716002",
                             "ASA-6-722023")
            } else {
                $log_ids = @($log_type)
            }
            foreach ($log_id in $log_ids) {
                $log = ""
                switch ($log_id) {
                    "ASA-6-113039" {
                        $log = @"
%${log_id}: Group $user_group User $user_id IP $user_ip AnyConnect parent session started.
"@
                    }
                    "ASA-6-716001" {
                        $log = @"
%${log_id}: Group $user_group User $user_id IP $user_ip WebVPN session started.
"@
                    }
                    "ASA-6-722022" {
                        $log = @"
%${log_id}: Group $user_group User $user_id IP $user_ip TCP connection established without compression
"@
                    }
                    "ASA-5-722033" {
                        $log = @"
%${log_id}: Group $user_group User $user_id IP $user_ip First SVC connection established for SVC session.
"@
                    }
                    "ASA-5-722034" {
                        $log = @"
%${log_id}: Group $user_group User $user_id IP $user_ip New SVC connection, no existing connection.
"@
                    }
                    "ASA-6-722051" {
                        $log = @"
%${log_id}: Group group-policy User $user_id IP $public_ip IPv4 Address $assigned_ip4 IPv6 Address $assigned_ip6 assigned to session
"@
                    }
                    "ASA-6-722055" {
                        $log = @"
%${log_id}: Group group-policy User $user_id IP $public_ip Client Type: Cisco AnyConnect VPN Agent for Windows
"@
                    }
                    "ASA-6-722053" {
                        $log = @"
%${log_id}: Group $user_group User $user_id IP $user_ip Unknown client user-agent connection.
"@
                    }
                    "ASA-4-113019" {
                        $recv_size = Get-Random -Minimum 1 -Maximum 100000000
                        $send_size = Get-Random -Minimum 1 -Maximum 100000000
                        $log = @"
%${log_id}: Group = $user_group , Username = $user_id , IP = $user_ip , Session disconnected. Session Type: SSL , Duration: 0h:32m:46s , Bytes xmt: $send_size , Bytes rcv: $recv_size , Reason: User Requested
"@
                    }
                    "ASA-6-716002" {
                        $log = @"
%${log_id}: Group GroupPolicy User $user_id IP $user_ip WebVPN session terminated: User requested.
"@
                    }
                    "ASA-6-722023" {
                        $log = @"
%${log_id}: Group $user_group User $user_id IP $user_ip SVC connection terminated without compression
"@
                    }
                    default {
                        throw "Unknown log type: " + $log_id
                    }
                }
                $this.syslog.Send($this.syslog.Build($log))
                if ($verbose) {
                    Write-Host $log
                } else {
                    Write-Host "log: ${user_ip}:${user_id}"
                }
            }
        }
    }
}

$main = [Main]::New($SyslogProtocol, $SyslogHost, $SyslogPort, $SyslogFormat, $SyslogFacility, $SyslogSeverity)
$main.Run($UserIP, $UserID, $UserGroup, $LogType, $Count, $ShowLogs)
