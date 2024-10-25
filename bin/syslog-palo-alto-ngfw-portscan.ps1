Param(
  [parameter(mandatory=$true)][string]$SyslogHost,
  [int]$SyslogPort = 514,
  [string]$SyslogProtocol = "UDP",
  [int]$SyslogFacility = 16,
  [int]$SyslogSeverity = 6,
  [string]$SyslogFormat = "RFC-5424",
  [bool]$ShowLogs = $false,
  [parameter(mandatory=$true)][string]$SourceIP,
  [parameter(mandatory=$true)][string]$DestinationIP
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

    [void]Run([string]$client_ip, [string]$target_ip, [bool]$verbose){
        [int64]$rnd_seq_no = Get-Random -Minimum 0x1000000 -Maximum ([int64]0x7fffffffff)
        [int64]$rnd_sess_id = Get-Random -Minimum 0xffff -Maximum 0xffffff
        for ($target_port = 1; $target_port -lt 65536; $target_port++){
          [int64]$timestamp = ($(Get-Date).ToUniversalTime().ToFileTime() - 116444736000000000) * 100
          [System.Globalization.CultureInfo]$cul = New-Object System.Globalization.CultureInfo("en-US")
          [DateTime]$utcnow = (Get-Date).ToUniversalTime()

          $rnd_seq_no++
          $rnd_sess_id++

          $ext_params = @{
              '__firewall_type' = 'firewall.traffic';
              '__timestamp' = $utcnow.ToString("yyyy/MM/dd HH:mm:ss", $cul);
              '__tz' = $utcnow.ToString("yyyy-MM-ddTHH:mm:ss.fff+00:00", $cul);
              'action' = 'allow';
              'app' = 'incomplete';
              'app_category' = 'unknown';
              'app_sub_category' = 'unknown';
              'bytes_received' = '60';
              'bytes_sent' = '60';
              'dest_device_category' = '';
              'dest_device_mac' = '';
              'dest_device_model' = '';
              'dest_device_osfamily' = '';
              'dest_device_osversion' = '';
              'dest_device_profile' = '';
              'dest_device_vendor' = '';
              'dest_ip' = $target_ip;
              'dest_port' = [string]$target_port;
              'dest_user' = '';
              'from_zone' = 'rlg';
              'inbound_if' = 'ethernet1/1';
              'log_source_id' = '012345678901234';
              'log_source_name' = 'panw-ngfw';
              'log_time' = $utcnow.ToString("MMM dd yyyy HH:mm:ss GMT", $cul);
              'log_type' = 'TRAFFIC';
              'nat_dest' = '0.0.0.0';
              'nat_dest_port' = '0';
              'nat_source' = '0.0.0.0';
              'nat_source_port' = '0';
              'outbound_if' = 'ethernet1/1';
              'packets_received' = '1';
              'packets_sent' = '1';
              'protocol' = 'tcp';
              'rule_matched' = 'Any';
              'rule_matched_uuid' = 'ce37e1dc-2ace-4425-99b8-6383ca48c765';
              'sequence_no' = [string]$rnd_seq_no;
              'session_end_reason' = 'aged-out';
              'session_id' = [string]$rnd_sess_id;
              'severity' = '1';
              'source_device_category' = '';
              'source_device_mac' = '';
              'source_device_model' = '';
              'source_device_osfamily' = '';
              'source_device_osversion' = '';
              'source_device_profile' = '';
              'source_device_vendor' = '';
              'source_ip' = $client_ip;
              'source_port' = [string](Get-Random -Minimum 10000 -Maximum 65534);
              'source_user' = '';
              'subtype' = 'end';
              'time_generated' = $utcnow.ToString("MMM dd yyyy HH:mm:ss GMT", $cul);
              'to_zone' = 'rlg';
              'total_time_elapsed' = '0';
              'url_category' = 'any';
              'vsys' = 'vsys1';
              'vsys_name' = '';
              'xff_ip' = '';
          };
          
          $exts = New-Object System.Collections.ArrayList
          foreach ($ent in $ext_params.GetEnumerator()) {
              [void]$exts.Add($ent.Key + '=' + $ent.Value.Replace('\', '\\').Replace('=', '\='))
          }
          $log = "CEF:0|PANW|NGFW_CEF|11.1.1|end|TRAFFIC|1|$exts"
          
          $this.syslog.Send($this.syslog.Build($log))
          if ($verbose) {
              Write-Host $log
          } else {
              Write-Host "log: ${client_ip} > ${target_ip}:${target_port}"
          }
        }
    }
}

$main = [Main]::New($SyslogProtocol, $SyslogHost, $SyslogPort, $SyslogFormat, $SyslogFacility, $SyslogSeverity)
$main.Run($SourceIP, $DestinationIP, $ShowLogs)
