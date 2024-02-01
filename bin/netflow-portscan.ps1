Param(
    [parameter(mandatory=$true)][string]$NetflowHost,
    [int]$NetflowPort = 2055,
    [string]$NetflowProtocol = "UDP",
    [bool]$Quiet = $false,
    [parameter(mandatory=$true)][string]$SourceIP,
    [parameter(mandatory=$true)][string]$ScanSubnet
)

class Netflow {
    [int64]$flow_id
    [int32]$flow_seq
    [int32]$bootup_time
    [int32]$source_id
    [int32]$version
    
    Netflow() {
        $this.bootup_time = ([datetimeoffset](Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime).ToUnixTimeSeconds()
        [int]$current = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        [int]$sysuptime = $current - $this.bootup_time
        
        $this.flow_id = $sysuptime
        $this.flow_seq = $sysuptime
        $this.source_id = 1
        $this.version = 9
    }

    [void]Send([byte[][]]$flowsets) {
        
    }

    hidden [byte[]] GetNetworkOrderBytes($value) {
        if ($value -is [System.Int16]) {
            [byte[]]$bytes = [BitConverter]::GetBytes([int16]$value)
        } elseif ($value -is [System.UInt16]) {
            [byte[]]$bytes = [BitConverter]::GetBytes([uint16]$value)
        } elseif ($value -is [System.Int32]) {
            [byte[]]$bytes = [BitConverter]::GetBytes([int32]$value)
        } elseif ($value -is [System.UInt32]) {
            [byte[]]$bytes = [BitConverter]::GetBytes([uint32]$value)
        } elseif ($value -is [System.Int64]) {
            [byte[]]$bytes = [BitConverter]::GetBytes([int64]$value)
        } elseif ($value -is [System.UInt64]) {
            [byte[]]$bytes = [BitConverter]::GetBytes([uint64]$value)
        } else {
            throw "Value is not integer: " + $value.GetType().FullName
        }
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($bytes)
        }
        return $bytes;
    }

    [byte[]]BuildHeader([uint16]$count) {
        [int]$current = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        [int]$sysuptime = $current - $this.bootup_time
        
        ++$this.flow_seq
        
        [byte[]]$header = $this.GetNetworkOrderBytes([uint16]$this.version)
        $header += $this.GetNetworkOrderBytes([uint16]$count)
        $header += $this.GetNetworkOrderBytes([int32]($current - $this.bootup_time))
        $header += $this.GetNetworkOrderBytes([int32]$current)
        $header += $this.GetNetworkOrderBytes([int32]$this.flow_seq)
        $header += $this.GetNetworkOrderBytes([int32]$this.source_id)
        return $header
    }

    [byte[]]BuildTemplate() {
        [byte[]]$flowset =
            0x00,0x00,0x00,0x4C,0x01,0x00,0x00,0x11,
            0x00,0x01,0x00,0x08,0x00,0x02,0x00,0x04,
            0x00,0x04,0x00,0x01,0x00,0x05,0x00,0x01,
            0x00,0x06,0x00,0x01,0x00,0x07,0x00,0x02,
            0x00,0x08,0x00,0x04,0x00,0x0A,0x00,0x04,
            0x00,0x0B,0x00,0x02,0x00,0x0C,0x00,0x04,
            0x00,0x0E,0x00,0x04,0x00,0x15,0x00,0x04,
            0x00,0x16,0x00,0x04,0x00,0x20,0x00,0x02,
            0x00,0x3D,0x00,0x01,0x00,0x94,0x00,0x08,
            0x00,0xE9,0x00,0x01
        
        return $this.BuildHeader(1) + $flowset
    }

    [byte[][]]BuildTcpConnectionRequest(
      [IPAddress]$client_ip, [uint16]$client_port,
      [IPAddress]$server_ip, [uint16]$server_port 
    ) {
        [int]$current = $(Get-Date -UFormat %s)
        
        ++$this.flow_id
        
        # TCP: > SYN
        [byte[]]$flowset_body =
            $this.GetNetworkOrderBytes([int64]66) + # Octets
            $this.GetNetworkOrderBytes([int32]1) + # Packets
            6 + # Protocol: TCP=6
            0 + # Protocol: IP ToS
            0x02 + # Protocol: TCP Flags
            $this.GetNetworkOrderBytes([uint16]$client_port) + # SrcPort
            $client_ip.GetAddressBytes()[0..3] + # SrcAddr
            $this.GetNetworkOrderBytes([int32]2) + # InputInt
            $this.GetNetworkOrderBytes([uint16]$server_port) + # DstPort
            $server_ip.GetAddressBytes()[0..3] + # DstAddr
            $this.GetNetworkOrderBytes([int32]2) + # OutputInt
            $this.GetNetworkOrderBytes([int32]($current - $this.bootup_time)) + # Duration - EndTime
            $this.GetNetworkOrderBytes([int32]($current - $this.bootup_time)) + # Duration - StartTime
            $this.GetNetworkOrderBytes([int16]0) + # ICMP Type
            0 + # Direction: INGRESS=0
            $this.GetNetworkOrderBytes([int64]$this.flow_id) + # Flow Id
            1 # Firewall Event
        
        [byte[]]$flowset1 = $this.GetNetworkOrderBytes([uint16]256) +
                            $this.GetNetworkOrderBytes([uint16]($flowset_body.Length + 4)) +
                            $flowset_body

        # TCP: > ACK, PSH, SYN
        $flowset_body =
            $this.GetNetworkOrderBytes([int64]60) + # Octets
            $this.GetNetworkOrderBytes([int32]1) + # Packets
            6 + # Protocol: TCP=6
            0 + # Protocol: IP ToS
            0x1a + # Protocol: TCP Flags
            $this.GetNetworkOrderBytes([uint16]$client_port) + # SrcPort
            $client_ip.GetAddressBytes()[0..3] + # SrcAddr
            $this.GetNetworkOrderBytes([int32]2) + # InputInt
            $this.GetNetworkOrderBytes([uint16]$server_port) + # DstPort
            $server_ip.GetAddressBytes()[0..3] + # DstAddr
            $this.GetNetworkOrderBytes([int32]2) + # OutputInt
            $this.GetNetworkOrderBytes([int32]($current - $this.bootup_time)) + # Duration - EndTime
            $this.GetNetworkOrderBytes([int32]($current - $this.bootup_time)) + # Duration - StartTime
            $this.GetNetworkOrderBytes([uint16]0) + # ICMP Type
            0 + # Direction: INGRESS=0
            $this.GetNetworkOrderBytes([int64]$this.flow_id) + # Flow Id
            5 # Firewall Event
        
        [byte[]]$flowset2 = $this.GetNetworkOrderBytes([uint16]256) +
                            $this.GetNetworkOrderBytes([uint16]($flowset_body.Length + 4)) +
                            $flowset_body

        return $flowset1, $flowset2
    }
}

class UdpNetflow : Netflow {
    [System.Net.Sockets.UdpClient]$socket
    [byte[][]]$pending_flowsets
    
    UdpNetflow([string]$netflow_host, [int]$netflow_port) {
        $this.socket = New-Object System.Net.Sockets.UdpClient([int32]0)
        $this.socket.Connect($netflow_host, $netflow_port)
        $this.socket.DontFragment = $true
        $this.pending_flowsets = $null
    }

    [void]SendTemplate() {
        $this.Flush()

        [byte[]]$payload = $this.BuildTemplate()
        [void]$this.socket.Send($payload, $payload.Length)
    }

    [void]SendFlowsets([byte[][]]$flowsets, [bool]$force) {
        $this.pending_flowsets += $flowsets
        
        [int]$limit = 24
        while (($this.pending_flowsets.Length -gt 0) -And
               ($force -Or ($this.pending_flowsets.Length -ge $limit))) {
            $flowsets = $this.pending_flowsets[0..($limit-1)]
            if ($limit -ge $this.pending_flowsets.Length) {
                $this.pending_flowsets = $null
            } else {
              $this.pending_flowsets = $this.pending_flowsets[$limit..($this.pending_flowsets.Length-1)]            
            }
            [byte[]]$payload = $this.BuildHeader($flowsets.Length)
            foreach($flowset in $flowsets) {
                $payload += $flowset
            }
            [void]$this.socket.Send($payload, $payload.Length)
        }
    }

    [void]Flush() {
        $this.SendFlowsets($null, $true)
    }

    [void]Close() {
        $this.socket.Close()
    }
}

class Main {
    [Netflow]$netflow
    
    Main([string]$netflow_protocol, [string]$netflow_host, [int]$netflow_port) {
        switch ($netflow_protocol) {
            "UDP" {
                $this.netflow = [UdpNetflow]::New($netflow_host, $netflow_port)
            }
            default {
                throw "Unknown netflow protocol: " + $netflow_protocol
            }
        }
    }

    hidden [IPAddress[]]GetIpRange([string]$subnet) {
        if (! $subnet -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
            throw "Subnet [$subnet] is not in a valid format"
        }
        # Split IP and subnet
        [string]$subnet_ip = ($subnet -split '\/')[0]
        [int]$subnet_bits = ($subnet -split '\/')[1]
        if ($subnet_bits -lt 7 -or $subnet_bits -gt 30) {
            throw "The number following the / must be between 7 and 30"
        }
        # Convert IP into binary
        # Split IP into different octects and for each one, figure out the binary with leading zeros and add to the total
        [string[]]$octets = $subnet_ip -split '\.'
        [string]$ip_in_binary = ''
        foreach ($octet in $octets) {
            # convert to binary
            [string]$octet_in_binary = [convert]::ToString($octet, 2)

            # get length of binary string add leading zeros to make octet
            $ip_in_binary += ('0' * (8 - ($octet_in_binary).Length) + $octet_in_binary)
        }
        # Get network ID by subtracting subnet mask
        [int]$host_bits = 32 - $subnet_bits
        [string]$network_id_in_binary = $ip_in_binary.Substring(0, $subnet_bits)

        # Get host ID and get the first host ID by converting all 1s into 0s
        [string]$host_id_in_binary = $ip_in_binary.Substring($subnet_bits, $host_bits) -replace '1', '0'

        # Work out all the host IDs in that subnet by cycling through $i from 1 up to max $host_id_in_binary (i.e. 1s stringed up to $host_bits)
        # Work out max $host_id_in_binary
        [int32]$imax = [convert]::ToInt32(('1' * $host_bits), 2) - 1
        [IPAddress[]]$ips = @()

        # Next ID is first network ID converted to decimal plus $i then converted to binary
        for ($i = 1 ; $i -le $imax ; $i++) {
            # Convert to decimal and add $i
            [int32]$next_host_id_in_decimal = [convert]::ToInt32($host_id_in_binary, 2) + $i

            # Convert back to binary
            [string]$next_host_id_in_binary = [convert]::ToString($next_host_id_in_decimal, 2)

            # Add leading zeros
            # Number of zeros to add
            [int]$num_of_zeros_to_add = $host_id_in_binary.Length - $next_host_id_in_binary.Length
            [string]$next_host_id_in_binary = ('0' * $num_of_zeros_to_add) + $next_host_id_in_binary

            # Work out next IP
            # Add networkID to hostID
            [string]$next_ip_in_binary = $network_id_in_binary + $next_host_id_in_binary

            # Split into octets and separate by . then join
            [string[]]$octets = @()
            for ($x = 1 ; $x -le 4 ; $x++) {
                # Work out start character position
                [int]$start_char_number = ($x - 1) * 8

                # Get octet in binary
                [string]$ip_octet_in_binary = $next_ip_in_binary.Substring($start_char_number, 8)

                # Convert octet into decimal
                $ip_octet_in_decimal = [convert]::ToInt32($ip_octet_in_binary, 2)

                # Add octet to IP
                $octets += $ip_octet_in_decimal
            }
            # Separate by .
            [IPAddress]$ip = $octets -join '.'
            $ips += $ip
        }
        return $ips
    }

    [void]Run([IPAddress]$source_ip, [string]$scan_subnet, [bool]$quiet) {
        [IPAddress[]]$dest_ips = $this.GetIpRange($scan_subnet)
        
        $this.netflow.SendTemplate()
        for ($dest_port = 1 ; $dest_port -le 65534 ; ++$dest_port) {
            if (!$quiet) {
                Write-Host "scan: ${source_ip} > ${scan_subnet}:${dest_port}"
            }
            foreach ($dest_ip in $dest_ips) {
                [uint16]$source_port = Get-Random -Minimum 10000 -Maximum 65534
                [byte[][]]$flowsets = $this.netflow.BuildTcpConnectionRequest($source_ip, $source_port, $dest_ip, $dest_port)
                $this.netflow.SendFlowsets($flowsets, $false)
            }
        }
        $this.netflow.Flush()
    }
}

$main = [Main]::New($NetflowProtocol, $NetflowHost, $NetflowPort)
$main.Run([IPAddress]$SourceIP, $ScanSubnet, $Quiet)
