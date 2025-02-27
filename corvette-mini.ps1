class Menu {
    [string]$home_dir
    [string]$my_script

    Menu([Management.Automation.InvocationInfo]$info) {
        $this.home_dir = [IO.Path]::GetTempPath()
        if ([string]::IsNullOrEmpty($info.MyCommand.Path)) {
            $this.my_script = $info.MyCommand
        } else {
            $this.my_script = [IO.File]::ReadAllText($info.MyCommand.Path)
        }
    }

    hidden [bool]LaunchCommand($cmd) {
        switch ($cmd) {
            "0" {
                $script_b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($this.my_script))
                Start-Process -FilePath "powershell.exe" -verb runas -ArgumentList @("-e", $script_b64)
            }
            "1" {
                Start-Process -FilePath "explorer.exe" -ArgumentList @($this.home_dir)
            }
            "2" {
                Start-Process -FilePath "cmd.exe" -WorkingDirectory $this.home_dir
            }
            "3" {
                Start-Process -FilePath "powershell.exe" -WorkingDirectory $this.home_dir
            }
            "4" {
                $args = @("/k cd /d `"$($this.home_dir)`"")
                Start-Process -FilePath "cmd.exe" -verb runas -ArgumentList $args
            }
            "5" {
                $args = @("-NoExit", "-Command", "cd `"" + $this.home_dir + "`"")
                Start-Process -FilePath "powershell.exe" -verb runas -ArgumentList $args
            }
            default {
                return $false
            }
        }
        return $true
    }

    [void]OpenMenu() {
        Write-Host "Corvette"
        while ($true) {
            Write-Host "************************************"
            Write-Host " 0) Run as administrator"
            Write-Host " 1) Open an explorer"
            Write-Host " 2) Create a new command shell"
            Write-Host " 3) Create a new powershell"
            Write-Host " 4) Create a new command shell (Run as administrator)"
            Write-Host " 5) Create a new powershell (Run as administrator)"

            while (!$this.LaunchCommand((Read-Host "Please choose a menu item to run"))) {}
        }
    }
}
[Menu]::New($MyInvocation).OpenMenu()
