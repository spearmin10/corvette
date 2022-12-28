class Menu {
    [string]$home_dir
    
    Menu() {
        $this.home_dir = [IO.Path]::GetTempPath()
    }

    hidden [bool]LaunchCommand($cmd) {
        switch ($cmd) {
            "1" {
                Start-Process -FilePath cmd.exe -WorkingDirectory $this.home_dir
            }
            "2" {
                Start-Process -FilePath powershell.exe -WorkingDirectory $this.home_dir
            }
            "3" {
                $args = @("/k cd /d `"$($this.home_dir)`"")
                Start-Process -FilePath cmd.exe -verb runas -ArgumentList $args
            }
            "4" {
                $args = @("-NoExit", "-Command", "cd `"" + $this.home_dir + "`"")
                Start-Process -FilePath powershell.exe -verb runas -ArgumentList $args
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
            Write-Host " 1) Create a new command shell"
            Write-Host " 2) Create a new powershell"
            Write-Host " 3) Create a new command shell (Run as administrator)"
            Write-Host " 4) Create a new powershell (Run as administrator)"

            while (!$this.LaunchCommand((Read-Host "Please choose a menu item to run"))) {}
        }
    }
}

[Menu]::New().OpenMenu()
