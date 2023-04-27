class Menu {
    [string]$home_dir
    
    Menu() {
        $this.home_dir = [IO.Path]::GetTempPath()
    }

    hidden [bool]LaunchCommand($cmd) {
        switch ($cmd) {
            "c" {
                Remove-Item -Path $this.props.home_dir -Recurse -Force -ErrorAction SilentlyContinue
                New-Item -ItemType Directory -Force -Path $this.props.home_dir
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
            Write-Host " c) Cleanup the working directory"
            Write-Host " 1) Open an explorer"
            Write-Host " 2) Create a new command shell"
            Write-Host " 3) Create a new powershell"
            Write-Host " 4) Create a new command shell (Run as administrator)"
            Write-Host " 5) Create a new powershell (Run as administrator)"

            while (!$this.LaunchCommand((Read-Host "Please choose a menu item to run"))) {}
        }
    }
}

[Menu]::New().OpenMenu()
