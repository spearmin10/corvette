Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

$home_dir = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ".\corvette"))
New-Item -ItemType Directory -Force -Path $home_dir > $null

$path = Join-Path $home_dir "corvette.ps1"
while ($true) {
    try {
        $cli = New-Object Net.WebClient
        $bin = $cli.DownloadData("https://raw.githubusercontent.com/spearmin10/corvette/main/corvette.ps1")
        if (![IO.File]::Exists($path) -Or ![Linq.Enumerable]::SequenceEqual([IO.File]::ReadAllBytes($path), $bin)) {
            Get-ChildItem -Path $home_dir -Exclude @("corvette.json","corvette.ps1") | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            [IO.File]::WriteAllBytes($path, $bin)
        }
        . $path
        break
    } catch {
        Write-Host $_
        Read-Host "Hit any keys to retry"
    }
}
