$home_dir = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ".\corvette"))
Get-ChildItem -Path $home_dir -Exclude @("corvette.json") | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

while ($true) {
    try {
        & ([ScriptBlock]::Create([Net.WebClient]::New().DownloadString('https://github.com/spearmin10/corvette/blob/main/corvette.ps1?raw=true')))
        break
    } catch {
        Write-Host $_
        Read-Host "Hit any keys to retry"
    }
}
