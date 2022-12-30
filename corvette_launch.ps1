Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

$home_dir = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ".\corvette"))
New-Item -ItemType Directory -Force -Path $home_dir > $null

$path = Join-Path $home_dir "corvette.ps1"
$cli = New-Object Net.WebClient
$cli.DownloadFile("https://raw.githubusercontent.com/spearmin10/corvette/main/corvette.ps1", $path)

. $path
