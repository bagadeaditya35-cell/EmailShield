# For the PORTABLE build: creates a desktop shortcut to EmailShield.exe in this folder.
$exe = Join-Path $PSScriptRoot "EmailShield.exe"
$lnk = Join-Path ([Environment]::GetFolderPath("Desktop")) "EmailShield.lnk"
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
$s.TargetPath = $exe; $s.WorkingDirectory = $PSScriptRoot; $s.IconLocation = $exe; $s.Save()
Write-Host "Shortcut created: $lnk"
