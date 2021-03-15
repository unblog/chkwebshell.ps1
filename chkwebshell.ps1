# PowerShell Script to Search for Forensic Artifacts. Detect malicious code on Exchange Server 
# which could compromise the system, this after zero day vulnerabilities or exploitation of Hafnium webshell injection.
# Run on Exchange Server Verion 2013/2016/2019 to Detect Hafnium webshells are present.
Write-Host "Determine zero day vulnerabilities and webshell injection ..." -fore yellow
$wroot = "$Env:SystemDrive\inetpub\wwwroot\aspnet_client\"
$Path1 = "$Env:ExchangeInstallPath\FrontEnd\HttpProxy\ecp\auth\TimeoutLogout.aspx"
$Path2 = "$Env:ExchangeInstallPath\FrontEnd\HttpProxy\owa\auth\Current\"
$Path3 = "$Env:ExchangeInstallPath\FrontEnd\HttpProxy\owa\auth\"
Write-Host "wwwroot should not contain .aspx files under path $wroot" -fore yellow
$Files = @(Get-ChildItem $wroot -Recurse -Include *.aspx)
if ($Files.length -eq 0) {
  Write-Host "No malicious files found." -fore green
} else {
  Write-Host "ATTENTION! malicious files found." -fore red
}
Write-Host
Get-ChildItem -path $wroot -Recurse -Include *.aspx
Write-Host "checking $Path1" -fore yellow
Get-ChildItem -path $Path1
$FileDate1 = Get-ChildItem $Path1 -Include @("*.aspx") | Where-Object { $_.CreationTime -ge "03/02/2021" }
if ($FileDate1.length -eq 0) {
  Write-Host "No newer file found." -fore green
} else {
  Write-Host "ATTENTION! $FileDate1 is newer since installation!" -fore red
}
$FileDate2 = Get-ChildItem $Path1 -Include @("*.aspx") | Where-Object { $_.LastWriteTime -ge "03/02/2021" }
if ($FileDate2.length -eq 0) {
  Write-Host "file was not modified." -fore green
} else {
  Write-Host "ATTENTION! $FileDate2 was modified!" -fore red
}
Write-Host "check if TimeoutLogout.aspx is legit! (should not have been modified (2.3.2021 (CET))." -fore yellow
Get-ChildItem -path $Path2
Write-Host "This path should not contain .aspx files." -fore yellow
$Version = Get-ChildItem -Path "$Env:ExchangeInstallPath\FrontEnd\HttpProxy\owa\auth\" -directory | Where-Object { $_.Name -match '^\d+[\.]\d[\.]\d+$' } | Sort-Object
Get-ChildItem $Path3$Version
Write-Host "This path should not contain .aspx files." -fore yellow
Get-ChildItem -path $Path3 -Recurse -Include *.aspx
Write-Host "Newer files e.g. after 2nd of March 2021 that do not belong to the installation!" -fore green
