$url = $(Read-Host -Prompt "Enter URL").Trim();
Write-Host "";
$out = $(Read-Host -Prompt "Enter output file").Trim();
Write-Host "";
if ($url.Length -lt 1 -or $out.Length -lt 1) {
	Write-Host "Both parameters are required";
} else {
	$client = $null;
	try {
		$client = New-Object Net.WebClient;
		$client.DownloadFile($url, $out);
		Write-Host "File was downloaded successfully";
	} catch {
		Write-Host $_.Exception.InnerException.Message;
	} finally {
		if ($client -ne $null) {
			$client.Dispose();
		}
	}
}
