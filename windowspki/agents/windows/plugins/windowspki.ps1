Write-Host '<<<windowspki:sep(0)>>>'
Import-Module PSPKI
$ca_hostname=$env:computername
$UnixEpoch = (Get-Date -Date "01/01/1970") ;
$start = (Get-Date).AddDays(-60)

foreach ($_ in Get-IssuedRequest -CertificationAuthority $ca_hostname -Filter "NotAfter -ge $start") {
  If ($_.CommonName) {$subject = $_.CommonName.Replace("`n",",")}
  Else {$subject = $_.SerialNumber}

  if ($_.CertificateTemplateOid.FriendlyName -notlike "*IEEE802-1x Client Authentication*" -And
    $_.CertificateTemplateOid.Value -ne "Machine" -And
    $_.CertificateTemplateOid.FriendlyName -ne "SCCM Client Certicate"
  ){
    $data = [ordered]@{
      starts = (New-TimeSpan -Start $UnixEpoch -End $_.NotBefore).TotalSeconds ;
      expires = (New-TimeSpan -Start $UnixEpoch -End $_.NotAfter).TotalSeconds ;
      subj = $subject ;
      serial = $_.SerialNumber ;
    }
  $data | ConvertTo-Json -Compress
  }
}