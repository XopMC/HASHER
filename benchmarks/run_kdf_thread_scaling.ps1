param([Parameter(Mandatory=$true)][string]$Exe,[Parameter(Mandatory=$true)][string]$InputFile,[Parameter(Mandatory=$true)][string]$Output,[int]$Runs=3)
$Exe=(Resolve-Path $Exe).Path;$InputFile=(Resolve-Path $InputFile).Path
$algorithms=@('hmac-md5','hmac-sha1','hmac-sha224','hmac-sha256','hmac-sha384','hmac-sha512',
'pbkdf-md5','pbkdf-sha1','pbkdf-sha224','pbkdf-sha256','pbkdf-sha384','pbkdf-sha512','pbkdf-rmd160','pbkdf-keccak256','pbkdf-keccak512',
'pbkdf2-hmac-md5','pbkdf2-hmac-sha1','pbkdf2-hmac-sha224','pbkdf2-hmac-sha256','pbkdf2-hmac-sha384','pbkdf2-hmac-sha512',
'evpkdf-md5','evpkdf-sha1','evpkdf-sha224','evpkdf-sha256','evpkdf-sha384','evpkdf-sha512','evpkdf-rmd160','evpkdf-keccak256','evpkdf-keccak512')
$lines=0;foreach($ignored in [IO.File]::ReadLines((Resolve-Path $InputFile))){$lines++}
'algorithm,threads,seconds,lines_per_second' | Set-Content -Encoding ascii $Output
foreach($algorithm in $algorithms){$extra=@();if($algorithm.StartsWith('hmac-')){$extra=@('-key','benchmark-key')}elseif($algorithm.StartsWith('pbkdf')-or $algorithm.StartsWith('evpkdf')){$extra=@('-salt','benchmark-salt','-kiter','1')}
 foreach($threads in 1,2,4,8){$times=@();for($run=0;$run-lt$Runs;$run++){$sw=[Diagnostics.Stopwatch]::StartNew();$extraText=$extra-join' ';$cmd='""'+$Exe+'" -'+$algorithm+' '+$extraText+' -t '+$threads+' -i "'+$InputFile+'" > NUL"';& $env:ComSpec /d /s /c $cmd;$sw.Stop();if($LASTEXITCODE-ne 0){throw "$algorithm failed"};$times+=$sw.Elapsed.TotalSeconds};$median=($times|Sort-Object)[[int][Math]::Floor($Runs/2)];$rate=[Math]::Round($lines/$median);"$algorithm,$threads,$($median.ToString('F6',[Globalization.CultureInfo]::InvariantCulture)),$rate"|Add-Content -Encoding ascii $Output}}
