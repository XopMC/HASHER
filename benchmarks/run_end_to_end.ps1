param(
  [Parameter(Mandatory=$true)][string]$BuildDir,
  [Parameter(Mandatory=$true)][string]$InputFile,
  [Parameter(Mandatory=$true)][string]$Output,
  [int]$Runs=3
)
$exe=(Resolve-Path "$BuildDir/HASHER.exe").Path
$source=(Resolve-Path "$BuildDir/hasher_pipe_source.exe").Path
$inputPath=(Resolve-Path $InputFile).Path
$lines=0;foreach($ignored in [IO.File]::ReadLines($inputPath)){$lines++}
$algorithms=@(
  'sha1','sha224','sha256','sha384','sha512','sha512/224','sha512/256',
  'sha3-224','sha3-256','sha3-384','sha3-512','keccak-224','keccak-256','keccak-384','keccak-512',
  'shake128','shake256','cshake128','cshake256','md2','md4','md5',
  'rmd-128','rmd-160','rmd-256','rmd-320','blake2b','blake2s','blake3','xxh128','sm3',
  'kmac128','kmac256','kmacxof128','kmacxof256',
  'tuplehash128','tuplehash256','tuplehashxof128','tuplehashxof256',
  'parallelhash128','parallelhash256','parallelhashxof128','parallelhashxof256',
  'hmac-md5','hmac-sha1','hmac-sha224','hmac-sha256','hmac-sha384','hmac-sha512',
  'pbkdf-md5','pbkdf-sha1','pbkdf-sha224','pbkdf-sha256','pbkdf-sha384','pbkdf-sha512','pbkdf-rmd160','pbkdf-keccak256','pbkdf-keccak512',
  'pbkdf2-md5','pbkdf2-sha1','pbkdf2-sha224','pbkdf2-sha256','pbkdf2-sha384','pbkdf2-sha512','pbkdf2-rmd160','pbkdf2-keccak256','pbkdf2-keccak512',
  'pbkdf2-hmac-md5','pbkdf2-hmac-sha1','pbkdf2-hmac-sha224','pbkdf2-hmac-sha256','pbkdf2-hmac-sha384','pbkdf2-hmac-sha512',
  'evpkdf-md5','evpkdf-sha1','evpkdf-sha224','evpkdf-sha256','evpkdf-sha384','evpkdf-sha512','evpkdf-rmd160','evpkdf-keccak256','evpkdf-keccak512'
)
'algorithm,mode,seconds,lines_per_second'|Set-Content -Encoding ascii $Output
foreach($algorithm in $algorithms){
  $extra=@()
  if($algorithm -like 'kmac*' -or $algorithm -like 'hmac-*'){$extra=@('-key','benchmark-key')}
  elseif($algorithm -like 'pbkdf*' -or $algorithm -like 'evpkdf*'){$extra=@('-salt','benchmark-salt','-kiter','1')}
  foreach($mode in 'file','pipe'){
    $times=@()
    for($run=0;$run-lt$Runs;$run++){
      $sw=[Diagnostics.Stopwatch]::StartNew()
      $extraText=$extra-join' '
      if($mode-eq'file') {
        $cmd='""'+$exe+'" -'+$algorithm+' '+$extraText+' -i "'+$inputPath+'" > NUL"'
      } else {
        $cmd='""'+$source+'" "'+$inputPath+'" | "'+$exe+'" -'+$algorithm+' '+$extraText+' > NUL"'
      }
      & $env:ComSpec /d /s /c $cmd
      $sw.Stop();if($LASTEXITCODE-ne 0){throw "$algorithm/$mode failed"}
      $times+=$sw.Elapsed.TotalSeconds
    }
    $median=($times|Sort-Object)[[int][Math]::Floor($Runs/2)]
    $rate=[Math]::Round($lines/$median)
    "$algorithm,$mode,$($median.ToString('F6',[Globalization.CultureInfo]::InvariantCulture)),$rate"|Add-Content -Encoding ascii $Output
  }
}
