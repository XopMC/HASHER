param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$InputFile,
  [Parameter(Mandatory=$true)][string]$Output,
  [int]$Runs=3,
  [UInt64]$KdfIterations=100
)
$Exe=(Resolve-Path $Exe).Path
$InputFile=(Resolve-Path $InputFile).Path
$algorithms=@('pbkdf2-md5','pbkdf2-sha1','pbkdf2-sha224','pbkdf2-sha256',
  'pbkdf2-sha384','pbkdf2-sha512','pbkdf2-rmd160','pbkdf2-keccak256','pbkdf2-keccak512')
$lines=0;foreach($ignored in [IO.File]::ReadLines($InputFile)){$lines++}
'algorithm,kdf_iterations,threads,seconds,lines_per_second' | Set-Content -Encoding ascii $Output
foreach($algorithm in $algorithms){
 foreach($threads in 1,2,4,8){
  $times=@()
  for($run=0;$run-lt$Runs;$run++){
   $sw=[Diagnostics.Stopwatch]::StartNew()
   $cmd='""'+$Exe+'" -'+$algorithm+' -salt benchmark-salt -kiter '+$KdfIterations+' -t '+$threads+' -i "'+$InputFile+'" > NUL"'
   & $env:ComSpec /d /s /c $cmd
   $sw.Stop()
   if($LASTEXITCODE-ne 0){throw "$algorithm failed"}
   $times+=$sw.Elapsed.TotalSeconds
  }
  $median=($times|Sort-Object)[[int][Math]::Floor($Runs/2)]
  $rate=[Math]::Round($lines/$median)
  "$algorithm,$KdfIterations,$threads,$($median.ToString('F6',[Globalization.CultureInfo]::InvariantCulture)),$rate" | Add-Content -Encoding ascii $Output
 }
}
