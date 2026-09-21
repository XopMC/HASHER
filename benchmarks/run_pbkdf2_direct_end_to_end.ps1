param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$PipeSource,
  [Parameter(Mandatory=$true)][string]$InputFile,
  [Parameter(Mandatory=$true)][string]$Output,
  [int]$Runs=3,
  [UInt64]$KdfIterations=1
)
$Exe=(Resolve-Path $Exe).Path;$PipeSource=(Resolve-Path $PipeSource).Path;$InputFile=(Resolve-Path $InputFile).Path
$algorithms=@('pbkdf2-md5','pbkdf2-sha1','pbkdf2-sha224','pbkdf2-sha256',
 'pbkdf2-sha384','pbkdf2-sha512','pbkdf2-rmd160','pbkdf2-keccak256','pbkdf2-keccak512')
$lines=0;foreach($ignored in [IO.File]::ReadLines($InputFile)){$lines++}
'algorithm,kdf_iterations,mode,seconds,lines_per_second'|Set-Content -Encoding ascii $Output
foreach($algorithm in $algorithms){foreach($mode in 'file','pipe'){$times=@();for($run=0;$run-lt$Runs;$run++){
 $args='-'+$algorithm+' -salt benchmark-salt -kiter '+$KdfIterations
 $command=if($mode-eq'file'){'""'+$Exe+'" '+$args+' -i "'+$InputFile+'" > NUL"'}else{'""'+$PipeSource+'" "'+$InputFile+'" | "'+$Exe+'" '+$args+' > NUL"'}
 $sw=[Diagnostics.Stopwatch]::StartNew();& $env:ComSpec /d /s /c $command;$sw.Stop();if($LASTEXITCODE-ne 0){throw "$algorithm failed"};$times+=$sw.Elapsed.TotalSeconds}
 $median=($times|Sort-Object)[[int][Math]::Floor($Runs/2)];$rate=[Math]::Round($lines/$median)
 "$algorithm,$KdfIterations,$mode,$($median.ToString('F6',[Globalization.CultureInfo]::InvariantCulture)),$rate"|Add-Content -Encoding ascii $Output}}
