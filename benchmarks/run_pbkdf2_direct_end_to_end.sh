#!/usr/bin/env bash
set -eo pipefail
export LC_ALL=C
build_dir=${1:?build directory required}
input=${2:?input file required}
output=${3:?output CSV required}
runs=${4:-3}
rounds=${5:-1}
exe="$build_dir/HASHER"
lines=$(wc -l < "$input")
algorithms=(pbkdf2-md5 pbkdf2-sha1 pbkdf2-sha224 pbkdf2-sha256 pbkdf2-sha384
 pbkdf2-sha512 pbkdf2-rmd160 pbkdf2-keccak256 pbkdf2-keccak512)
printf 'algorithm,kdf_iterations,mode,seconds,lines_per_second\n' > "$output"
for algorithm in "${algorithms[@]}"; do
 for mode in file pipe; do
  times=()
  for ((run=0;run<runs;++run)); do
   start=$(perl -MTime::HiRes=time -e 'print time')
   if [[ $mode == file ]]; then
    "$exe" "-$algorithm" -salt benchmark-salt -kiter "$rounds" -i "$input" >/dev/null
   else
    "$exe" "-$algorithm" -salt benchmark-salt -kiter "$rounds" < "$input" >/dev/null
   fi
   end=$(perl -MTime::HiRes=time -e 'print time')
   times+=("$(perl -e 'print $ARGV[1]-$ARGV[0]' "$start" "$end")")
  done
  median=$(printf '%s\n' "${times[@]}" | sort -n | sed -n "$((runs/2+1))p")
  throughput=$(perl -e 'printf "%.0f",$ARGV[0]/$ARGV[1]' "$lines" "$median")
  printf '%s,%s,%s,%.6f,%s\n' "$algorithm" "$rounds" "$mode" "$median" "$throughput" >> "$output"
 done
done
