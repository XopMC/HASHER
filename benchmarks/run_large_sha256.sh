#!/usr/bin/env bash
set -euo pipefail
build_dir=${1:?build directory required}
input=${2:?input required}
actual_output=${3:-/tmp/hasher-sha256-output.txt}
runs=${4:-5}
now() { perl -MTime::HiRes=time -e 'print time'; }
elapsed() { perl -e 'printf "%.6f",$ARGV[1]-$ARGV[0]' "$1" "$2"; }
for mode in file pipe; do
  for ((run=0; run<runs; ++run)); do
    start=$(now)
    if [[ $mode == file ]]; then
      "$build_dir/HASHER" -sha256 -i "$input" >/dev/null
    else
      "$build_dir/hasher_pipe_source" "$input" | "$build_dir/HASHER" -sha256 >/dev/null
    fi
    end=$(now)
    printf 'sha256,%s,%s\n' "$mode" "$(elapsed "$start" "$end")"
  done
done
start=$(now)
"$build_dir/HASHER" -sha256 -i "$input" > "$actual_output"
end=$(now)
printf 'sha256,actual-output,%s\n' "$(elapsed "$start" "$end")"
wc -c < "$actual_output"
tail -c 1 "$actual_output" | od -An -tu1
