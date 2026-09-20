#!/usr/bin/env bash
set -eo pipefail
export LC_ALL=C
build_dir=${1:?build directory required};input=${2:?input file required};output=${3:?output CSV required};runs=${4:-3}
exe="$build_dir/HASHER";pipe_source="$build_dir/hasher_pipe_source";lines=$(wc -l < "$input")
algorithms=(hmac-md5 hmac-sha1 hmac-sha224 hmac-sha256 hmac-sha384 hmac-sha512
 pbkdf-md5 pbkdf-sha1 pbkdf-sha224 pbkdf-sha256 pbkdf-sha384 pbkdf-sha512 pbkdf-rmd160 pbkdf-keccak256 pbkdf-keccak512
 pbkdf2-hmac-md5 pbkdf2-hmac-sha1 pbkdf2-hmac-sha224 pbkdf2-hmac-sha256 pbkdf2-hmac-sha384 pbkdf2-hmac-sha512
 evpkdf-md5 evpkdf-sha1 evpkdf-sha224 evpkdf-sha256 evpkdf-sha384 evpkdf-sha512 evpkdf-rmd160 evpkdf-keccak256 evpkdf-keccak512)
printf 'algorithm,mode,seconds,lines_per_second\n' > "$output"
for algorithm in "${algorithms[@]}";do extra=();case "$algorithm" in hmac-*)extra=(-key benchmark-key);;pbkdf*|evpkdf*)extra=(-salt benchmark-salt -kiter 1);;esac
 for mode in file pipe;do times=();for((run=0;run<runs;++run));do start=$(perl -MTime::HiRes=time -e 'print time');if [[ $mode == file ]];then "$exe" "-$algorithm" "${extra[@]}" -i "$input" >/dev/null;else "$pipe_source" "$input"|"$exe" "-$algorithm" "${extra[@]}" >/dev/null;fi;end=$(perl -MTime::HiRes=time -e 'print time');times+=("$(perl -e 'print $ARGV[1]-$ARGV[0]' "$start" "$end")");done
 median=$(printf '%s\n' "${times[@]}"|sort -n|sed -n "$((runs/2+1))p");throughput=$(perl -e 'printf "%.0f",$ARGV[0]/$ARGV[1]' "$lines" "$median");printf '%s,%s,%.6f,%s\n' "$algorithm" "$mode" "$median" "$throughput" >> "$output";done;done
