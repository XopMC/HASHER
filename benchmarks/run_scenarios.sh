#!/usr/bin/env bash
set -eo pipefail
export LC_ALL=C

build_dir=${1:?build directory required}
input=${2:?input file required}
output=${3:?output CSV required}
runs=${4:-3}
exe="$build_dir/HASHER"
pipe_source="$build_dir/hasher_pipe_source"
all='-sha1 -sha224 -sha256 -sha384 -sha512 -sha512/224 -sha512/256 -sha3-224 -sha3-256 -sha3-384 -sha3-512 -keccak-224 -keccak-256 -keccak-384 -keccak-512 -shake128 -shake256 -cshake128 -cshake256 -md2 -md4 -md5 -rmd-128 -rmd-160 -rmd-256 -rmd-320 -blake2b -blake2s -blake3 -xxh128 -sm3 -kmac128 -kmac256 -kmacxof128 -kmacxof256 -tuplehash128 -tuplehash256 -tuplehashxof128 -tuplehashxof256 -parallelhash128 -parallelhash256 -parallelhashxof128 -parallelhashxof256 -hmac-md5 -hmac-sha1 -hmac-sha224 -hmac-sha256 -hmac-sha384 -hmac-sha512 -pbkdf-md5 -pbkdf-sha1 -pbkdf-sha224 -pbkdf-sha256 -pbkdf-sha384 -pbkdf-sha512 -pbkdf-rmd160 -pbkdf-keccak256 -pbkdf-keccak512 -pbkdf2-hmac-md5 -pbkdf2-hmac-sha1 -pbkdf2-hmac-sha224 -pbkdf2-hmac-sha256 -pbkdf2-hmac-sha384 -pbkdf2-hmac-sha512 -evpkdf-md5 -evpkdf-sha1 -evpkdf-sha224 -evpkdf-sha256 -evpkdf-sha384 -evpkdf-sha512 -evpkdf-rmd160 -evpkdf-keccak256 -evpkdf-keccak512 -key benchmark-key -salt benchmark-salt -kiter 1'
scenarios=(
  'sha256+sha512|-sha256 -sha512'
  'ten|-sha1 -sha256 -sha512 -sha3-256 -keccak-256 -md5 -rmd-160 -blake2b -blake3 -xxh128'
  "all|$all"
  'sha256-iter10|-sha256 -iter 10'
  'sha256-iter1_3-5|-sha256 -iter 1,3-5'
)

printf 'scenario,mode,run,seconds\n' > "$output"
for spec in "${scenarios[@]}"; do
  name=${spec%%|*}
  read -r -a args <<< "${spec#*|}"
  for mode in file pipe; do
    for ((run=1; run<=runs; ++run)); do
      start=$(date +%s%N)
      if [[ $mode == file ]]; then
        "$exe" "${args[@]}" -i "$input" >/dev/null
      else
        "$pipe_source" "$input" | "$exe" "${args[@]}" >/dev/null
      fi
      end=$(date +%s%N)
      seconds=$(awk "BEGIN {printf \"%.6f\",($end-$start)/1000000000}")
      printf '%s,%s,%s,%s\n' "$name" "$mode" "$run" "$seconds" >> "$output"
    done
  done
done
