#!/usr/bin/env bash
set -eo pipefail
export LC_ALL=C

build_dir=${1:?build directory required}
input=${2:?input file required}
output=${3:?output CSV required}
runs=${4:-3}
exe="$build_dir/HASHER"
lines=$(wc -l < "$input")
algorithms=(
  sha1 sha224 sha256 sha384 sha512 sha512/224 sha512/256
  sha3-224 sha3-256 sha3-384 sha3-512 keccak-224 keccak-256 keccak-384 keccak-512
  shake128 shake256 cshake128 cshake256 md2 md4 md5
  rmd-128 rmd-160 rmd-256 rmd-320 blake2b blake2s blake3 xxh128 sm3
  kmac128 kmac256 kmacxof128 kmacxof256
  tuplehash128 tuplehash256 tuplehashxof128 tuplehashxof256
  parallelhash128 parallelhash256 parallelhashxof128 parallelhashxof256
  hmac-md5 hmac-sha1 hmac-sha224 hmac-sha256 hmac-sha384 hmac-sha512
  pbkdf-md5 pbkdf-sha1 pbkdf-sha224 pbkdf-sha256 pbkdf-sha384 pbkdf-sha512 pbkdf-rmd160 pbkdf-keccak256 pbkdf-keccak512
  pbkdf2-md5 pbkdf2-sha1 pbkdf2-sha224 pbkdf2-sha256 pbkdf2-sha384 pbkdf2-sha512 pbkdf2-rmd160 pbkdf2-keccak256 pbkdf2-keccak512
  pbkdf2-hmac-md5 pbkdf2-hmac-sha1 pbkdf2-hmac-sha224 pbkdf2-hmac-sha256 pbkdf2-hmac-sha384 pbkdf2-hmac-sha512
  evpkdf-md5 evpkdf-sha1 evpkdf-sha224 evpkdf-sha256 evpkdf-sha384 evpkdf-sha512 evpkdf-rmd160 evpkdf-keccak256 evpkdf-keccak512)

printf 'algorithm,threads,seconds,lines_per_second\n' > "$output"
for algorithm in "${algorithms[@]}"; do
  extra=()
  case "$algorithm" in kmac*|hmac-*) extra=(-key-utf8 benchmark-key);; esac
  case "$algorithm" in pbkdf*|evpkdf*) extra=(-salt benchmark-salt -kiter 1);; esac
  for threads in 1 2 4 8; do
    times=()
    for ((run=0; run<runs; ++run)); do
      start=$(perl -MTime::HiRes=time -e 'print time')
      "$exe" "-$algorithm" "${extra[@]}" -t "$threads" -i "$input" >/dev/null
      end=$(perl -MTime::HiRes=time -e 'print time')
      times+=("$(perl -e 'printf "%.6f",$ARGV[1]-$ARGV[0]' "$start" "$end")")
    done
    median=$(printf '%s\n' "${times[@]}" | sort -n | sed -n "$((runs/2+1))p")
    throughput=$(awk "BEGIN {printf \"%.0f\",$lines/$median}")
    printf '%s,%s,%s,%s\n' "$algorithm" "$threads" "$median" "$throughput" >> "$output"
  done
done
