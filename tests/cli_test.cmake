if(NOT EXISTS "${HASHER_EXE}")
  message(FATAL_ERROR "HASHER executable is missing")
endif()
set(tmp "${CMAKE_CURRENT_BINARY_DIR}/hasher-cli-test.txt")

function(run out rc)
  execute_process(COMMAND "${HASHER_EXE}" ${ARGN} INPUT_FILE "${tmp}"
                  OUTPUT_VARIABLE value ERROR_VARIABLE error RESULT_VARIABLE code)
  set(${out} "${value}" PARENT_SCOPE)
  set(${rc} "${code}" PARENT_SCOPE)
endfunction()

file(WRITE "${tmp}" "abc\n")
run(got rc -sha256 -t 1)
set(want "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n")
if(NOT rc EQUAL 0 OR NOT got STREQUAL want)
  message(FATAL_ERROR "default SHA-256 contract failed")
endif()

run(serial rc1 -sha256 -sha512 -md5 -iter 1,3-5 -t 1)
run(parallel rc8 -sha256 -sha512 -md5 -iter 1,3-5 -t 8)
if(NOT rc1 EQUAL 0 OR NOT rc8 EQUAL 0 OR NOT serial STREQUAL parallel)
  message(FATAL_ERROR "thread determinism failed")
endif()
string(REGEX MATCHALL "\n" lines "${serial}")
list(LENGTH lines line_count)
if(NOT line_count EQUAL 12 OR serial MATCHES "[\t ]")
  message(FATAL_ERROR "one-digest-per-line contract failed")
endif()

run(iter2 iter2rc -sha256 -iter 2)
if(NOT iter2rc EQUAL 0 OR NOT iter2 STREQUAL "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358\n")
  message(FATAL_ERROR "binary iteration chain failed")
endif()
run(dedup deduprc -sha256 -sha256)
if(NOT deduprc EQUAL 0 OR NOT dedup STREQUAL want)
  message(FATAL_ERROR "duplicate algorithm was not canonicalized")
endif()
run(explicit explicitrc -sha1)
if(NOT explicitrc EQUAL 0 OR NOT explicit STREQUAL "a9993e364706816aba3e25717850c26c9cd0d89d\n")
  message(FATAL_ERROR "explicit algorithm did not disable default SHA-256")
endif()
foreach(pair IN ITEMS "keccak256;keccak-256" "rmd160;rmd-160" "rmd256;rmd-256" "rmd260;rmd-256" "turplehash128;tuplehash128")
  list(GET pair 0 alias)
  list(GET pair 1 canonical)
  run(alias_out alias_rc "-${alias}")
  run(canonical_out canonical_rc "-${canonical}")
  if(NOT alias_rc EQUAL 0 OR NOT canonical_rc EQUAL 0 OR NOT alias_out STREQUAL canonical_out)
    message(FATAL_ERROR "alias -${alias} does not match -${canonical}")
  endif()
endforeach()

set(tmp2 "${CMAKE_CURRENT_BINARY_DIR}/hasher-cli-test-2.txt")
file(WRITE "${tmp2}" "def\n")
execute_process(COMMAND "${HASHER_EXE}" -sha256 -i "${tmp}" -i "${tmp2}"
                OUTPUT_VARIABLE multi RESULT_VARIABLE multirc)
string(REGEX MATCHALL "\n" multi_lines "${multi}")
list(LENGTH multi_lines multi_count)
if(NOT multirc EQUAL 0 OR NOT multi_count EQUAL 2)
  message(FATAL_ERROR "multi-file input failed")
endif()

file(WRITE "${tmp}" "616263\n")
run(hexout hexrc -sha256 -hex)
if(NOT hexrc EQUAL 0 OR NOT hexout STREQUAL want)
  message(FATAL_ERROR "hex input failed")
endif()
file(WRITE "${tmp}" "123\n")
run(odd_hex odd_hex_rc -sha256 -hex)
if(NOT odd_hex_rc EQUAL 0 OR NOT odd_hex STREQUAL "b71de80778f2783383f5d5a3028af84eab2f18a4eb38968172ca41724dd4b3f4\n")
  message(FATAL_ERROR "odd hex left-padding failed")
endif()

string(REPEAT "a" 1024 first)
file(WRITE "${tmp}" "${first}CR-is-past-limit\n")
run(longout longrc -sha256 -t 1)
file(WRITE "${tmp}" "${first}\n")
run(truncated trc -sha256 -t 1)
if(NOT longrc EQUAL 0 OR NOT trc EQUAL 0 OR NOT longout STREQUAL truncated)
  message(FATAL_ERROR "1024-byte truncation failed")
endif()

string(REPEAT "a" 1023 crprefix)
file(WRITE "${tmp}" "${crprefix}\rdiscarded-tail\n")
run(crlimit crrc -sha256 -t 1)
if(NOT crrc EQUAL 0 OR NOT crlimit STREQUAL "0e9d2f73e97662c9a156111ea556fc536782043f2a1cd69fecbe3b69cab64c9d\n")
  message(FATAL_ERROR "CR at truncation boundary failed")
endif()

file(WRITE "${tmp}" "")
run(empty emptyrc -sha256)
if(NOT emptyrc EQUAL 0 OR NOT empty STREQUAL "")
  message(FATAL_ERROR "empty source must produce no records")
endif()
file(WRITE "${tmp}" "abc")
run(final finalrc -sha256)
if(NOT finalrc EQUAL 0 OR NOT final STREQUAL want)
  message(FATAL_ERROR "final line without LF failed")
endif()
file(WRITE "${tmp}" "\n")
run(emptyline elrc -sha256)
if(NOT elrc EQUAL 0 OR NOT emptyline STREQUAL "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")
  message(FATAL_ERROR "empty input line failed")
endif()

file(WRITE "${tmp}" "abg\n")
run(permissive_hex permissive_hex_rc -sha256 -hex)
if(NOT permissive_hex_rc EQUAL 0 OR NOT permissive_hex STREQUAL "184f7ab2b2c219b5e7bb0492c91a02f88274d93d1ae8467fcb9ae775bec2f5ee\n")
  message(FATAL_ERROR "permissive hex input failed")
endif()
run(invalid_len invalid_len_rc -sha256 -out-len 16)
run(invalid_threads invalid_threads_rc -sha256 -t 9)
run(invalid_key invalid_key_rc -hmac-sha256 -key-utf8 a -key-hex 62)
run(invalid_typo invalid_typo_rc -snake128)
run(invalid_kdf_param invalid_kdf_param_rc -sha256 -kiter 2)
if(invalid_len_rc EQUAL 0 OR invalid_threads_rc EQUAL 0 OR invalid_key_rc EQUAL 0 OR invalid_typo_rc EQUAL 0 OR invalid_kdf_param_rc EQUAL 0)
  message(FATAL_ERROR "invalid CLI input was accepted")
endif()

execute_process(COMMAND "${HASHER_EXE}" -h OUTPUT_VARIABLE h RESULT_VARIABLE hrc)
execute_process(COMMAND "${HASHER_EXE}" -help OUTPUT_VARIABLE help RESULT_VARIABLE helprc)
if(NOT hrc EQUAL 0 OR NOT helprc EQUAL 0 OR NOT h STREQUAL help)
  message(FATAL_ERROR "help aliases differ")
endif()
set(help_options
  -h -help -i -hex -iter -t -key -key-utf8 -key-hex -func -func-hex
  -custom -len -bsize -seed -function-name-utf8
  -function-name-hex -custom-utf8 -custom-hex -out-len -block-size -seed-hex
  -sha1 -sha224 -sha256 -sha384 -sha512 -sha512/224 -sha512/256
  -sha3-224 -sha3-256 -sha3-384 -sha3-512 -keccak-224 -keccak-256
  -keccak-384 -keccak-512 -shake128 -shake256 -cshake128 -cshake256
  -md2 -md4 -md5 -rmd-128 -rmd-160 -rmd-256 -rmd-320 -blake2b
  -blake2s -blake3 -xxh128 -sm3 -kmac128 -kmac256 -kmacxof128
  -kmacxof256 -tuplehash128 -tuplehash256 -tuplehashxof128 -tuplehashxof256
  -parallelhash128 -parallelhash256 -parallelhashxof128 -parallelhashxof256
  -hmac-md5 -hmac-sha1 -hmac-sha224 -hmac-sha256 -hmac-sha384 -hmac-sha512
  -salt -salt-hex -kiter
  -pbkdf-md5 -pbkdf-sha1 -pbkdf-sha224 -pbkdf-sha256 -pbkdf-sha384 -pbkdf-sha512
  -pbkdf-rmd160 -pbkdf-keccak256 -pbkdf-keccak512
  -pbkdf2-md5 -pbkdf2-sha1 -pbkdf2-sha224 -pbkdf2-sha256 -pbkdf2-sha384 -pbkdf2-sha512
  -pbkdf2-rmd160 -pbkdf2-keccak256 -pbkdf2-keccak512
  -pbkdf2-hmac-md5 -pbkdf2-hmac-sha1 -pbkdf2-hmac-sha224 -pbkdf2-hmac-sha256
  -pbkdf2-hmac-sha384 -pbkdf2-hmac-sha512
  -evpkdf-md5 -evpkdf-sha1 -evpkdf-sha224 -evpkdf-sha256 -evpkdf-sha384 -evpkdf-sha512
  -evpkdf-rmd160 -evpkdf-keccak256 -evpkdf-keccak512)
foreach(option IN LISTS help_options)
  string(FIND "${h}" "${option}" position)
  if(position EQUAL -1)
    message(FATAL_ERROR "help is missing ${option}")
  endif()
endforeach()

file(WRITE "${tmp}" "abc\n")
run(short_key short_key_rc -hmac-sha256 -key secret)
run(long_key long_key_rc -hmac-sha256 -key-utf8 secret)
run(empty_key empty_key_rc -hmac-sha256)
run(empty_kmac empty_kmac_rc -kmac128)
string(LENGTH "${empty_kmac}" empty_kmac_len)
run(short_cshake short_cshake_rc -cshake128 -func App -custom Test -len 48)
run(long_cshake long_cshake_rc -cshake128 -function-name-utf8 App -custom-utf8 Test -out-len 48)
run(short_parallel short_parallel_rc -parallelhash128 -bsize 64 -len 48)
run(long_parallel long_parallel_rc -parallelhash128 -block-size 64 -out-len 48)
run(short_seed short_seed_rc -xxh128 -seed 1234)
run(long_seed long_seed_rc -xxh128 -seed-hex 1234)
if(NOT short_key_rc EQUAL 0 OR NOT long_key_rc EQUAL 0 OR NOT short_key STREQUAL long_key OR
   NOT empty_key_rc EQUAL 0 OR NOT empty_key STREQUAL "fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351\n" OR
   NOT empty_kmac_rc EQUAL 0 OR NOT empty_kmac_len EQUAL 65 OR
   NOT short_cshake_rc EQUAL 0 OR NOT long_cshake_rc EQUAL 0 OR NOT short_cshake STREQUAL long_cshake OR
   NOT short_parallel_rc EQUAL 0 OR NOT long_parallel_rc EQUAL 0 OR NOT short_parallel STREQUAL long_parallel OR
   NOT short_seed_rc EQUAL 0 OR NOT long_seed_rc EQUAL 0 OR NOT short_seed STREQUAL long_seed)
  message(FATAL_ERROR "short parameter aliases do not match long forms")
endif()

file(WRITE "${tmp}" "password\n")
run(pbkdf1 pbkdf1_rc -pbkdf-sha256 -salt salt -kiter 2)
run(pbkdf2_direct pbkdf2_direct_rc -pbkdf2-sha256 -salt salt -kiter 2 -len 32)
run(pbkdf2 pbkdf2_rc -pbkdf2-hmac-sha256 -salt salt -kiter 2 -len 32)
run(evpkdf evpkdf_rc -evpkdf-md5 -salt saltsalt -kiter 1 -len 32)
run(pbkdf2_alias pbkdf2_alias_rc -pbkdf-hmac-sha256 -salt salt -kiter 2 -len 32)
if(NOT pbkdf1_rc EQUAL 0 OR NOT pbkdf1 STREQUAL "a6b9d96cc74d52749372886896349c07e2137fe8788b496d76f6d56e49a9bd52\n" OR
   NOT pbkdf2_direct_rc EQUAL 0 OR NOT pbkdf2_direct STREQUAL "eb81bb537eb16b0b73d0ad1ed9fb8727a6138a8c7c4b69496028e39d2ea0375a\n" OR
   NOT pbkdf2_rc EQUAL 0 OR NOT pbkdf2 STREQUAL "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43\n" OR
   NOT evpkdf_rc EQUAL 0 OR NOT evpkdf STREQUAL "fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f2\n" OR
   NOT pbkdf2_alias_rc EQUAL 0 OR NOT pbkdf2_alias STREQUAL pbkdf2)
  message(FATAL_ERROR "KDF CLI contract failed")
endif()
