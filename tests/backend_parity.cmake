if(NOT EXISTS "${HASHER_EXE}")
  message(FATAL_ERROR "HASHER executable is missing")
endif()
set(input "${CMAKE_CURRENT_BINARY_DIR}/hasher-backend-parity.txt")
file(WRITE "${input}" "\n")
foreach(n 1 55 56 63 64 65 127 128 129 255 256 511 512 1023 1024)
  string(REPEAT "x" ${n} line)
  file(APPEND "${input}" "${line}\n")
endforeach()
set(args
  -sha1 -sha224 -sha256 -sha384 -sha512 -sha512/224 -sha512/256
  -sha3-224 -sha3-256 -sha3-384 -sha3-512
  -keccak-224 -keccak-256 -keccak-384 -keccak-512
  -shake128 -shake256 -cshake128 -cshake256
  -md2 -md4 -md5 -rmd-128 -rmd-160 -rmd-256 -rmd-320
  -blake2b -blake2s -blake3 -xxh128 -sm3
  -kmac128 -kmac256 -kmacxof128 -kmacxof256
  -tuplehash128 -tuplehash256 -tuplehashxof128 -tuplehashxof256
  -parallelhash128 -parallelhash256 -parallelhashxof128 -parallelhashxof256
  -hmac-md5 -hmac-sha1 -hmac-sha224 -hmac-sha256 -hmac-sha384 -hmac-sha512
  -key backend-parity-key -t 1)
execute_process(COMMAND "${HASHER_EXE}" ${args} INPUT_FILE "${input}"
                OUTPUT_VARIABLE automatic RESULT_VARIABLE auto_rc)
execute_process(COMMAND "${CMAKE_COMMAND}" -E env HASHER_FORCE_IMPL=portable "${HASHER_EXE}" ${args}
                INPUT_FILE "${input}" OUTPUT_VARIABLE portable RESULT_VARIABLE portable_rc)
if(NOT auto_rc EQUAL 0 OR NOT portable_rc EQUAL 0 OR NOT automatic STREQUAL portable)
  message(FATAL_ERROR "auto/portable backend parity failed")
endif()
string(REGEX MATCHALL "\n" lines "${automatic}")
list(LENGTH lines count)
math(EXPR expected "16 * 49")
if(NOT count EQUAL expected)
  message(FATAL_ERROR "backend parity produced ${count}, expected ${expected} digest lines")
endif()

foreach(algorithm sha3-224 sha3-256 sha3-384 sha3-512 keccak-224 keccak-256 keccak-384 keccak-512 shake128 shake256 cshake128 cshake256)
  execute_process(COMMAND "${HASHER_EXE}" "-${algorithm}" -t 4 INPUT_FILE "${input}"
                  OUTPUT_VARIABLE batch RESULT_VARIABLE batch_rc)
  execute_process(COMMAND "${CMAKE_COMMAND}" -E env HASHER_FORCE_IMPL=portable "${HASHER_EXE}" "-${algorithm}" -t 4
                  INPUT_FILE "${input}" OUTPUT_VARIABLE scalar RESULT_VARIABLE scalar_rc)
  if(NOT batch_rc EQUAL 0 OR NOT scalar_rc EQUAL 0 OR NOT batch STREQUAL scalar)
    message(FATAL_ERROR "x4/scalar parity failed for ${algorithm}")
  endif()
endforeach()

set(kdfs pbkdf-md5 pbkdf-sha1 pbkdf-sha224 pbkdf-sha256 pbkdf-sha384 pbkdf-sha512
  pbkdf-rmd160 pbkdf-keccak256 pbkdf-keccak512 pbkdf2-hmac-md5 pbkdf2-hmac-sha1
  pbkdf2-hmac-sha224 pbkdf2-hmac-sha256 pbkdf2-hmac-sha384 pbkdf2-hmac-sha512
  evpkdf-md5 evpkdf-sha1 evpkdf-sha224 evpkdf-sha256 evpkdf-sha384 evpkdf-sha512
  evpkdf-rmd160 evpkdf-keccak256 evpkdf-keccak512)
foreach(algorithm IN LISTS kdfs)
  execute_process(COMMAND "${HASHER_EXE}" "-${algorithm}" -salt backend-salt -kiter 2 -t 2 INPUT_FILE "${input}"
                  OUTPUT_VARIABLE kdf_auto RESULT_VARIABLE kdf_auto_rc)
  execute_process(COMMAND "${CMAKE_COMMAND}" -E env HASHER_FORCE_IMPL=portable "${HASHER_EXE}" "-${algorithm}" -salt backend-salt -kiter 2 -t 2
                  INPUT_FILE "${input}" OUTPUT_VARIABLE kdf_portable RESULT_VARIABLE kdf_portable_rc)
  if(NOT kdf_auto_rc EQUAL 0 OR NOT kdf_portable_rc EQUAL 0 OR NOT kdf_auto STREQUAL kdf_portable)
    message(FATAL_ERROR "KDF backend parity failed for ${algorithm}")
  endif()
endforeach()
