cmake_minimum_required(VERSION 3.25)
cmake_policy(SET CMP0091 NEW)
if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
endif()
project(HASHER VERSION 0.1.0 LANGUAGES C CXX)

set(HASHER_EXPECT_ARCH "" CACHE STRING "Expected target architecture")
set(HASHER_PGO "OFF" CACHE STRING "OFF, GENERATE, or USE")
set(HASHER_PGO_PROFILE "" CACHE FILEPATH "Merged LLVM PGO profile")
option(HASHER_ENABLE_LTO "Enable ThinLTO in release builds" ON)
set(HASHER_LTO_MODE "THIN" CACHE STRING "THIN or FULL")
set_property(CACHE HASHER_LTO_MODE PROPERTY STRINGS THIN FULL)
option(HASHER_ENABLE_SANITIZERS "Enable ASan/UBSan in debug builds" ON)
if(NOT HASHER_LTO_MODE MATCHES "^(THIN|FULL)$")
  message(FATAL_ERROR "HASHER_LTO_MODE must be THIN or FULL")
endif()
if(HASHER_LTO_MODE STREQUAL "FULL")
  set(HASHER_LTO_FLAG "-flto=full")
else()
  set(HASHER_LTO_FLAG "-flto=thin")
endif()

if(NOT CMAKE_C_COMPILER_ID MATCHES "^(Clang|AppleClang)$" OR
   NOT CMAKE_CXX_COMPILER_ID MATCHES "^(Clang|AppleClang)$")
  message(FATAL_ERROR "HASHER supports only Clang/LLVM")
endif()
if(CMAKE_C_COMPILER_VERSION VERSION_LESS 21 OR CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 22)
  message(FATAL_ERROR "HASHER requires Clang/AppleClang 21.x")
endif()
if(HASHER_EXPECT_ARCH AND NOT CMAKE_SYSTEM_PROCESSOR MATCHES "${HASHER_EXPECT_ARCH}")
  message(FATAL_ERROR "Target architecture '${CMAKE_SYSTEM_PROCESSOR}' does not match '${HASHER_EXPECT_ARCH}'")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
  find_program(HASHER_MOLD mold REQUIRED)
  add_link_options(-fuse-ld=mold)
endif()
if(WIN32 AND CMAKE_LINKER AND NOT CMAKE_LINKER MATCHES "lld-link(\\.exe)?$")
  message(FATAL_ERROR "Windows builds require lld-link")
endif()

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

set(WITH_LTM OFF CACHE BOOL "" FORCE)
set(WITH_TFM OFF CACHE BOOL "" FORCE)
set(WITH_GMP OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(libtomcrypt
  GIT_REPOSITORY https://github.com/libtom/libtomcrypt.git
  GIT_TAG 6c6d5104de66f3ca0dfd7b68540ef86869982b07
  GIT_SHALLOW FALSE)
FetchContent_MakeAvailable(libtomcrypt)

FetchContent_Declare(blake3_src
  GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
  GIT_TAG 6aab490a26124663329dfd3961b8469f8fdb158b
  GIT_SHALLOW FALSE
  SOURCE_SUBDIR c)
set(BLAKE3_USE_TBB OFF CACHE BOOL "" FORCE)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(AMD64|amd64|x86_64|X86_64)$")
  set(BLAKE3_SIMD_TYPE "x86-intrinsics" CACHE STRING "" FORCE)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64|AArch64)$")
  set(BLAKE3_SIMD_TYPE "neon-intrinsics" CACHE STRING "" FORCE)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64|AArch64)$")
  add_library(sm3_arm_ni STATIC src/hash/sm3_arm_ni.c)
  target_include_directories(sm3_arm_ni PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/hash)
  if(MSVC)
    target_compile_options(sm3_arm_ni PRIVATE /clang:-march=armv8.4-a+sm4)
  else()
    target_compile_options(sm3_arm_ni PRIVATE -march=armv8.4-a+sm4)
  endif()
  target_compile_features(sm3_arm_ni PUBLIC c_std_11)
endif()
FetchContent_MakeAvailable(blake3_src)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(AMD64|amd64|x86_64|X86_64)$")
  target_compile_definitions(blake3 PRIVATE BLAKE3_TESTING=1)
endif()

FetchContent_Declare(blake2_src
  GIT_REPOSITORY https://github.com/BLAKE2/BLAKE2.git
  GIT_TAG ed1974ea83433eba7b2d95c5dcd9ac33cb847913
  GIT_SHALLOW FALSE)
FetchContent_GetProperties(blake2_src)
if(NOT blake2_src_POPULATED)
  FetchContent_Populate(blake2_src)
endif()
set(HASHER_BLAKE2_RENAMES
  blake2b=hasher_fast_blake2b blake2b_init=hasher_fast_blake2b_init
  blake2b_init_key=hasher_fast_blake2b_init_key blake2b_init_param=hasher_fast_blake2b_init_param
  blake2b_update=hasher_fast_blake2b_update blake2b_final=hasher_fast_blake2b_final
  blake2s=hasher_fast_blake2s blake2s_init=hasher_fast_blake2s_init
  blake2s_init_key=hasher_fast_blake2s_init_key blake2s_init_param=hasher_fast_blake2s_init_param
  blake2s_update=hasher_fast_blake2s_update blake2s_final=hasher_fast_blake2s_final)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(AMD64|amd64|x86_64|X86_64)$")
  add_library(blake2_fast STATIC ${blake2_src_SOURCE_DIR}/sse/blake2b.c ${blake2_src_SOURCE_DIR}/sse/blake2s.c)
  target_include_directories(blake2_fast PRIVATE ${blake2_src_SOURCE_DIR}/sse)
  if(MSVC)
    target_compile_options(blake2_fast PRIVATE /clang:-msse4.1)
  else()
    target_compile_options(blake2_fast PRIVATE -msse4.1)
  endif()
  set(HASHER_BLAKE2_KIND HASHER_BLAKE2_FAST_X86=1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64|AArch64)$")
  add_library(blake2_fast STATIC ${blake2_src_SOURCE_DIR}/neon/blake2b.c ${blake2_src_SOURCE_DIR}/neon/blake2s.c)
  target_include_directories(blake2_fast PRIVATE ${blake2_src_SOURCE_DIR}/neon)
  set(HASHER_BLAKE2_KIND HASHER_BLAKE2_FAST_ARM=1)
endif()
if(TARGET blake2_fast)
  target_compile_definitions(blake2_fast PRIVATE ${HASHER_BLAKE2_RENAMES})
  target_compile_features(blake2_fast PUBLIC c_std_11)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(AMD64|amd64|x86_64|X86_64)$")
  add_library(sm3_x86_ni STATIC src/hash/sm3_x86_ni.c)
  target_include_directories(sm3_x86_ni PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/hash)
  if(MSVC)
    target_compile_options(sm3_x86_ni PRIVATE /clang:-msm3 /clang:-mssse3 /clang:-mavx2)
  else()
    target_compile_options(sm3_x86_ni PRIVATE -msm3 -mssse3 -mavx2)
  endif()
  target_compile_features(sm3_x86_ni PUBLIC c_std_11)

  FetchContent_Declare(sha2_intrinsics_src
    GIT_REPOSITORY https://github.com/aws-samples/sha2-with-c-intrinsic.git
    GIT_TAG 35156390899935c8a00b82eebd9ebc0fa8069348
    GIT_SHALLOW FALSE)
  FetchContent_GetProperties(sha2_intrinsics_src)
  if(NOT sha2_intrinsics_src_POPULATED)
    FetchContent_Populate(sha2_intrinsics_src)
  endif()
  add_library(sha512_avx_backend STATIC
    ${sha2_intrinsics_src_SOURCE_DIR}/src/sha512_consts.c
    ${sha2_intrinsics_src_SOURCE_DIR}/src/sha512_compress_x86_64_avx.c)
  target_include_directories(sha512_avx_backend PUBLIC
    ${sha2_intrinsics_src_SOURCE_DIR}/include
    ${sha2_intrinsics_src_SOURCE_DIR}/include/internal)
  target_compile_definitions(sha512_avx_backend PRIVATE X86_64=1)
  if(MSVC)
    target_compile_options(sha512_avx_backend PRIVATE /clang:-mavx)
  else()
    target_compile_options(sha512_avx_backend PRIVATE -mavx)
  endif()
  target_compile_features(sha512_avx_backend PUBLIC c_std_11)
  set(HASHER_HAVE_SHA512_AVX TRUE)
endif()

FetchContent_Declare(xxhash_src
  GIT_REPOSITORY https://github.com/Cyan4973/xxHash.git
  GIT_TAG 1798053afaa7ee83ae21adee5649238be8a66197
  GIT_SHALLOW FALSE)
FetchContent_MakeAvailable(xxhash_src)

FetchContent_Declare(rhash_src
  GIT_REPOSITORY https://github.com/rhash/RHash.git
  GIT_TAG 3dbba4baa3cbdc3baf06d3ba086d8094bd98cd88
  GIT_SHALLOW FALSE)
FetchContent_GetProperties(rhash_src)
if(NOT rhash_src_POPULATED)
  FetchContent_Populate(rhash_src)
endif()
add_library(rhash_fast STATIC
  ${rhash_src_SOURCE_DIR}/librhash/md4.c
  ${rhash_src_SOURCE_DIR}/librhash/md5.c
  ${rhash_src_SOURCE_DIR}/librhash/ripemd-160.c
  src/hash/legacy_rhash.c)
target_include_directories(rhash_fast PRIVATE ${rhash_src_SOURCE_DIR}/librhash src/hash)
target_compile_features(rhash_fast PUBLIC c_std_11)
add_library(xxhash STATIC ${xxhash_src_SOURCE_DIR}/xxhash.c)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(AMD64|amd64|x86_64|X86_64)$")
  target_sources(xxhash PRIVATE ${xxhash_src_SOURCE_DIR}/xxh_x86dispatch.c)
  target_compile_definitions(xxhash PUBLIC HASHER_XXH_X86_DISPATCH=1)
endif()
target_include_directories(xxhash PUBLIC ${xxhash_src_SOURCE_DIR})
target_compile_features(xxhash PUBLIC c_std_11)

FetchContent_Declare(xkcp_src
  GIT_REPOSITORY https://github.com/XKCP/XKCP.git
  GIT_TAG eb5244d6b95fb1c434b211bac293093e18aa8fd1
  GIT_SHALLOW FALSE)
FetchContent_GetProperties(xkcp_src)
if(NOT xkcp_src_POPULATED)
  FetchContent_Populate(xkcp_src)
endif()
add_library(xkcp_keccak STATIC
  ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c)
target_include_directories(xkcp_keccak PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/hash/xkcp
  ${xkcp_src_SOURCE_DIR}/lib/common
  ${xkcp_src_SOURCE_DIR}/lib/low/common
  ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600/common
  ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600/plain-64bits
  ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600/plain-64bits/SnP)
target_compile_features(xkcp_keccak PUBLIC c_std_11)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(AMD64|amd64|x86_64|X86_64)$")
  add_library(xkcp_keccak_x4_avx2 STATIC
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600-times4/AVX2/KeccakP-1600-times4-AVX2.c
    src/hash/keccak_x4_avx2.c)
  target_include_directories(xkcp_keccak_x4_avx2 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash ${CMAKE_CURRENT_SOURCE_DIR}/src/hash/xkcp
    ${xkcp_src_SOURCE_DIR}/lib/common ${xkcp_src_SOURCE_DIR}/lib/low/common
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600/common
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600-times4/AVX2
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600-times4/AVX2/SnP)
  if(MSVC)
    target_compile_options(xkcp_keccak_x4_avx2 PRIVATE /clang:-mavx2)
  else()
    target_compile_options(xkcp_keccak_x4_avx2 PRIVATE -mavx2)
  endif()
  target_compile_features(xkcp_keccak_x4_avx2 PUBLIC c_std_11)
  set(HASHER_HAVE_XKCP_X4_AVX2 TRUE)

  add_library(xkcp_keccak_x4_avx512 STATIC
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600-times4/AVX512/KeccakP-1600-times4-AVX512.c
    src/hash/keccak_x4_avx512.c)
  target_include_directories(xkcp_keccak_x4_avx512 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash ${CMAKE_CURRENT_SOURCE_DIR}/src/hash/xkcp
    ${xkcp_src_SOURCE_DIR}/lib/common ${xkcp_src_SOURCE_DIR}/lib/low/common
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600/common
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600-times4/AVX512
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600-times4/AVX512/SnP)
  if(MSVC)
    target_compile_options(xkcp_keccak_x4_avx512 PRIVATE /clang:-mavx512f /clang:-mavx512vl)
  else()
    target_compile_options(xkcp_keccak_x4_avx512 PRIVATE -mavx512f -mavx512vl)
  endif()
  target_compile_features(xkcp_keccak_x4_avx512 PUBLIC c_std_11)
  set(HASHER_HAVE_XKCP_X4_AVX512 TRUE)

  add_library(xkcp_keccak_avx512 STATIC
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600/AVX512/C/KeccakP-1600-AVX512.c)
  target_include_directories(xkcp_keccak_avx512 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash/xkcp
    ${xkcp_src_SOURCE_DIR}/lib/common
    ${xkcp_src_SOURCE_DIR}/lib/low/common
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600/common
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600/AVX512/C)
  if(MSVC)
    target_compile_options(xkcp_keccak_avx512 PRIVATE /clang:-mavx512f /clang:-mavx512vl)
  else()
    target_compile_options(xkcp_keccak_avx512 PRIVATE -mavx512f -mavx512vl)
  endif()
  target_compile_features(xkcp_keccak_avx512 PUBLIC c_std_11)
  set(HASHER_HAVE_XKCP_AVX512 TRUE)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64|AArch64)$")
  add_library(xkcp_keccak_arm_sha3 STATIC src/hash/keccak_arm_sha3.c)
  target_include_directories(xkcp_keccak_arm_sha3 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash/xkcp
    ${xkcp_src_SOURCE_DIR}/lib/common
    ${xkcp_src_SOURCE_DIR}/lib/low/common
    ${xkcp_src_SOURCE_DIR}/lib/low/KeccakP-1600-times2/ARMv8A)
  if(MSVC)
    target_compile_options(xkcp_keccak_arm_sha3 PRIVATE /clang:-march=armv8.2-a+sha3)
  else()
    target_compile_options(xkcp_keccak_arm_sha3 PRIVATE -march=armv8.2-a+sha3)
  endif()
  target_compile_features(xkcp_keccak_arm_sha3 PUBLIC c_std_11)
  set(HASHER_HAVE_XKCP_ARM_SHA3 TRUE)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64|AArch64)$")
  FetchContent_Declare(gmssl_src
    GIT_REPOSITORY https://github.com/guanzhi/GmSSL.git
    GIT_TAG 24ae482701a7b124826c382fffc55c19f76d475d
    GIT_SHALLOW FALSE)
  FetchContent_GetProperties(gmssl_src)
  if(NOT gmssl_src_POPULATED)
    FetchContent_Populate(gmssl_src)
  endif()
  set(HASHER_SM3_RENAMES
    sm3_compress_blocks=hasher_gmssl_sm3_compress_blocks
    sm3_init=hasher_gmssl_sm3_init
    sm3_update=hasher_gmssl_sm3_update
    sm3_finish=hasher_gmssl_sm3_finish
    sm3_digest=hasher_gmssl_sm3_digest)
  add_library(sm3_fast STATIC
    ${gmssl_src_SOURCE_DIR}/src/sm3_arm64.c
    src/hash/sm3_fast_wrapper.c)
  set(HASHER_SM3_KIND HASHER_SM3_FAST_ARM=1)
endif()
if(TARGET sm3_fast)
  target_include_directories(sm3_fast PRIVATE ${gmssl_src_SOURCE_DIR}/include)
  target_compile_definitions(sm3_fast PRIVATE ${HASHER_SM3_RENAMES})
  target_compile_features(sm3_fast PUBLIC c_std_11)
endif()

add_library(hasher_core STATIC
  src/hash/hash_api.c
  src/hash/evpkdf.c
  src/hash/pbkdf.c
  src/hash/pbkdf2.c
  src/hash/blake3_control.c
  src/hash/keccak_core.c
  src/hash/sha512_fast.c
  src/hash/sp800185.c
  src/runtime/cpu_features.c)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
  target_sources(hasher_core PRIVATE src/hash/sha256_arm.c src/hash/sha512_arm.c)
  if(MSVC)
    set_source_files_properties(src/hash/sha256_arm.c PROPERTIES COMPILE_OPTIONS "/clang:-march=armv8-a+crypto")
    set_source_files_properties(src/hash/sha512_arm.c PROPERTIES COMPILE_OPTIONS "/clang:-march=armv8.2-a+sha3")
  else()
    set_source_files_properties(src/hash/sha256_arm.c PROPERTIES COMPILE_OPTIONS "-march=armv8-a+crypto")
    set_source_files_properties(src/hash/sha512_arm.c PROPERTIES COMPILE_OPTIONS "-march=armv8.2-a+sha3")
  endif()
  target_compile_definitions(hasher_core PRIVATE HASHER_HAVE_ARM_SHA2=1 HASHER_HAVE_SHA512_ARM=1)
endif()
target_include_directories(hasher_core PUBLIC include PRIVATE ${libtomcrypt_SOURCE_DIR}/src/headers)
target_link_libraries(hasher_core PUBLIC libtomcrypt BLAKE3::blake3 xxhash xkcp_keccak rhash_fast)
if(TARGET sm3_x86_ni)
  target_compile_definitions(hasher_core PRIVATE HASHER_SM3_X86_NI=1)
  target_link_libraries(hasher_core PUBLIC sm3_x86_ni)
endif()
if(TARGET sm3_arm_ni)
  target_compile_definitions(hasher_core PRIVATE HASHER_SM3_ARM_NI=1)
  target_link_libraries(hasher_core PUBLIC sm3_arm_ni)
endif()
if(TARGET blake2_fast)
  target_compile_definitions(hasher_core PRIVATE ${HASHER_BLAKE2_KIND})
  target_link_libraries(hasher_core PUBLIC blake2_fast)
endif()
if(TARGET sm3_fast)
  target_compile_definitions(hasher_core PRIVATE ${HASHER_SM3_KIND})
  target_link_libraries(hasher_core PUBLIC sm3_fast)
endif()
if(HASHER_HAVE_XKCP_AVX512)
  target_compile_definitions(hasher_core PRIVATE HASHER_XKCP_AVX512=1)
  target_link_libraries(hasher_core PUBLIC xkcp_keccak_avx512)
endif()
if(HASHER_HAVE_XKCP_X4_AVX2)
  target_compile_definitions(hasher_core PRIVATE HASHER_XKCP_X4_AVX2=1)
  target_link_libraries(hasher_core PUBLIC xkcp_keccak_x4_avx2)
endif()
if(HASHER_HAVE_XKCP_X4_AVX512)
  target_compile_definitions(hasher_core PRIVATE HASHER_XKCP_X4_AVX512=1)
  target_link_libraries(hasher_core PUBLIC xkcp_keccak_x4_avx512)
endif()
if(HASHER_HAVE_XKCP_ARM_SHA3)
  target_compile_definitions(hasher_core PRIVATE HASHER_XKCP_ARM_SHA3=1)
  target_link_libraries(hasher_core PUBLIC xkcp_keccak_arm_sha3)
endif()
if(HASHER_HAVE_SHA512_AVX)
  target_compile_definitions(hasher_core PRIVATE HASHER_HAVE_SHA512_AVX=1 X86_64=1)
  target_include_directories(hasher_core PRIVATE
    ${sha2_intrinsics_src_SOURCE_DIR}/include
    ${sha2_intrinsics_src_SOURCE_DIR}/include/internal)
  target_link_libraries(hasher_core PUBLIC sha512_avx_backend)
endif()
target_compile_definitions(hasher_core PRIVATE XXH_STATIC_LINKING_ONLY _CRT_SECURE_NO_WARNINGS)

add_executable(HASHER src/cli/main.cpp)
target_link_libraries(HASHER PRIVATE hasher_core)
target_compile_definitions(HASHER PRIVATE _CRT_SECURE_NO_WARNINGS)

if(MSVC)
  target_compile_options(hasher_core PRIVATE /W4 /WX /clang:-Wno-inconsistent-dllimport $<$<CONFIG:Release>:/O2> $<$<CONFIG:Release>:/clang:-O3> $<$<AND:$<CONFIG:Release>,$<BOOL:${HASHER_ENABLE_LTO}>>:/clang:${HASHER_LTO_FLAG}>)
  target_compile_options(HASHER PRIVATE /W4 /WX /EHsc- /GR- $<$<CONFIG:Release>:/O2> $<$<CONFIG:Release>:/clang:-O3> $<$<AND:$<CONFIG:Release>,$<BOOL:${HASHER_ENABLE_LTO}>>:/clang:${HASHER_LTO_FLAG}>)
  target_link_options(HASHER PRIVATE $<$<AND:$<CONFIG:Release>,$<BOOL:${HASHER_ENABLE_LTO}>>:/LTCG> $<$<CONFIG:Release>:/OPT:REF> $<$<CONFIG:Release>:/OPT:ICF>)
else()
  target_compile_options(hasher_core PRIVATE -Wall -Wextra -Wpedantic -Werror -fvisibility=hidden -ffunction-sections -fdata-sections $<$<CONFIG:Release>:-O3> $<$<AND:$<CONFIG:Release>,$<BOOL:${HASHER_ENABLE_LTO}>>:${HASHER_LTO_FLAG}>)
  target_compile_options(HASHER PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-exceptions -fno-rtti -fvisibility=hidden -ffunction-sections -fdata-sections $<$<CONFIG:Release>:-O3> $<$<AND:$<CONFIG:Release>,$<BOOL:${HASHER_ENABLE_LTO}>>:${HASHER_LTO_FLAG}>)
  target_link_options(HASHER PRIVATE $<$<AND:$<CONFIG:Release>,$<BOOL:${HASHER_ENABLE_LTO}>>:${HASHER_LTO_FLAG}>)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(HASHER PRIVATE -static-libstdc++ -static-libgcc -Wl,--gc-sections -Wl,--icf=all -Wl,--build-id=sha1)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
    target_link_options(HASHER PRIVATE -Wl,--gc-sections -Wl,--icf=all -Wl,--build-id=sha1)
  elseif(APPLE)
    target_link_options(HASHER PRIVATE -Wl,-dead_strip)
  endif()
endif()

if(HASHER_PGO STREQUAL "GENERATE")
  if(MSVC)
    target_compile_options(hasher_core PRIVATE /clang:-fprofile-instr-generate /clang:-fcoverage-mapping)
    target_compile_options(HASHER PRIVATE /clang:-fprofile-instr-generate /clang:-fcoverage-mapping)
    get_filename_component(HASHER_CLANG_BIN "${CMAKE_C_COMPILER}" DIRECTORY)
    string(REGEX MATCH "^[0-9]+" HASHER_CLANG_MAJOR "${CMAKE_C_COMPILER_VERSION}")
    find_file(HASHER_PROFILE_RUNTIME clang_rt.profile-x86_64.lib
      PATHS "${HASHER_CLANG_BIN}/../lib/clang/${HASHER_CLANG_MAJOR}/lib/windows" NO_DEFAULT_PATH REQUIRED)
    target_link_libraries(HASHER PRIVATE "${HASHER_PROFILE_RUNTIME}")
  else()
    target_compile_options(hasher_core PRIVATE -fprofile-instr-generate -fcoverage-mapping)
    target_compile_options(HASHER PRIVATE -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(HASHER PRIVATE -fprofile-instr-generate)
  endif()
elseif(HASHER_PGO STREQUAL "USE")
  if(NOT HASHER_PGO_PROFILE OR NOT EXISTS "${HASHER_PGO_PROFILE}")
    message(FATAL_ERROR "HASHER_PGO=USE requires HASHER_PGO_PROFILE")
  endif()
  if(MSVC)
    target_compile_options(hasher_core PRIVATE /clang:-fprofile-instr-use=${HASHER_PGO_PROFILE} /clang:-Werror=profile-instr-out-of-date /clang:-Werror=profile-instr-unprofiled)
    target_compile_options(HASHER PRIVATE /clang:-fprofile-instr-use=${HASHER_PGO_PROFILE} /clang:-Werror=profile-instr-out-of-date /clang:-Werror=profile-instr-unprofiled)
  else()
    target_compile_options(hasher_core PRIVATE -fprofile-instr-use=${HASHER_PGO_PROFILE} -Werror=profile-instr-out-of-date -Werror=profile-instr-unprofiled)
    target_compile_options(HASHER PRIVATE -fprofile-instr-use=${HASHER_PGO_PROFILE} -Werror=profile-instr-out-of-date -Werror=profile-instr-unprofiled)
    target_link_options(HASHER PRIVATE -fprofile-instr-use=${HASHER_PGO_PROFILE})
  endif()
elseif(NOT HASHER_PGO STREQUAL "OFF")
  message(FATAL_ERROR "HASHER_PGO must be OFF, GENERATE, or USE")
endif()

if(HASHER_ENABLE_SANITIZERS AND NOT MSVC)
  foreach(target hasher_core HASHER)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Debug>:-fsanitize=address,undefined> $<$<CONFIG:Debug>:-fno-omit-frame-pointer>)
    target_link_options(${target} PRIVATE $<$<CONFIG:Debug>:-fsanitize=address,undefined>)
  endforeach()
endif()

option(HASHER_BUILD_TESTS "Build HASHER tests" ON)
option(HASHER_BUILD_BENCHMARKS "Build HASHER benchmarks" ON)
if(HASHER_BUILD_TESTS)
  enable_testing()
  add_executable(hasher_tests tests/test_hashes.cpp)
  target_link_libraries(hasher_tests PRIVATE hasher_core)
  if(MSVC)
    target_link_options(hasher_tests PRIVATE $<$<AND:$<CONFIG:Release>,$<BOOL:${HASHER_ENABLE_LTO}>>:/LTCG>)
  else()
    target_link_options(hasher_tests PRIVATE $<$<AND:$<CONFIG:Release>,$<BOOL:${HASHER_ENABLE_LTO}>>:${HASHER_LTO_FLAG}>)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      target_link_options(hasher_tests PRIVATE -static-libstdc++ -static-libgcc)
    endif()
    target_compile_options(hasher_tests PRIVATE $<$<AND:$<CONFIG:Debug>,$<BOOL:${HASHER_ENABLE_SANITIZERS}>>:-fsanitize=address,undefined> $<$<AND:$<CONFIG:Debug>,$<BOOL:${HASHER_ENABLE_SANITIZERS}>>:-fno-omit-frame-pointer>)
    target_link_options(hasher_tests PRIVATE $<$<AND:$<CONFIG:Debug>,$<BOOL:${HASHER_ENABLE_SANITIZERS}>>:-fsanitize=address,undefined>)
  endif()
  add_test(NAME hashes COMMAND hasher_tests)
  add_test(NAME hashes_portable COMMAND hasher_tests)
  set_tests_properties(hashes_portable PROPERTIES ENVIRONMENT "HASHER_FORCE_IMPL=portable")
  add_test(NAME hashes_native COMMAND hasher_tests)
  set_tests_properties(hashes_native PROPERTIES ENVIRONMENT "HASHER_FORCE_IMPL=native")
  add_test(NAME cli COMMAND ${CMAKE_COMMAND} -DHASHER_EXE=$<TARGET_FILE:HASHER> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_test.cmake)
  add_test(NAME backend_parity COMMAND ${CMAKE_COMMAND} -DHASHER_EXE=$<TARGET_FILE:HASHER> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/backend_parity.cmake)
  if(TARGET sm3_x86_ni)
    add_executable(sm3_ni_kat EXCLUDE_FROM_ALL tests/test_sm3_ni.c)
    target_link_libraries(sm3_ni_kat PRIVATE sm3_x86_ni)
    target_compile_features(sm3_ni_kat PRIVATE c_std_11)
  endif()
  if(TARGET sm3_arm_ni)
    add_executable(sm3_arm_ni_kat EXCLUDE_FROM_ALL tests/test_sm3_ni.c)
    target_compile_definitions(sm3_arm_ni_kat PRIVATE HASHER_SM3_TEST_HEADER="sm3_arm_ni.h" HASHER_SM3_TEST_FN=hasher_sm3_arm_ni)
    target_link_libraries(sm3_arm_ni_kat PRIVATE sm3_arm_ni)
    target_compile_features(sm3_arm_ni_kat PRIVATE c_std_11)
  endif()
  if(UNIX)
    find_program(HASHER_BASH_EXECUTABLE bash REQUIRED)
    add_test(NAME broken_pipe COMMAND ${HASHER_BASH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/broken_pipe_test.sh $<TARGET_FILE:HASHER>)
  endif()
endif()
if(HASHER_BUILD_BENCHMARKS)
  add_executable(hasher_bench benchmarks/bench_hash.cpp)
  target_link_libraries(hasher_bench PRIVATE hasher_core)
  if(MSVC)
    target_compile_options(hasher_bench PRIVATE /W4 /WX /O2 /EHsc- /GR-)
    target_link_options(hasher_bench PRIVATE $<$<AND:$<CONFIG:Release>,$<BOOL:${HASHER_ENABLE_LTO}>>:/LTCG>)
  else()
    target_compile_options(hasher_bench PRIVATE -Wall -Wextra -Wpedantic -Werror -O3 -fno-exceptions -fno-rtti)
    target_link_options(hasher_bench PRIVATE $<$<AND:$<CONFIG:Release>,$<BOOL:${HASHER_ENABLE_LTO}>>:${HASHER_LTO_FLAG}>)
    target_compile_options(hasher_bench PRIVATE $<$<AND:$<CONFIG:Debug>,$<BOOL:${HASHER_ENABLE_SANITIZERS}>>:-fsanitize=address,undefined> $<$<AND:$<CONFIG:Debug>,$<BOOL:${HASHER_ENABLE_SANITIZERS}>>:-fno-omit-frame-pointer>)
    target_link_options(hasher_bench PRIVATE $<$<AND:$<CONFIG:Debug>,$<BOOL:${HASHER_ENABLE_SANITIZERS}>>:-fsanitize=address,undefined>)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      target_link_options(hasher_bench PRIVATE -static-libstdc++ -static-libgcc)
    endif()
  endif()
  add_executable(hasher_pipe_source benchmarks/pipe_source.c)
  if(MSVC)
    target_compile_definitions(hasher_pipe_source PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(hasher_pipe_source PRIVATE /W4 /WX /O2)
  else()
    target_compile_options(hasher_pipe_source PRIVATE -Wall -Wextra -Wpedantic -Werror -O3)
  endif()
endif()
