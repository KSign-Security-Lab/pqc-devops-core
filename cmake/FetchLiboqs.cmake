# Download and build a minimal static liboqs (ML-KEM + ML-DSA only).
include(FetchContent)

set(SDC_LIBOQS_TAG "0.12.0" CACHE STRING "liboqs git tag to fetch")

set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(OQS_DIST_BUILD ON CACHE BOOL "" FORCE)
set(OQS_MINIMAL_BUILD
    "KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
    CACHE STRING "" FORCE)

# liboqs honours BUILD_SHARED_LIBS; build it static and PIC so it can be
# linked into both libsdc.so and libsdc.a.
set(_sdc_saved_shared ${BUILD_SHARED_LIBS})
set(BUILD_SHARED_LIBS OFF)

FetchContent_Declare(liboqs
  GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
  GIT_TAG        ${SDC_LIBOQS_TAG}
  GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(liboqs)

set(BUILD_SHARED_LIBS ${_sdc_saved_shared})

# liboqs generates its public headers into the build tree but does not
# attach that directory to the `oqs` target's build interface.
target_include_directories(oqs INTERFACE $<BUILD_INTERFACE:${liboqs_BINARY_DIR}/include>)
