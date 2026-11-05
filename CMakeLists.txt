cmake_minimum_required(VERSION 3.16)
project(sdc VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

include(GNUInstallDirs)
include(CTest)
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

option(SDC_WITH_OPENSSL  "Build the OpenSSL 3 provider"           ON)
option(SDC_WITH_NETTLE   "Build the Nettle/Hogweed provider"      ON)
option(SDC_WITH_GCRYPT   "Build the libgcrypt provider"           ON)
option(SDC_WITH_LIBOQS   "Build the liboqs (ML-KEM/ML-DSA) provider" ON)
option(SDC_FETCH_LIBOQS  "Download and build liboqs if not found" ON)
option(SDC_BUILD_EXAMPLES "Build examples" ON)
option(SDC_WERROR        "Treat warnings as errors"               OFF)
option(SDC_SANITIZE      "Build with ASan + UBSan"                OFF)

if(SDC_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

add_library(sdc_objs OBJECT
  src/core/sdc.c
  src/core/registry.c
  src/core/alg_table.c
  src/core/encoding.c
  src/core/hybrid.c)
target_include_directories(sdc_objs
  PUBLIC  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(sdc_objs PRIVATE _DEFAULT_SOURCE)
set_target_properties(sdc_objs PROPERTIES C_VISIBILITY_PRESET hidden)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(sdc_objs PRIVATE -Wall -Wextra -Wshadow -Wstrict-prototypes)
  if(SDC_WERROR)
    target_compile_options(sdc_objs PRIVATE -Werror)
  endif()
endif()

set(SDC_LINK_LIBS Threads::Threads)
set(SDC_PC_REQUIRES "")
set(SDC_PC_LIBS_PRIVATE "-lpthread")
set(SDC_PROVIDERS "")

# --- OpenSSL -----------------------------------------------------------------
if(SDC_WITH_OPENSSL)
  find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
  target_sources(sdc_objs PRIVATE src/providers/openssl.c)
  target_compile_definitions(sdc_objs PRIVATE SDC_HAVE_OPENSSL OPENSSL_API_COMPAT=30000 OPENSSL_NO_DEPRECATED)
  target_link_libraries(sdc_objs PRIVATE OpenSSL::Crypto)
  list(APPEND SDC_LINK_LIBS OpenSSL::Crypto)
  string(APPEND SDC_PC_REQUIRES " libcrypto")
  list(APPEND SDC_PROVIDERS openssl)
endif()

# --- Nettle ------------------------------------------------------------------
if(SDC_WITH_NETTLE)
  pkg_check_modules(NETTLE REQUIRED IMPORTED_TARGET nettle>=3.6 hogweed>=3.6)
  find_library(GMP_LIBRARY gmp REQUIRED)
  target_sources(sdc_objs PRIVATE src/providers/nettle.c)
  target_compile_definitions(sdc_objs PRIVATE SDC_HAVE_NETTLE)
  target_link_libraries(sdc_objs PRIVATE PkgConfig::NETTLE)
  list(APPEND SDC_LINK_LIBS PkgConfig::NETTLE ${GMP_LIBRARY})
  string(APPEND SDC_PC_REQUIRES " nettle hogweed")
  string(APPEND SDC_PC_LIBS_PRIVATE " -lgmp")
  list(APPEND SDC_PROVIDERS nettle)
endif()

# --- libgcrypt ---------------------------------------------------------------
if(SDC_WITH_GCRYPT)
  pkg_check_modules(GCRYPT REQUIRED IMPORTED_TARGET libgcrypt>=1.8)
  target_sources(sdc_objs PRIVATE src/providers/gcrypt.c)
  target_compile_definitions(sdc_objs PRIVATE SDC_HAVE_GCRYPT)
  target_link_libraries(sdc_objs PRIVATE PkgConfig::GCRYPT)
  list(APPEND SDC_LINK_LIBS PkgConfig::GCRYPT)
  string(APPEND SDC_PC_REQUIRES " libgcrypt")
  list(APPEND SDC_PROVIDERS gcrypt)
endif()

# --- liboqs ------------------------------------------------------------------
if(SDC_WITH_LIBOQS)
  find_package(liboqs QUIET)
  if(liboqs_FOUND)
    set(SDC_OQS_TARGET OQS::oqs)
  elseif(SDC_FETCH_LIBOQS)
    include(cmake/FetchLiboqs.cmake)
    set(SDC_OQS_TARGET oqs)
  else()
    message(FATAL_ERROR "liboqs not found; install it, set SDC_FETCH_LIBOQS=ON, or SDC_WITH_LIBOQS=OFF")
  endif()
  target_sources(sdc_objs PRIVATE src/providers/liboqs.c)
  target_compile_definitions(sdc_objs PRIVATE SDC_HAVE_LIBOQS)
  target_link_libraries(sdc_objs PRIVATE ${SDC_OQS_TARGET})
  list(APPEND SDC_LINK_LIBS ${SDC_OQS_TARGET})
  string(APPEND SDC_PC_LIBS_PRIVATE " -loqs")
  list(APPEND SDC_PROVIDERS liboqs)
endif()

if(NOT SDC_PROVIDERS)
  message(FATAL_ERROR "At least one SDC_WITH_<provider> must be enabled")
endif()
message(STATUS "SDC providers (default order): ${SDC_PROVIDERS}")

# --- libraries -----------------------------------------------------------------
add_library(sdc SHARED $<TARGET_OBJECTS:sdc_objs>)
add_library(sdc_static STATIC $<TARGET_OBJECTS:sdc_objs>)
foreach(t sdc sdc_static)
  target_include_directories(${t} PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
endforeach()
target_link_libraries(sdc PRIVATE ${SDC_LINK_LIBS})
target_link_libraries(sdc_static PUBLIC ${SDC_LINK_LIBS})
set_target_properties(sdc PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
set_target_properties(sdc_static PROPERTIES OUTPUT_NAME sdc)
add_library(sdc::sdc ALIAS sdc)
add_library(sdc::sdc_static ALIAS sdc_static)

install(TARGETS sdc sdc_static
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/sdc/sdc.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sdc)
configure_file(cmake/sdc.pc.in ${PROJECT_BINARY_DIR}/sdc.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/sdc.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# --- tests & examples ------------------------------------------------------------
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
if(SDC_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
