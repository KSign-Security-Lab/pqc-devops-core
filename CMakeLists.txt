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
find_package(Threads REQUIRED)

option(SDC_WERROR        "Treat warnings as errors"               OFF)

add_library(sdc_objs OBJECT
  src/core/sdc.c
  src/core/registry.c
  src/core/alg_table.c)
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
set(SDC_PROVIDERS "")

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
