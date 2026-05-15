# - Config file for the OpenFHE package
# It defines the following variables
#  OpenFHE_INCLUDE_DIRS - include directories for OpenFHE
#  OpenFHE_LIBRARIES    - libraries to link against
get_filename_component(OpenFHE_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Our library dependencies (contains definitions for IMPORTED targets)
if(NOT OpenFHE_BINARY_DIR)
    include("${OpenFHE_CMAKE_DIR}/OpenFHETargets.cmake")
endif()

# These are IMPORTED targets created by OpenFHETargets.cmake
# set(OpenFHE_INCLUDE "${OpenFHE_CMAKE_DIR}/../../include/openfhe")
# set(OpenFHE_LIBDIR "${OpenFHE_CMAKE_DIR}/../../lib")
set(OpenFHE_INCLUDE "C:/Users/acer/Desktop/abse-android-src/prebuilt/x86_64/include/openfhe")
set(OpenFHE_LIBDIR "C:/Users/acer/Desktop/abse-android-src/prebuilt/x86_64/lib")
set(OpenFHE_LIBRARIES OPENFHEcore;OPENFHEpke;OPENFHEbinfhe  )
set(OpenFHE_STATIC_LIBRARIES   )
set(OpenFHE_SHARED_LIBRARIES OPENFHEcore;OPENFHEpke;OPENFHEbinfhe  )
set(BASE_OPENFHE_VERSION 1.5.1)

set(OPENMP_INCLUDES "")
set(OPENMP_LIBRARIES "")

set(OpenFHE_CXX_FLAGS "-g -DANDROID -fdata-sections -ffunction-sections -funwind-tables -fstack-protector-strong -no-canonical-prefixes -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security   -Wall -Werror -DOPENFHE_VERSION=1.5.1 -O3 -DMATHBACKEND=4 -Wno-unknown-pragmas")
set(OpenFHE_C_FLAGS "-g -DANDROID -fdata-sections -ffunction-sections -funwind-tables -fstack-protector-strong -no-canonical-prefixes -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security  -Wall -Werror -DOPENFHE_VERSION=1.5.1 -O3 -DMATHBACKEND=4 -Wno-unknown-pragmas")

set(OpenFHE_EXE_LINKER_FLAGS "-static-libstdc++ -Wl,--build-id=sha1 -Wl,--no-rosegment -Wl,--no-undefined-version -Wl,--fatal-warnings -Wl,--no-undefined -Qunused-arguments  ")

# CXX info
set(OpenFHE_CXX_STANDARD "17")
set(OpenFHE_CXX_COMPILER_ID "Clang")
set(OpenFHE_CXX_COMPILER_VERSION "19.0.1")

# Build Options
set(OpenFHE_STATIC "OFF")
set(OpenFHE_SHARED "ON")
set(OpenFHE_TCM "OFF")
set(OpenFHE_NTL "OFF")
set(OpenFHE_OPENMP "OFF")
set(OpenFHE_NATIVE_SIZE "64")
set(OpenFHE_CKKS_M_FACTOR "1")
set(OpenFHE_NATIVEOPT "OFF")
set(OpenFHE_NOISEDEBUG "OFF")
set(OpenFHE_REDUCEDNOISE "OFF")

# Math Backend
set(OpenFHE_BACKEND "4")

# Build Details
set(OpenFHE_EMSCRIPTEN "")
set(OpenFHE_ARCHITECTURE "unknown")
set(OpenFHE_BACKEND_FLAGS_BASE "-DMATHBACKEND=4")

# Compile Definitions
if("ON")
    set(OpenFHE_BINFHE_COMPILE_DEFINITIONS "_compile_defs-NOTFOUND")
    set(OpenFHE_CORE_COMPILE_DEFINITIONS "_compile_defs-NOTFOUND")
    set(OpenFHE_PKE_COMPILE_DEFINITIONS "_compile_defs-NOTFOUND")
    set(OpenFHE_COMPILE_DEFINITIONS
        ${OpenFHE_BINFHE_COMPILE_DEFINITIONS}
        ${OpenFHE_CORE_COMPILE_DEFINITIONS}
        ${OpenFHE_PKE_COMPILE_DEFINITIONS})
endif()

if("OFF")
    set(OpenFHE_BINFHE_COMPILE_DEFINITIONS_STATIC "")
    set(OpenFHE_CORE_COMPILE_DEFINITIONS_STATIC "")
    set(OpenFHE_PKE_COMPILE_DEFINITIONS_STATIC "")
    set(OpenFHE_COMPILE_DEFINITIONS_STATIC
        ${OpenFHE_BINFHE_COMPILE_DEFINITIONS_STATIC}
        ${OpenFHE_CORE_COMPILE_DEFINITIONS_STATIC}
        ${OpenFHE_PKE_COMPILE_DEFINITIONS_STATIC})
endif()
