cmake_minimum_required(VERSION 3.22.1)

project("pqabse_native_bridge")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(DEFINED ENV{ABSE_ANDROID_PREBUILT_ROOT} AND NOT "$ENV{ABSE_ANDROID_PREBUILT_ROOT}" STREQUAL "")
    set(_abse_prebuilt_base "$ENV{ABSE_ANDROID_PREBUILT_ROOT}")
else()
    set(_abse_prebuilt_base "C:/Users/acer/Desktop/abse-android-src/prebuilt")
endif()

set(ABSE_ANDROID_PREBUILT_ROOT "${_abse_prebuilt_base}/${ANDROID_ABI}" CACHE PATH "ABI-specific ABSE Android prebuilt root")
set(ABSE_PREBUILT_AVAILABLE OFF)

set(_liboqs_lib "${ABSE_ANDROID_PREBUILT_ROOT}/lib/liboqs.a")
set(_openfhe_core_lib "${ABSE_ANDROID_PREBUILT_ROOT}/lib/libOPENFHEcore_static.a")
set(_openfhe_pke_lib "${ABSE_ANDROID_PREBUILT_ROOT}/lib/libOPENFHEpke_static.a")
set(_openfhe_binfhe_lib "${ABSE_ANDROID_PREBUILT_ROOT}/lib/libOPENFHEbinfhe_static.a")
set(_openfhe_core_type STATIC)
set(_openfhe_pke_type STATIC)
set(_openfhe_binfhe_type STATIC)
set(_prebuilt_include_root "${ABSE_ANDROID_PREBUILT_ROOT}/include")

if(NOT EXISTS "${_openfhe_core_lib}" AND EXISTS "${ABSE_ANDROID_PREBUILT_ROOT}/lib/libOPENFHEcore.so")
    set(_openfhe_core_lib "${ABSE_ANDROID_PREBUILT_ROOT}/lib/libOPENFHEcore.so")
    set(_openfhe_core_type SHARED)
endif()

if(NOT EXISTS "${_openfhe_pke_lib}" AND EXISTS "${ABSE_ANDROID_PREBUILT_ROOT}/lib/libOPENFHEpke.so")
    set(_openfhe_pke_lib "${ABSE_ANDROID_PREBUILT_ROOT}/lib/libOPENFHEpke.so")
    set(_openfhe_pke_type SHARED)
endif()

if(NOT EXISTS "${_openfhe_binfhe_lib}" AND EXISTS "${ABSE_ANDROID_PREBUILT_ROOT}/lib/libOPENFHEbinfhe.so")
    set(_openfhe_binfhe_lib "${ABSE_ANDROID_PREBUILT_ROOT}/lib/libOPENFHEbinfhe.so")
    set(_openfhe_binfhe_type SHARED)
endif()

if(EXISTS "${_liboqs_lib}" AND EXISTS "${_openfhe_core_lib}" AND EXISTS "${_openfhe_pke_lib}" AND EXISTS "${_openfhe_binfhe_lib}" AND EXISTS "${_prebuilt_include_root}")
    set(ABSE_PREBUILT_AVAILABLE ON)
endif()

add_library(
    pqabse_native_bridge
    SHARED
    pqabse_native_bridge.cpp
)

find_library(log-lib log)

if(ABSE_PREBUILT_AVAILABLE)
    add_library(oqs STATIC IMPORTED)
    set_target_properties(oqs PROPERTIES IMPORTED_LOCATION "${_liboqs_lib}")

    add_library(openfhe_core ${_openfhe_core_type} IMPORTED)
    set_target_properties(openfhe_core PROPERTIES IMPORTED_LOCATION "${_openfhe_core_lib}")

    add_library(openfhe_pke ${_openfhe_pke_type} IMPORTED)
    set_target_properties(openfhe_pke PROPERTIES IMPORTED_LOCATION "${_openfhe_pke_lib}")

    add_library(openfhe_binfhe ${_openfhe_binfhe_type} IMPORTED)
    set_target_properties(openfhe_binfhe PROPERTIES IMPORTED_LOCATION "${_openfhe_binfhe_lib}")

    target_include_directories(
        pqabse_native_bridge
        PRIVATE
        "${_prebuilt_include_root}"
        "${_prebuilt_include_root}/openfhe"
        "${_prebuilt_include_root}/openfhe/core"
    )

    target_compile_definitions(
        pqabse_native_bridge
        PRIVATE
        PQABSE_PREBUILT_AVAILABLE=1
        PQABSE_PREBUILT_ABI="${ANDROID_ABI}"
        PQABSE_PREBUILT_ROOT="${ABSE_ANDROID_PREBUILT_ROOT}"
    )

    target_link_libraries(
        pqabse_native_bridge
        oqs
        openfhe_core
        openfhe_pke
        openfhe_binfhe
        ${log-lib}
    )
else()
    target_compile_definitions(
        pqabse_native_bridge
        PRIVATE
        PQABSE_PREBUILT_AVAILABLE=0
        PQABSE_PREBUILT_ABI="${ANDROID_ABI}"
        PQABSE_PREBUILT_ROOT="${ABSE_ANDROID_PREBUILT_ROOT}"
    )

    target_link_libraries(
        pqabse_native_bridge
        ${log-lib}
    )
endif()
