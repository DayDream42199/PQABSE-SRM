cmake_minimum_required(VERSION 3.22.1)

project(abse_android_bridge_example)

include("${CMAKE_CURRENT_LIST_DIR}/ABSEAndroidPrebuilt.cmake")

add_library(
  abse_android_bridge_example
  SHARED
  # Replace these with the real Android JNI wrapper source and any repo sources
  # you decide to vendor into the app-native build.
  ${CMAKE_CURRENT_LIST_DIR}/placeholder.cpp
)

target_include_directories(abse_android_bridge_example PRIVATE
  ${ABSE_ANDROID_PREBUILT_INCLUDE_DIRS}
)

target_link_libraries(abse_android_bridge_example
  oqs
  OPENFHEcore
)
