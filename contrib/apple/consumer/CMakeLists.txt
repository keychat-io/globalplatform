cmake_minimum_required(VERSION 3.13)
project(gp_callback_link C)
set(CMAKE_MACOSX_BUNDLE OFF)
find_package(globalplatform CONFIG REQUIRED)
add_executable(gp_callback_smoke_normal callback-smoke.c)
target_link_libraries(gp_callback_smoke_normal PRIVATE globalplatform::globalplatform)
add_executable(gp_callback_smoke callback-smoke.c)
target_link_libraries(gp_callback_smoke PRIVATE globalplatform::globalplatform)
# Pull every SDK object into the executable, covering unresolved references in
# paths the smoke entry point does not call. Do not strip unreachable functions.
target_link_options(gp_callback_smoke PRIVATE
  "LINKER:-force_load,$<TARGET_FILE:globalplatform::globalplatform>")
