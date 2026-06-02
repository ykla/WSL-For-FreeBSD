# Standalone CMake project for the FreeBSD-side hvinit / hvbridge.
#
# This file is INTENTIONALLY NOT pulled in by the root ../CMakeLists.txt
# (which builds the WSL Windows host). The FreeBSD guest helpers are
# built natively on a FreeBSD host with the hvs(4) driver available.
#
# Build it on a FreeBSD system (or a FreeBSD jail/Docker image) with:
#
#   cmake -S FreeBSD -B FreeBSD/build -DCMAKE_BUILD_TYPE=Release
#   cmake --build FreeBSD/build
#
# Targets:
#   hvinit   - LX_INIT responder that runs as PID 1 inside the FreeBSD VM
#   hvbridge - per-instance PTY + echo bridge listening on AF_HYPERV:60000
#
# If you are on a non-FreeBSD host you can still configure this project
# to verify that the sources parse, but linking will fail (libutil /
# AF_HYPERV are FreeBSD-only). In that case use `make -C FreeBSD` on a
# FreeBSD system instead.

cmake_minimum_required(VERSION 3.20)
project(wslfb_freebsd_guest C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    message(WARNING
        "wslfb_freebsd_guest is intended to be built on FreeBSD. "
        "Detected host: ${CMAKE_SYSTEM_NAME}. Linking will fail unless "
        "you provide a FreeBSD sysroot and the hvs(4)/libutil dependencies.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_compile_options(-Wall -Wextra -Werror -Wno-unused-parameter)

find_library(LIBUTIL_LIB NAMES util REQUIRED)

add_executable(hvinit hvinit.c)
target_link_libraries(hvinit PRIVATE ${LIBUTIL_LIB})

add_executable(hvbridge hvbridge.c)
target_link_libraries(hvbridge PRIVATE ${LIBUTIL_LIB})

set_target_properties(hvinit hvbridge PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
