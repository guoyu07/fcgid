project(fcgid)

cmake_minimum_required(VERSION 2.6)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(LIBPHENOM_PATH "" CACHE PATH "Path for libphenom")
if (NOT LIBPHENOM_PATH)
    message(SEND_ERROR
        "Please specify libphenom path with -DLIBPHENOM_PATH=/path/to/libphenom")
endif(NOT LIBPHENOM_PATH)

include_directories(${LIBPHENOM_PATH}/include)
link_directories(${LIBPHENOM_PATH}/lib)

set(CMAKE_INSTALL_RPATH "${LIBPHENOM_PATH}/lib")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

add_subdirectory(src)
