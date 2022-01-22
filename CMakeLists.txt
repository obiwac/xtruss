cmake_minimum_required(VERSION 3.12)
project(xtruss LANGUAGES C)

include(cmake/setup.cmake)

# Scan the docs directory first, so that when we start calling
# installed_program(), we'll know if we have man pages available
add_subdirectory(doc)

add_compile_definitions(HAVE_CMAKE_H)

add_library(utils STATIC
  ${GENERATED_COMMIT_C})
add_dependencies(utils cmake_commit_c)
add_subdirectory(utils)

add_library(eventloop STATIC
  callback.c timing.c)

add_library(console STATIC
  console.c)

add_library(crypto STATIC)
add_subdirectory(crypto)

add_library(network STATIC
  nullplug.c errsock.c noproxy.c x11disp.c)

foreach(subdir ${platform} ${extra_dirs})
  add_subdirectory(${subdir})
endforeach()

configure_file(cmake/cmake.h.in ${GENERATED_SOURCES_DIR}/cmake.h)
