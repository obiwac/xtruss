include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckCSourceCompiles)
include(GNUInstallDirs)

set(CMAKE_REQUIRED_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS}
  -D_DEFAULT_SOURCE -D_GNU_SOURCE)

check_symbol_exists(CLOCK_MONOTONIC "time.h" HAVE_CLOCK_MONOTONIC)
check_symbol_exists(clock_gettime "time.h" HAVE_CLOCK_GETTIME)

check_c_source_compiles("
#define _GNU_SOURCE
#include <features.h>
#include <sys/socket.h>
int main(int argc, char **argv) {
    struct ucred cr;
    socklen_t crlen = sizeof(cr);
    return getsockopt(0, SOL_SOCKET, SO_PEERCRED, &cr, &crlen) +
           cr.pid + cr.uid + cr.gid;
}" HAVE_SO_PEERCRED)

function(add_optional_system_lib library testfn)
  check_library_exists(${library} ${testfn} "" HAVE_LIB${library})
  if (HAVE_LIB${library})
    set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES};-l${library})
    link_libraries(-l${library})
  endif()
endfunction()

add_optional_system_lib(m pow)
add_optional_system_lib(rt clock_gettime)
add_optional_system_lib(xnet socket)

if(STRICT AND (CMAKE_C_COMPILER_ID MATCHES "GNU" OR
               CMAKE_C_COMPILER_ID MATCHES "Clang"))
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wpointer-arith -Wvla")
endif()

function(installed_program target)
  if(CMAKE_VERSION VERSION_LESS 3.14)
    # CMake 3.13 and earlier required an explicit install destination.
    install(TARGETS ${target} RUNTIME DESTINATION bin)
  else()
    # 3.14 and above selects a sensible default, which we should avoid
    # overriding here so that end users can override it using
    # CMAKE_INSTALL_BINDIR.
    install(TARGETS ${target})
  endif()

  if(HAVE_MANPAGE_${target}_1)
    install(FILES ${CMAKE_BINARY_DIR}/doc/${target}.1
      DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
  else()
    message(WARNING "Could not build man page ${target}.1")
  endif()
endfunction()
