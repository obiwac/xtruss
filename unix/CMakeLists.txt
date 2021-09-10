set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_sources_from_current_dir(utils
  utils/block_signal.c
  utils/cloexec.c
  utils/dputs.c
  utils/filename.c
  utils/fontspec.c
  utils/getticks.c
  utils/nonblock.c
  utils/pollwrap.c
  utils/signal.c
  # We want the ISO C implementation of ltime(), because we don't have
  # a local better alternative
  ../utils/ltime.c)
add_sources_from_current_dir(eventloop
  cliloop.c uxsel.c)
add_sources_from_current_dir(console
  console.c)
add_sources_from_current_dir(network
  network.c peerinfo.c x11.c)

add_executable(xtruss
  uxxtruss.c
  ${CMAKE_SOURCE_DIR}/xtruss.c
  ${CMAKE_SOURCE_DIR}/xtruss-trace.c
  ${CMAKE_SOURCE_DIR}/xtruss-proxy.c
  ${CMAKE_SOURCE_DIR}/xtruss-record.c
  ${CMAKE_SOURCE_DIR}/norand.c)
target_link_libraries(xtruss eventloop console network utils crypto)
installed_program(xtruss)
