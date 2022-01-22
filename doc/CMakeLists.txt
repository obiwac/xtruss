cmake_minimum_required(VERSION 3.12)
project(putty-documentation LANGUAGES)

# This build script can be run standalone, or included as a
# subdirectory of the main PuTTY cmake build system. If the latter, a
# couple of things change: it has to set variables telling the rest of
# the build system what manpages are available to be installed, and it
# will change whether the 'make doc' target is included in 'make all'.

include(FindGit)
include(FindPerl)
find_program(HALIBUT halibut)

set(doc_outputs)
set(manpage_outputs)

macro(register_manpage title section)
  list(APPEND manpage_outputs ${title}.${section})
  if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Only set this variable if there _is_ a parent scope.
    set(HAVE_MANPAGE_${title}_${section} ON PARENT_SCOPE)
  endif()
endmacro()

macro(manpage title section)
  if(HALIBUT)
    add_custom_command(OUTPUT ${title}.${section}
      COMMAND ${HALIBUT} --man=${title}.${section}
        ${CMAKE_CURRENT_SOURCE_DIR}/mancfg.but
        ${CMAKE_CURRENT_SOURCE_DIR}/man-${title}.but
      DEPENDS
        mancfg.but man-${title}.but)
    register_manpage(${title} ${section})
  elseif(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${title}.${section})
    add_custom_command(OUTPUT ${title}.${section}
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/${title}.${section} ${title}.${section}
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${title}.${section})
    register_manpage(${title} ${section})
  endif()
endmacro()

manpage(xtruss 1)

add_custom_target(manpages ALL DEPENDS ${manpage_outputs})
add_custom_target(doc DEPENDS ${doc_outputs} manpages)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  # If we're doing a cmake from just the doc subdir, we expect the
  # user to want to make all the documentation, including HTML and so
  # forth. (What else would be the point?)
  #
  # But if we're included from the main makefile, then by default we
  # only make the man pages (which are necessary for 'make install'),
  # and we leave everything else to a separate 'make doc' target which
  # the user can invoke if they need to.
  add_custom_target(doc-default ALL DEPENDS doc)
endif()
