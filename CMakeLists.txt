cmake_minimum_required(VERSION 2.6)

if ( NOT UNIX )
    message (FATAL_ERROR "Not Unix!")
endif ()

project(cisco_interfaces C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/")

option(WITH_DEBUG_MODE "Build with debug mode" OFF)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/)
include_directories (${SRC_DIR})

if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/lib/nagios" CACHE PATH "install prefix")
endif()

if(NOT DEFINED InstallPath)
  set(InstallPath "${CMAKE_INSTALL_PREFIX}}/plugins" CACHE PATH "install destination")
endif()


if ( WITH_DEBUG_MODE )
     add_definitions( -DDEBUG=1 )
endif()

set(SOURCES ${SRC_DIR}cisco_interfaces.c ${SRC_DIR}utils.c)
set(HEADERS ${SRC_DIR}cisco_interfaces.h ${SRC_DIR}utils.h)

set(CMAKE_REQUIRED_INCLUDES "/usr/local/include" "/usr/include")

find_package(NetSNMP REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(_OPENSSL QUIET openssl)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})


set(CMAKE_C_FLAGS_WARN "-Wall -Wextra -pedantic -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations")

if ( CMAKE_COMPILER_IS_GNUCC )
    set(CMAKE_C_FLAGS "-std=c99 -g -O2 ${CMAKE_C_FLAGS_WARN} -DNETSNMP_USE_INLINE -DNETSNMP_ENABLE_IPV6 -fno-strict-aliasing -fstack-protector-strong -Werror=format-security -D_REENTRANT -D_GNU_SOURCE -fwrapv -pipe -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2 -DHAVE_POW=1 -DHAVE_GETADDRINFO=1 -Wl,-z,relro -Wl,-z,now -lm")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG -g -O0")
endif ()

set (TARGET check_${PROJECT_NAME})

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} ${NETSNMP_LIBRARIES} ${OPENSSL_LIBRARIES})

set_target_properties (
  ${PROJECT_NAME} PROPERTIES
  COMPILE_FLAGS ""
  OUTPUT_NAME ${TARGET}
)

install(
  TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION ${InstallPath}
)


