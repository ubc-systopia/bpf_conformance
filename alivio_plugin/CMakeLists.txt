# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(alivio_plugin alivio_plugin.cc)

if(MSVC)
  target_compile_options(alivio_plugin PRIVATE /W4)
else()
  target_compile_options(alivio_plugin PRIVATE -Wall -Wextra -pedantic)
endif()
