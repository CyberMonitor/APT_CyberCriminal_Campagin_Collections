cmake_minimum_required (VERSION 2.8)

project ( lotus_parser )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	file_util.cpp
	lotus_headers.cpp
	lotus_print.cpp
)

set (hdrs
	file_util.h
	lotus_headers.h
	lotus_print.h
)

set (rsrc
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )

