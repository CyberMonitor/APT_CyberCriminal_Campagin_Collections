cmake_minimum_required (VERSION 2.8)

project ( isfb_parser )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	util.cpp
	isfb_parser.cpp
	isfb_to_pe.cpp
)

set (hdrs
	util.h
	isfb_header.h
	isfb_parser.h
	isfb_to_pe.h
)

set (rsrc
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )