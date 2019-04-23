#pragma once
#include "isfb_parser.h"

BYTE* alloc_pe(IN const isfb_hdr &hdr, OUT size_t &out_size);

size_t copy_sections(IN const isfb_hdr &hdr, IN OUT BYTE* buf, IN const size_t buf_size);

size_t copy_headers(IN const isfb_hdr &hdr, IN OUT BYTE* buf, IN const size_t buf_size);

size_t copy_ddirs(IN const isfb_hdr &hdr, IN OUT BYTE* buf, IN const size_t buf_size);

bool isfb_to_pe(const isfb_hdr& hdr, char* filename);
