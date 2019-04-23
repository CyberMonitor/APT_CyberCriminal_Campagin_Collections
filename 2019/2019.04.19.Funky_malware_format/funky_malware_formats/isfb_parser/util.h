#pragma once

#include <Windows.h>

BYTE* load_file(const char *filename, OUT size_t &read_size);
bool dump_to_file(char *filename, BYTE* buffer, size_t buffer_size);
bool validate_ptr(IN const void* buffer_bgn, IN SIZE_T buffer_size, IN const void* field_bgn, IN SIZE_T field_size);
