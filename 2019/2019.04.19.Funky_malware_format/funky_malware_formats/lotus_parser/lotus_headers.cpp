#include "lotus_headers.h"
#include <iostream>

bool lotus::decode_file(IN OUT BYTE* content, IN size_t content_size)
{
	lotus::header1_t* hdr1 = lotus::get_hdr1(content, content_size);
	if (!hdr1) return false;

	DWORD xor_val[2] = { 0 };
	xor_val[0] = hdr1->xor_val1;
	xor_val[1] = hdr1->xor_val2;
	if (xor_val[0] == 0 && xor_val[1] == 0) return true; // already decoded

	DWORD* dwcontent_ptr = (DWORD*)content;
	const size_t dwcontent_size = content_size / sizeof(DWORD);
	for (size_t i = 0; i < dwcontent_size; i++) {
		dwcontent_ptr[i] ^= xor_val[i%2];
	}
	return true;
}

lotus::header1_t* lotus::get_hdr1(IN BYTE* content, IN size_t content_size)
{
	if (content_size < sizeof(lotus::header1_t)) {
		return nullptr;
	}
	return (lotus::header1_t*)content;
}

BYTE* lotus::get_code(IN BYTE* content, IN size_t content_size, OUT size_t &code_size)
{
	lotus::header1_t *hdr = get_hdr1(content, content_size);
	if (!hdr) return nullptr;
	if (hdr->code_size + sizeof(lotus::header1_t) > content_size) {
		return nullptr;
	}
	BYTE *ptr = (BYTE*)hdr + sizeof(lotus::header1_t);
	code_size = hdr->code_size;
	return ptr;
}

lotus::header2_t* lotus::get_hdr2(IN BYTE* content, IN size_t content_size)
{
	lotus::header1_t* hdr1 = get_hdr1(content, content_size);
	if (!hdr1) {
		return nullptr;
	}
	size_t offset = hdr1->code_size + sizeof(lotus::header1_t);
	if (offset + sizeof(lotus::header2_t) > content_size) {
		return nullptr;
	}
	BYTE *ptr = content + offset;
	return (lotus::header2_t*)ptr;
}

DWORD* lotus::get_records(IN BYTE* content, IN size_t content_size)
{
	lotus::header2_t *part2 = get_hdr2(content, content_size);
	if (!part2) return nullptr;

	BYTE *ptr = (BYTE*)part2 + sizeof(lotus::header2_t);
	return (DWORD*)ptr;
}
