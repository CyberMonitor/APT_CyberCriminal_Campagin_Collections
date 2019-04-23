#include "isfb_to_pe.h"
#include "util.h"

#include <iostream>

BYTE* alloc_pe(IN const isfb_hdr &hdr, OUT size_t &out_size)
{
	out_size = 0;
	BYTE* allocated = (BYTE*)VirtualAlloc(0, hdr.image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (allocated) {
		out_size = hdr.image_size;
	}
	return allocated;
}

size_t copy_sections(IN const isfb_hdr &hdr, IN OUT BYTE* buf, IN const size_t buf_size)
{
	size_t copied_cntr = 0;
	for (size_t i = 0; i < hdr.sections_count; i++) {
		if (hdr.sections[i].virtual_size == 0) continue;

		BYTE* vptr = buf + hdr.sections[i].virtual_offset;
		if (!validate_ptr(buf, buf_size, vptr, hdr.sections[i].raw_size)) continue;

		BYTE* rptr = (BYTE*)&hdr + hdr.sections[i].raw_offset;
		if (!validate_ptr((BYTE*)&hdr, hdr.size, rptr, hdr.sections[i].raw_size)) continue;

		memcpy(vptr, rptr, hdr.sections[i].raw_size);
		copied_cntr++;
	}
	return copied_cntr;
}

size_t copy_ddirs(IN const isfb_hdr &hdr, IN OUT BYTE* buf, IN const size_t buf_size)
{
	size_t copied_cntr = 0;
	for (size_t i = 0; i < ISFB_DDIR_COUNT; i++) {
		const ISFB_DDIR &ddir = hdr.data_dir[i];

		if (ddir.size == 0) continue;

		BYTE* vptr = buf + ddir.original_rva;
		if (!validate_ptr(buf, buf_size, vptr, ddir.size)) continue;

		BYTE* rptr = (BYTE*)&hdr + ddir.offset;
		if (!validate_ptr((BYTE*)&hdr, hdr.size, rptr, ddir.size)) continue;
		memcpy(vptr, rptr, ddir.size);
		copied_cntr++;
	}
	return copied_cntr;
}

template <typename IMAGE_NT_HEADERS_T>
size_t fill_nt_hdr(IN const isfb_hdr &hdr, IN OUT IMAGE_NT_HEADERS_T* nt_hdrs)
{
	if (!nt_hdrs) return 0;

	nt_hdrs->OptionalHeader.AddressOfEntryPoint = hdr.entry_point;
	nt_hdrs->OptionalHeader.SizeOfImage = hdr.image_size;
	return sizeof(IMAGE_NT_HEADERS_T);
}

template <typename IMAGE_NT_HEADERS_T>
size_t realign_sections(IN const isfb_hdr &hdr, IN OUT IMAGE_NT_HEADERS_T* nt_hdr, IN OUT BYTE* buf, IN const size_t buf_size)
{
	if (!nt_hdr) return 0;

	IMAGE_SECTION_HEADER* sec_ptr = (IMAGE_SECTION_HEADER*)((BYTE*)&nt_hdr->OptionalHeader + nt_hdr->FileHeader.SizeOfOptionalHeader);
	for (size_t i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++) {
		//std::cout << "section: " << std::hex << sec_ptr[i].PointerToRawData << "\n";
		sec_ptr[i].PointerToRawData = sec_ptr[i].VirtualAddress;
	}
	nt_hdr->OptionalHeader.FileAlignment = nt_hdr->OptionalHeader.SectionAlignment;
	return nt_hdr->FileHeader.NumberOfSections;
}


size_t copy_headers(IN const isfb_hdr &hdr, IN OUT BYTE* buf, IN const size_t buf_size)
{
	BYTE* rptr = (BYTE*)&hdr + hdr.nt_hdr_offset;
	if (!validate_ptr((BYTE*)&hdr, hdr.size, rptr, hdr.nt_hdr_size)) return 0;
	
	BYTE* vptr = buf + sizeof(IMAGE_DOS_HEADER);
	if (!validate_ptr(buf, buf_size, vptr, hdr.nt_hdr_size)) return 0;

	memcpy(vptr, rptr, hdr.nt_hdr_size);
	
	IMAGE_DOS_HEADER dos_hdr = { 0 };
	dos_hdr.e_magic = IMAGE_DOS_SIGNATURE;
	dos_hdr.e_lfanew = sizeof(IMAGE_DOS_HEADER);
	memcpy(buf, &dos_hdr, sizeof(IMAGE_DOS_HEADER));

	DWORD nt_sign = IMAGE_NT_SIGNATURE;
	memcpy(vptr, &nt_sign, sizeof(IMAGE_NT_SIGNATURE));

	if (hdr.magic == IMAGE_FILE_MACHINE_I386) {
		IMAGE_NT_HEADERS32* nt_hdr = (IMAGE_NT_HEADERS32*)vptr;
		fill_nt_hdr<IMAGE_NT_HEADERS32>(hdr, nt_hdr);
		realign_sections(hdr, nt_hdr, buf, buf_size);
	}
	else {
		IMAGE_NT_HEADERS64* nt_hdr = (IMAGE_NT_HEADERS64*)vptr;
		fill_nt_hdr<IMAGE_NT_HEADERS64>(hdr, nt_hdr);
		realign_sections(hdr, nt_hdr, buf, buf_size);
	}
	return hdr.nt_hdr_size;
}

bool isfb_to_pe(const isfb_hdr& hdr, char* filename)
{
	size_t buf_size = 0;
	BYTE* buf = alloc_pe(hdr, buf_size);
	if (!buf) return false;

	copy_sections(hdr, buf, buf_size);
	copy_headers(hdr, buf, buf_size);
	copy_ddirs(hdr, buf, buf_size);
	dump_to_file(filename, buf, buf_size);
	return true;
}
