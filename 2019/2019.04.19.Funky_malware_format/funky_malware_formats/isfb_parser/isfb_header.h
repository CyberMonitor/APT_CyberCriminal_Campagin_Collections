#pragma once
#include <Windows.h>

#define ISFB_MAGIC 0x00005850

enum ISFB_DDIR_ID {
	ISFB_DDIR_IMPORT = 0, //loaded
	ISFB_DDIR_EXPORT = 1, //exports retrieved and copied
	ISFB_DDIR_IAT = 2, //copied
	ISFB_DDIR_SECURITY = 3, //copied
	ISFB_DDIR_UNKNOWN = 4, //copied
	ISFB_DDIR_RELOCS = 5, //loaded
	ISFB_DDIR_COUNT
};

struct ISFB_DDIR {
	DWORD original_rva; //RVA in the PE
	DWORD size;
	DWORD offset; //offset in the custom header
};

struct ISFB_SECTION {
	DWORD virtual_offset;
	DWORD virtual_size;
	DWORD raw_offset;
	DWORD raw_size;
	DWORD characteristics;
};

struct isfb_hdr {
	DWORD magic;
	DWORD checksum;
	DWORD size;

	DWORD nt_hdr_offset;
	DWORD image_size;
	DWORD nt_hdr_size;

	ISFB_DDIR data_dir[ISFB_DDIR_COUNT];

	WORD machine_id; //from: FileHeader -> Machine
	WORD sections_count;
	DWORD entry_point;

	ISFB_SECTION sections[1]; // sections[sections_count]
};
