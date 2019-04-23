#pragma once
#include <Windows.h>

namespace lotus {

	typedef struct
	{
		DWORD prolog;
		DWORD xor_val2;
		DWORD xor_val1;
		DWORD code_size;
		//BYTE code[1]; //code[code_size]
	} header1_t;

	typedef struct
	{
		DWORD prolog;
		DWORD iat_size;
		//DWORD records[1];
	} header2_t;
	
	typedef enum {
		RTYPE_NONE = 0,
		RTYPE_RELOC = 1,
		RTYPE_EP = 2,
		RTYPE_IMPORT = 3
	} record_type_t;

	typedef enum {
		ITYPE_ORDINAL = 1,
		ITYPE_NAME = 2,
		ITYPE_ERASE_FUNC = 3,
		ITYPE_ERASE_DLL = 4
	} import_type_t;

	typedef struct
	{
		DWORD counter; //TODO: check what it really is
		DWORD dll_rva;
		DWORD func_rva;
		DWORD iat_rva;
	} import_t;

	typedef struct {
		DWORD reloc_field;
	} reloc_t;

	typedef struct {
		DWORD count;
		DWORD entry_rva;
		DWORD name_rva; //export name
	} entry_point_t;

	bool decode_file(IN OUT BYTE* content, IN size_t content_size);

	header1_t* get_hdr1(IN BYTE* content, IN size_t content_size);
	header2_t* get_hdr2(IN BYTE* content, IN size_t content_size);

	BYTE* get_code(IN BYTE* content, IN size_t content_size, OUT size_t &code_size);
	DWORD* get_records(IN BYTE* content, IN size_t content_size);

}; //namespace lotus

