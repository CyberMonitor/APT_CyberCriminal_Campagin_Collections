#include "lotus_print.h"
#include <string>
#include <iostream>
#include <sstream>      // std::stringstream

DWORD* print_dwords(DWORD *buf, size_t num)
{
	for (size_t i = 0; i < num; i++) {
		std::cout << " : " << std::hex << buf[i];
	}
	std::cout << std::endl;
	return buf + num;
}

std::string type_to_string(lotus::record_type_t &type)
{
	switch (type) {
		case lotus::RTYPE_EP:
			return "[Entry Point]";
		case lotus::RTYPE_IMPORT:
			return "[Import]";
		case lotus::RTYPE_RELOC:
			return "[Reloc]";
	}
	return "";
}

std::string counter_to_string(DWORD cntr)
{
	switch (cntr) {
	case lotus::ITYPE_ORDINAL:
			return "[import by Ordinal]";
		case lotus::ITYPE_NAME:
			return "[import by Name]";
		case lotus::ITYPE_ERASE_FUNC:
			return "[erase function name]";
		case lotus::ITYPE_ERASE_DLL:
			return "[erase DLL name]";
	}
	return "";
}

void print_ep(BYTE *part1, lotus::entry_point_t* ep)
{
	std::cout << "Entry Point: " << std::hex << ep->entry_rva << " : ";
	if (ep->name_rva == 0) {
		std::cout << ep->name_rva << " (unnamed)\n";
	}
	else {
		char* name_ptr = (char*)(part1 + ep->name_rva);
		std::cout << std::hex << ep->name_rva << " " << name_ptr << std::endl;
	}
}

void print_imports(BYTE *part1, lotus::import_t* imp)
{
	if (!imp || !part1) return;

	std::cout << imp->counter << " : " << counter_to_string(imp->counter) << "\n";

	char* dll_ptr = (char*)(part1 + imp->dll_rva);
	//TODO: check the pointers
	std::cout << std::hex << imp->dll_rva << " : " << dll_ptr << std::endl;

	if (imp->counter != lotus::ITYPE_ORDINAL) {
		char* imp_ptr = (char*)(part1 + imp->func_rva);
		std::cout << std::hex << imp->func_rva << " : " << imp_ptr;
	}
	else {
		std::cout << std::hex << imp->func_rva;
	}
	std::cout << std::endl;
}

void print_table(BYTE *content, size_t content_size, size_t module_size)
{
	BYTE *code_part = content + sizeof(lotus::header1_t);
	size_t code_size = content_size - sizeof(lotus::header1_t);

	DWORD *table = lotus::get_records(content, content_size);
	size_t i = 0;

	size_t args_by_type[4];
	args_by_type[lotus::RTYPE_NONE] = 0;
	args_by_type[lotus::RTYPE_RELOC] = 1;
	args_by_type[lotus::RTYPE_EP] = 3;
	args_by_type[lotus::RTYPE_IMPORT] = 4;

	while (true) {
		lotus::record_type_t type = (lotus::record_type_t) table[i++];
		if (type == lotus::RTYPE_NONE) break;

		std::cout << "type: " << std::hex << type << " " << type_to_string(type);
		size_t arg_num = args_by_type[type];
		print_dwords(&table[i], arg_num);

		switch (type) {
		case lotus::RTYPE_RELOC:
			break;
		case lotus::RTYPE_EP:
			print_ep(code_part, (lotus::entry_point_t*) &table[i]);
			break;
		case lotus::RTYPE_IMPORT:
			print_imports(code_part, (lotus::import_t*) &table[i]);
			break;
		}
		table += arg_num;
	}
}

bool lotus::print_headers(BYTE *content, size_t content_size)
{
	if (!lotus::decode_file(content, content_size)) {
		std::cerr << "Decoding failed!" << std::endl;
		return false;
	}
	lotus::header1_t *hdr1 = lotus::get_hdr1(content, content_size);
	if (!hdr1) {
		return false;
	}
	std::cout << "\nHDR1: \nprolog: " << std::hex << hdr1->prolog
		<< "\ncode size: " << std::hex << hdr1->code_size
		<< "\n---" << std::endl;

	lotus::header2_t *hdr2 = lotus::get_hdr2(content, content_size);
	if (!hdr2) {
		return false;
	}
	std::cout << "HDR2: \nprolog: " << std::hex << hdr2->prolog
		<< "\nIAT size: " << std::hex << hdr2->iat_size
		<< "\n---\n" << std::endl;

	print_table(content, content_size, hdr1->code_size);
	std::cout << std::endl;
	return true;
}
