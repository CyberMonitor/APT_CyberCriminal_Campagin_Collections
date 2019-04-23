#include "isfb_parser.h"

#include <iostream>

void isfb::print_data_dir(const ISFB_DDIR &hdr)
{
	std::cout << "original_rva: " << std::hex << hdr.original_rva << "\n";
	std::cout << "size:         " << std::hex << hdr.size << "\n";
	std::cout << "offset:       " << std::hex << hdr.offset << "\n";
}

void isfb::print_sections(const ISFB_SECTION &hdr)
{
	std::cout << "virtual_offset:   " << std::hex << hdr.virtual_offset << "\n";
	std::cout << "virtual_size:     " << std::hex << hdr.virtual_size << "\n";
	std::cout << "raw_offset:       " << std::hex << hdr.raw_offset << "\n";
	std::cout << "raw_size:         " << std::hex << hdr.raw_size << "\n";
	std::cout << "characteristics:  " << std::hex << hdr.characteristics << "\n";
}

void isfb::print_header(const isfb_hdr &hdr)
{
	std::cout << "ISFB header:\n";
	std::cout << "magic:    " << std::hex << hdr.magic << "\n";
	std::cout << "checksum: " << std::hex << hdr.checksum << "\n";
	std::cout << "size:     " << std::hex << hdr.size << "\n";
	std::cout << "\n";
	std::cout << "nt_hdr_offset: " << std::hex << hdr.nt_hdr_offset << "\n";
	std::cout << "image_size:    " << std::hex << hdr.image_size << "\n";
	std::cout << "nt_hdr_size:   " << std::hex << hdr.nt_hdr_size << "\n";
	std::cout << "\n";
	std::cout << "Data Directories:\n";
	for (size_t i = 0; i < ISFB_DDIR_COUNT; i++) {
		std::cout << "---\n#" << i << "\n";
		print_data_dir(hdr.data_dir[i]);
	}
	std::cout << "\n";
	std::cout << "machine_id:\t" << std::hex << hdr.machine_id << "\n";
	std::cout << "sections_count:\t" << std::hex << hdr.sections_count << "\n";
	std::cout << "entry_point:\t" << std::hex << hdr.entry_point << "\n";
	std::cout << "\n";
	std::cout << "Sections:\n";
	for (size_t i = 0; i < hdr.sections_count; i++) {
		std::cout << "---\n#" << i << "\n";
		print_sections(hdr.sections[i]);
	}
};

