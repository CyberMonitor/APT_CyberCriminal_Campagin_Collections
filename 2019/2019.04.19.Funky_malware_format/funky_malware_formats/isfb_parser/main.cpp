
#include <iostream>
#include "isfb_parser.h"
#include "util.h"
#include "isfb_to_pe.h"

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "PX to PE:\nparser and converter for the custom format used by ISFB malware\n";
		std::cout << "Args: <in: PX module> [out: PE file]" << std::endl;
		system("pause");
		return -1;
	}
	size_t buffer_size = 0;
	BYTE* buffer =  load_file(argv[1], buffer_size);
	if (!buffer) {
		std::cerr << "[!] Couldn't load the file: " << argv[1] << "\n";
		return -2;
	}
	isfb_hdr* hdr = (isfb_hdr*) buffer;
	if (hdr->magic != ISFB_MAGIC) {
		std::cerr << "[!] This is not the ISFB magic!\n";
		return -3;
	}
	isfb::print_header(*hdr);
	if (argc > 2) {
		if (isfb_to_pe(*hdr, argv[2])) {
			std::cout << "Saved as a PE: " << argv[2] << std::endl;
		}
		else {
			std::cerr << "Failed converting into PE" << std::endl;
			return -4;
		}
	}
	return 0;
}
