#include <iostream>
#include <windows.h>

#include "file_util.h"
#include "lotus_print.h"


int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "Parser for a executable BLOB format used by Ocean Lotus\n";
		std::cout << "Args: <module>" << std::endl;
		system("pause");
		return -1;
	}
	size_t content_size = 0;
	BYTE *content = load_file(argv[1], content_size);
	if (!content) {
		std::cerr << "Failed to load: " << argv[1] << std::endl;
		return -1;
	}
	std::cout << "Loaded: " << argv[1] << "\nLoaded size: " << std::hex << content_size << std::endl;
	lotus::print_headers(content, content_size);

	return 0;
}
