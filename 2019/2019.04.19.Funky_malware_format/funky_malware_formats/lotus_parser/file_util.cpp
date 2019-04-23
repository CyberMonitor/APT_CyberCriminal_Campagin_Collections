#include "file_util.h"

#ifdef _DEBUG
#include <iostream>
#endif

BYTE* load_file(const char *filename, OUT size_t &read_size)
{
	HANDLE file = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
		std::cerr << "Could not open file!" << std::endl;
#endif
		return nullptr;
	}
	HANDLE mapping = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
	if (!mapping) {
#ifdef _DEBUG
		std::cerr << "Could not create mapping!" << std::endl;
#endif
		CloseHandle(file);
		return nullptr;
	}
	BYTE *dllRawData = (BYTE*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	if (dllRawData == nullptr) {
#ifdef _DEBUG
		std::cerr << "Could not map view of file" << std::endl;
#endif
		CloseHandle(mapping);
		CloseHandle(file);
		return nullptr;
	}
	size_t r_size = GetFileSize(file, 0);
	if (read_size != 0 && read_size <= r_size) {
		r_size = read_size;
	}
	BYTE* localCopyAddress = (BYTE*)calloc(r_size, 1);
	if (localCopyAddress != nullptr) {
		memcpy(localCopyAddress, dllRawData, r_size);
		read_size = r_size;
	}
	else {
		read_size = 0;
#ifdef _DEBUG
		std::cerr << "Could not allocate memory in the current process" << std::endl;
#endif
	}
	UnmapViewOfFile(dllRawData);
	CloseHandle(mapping);
	CloseHandle(file);
	return localCopyAddress;
}
