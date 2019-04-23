#pragma once
#include "isfb_header.h"

namespace isfb
{
	void print_header(const isfb_hdr &hdr);

	void print_data_dir(const ISFB_DDIR &hdr);

	void print_sections(const ISFB_SECTION &hdr);
};
