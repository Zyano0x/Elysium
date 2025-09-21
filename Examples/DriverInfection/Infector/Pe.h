#pragma once
#include "pch.h"

/* 
	Purpose:

	Class to manipulate the PE file 
*/
class Pe
{
	friend class Infect;

public:
	/* Shared functions */
	bool openFile(const std::string& name);
	bool saveFile(const std::string& name);

	bool parseHeaders();
	void shiftSectionsPointers(int64_t shift_size);

	bool addSection(const std::string& name, size_t size, DWORD flags);
protected:
	/* Internal functions */
	DWORD rvaToRaw(DWORD rva);
	DWORD rawToRva(DWORD rva);
	size_t alignUp(size_t value, size_t alignment);
	uint8_t* getSectionData(const IMAGE_SECTION_HEADER& section);
	IMAGE_SECTION_HEADER* getSectionByName(const std::string& section_name);

	std::vector<char> buffer;

	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* ntHeaders;
	IMAGE_SECTION_HEADER* sectionHeaders;
};