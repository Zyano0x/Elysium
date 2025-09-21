#include "pch.h"
#include "Pe.h"

/*
	Purpose:

	Open the file and read to the buffer
*/
bool Pe::openFile(const std::string& name)
{
	/* Open file as a binary and move the read position at the end */
	std::ifstream file(name, std::ios::binary | std::ios::ate);
	/* Can't open file? */
	if (!file)
	{
		/* No? Abort! */
		return false;
	}

	/* Get size by current file position ( end of file ) */
	std::streamsize size = file.tellg();
	/* Is size smaller even than DOS header? */
	if (size < sizeof(IMAGE_DOS_HEADER))
	{
		/* Yes? Abort! */
		return false;
	}

	/* Resize the buffer according to the file size */
	buffer.resize(static_cast<size_t>(size));

	/* Set the file position at the beginning */
	file.seekg(0, std::ios::beg);

	/* Read the file to the buffer */
	if (!file.read(buffer.data(), size))
	{
		/* Failure? Abort! */
		return false;
	}

	/* Success */
	return true;
}

/*
	Purpose:

	Save our buffer as a new file
*/
bool Pe::saveFile(const std::string& name)
{
	/* Create a new file */
	std::ofstream file(name, std::ios::binary);
	/* Is file created? */
	if (!file)
	{
		std::cout << "error1" << std::endl;
		/* No? Abort! */
		return false;
	}

	/* Write local buffer into new created file */
	file.write(buffer.data(), buffer.size());
	/* Is file writed successfully? */
	if (file.good() == false)
	{
		std::cout << "error2" << std::endl;
		/* No? Abort! */
		return false;
	}

	/* Success */
	return true;
}


/*
	Purpose:

	Parse the DOS, NT and SECTION headers from image.
*/
bool Pe::parseHeaders()
{
	if (buffer.empty()) 
	{
		return false;
	}

	/* Get DOS header */
	dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
	/* Is our image contain DOS header? */
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		/* No? Abort! */
		return false;
	}

	/* Get NT headers */
	ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dosHeader->e_lfanew);
	/* Is our image had NT headers? */
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		/* No? Abort! */
		return false;
	}

	/* Get first section header */
	sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);

	return true;
}

/* 
	Purpose:

	Convert relative virtual address to raw file offset.
*/
DWORD Pe::rvaToRaw(DWORD rva)
{
	/* Get number of sections */
	const WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;

	/* Loop through all sections */
	for (WORD i = 0; i < numberOfSections; i++)
	{
		/* Get section header */
		const IMAGE_SECTION_HEADER& sec = sectionHeaders[i];

		/* Get the section virtual address  */
		DWORD secVA = sec.VirtualAddress;

		/* Get the section size */
		DWORD secSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;

		/* Check if the RVA is inside this section */
		if (rva >= secVA && rva < secVA + secSize)
		{
			/* Calculate file offset */
			DWORD delta = rva - secVA;

			/* Return file offset */
			return sec.PointerToRawData + delta;
		}
	}

	/* Is rva inside headers? */
	if (rva < ntHeaders->OptionalHeader.SizeOfHeaders)
		/* Yes? Return rva */
		return rva;

	return 0;
}

/*
	Purpose:

	Convert raw file offset to relative virtual address.
*/
DWORD Pe::rawToRva(DWORD raw)
{
	/* Get the number of sections in the PE */
	const WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;

	/* Loop through all section headers */
	for (WORD i = 0; i < numberOfSections; i++)
	{
		/* Get the current section header */
		const IMAGE_SECTION_HEADER& sec = sectionHeaders[i];

		/* Get the section raw file offset */
		DWORD secRaw = sec.PointerToRawData;

		/* Get the section size in the file */
		DWORD secSize = sec.SizeOfRawData;

		/* Check if the raw offset is inside this section */
		if (raw >= secRaw && raw < secRaw + secSize)
		{
			/* Calculate the delta from the section start */
			DWORD delta = raw - secRaw;

			/* Return the corresponding RVA */
			return sec.VirtualAddress + delta;
		}
	}

	/* The raw offset is inside the PE headers? */
	if (raw < ntHeaders->OptionalHeader.SizeOfHeaders)
		/* Yes? Return the raw offset as RVA */
		return raw;

	return 0;
}

/*
	Purpose:

	Shift section file offsets by an offset.
	Used when headers are extended, so raw data of sections must move forward in the file.
*/
void Pe::shiftSectionsPointers(int64_t shift_size)
{
	/* Get the number of sections in the PE */
	const size_t numberOfSections = ntHeaders->FileHeader.NumberOfSections;

	/* Loop through all section headers */
	for (size_t i = 0; i < numberOfSections; ++i)
	{
		/* Get the current section header */
		IMAGE_SECTION_HEADER& section = sectionHeaders[i];

		/* Skip sections with no data */
		if (section.PointerToRawData == 0 || section.SizeOfRawData == 0)
			continue;

		/* Shift the raw file offset of the section */
		section.PointerToRawData = static_cast<DWORD>(
			static_cast<int64_t>(section.PointerToRawData) + shift_size
			);

		/* Shift the virtual address of the section */
		section.VirtualAddress = static_cast<DWORD>(
			static_cast<int64_t>(section.VirtualAddress) + shift_size
			);
	}

	/* Loop through all data directories */
	for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
	{
		auto& dir = ntHeaders->OptionalHeader.DataDirectory[i];

		/* Skip empty directories */
		if (dir.VirtualAddress == 0 || dir.Size == 0)
			continue;

		/* Convert RVA to raw offset */
		DWORD raw = rvaToRaw(dir.VirtualAddress);
		if (raw == 0)
			continue;

		/* Shift directory RVA by the offset */
		dir.VirtualAddress = rawToRva(raw + shift_size);
	}

	/* Shift the PE entry point by the offset */
	ntHeaders->OptionalHeader.AddressOfEntryPoint += shift_size;
}

/*
	Purpose:

	Create the new section in the PE file
*/
bool Pe::addSection(const std::string& name, size_t size, DWORD flags)
{
	/* Is section name length valid? */
	if (name.size() > 8)
		/* No? Return false! */
		return false;

	/* Get current number of sections */
	WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;

	/* Is PE has reached the maximum number of sections? */
	if (numberOfSections >= 96)
		/* Yes? Return false! */
		return false;

	/* Get PE alignment values */
	size_t sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
	size_t fileAlignment = ntHeaders->OptionalHeader.FileAlignment;

	/* Calculate end of headers */
	size_t headersEnd = dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + numberOfSections * sizeof(IMAGE_SECTION_HEADER);

	/* Align old and new headers size */
	DWORD oldSizeOfHeaders = alignUp(headersEnd, fileAlignment);
	DWORD newSizeOfHeaders = alignUp(headersEnd + sizeof(IMAGE_SECTION_HEADER), fileAlignment);

	/* Calculate how much to shift sections due to header expansion */
	DWORD headerShiftSize = newSizeOfHeaders - oldSizeOfHeaders;

	/* Insert padding in buffer to accommodate new section header */
	buffer.insert(buffer.begin() + headersEnd, headerShiftSize, 0);

	/* Re-parse headers after buffer modification */
	Pe::parseHeaders();

	/* Headers are extended? */
	if (headerShiftSize > 0)
		/* Yes? Shift existing section pointers */
		Pe::shiftSectionsPointers(headerShiftSize);

	/* Update SizeOfImage and SizeOfHeaders in optional header */
	ntHeaders->OptionalHeader.SizeOfImage += headerShiftSize;
	ntHeaders->OptionalHeader.SizeOfHeaders = newSizeOfHeaders;

	/* Get last section to calculate new section addresses */
	IMAGE_SECTION_HEADER* lastSection = &sectionHeaders[numberOfSections - 1];

	/* Align requested section size to section alignment */
	size_t alignedSize = alignUp(size, sectionAlignment);

	/* Calculate Virtual Address (RVA) for new section */
	DWORD newSectionVA = alignUp(lastSection->VirtualAddress + lastSection->Misc.VirtualSize, sectionAlignment);

	/* Calculate raw file offset for new section */
	DWORD newSectionRaw = alignUp(lastSection->PointerToRawData + lastSection->SizeOfRawData, fileAlignment);

	/* Initialize new section header */
	IMAGE_SECTION_HEADER newSection = { 0 };
	memset(&newSection, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(&newSection.Name, name.c_str(), name.size());
	newSection.Misc.VirtualSize = (DWORD)size;
	newSection.VirtualAddress = newSectionVA;
	newSection.SizeOfRawData = (DWORD)alignUp(size, fileAlignment);
	newSection.PointerToRawData = newSectionRaw;
	newSection.Characteristics = flags;

	/* Copy new section header into section headers array */
	memcpy(&sectionHeaders[numberOfSections], &newSection, sizeof(IMAGE_SECTION_HEADER));

	/* Increment number of sections */
	ntHeaders->FileHeader.NumberOfSections++;

	/* Update SizeOfImage to include new section */
	ntHeaders->OptionalHeader.SizeOfImage = newSectionVA + alignedSize;

	/* Insert zero-initialized space for new section data in buffer */
	buffer.insert(buffer.begin() + newSectionRaw, newSection.SizeOfRawData, 0);

	/* Re-parse headers after buffer modification */
	Pe::parseHeaders();

	/* Adjust Security Directory if it exists and comes after new section */
	IMAGE_DATA_DIRECTORY& secDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	if (secDir.VirtualAddress && secDir.Size)
	{
		if (secDir.VirtualAddress >= newSectionRaw)
		{
			secDir.VirtualAddress += newSection.SizeOfRawData;
		}
	}

	/* Section successfully added */
	return true;
}


/*
	Purpose:

	Internal function to calculate the align
*/
size_t Pe::alignUp(size_t value, size_t alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}

/*
	Purpose:

	Internal function to get the section data pointer
*/
uint8_t* Pe::getSectionData(const IMAGE_SECTION_HEADER& section)
{
	/* Section is outside the file? */
	if (section.PointerToRawData + section.SizeOfRawData > buffer.size())
	{
		/* Yes? Return nullptr! */
		return 0;
	}

	/* Return pointer to the data */
	return (uint8_t*)( buffer.data() + section.PointerToRawData );
}

/*
	Purpose:

	Internal function to get the section header by section name
*/
IMAGE_SECTION_HEADER* Pe::getSectionByName(const std::string& section_name)
{
	/* Check the section name boundary */
	if (section_name.size() > 8)
	{
		return nullptr;
	}

	for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER* section = &sectionHeaders[i];

		if (std::string(reinterpret_cast<char*>(section->Name)) == section_name)
		{
			return section;
		}
	}

	return nullptr;
}