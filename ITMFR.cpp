#include <iostream>
#include <stdint.h>

#include <Windows.h>

#include <vector>

#include <stdlib.h>

// ----------------------------------------------------------------------------

void MallocDebug_Init()
{

}
void MallocDebug_Done()
{

}

void* MallocDebug_malloc(size_t size)
{
	return malloc(size);
}

void* MallocDebug_calloc(size_t num, size_t size)
{
	return calloc(num, size);
}

void* MallocDebug_realloc(void* ptr, size_t size)
{
	return realloc(ptr, size);
}

void MallocDebug_free(void* ptr)
{
	free(ptr);
}

// ----------------------------------------------------------------------------

int main()
{
	HMODULE hPEFile = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;

	// Položka pDosHeader->e_lfanew pak obsahuje relativní virtuální adresu (RVA) NT
	// hlavičky PIMAGE_NT_HEADERS vzhledem k začátku PE souboru (tj. od bázové adresy
	// vrácené funkcí GetModuleHandle):
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);

	// Struktura IMAGE_NT_HEADERS obsahuje v struktuře pNTHeaders->OptionalHeader
	// pole s datovými adresáři DataDirectory, z nichž každý obsahuje položku
	// VirtualAddress (RVA od pDosHeader) a položku Size s velikostí adresáře
	// v bajtech. Z těchto adresářů jsou pro toto cvičení důležité:

	// import table (IMAGE_DIRECTORY_ENTRY_IMPORT)
	IMAGE_DATA_DIRECTORY importTable = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	// import address table (IMAGE_DIRECTORY_ENTRY_IAT)
	IMAGE_DATA_DIRECTORY importAddressTable = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

	// for import symbols -> array of IMAGE_IMPORT_DESCRIPTOR structures
	// each structure contains infi about DLL the PE file imports symbols from
	IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)pDosHeader + importTable.VirtualAddress);
	DWORD importDescriptorCount = importTable.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

	std::vector<DWORD> names;

	for (size_t i = 0; i < importDescriptorCount; i++)
	{
		auto& id = pImportDescriptor[i];

		if (id.OriginalFirstThunk == 0
			&& id.TimeDateStamp == 0
			&& id.ForwarderChain == 0
			&& id.Name == 0
			&& id.FirstThunk == 0)
		{
			// End of import descriptors
			break;
		}

		// Get the name of the DLL
		char* dllName = (char*)((BYTE*)pDosHeader + id.Name);
		std::cout << "DLL: " << dllName << std::endl;

		// Get the first thunk (IAT)
		PIMAGE_THUNK_DATA pThunk;

		if (id.OriginalFirstThunk != 0)
		{
			pThunk = (PIMAGE_THUNK_DATA)((BYTE*)pDosHeader + id.OriginalFirstThunk);
		}
		else
		{
			pThunk = (PIMAGE_THUNK_DATA)((BYTE*)pDosHeader + id.FirstThunk);
		}

		while (pThunk->u1.AddressOfData != 0)
		{
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				std::cout << "  Ordinal: " << (pThunk->u1.Ordinal & 0xFFFF) << std::endl;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDosHeader + pThunk->u1.AddressOfData);
				std::cout << "  Function: " << pImportByName->Name << std::endl;
			}
			pThunk++;
		}
	}






	return 0;
}

// ----------------------------------------------------------------------------