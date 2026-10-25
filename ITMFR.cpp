#include <iostream>
#include <stdint.h>

#include <Windows.h>
#include <memoryapi.h>

#include <stdlib.h>
#include <string.h>
#include <cstring>

#include <vector>
#include <unordered_map>
#include <unordered_set>

// ----------------------------------------------------------------------------

void MallocDebug_Init();
void MallocDebug_Done();

void* MallocDebug_malloc(size_t size);
void* MallocDebug_calloc(size_t num, size_t size);
void* MallocDebug_realloc(void* ptr, size_t size);
void MallocDebug_free(void* ptr);

// ----------------------------------------------------------------------------

bool initialized = false;
bool switched = false;

constexpr size_t funcCount = 4;

DWORD oldProtect[funcCount] = { 0, 0, 0, 0 };
ULONGLONG* originAddr[funcCount] = { nullptr, nullptr, nullptr, nullptr };

ULONGLONG funcAddr[funcCount] = { 0, 0, 0, 0 };
ULONGLONG myFuncAddr[funcCount] = { 
	(ULONGLONG)MallocDebug_malloc,
	(ULONGLONG)MallocDebug_calloc,
	(ULONGLONG)MallocDebug_realloc,
	(ULONGLONG)MallocDebug_free
};

const char* funcNames[funcCount] = { "malloc", "calloc", "realloc", "free" };

std::unordered_map<void*, size_t> allocatedMemory;
std::unordered_set<void*> freedMemory;

PIMAGE_DOS_HEADER pDosHeader;

// ----------------------------------------------------------------------------

void MallocDebug_Init()
{
	std::cout << "MallocDebug_Init()" << std::endl;

	if (!initialized)
	{
		HMODULE hPEFile = GetModuleHandle(NULL);
		pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;

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
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)pDosHeader + id.OriginalFirstThunk);
			PIMAGE_THUNK_DATA pIATThunk = (PIMAGE_THUNK_DATA)((BYTE*)pDosHeader + id.FirstThunk);

			while (pThunk->u1.AddressOfData != 0)
			{
				if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					PIMAGE_THUNK_DATA ordinal = (PIMAGE_THUNK_DATA)(pThunk->u1.Ordinal & 0xFFFF);

					// Import by ordinal
					std::cout << "  Ordinal: " << ordinal << std::endl;
				}
				else
				{
					// Import by name
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDosHeader + pThunk->u1.AddressOfData);
					//std::cout << "  Function: " << pImportByName->Name << std::endl;
						//<< " at address: " << std::hex << (ULONGLONG)((BYTE*)pDosHeader + pIATThunk->u1.Function) << std::dec << std::endl << std::endl;

					// Check if the function is one of the functions we want to hook
					for (size_t i = 0; i < funcCount; i++) {
						if ((void*)originAddr[i] != nullptr)
							continue;

						if (strcmp(pImportByName->Name, funcNames[i]) == 0) {
							originAddr[i] = (ULONGLONG*)&pIATThunk->u1.Function;
							funcAddr[i] = *originAddr[i];

							std::cout << "    Found function: " << funcNames[i] << " at address: " << std::hex << funcAddr[i] << std::dec << std::endl;
						}
					}
				}

				pIATThunk++;
				pThunk++;
			}
		}

		initialized = true;
		std::cout << std::endl;

		for (size_t i = 0; i < funcCount; i++)
		{
			if ((void*)originAddr[i] == nullptr)
			{
				std::cerr << "Error: Function " << funcNames[i] << " not found in import table." << std::endl;
				initialized = false;
			}
		}

		if (!initialized)
			exit(1);

		system("pause");
	}

	if (!switched && initialized)
	{
		std::cout << "Switching to debug functions..." << std::endl;

		for (size_t i = 0; i < funcCount; i++)
		{
			oldProtect[i] = PAGE_EXECUTE_READWRITE;

			VirtualProtect(originAddr[i], sizeof(ULONGLONG), oldProtect[i], &oldProtect[i]);
			*originAddr[i] = myFuncAddr[i];
			VirtualProtect(originAddr[i], sizeof(ULONGLONG), oldProtect[i], &oldProtect[i]);

			std::cout << "    Switched function: " << funcNames[i] << std::endl
				<< "	From address: " << std::hex << funcAddr[i] << " to address: " << myFuncAddr[i] << std::dec << std::endl;
		}
		std::cout << std::endl;

		switched = true;

		system("pause");
	}
}
void MallocDebug_Done()
{
	std::cout << "MallocDebug_Done()" << std::endl;

	if (switched)
	{
		for (size_t i = 0; i < funcCount; i++)
		{
			VirtualProtect(originAddr[i], sizeof(ULONGLONG), oldProtect[i], &oldProtect[i]);
			*originAddr[i] = funcAddr[i];
			VirtualProtect(originAddr[i], sizeof(ULONGLONG), oldProtect[i], &oldProtect[i]);
		}

		switched = false;
	}

	for (const auto& [ptr, size] : allocatedMemory)
	{
		std::cerr << "Warning: Memory leak detected for pointer: " << ptr << ", size: " << size << " bytes" << std::endl;
	}

	if (allocatedMemory.empty())
	{
		std::cout << "No memory leaks detected." << std::endl;
	}

	switched = false;
}

void* MallocDebug_malloc(size_t size)
{
	std::cout << "MallocDebug_malloc(" << size << ")" << std::endl;
	std::cout << "This: " << std::hex << (ULONGLONG)MallocDebug_malloc << std::endl;
	std::cout << "Calling original: " << funcAddr[0] << std::dec << std::endl << std::endl;

	system("pause");

	if (!initialized) {
		std::cerr << "Error: Not initialized" << std::endl;
		return nullptr;
	}

	void* ptr = ((void* (*)(size_t))funcAddr[0])(size);
	if (ptr == nullptr)
		return ptr;

	freedMemory.erase(ptr);
	allocatedMemory.insert({ ptr, size });

	return ptr;
}

void* MallocDebug_calloc(size_t num, size_t size)
{
	std::cout << "MallocDebug_calloc(" << num << ", " << size << ")" << std::endl;

	if (!initialized) {
		std::cerr << "Error: Not initialized" << std::endl;
		return nullptr;
	}

	void* ptr = ((void* (*)(size_t, size_t))funcAddr[1])(num, size);
	if (ptr == nullptr)
		return ptr;

	freedMemory.erase(ptr);
	allocatedMemory.insert({ ptr, num * size });

	return ptr;
}

void* MallocDebug_realloc(void* oldPtr, size_t size)
{
	std::cout << "MallocDebug_realloc(" << oldPtr << ", " << size << ")" << std::endl;

	if (!initialized) {
		std::cerr << "Error: Not initialized" << std::endl;
		return nullptr;
	}

	void* ptr = ((void* (*)(void*, size_t))funcAddr[2])(oldPtr, size);
	
	// failure, old is not freed and still valid
	if (ptr == nullptr)
		return ptr;

	// acts as a malloc
	if (oldPtr == nullptr) {
		// in case of a realloc calling malloc internally
		// dont add, it was already done by the malloc call, which is overriden as well
		if (!allocatedMemory.contains(ptr)) {
			freedMemory.erase(ptr);
			allocatedMemory.insert({ ptr, size });
		}

		return ptr;
	}

	freedMemory.erase(ptr);

	if (ptr != oldPtr) {
		freedMemory.insert(oldPtr);

		allocatedMemory.erase(oldPtr);
		allocatedMemory.insert({ ptr, size });
	}
	else {
		allocatedMemory[ptr] = size;
	}

	return ptr;
}

void MallocDebug_free(void* ptr)
{
	std::cout << "MallocDebug_free(" << ptr << ")" << std::endl;

	if (!initialized) {
		std::cerr << "Error: Not initialized" << std::endl;
		return;
	}

	if (ptr == nullptr) {
		std::cout << "Warning: Freeing nullptr pointer" << std::endl;
	}
	else {
		if (freedMemory.contains(ptr)) {
			std::cerr << "Warning: Double free detected for pointer: " << ptr << std::endl;
		}
		else if (!allocatedMemory.contains(ptr)) {
			std::cerr << "Warning: Freeing not allocated pointer: " << ptr << std::endl;
		}

		freedMemory.insert(ptr);
		allocatedMemory.erase(ptr);
	}

	((void (*)(void*))funcAddr[3])(ptr);
}

// ----------------------------------------------------------------------------

int main()
{
	// Test normal

	try {
		MallocDebug_Init();

		void* ptr = malloc(10);
		free(ptr);

		MallocDebug_Done();

		// Test leak

		MallocDebug_Init();

		ptr = malloc(10);
		void* ptr2 = calloc(5, 10);
		void* ptr3 = realloc(ptr, 20);

		MallocDebug_Done();
	}
	catch (const std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
	}

	system("pause");

	return 0;
}

// ----------------------------------------------------------------------------