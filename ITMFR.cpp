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

void DisableOriginal();
void EnableOriginal();

void MallocDebug_Init();
void MallocDebug_Done();

void* MallocDebug_malloc(size_t size);
void* MallocDebug_calloc(size_t num, size_t size);
void* MallocDebug_realloc(void* ptr, size_t size);
void MallocDebug_free(void* ptr);

// ----------------------------------------------------------------------------

// init for reading the import table and finding the functions to intercept
bool initialized = false;
// switched for telling the state, if the original functions are disabled and the debug functions are enabled
bool switched = false;

// number of functions
constexpr size_t funcCount = 4;

// read/write protection for the IAT entries
DWORD oldProtect[funcCount] = { 0, 0, 0, 0 };
// addresses in the IAT
// dereference to overwrite the function address
ULONGLONG* originAddr[funcCount] = { nullptr, nullptr, nullptr, nullptr };

// original function addresses
ULONGLONG funcAddr[funcCount] = { 0, 0, 0, 0 };
// our debug functions addresses
ULONGLONG myFuncAddr[funcCount] = { 
	(ULONGLONG)MallocDebug_malloc,
	(ULONGLONG)MallocDebug_calloc,
	(ULONGLONG)MallocDebug_realloc,
	(ULONGLONG)MallocDebug_free
};

// functions to be intercepted, HAS to be in the same order as the arrays above
const char* funcNames[funcCount] = { "malloc", "calloc", "realloc", "free" };

PIMAGE_DOS_HEADER pDosHeader;
// function pointer types for the original functions
typedef void* (*malloc_t)(size_t);
typedef void* (*calloc_t)(size_t, size_t);
typedef void* (*realloc_t)(void*, size_t);
typedef void (*free_t)(void*);

// ----------------------------------------------------------------------------

struct MemoryBlock
{
	size_t size;
	size_t used_function;
	void* old_ptr;
	size_t num;
};

// checking for double frees and memory leaks
std::unordered_map<void*, MemoryBlock> allocatedMemory;
std::unordered_set<void*> freedMemory;

// ----------------------------------------------------------------------------

void DisableOriginal()
{
	// Disable original functions by replacing the IAT entries with our debug functions addresses

	if (!initialized)
		return;

	for (size_t i = 0; i < funcCount; i++)
	{
		if (!funcAddr[i])
			continue;

		oldProtect[i] = PAGE_EXECUTE_READWRITE;

		VirtualProtect(originAddr[i], sizeof(ULONGLONG), oldProtect[i], &oldProtect[i]);
		*(originAddr[i]) = myFuncAddr[i];
		VirtualProtect(originAddr[i], sizeof(ULONGLONG), oldProtect[i], &oldProtect[i]);
	}
}

void EnableOriginal()
{
	// Enable original functions by restoring the IAT entries with the original function addresses

	if (!initialized)
		return;

	for (size_t i = 0; i < funcCount; i++)
	{
		if (!funcAddr[i])
			continue;

		VirtualProtect(originAddr[i], sizeof(ULONGLONG), oldProtect[i], &(oldProtect[i]));
		*(originAddr[i]) = funcAddr[i];
		VirtualProtect(originAddr[i], sizeof(ULONGLONG), oldProtect[i], &(oldProtect[i]));
	}
}

// ----------------------------------------------------------------------------

void MallocDebug_Init()
{
	std::cout << "MallocDebug_Init()" << std::endl;

	if (!initialized)
	{
		HMODULE hPEFile = GetModuleHandle(NULL);
		pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;

		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);

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

			// if any of the thunks is null, skip this import descriptor, probably a malformed PE file or bug
			if (pThunk == nullptr || pIATThunk == nullptr)
			{
				std::cout << "Error: Invalid thunk data" << std::endl;
				continue;
			}

			while (pThunk->u1.AddressOfData != 0)
			{
				if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					// Import by ordinal
					PIMAGE_THUNK_DATA ordinal = (PIMAGE_THUNK_DATA)(pThunk->u1.Ordinal & 0xFFFF);

					std::cout << "  Warning: ordinal " << ordinal << " ignored" << std::endl;
				}
				else
				{
					// get the name and hint
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDosHeader + pThunk->u1.AddressOfData);

					// Check if the function is one of the functions we want to intercept
					for (size_t i = 0; i < funcCount; i++) {
						if ((void*)originAddr[i] != nullptr)
							continue;

						if (strcmp(pImportByName->Name, funcNames[i]) == 0) {
							originAddr[i] = &(pIATThunk->u1.Function);
							funcAddr[i] = pIATThunk->u1.Function;

							std::cout << "    Found function: " << funcNames[i] << " at address: " << std::hex << funcAddr[i] << std::dec << std::endl;
						}
					}
				}

				// parallel iteration of the thunks, same order
				pIATThunk++;
				pThunk++;
			}
		}

		initialized = true;

		for (size_t i = 0; i < funcCount; i++)
		{
			if (!funcAddr[i])
			{
				std::cout << "Warning: Function " << funcNames[i] << " NOT found in import table, wont be used." << std::endl;
			}
		}
		std::cout << std::endl;

		system("pause");
	}

	if (!switched && initialized)
	{
		std::cout << "Switching to debug functions..." << std::endl;
		DisableOriginal();

		switched = true;
	}

	std::cout << std::endl;
}
void MallocDebug_Done()
{
	std::cout << "MallocDebug_Done()" << std::endl;

	if (switched)
	{
		std::cout << "Switching to original functions..." << std::endl;
		EnableOriginal();

		switched = false;
	}

	// memory leaks
	for (const auto& [ptr, block] : allocatedMemory)
	{
		std::cout << "Warning: Memory leak detected: " << ptr << std::endl;
		std::cout << "	function: " << funcNames[block.used_function] << std::endl;
		if (block.used_function == 0) {
			std::cout << "	size: " << block.size << std::endl;
		}
		else if (block.used_function == 1) {
			std::cout << "	size: " << block.num << " * " << block.size << " (" << block.num * block.size << ")" << std::endl;
		}
		else if (block.used_function == 2) {
			std::cout << "	size: " << block.size << std::endl;
			std::cout << "	old_ptr: " << std::hex << block.old_ptr << std::dec << std::endl;
		}
	}
	if (allocatedMemory.empty())
	{
		std::cout << "No memory leaks detected." << std::endl;
	}

	switched = false;

	std::cout << std::endl;
}

void* MallocDebug_malloc(size_t size)
{
	std::cout << "MallocDebug_malloc(" << size << ")" << std::endl;

	if (!funcAddr[0]) {
		std::cout << "Error: malloc function not found" << std::endl << std::endl;
		return nullptr;
	}

	malloc_t original_malloc = (malloc_t)(uintptr_t)funcAddr[0];
	void* ptr = original_malloc(size);

	std::cout << "ptr = " << std::hex << ptr << std::dec << std::endl << std::endl;

	// can return nullptr if error
	// dont add the nullptr in the allocatedMemory map, not a valid pointer
	if (ptr == nullptr)
		return ptr;

	// remove from already freed memory, it is being allocated again
	// and add to allocated memory to be then checked for leaks
	EnableOriginal();
	freedMemory.erase(ptr);
	allocatedMemory.insert({ ptr, { size, 0, nullptr, 0 } });
	DisableOriginal();

	return ptr;
}

void* MallocDebug_calloc(size_t num, size_t size)
{
	std::cout << "MallocDebug_calloc(" << num << ", " << size << ")" << std::endl;

	if (!funcAddr[1]) {
		std::cout << "Error: calloc function not found" << std::endl << std::endl;
		return nullptr;
	}

	calloc_t original_calloc = (calloc_t)(uintptr_t)funcAddr[1];
	void* ptr = original_calloc(num, size);

	std::cout << "ptr = " << std::hex << ptr << std::dec << std::endl << std::endl;

	// can return nullptr if error
	if (ptr == nullptr)
		return ptr;

	EnableOriginal();
	freedMemory.erase(ptr);
	allocatedMemory.insert({ ptr, { size, 1, nullptr, num } });
	DisableOriginal();

	return ptr;
}

void* MallocDebug_realloc(void* oldPtr, size_t size)
{
	std::cout << "MallocDebug_realloc(" << std::hex << oldPtr << std::dec << ", " << size << ")" << std::endl;

	if (!funcAddr[2]) {
		std::cout << "Error: realloc function not found" << std::endl << std::endl;
		return nullptr;
	}

	realloc_t original_realloc = (realloc_t)(uintptr_t)funcAddr[2];
	void* ptr = original_realloc(oldPtr, size);

	std::cout << "ptr = " << std::hex << ptr << std::dec << std::endl << std::endl;

	if (ptr == nullptr)
		return ptr;

	EnableOriginal();
	if (oldPtr == nullptr) {
		// acts as a malloc
		// in case of a realloc calling malloc internally
		// dont add, it was already done by the malloc call, which is overriden as well

		if (!allocatedMemory.contains(ptr)) {
			freedMemory.erase(ptr);
			allocatedMemory.insert({ ptr, { size, 2, oldPtr, 0 } });
		}
		DisableOriginal();

		return ptr;
	}

	freedMemory.erase(ptr);

	if (ptr != oldPtr) {
		// entirely new allocation
		// old pointer freed, new pointer allocated
		freedMemory.insert(oldPtr);
		allocatedMemory.erase(oldPtr);

		allocatedMemory.insert({ ptr, { size, 2, oldPtr, 0 } });
	}
	else {
		// expanding existing allocation, instead of entirely new allocation
		allocatedMemory[ptr] = { size, 2, oldPtr, 0 };
	}
	DisableOriginal();

	return ptr;
}

void MallocDebug_free(void* ptr)
{
	std::cout << "MallocDebug_free(" << std::hex << ptr << std::dec << ")" << std::endl;

	if (!funcAddr[3]) {
		std::cout << "Error: free function not found" << std::endl << std::endl;
		return;
	}

	if (ptr == nullptr) {
		// freeing nullptr is valid, but warn about it
		std::cout << "Warning: Freeing nullptr pointer" << std::endl;
	}
	else {
		// check for double free and freeing not allocated pointer
		EnableOriginal();
		if (freedMemory.contains(ptr)) {
			std::cout << "Warning: Double free detected for pointer: " << ptr << std::endl;
		}
		else if (!allocatedMemory.contains(ptr)) {
			std::cout << "Warning: Freeing not allocated pointer: " << ptr << std::endl;
		}

		// clean up after free
		freedMemory.insert(ptr);
		allocatedMemory.erase(ptr);
		DisableOriginal();
	}

	std::cout << std::endl;

	free_t original_free = (free_t)(uintptr_t)funcAddr[3];
	original_free(ptr);
}

// ----------------------------------------------------------------------------

int main()
{
	try {
		// Test normal

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

		// Done
	}
	catch (const std::exception& e) {
		std::cout << "Exception: " << e.what() << std::endl;
	}

	system("pause");

	return 0;
}

// ----------------------------------------------------------------------------