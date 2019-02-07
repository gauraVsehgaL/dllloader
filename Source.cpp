#include <iostream>
#include <Windows.h>
#include "resource.h"
#include <fstream>
#include <vector>
auto LoadResource()
{
	auto rsrc = FindResource(nullptr, MAKEINTRESOURCE(IDR_DLL1), "dll");
	if (!rsrc)
		return (void*)nullptr;
	auto mem = LoadResource(nullptr, rsrc);
	auto ptr = LockResource(mem);
	auto size = SizeofResource(nullptr, rsrc);
	return ptr;
}


std::vector<BYTE> MapDllIntoMemory(void *dlldata)
{
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dlldata);
	//PIMAGE_NT_HEADERS pinh = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(lpPayload) + pidh->e_lfanew);

	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(dlldata) + pDosHeader->e_lfanew);
	//HANDLE hMapping = ::CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, pinh->OptionalHeader.SizeOfImage, NULL);
	
	auto hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, pNtHeaders->OptionalHeader.SizeOfImage, NULL);
	if (!hMapping)
	{
		std::cout << "CreateFileMapping failed "<<GetLastError();
		return{};
	}
	auto dllinmem = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
	if (!dllinmem)
		return {};
	//	copy headers
	CopyMemory(dllinmem, dlldata, pNtHeaders->OptionalHeader.SizeOfHeaders);
	//	copy sections
	auto FirstSectionHeader = reinterpret_cast<DWORD>(dlldata) + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	
	for (auto i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pish = reinterpret_cast<PIMAGE_SECTION_HEADER>(FirstSectionHeader + sizeof(IMAGE_SECTION_HEADER) * i);
		CopyMemory(
			reinterpret_cast<void*>(reinterpret_cast<DWORD>(dllinmem) + pish->VirtualAddress),
			reinterpret_cast<void*>(reinterpret_cast<DWORD>(dlldata) + pish->PointerToRawData),
			pish->SizeOfRawData
		);
	}

	return std::vector<BYTE>(reinterpret_cast<BYTE*>(dllinmem), reinterpret_cast<BYTE*>(dllinmem) + pNtHeaders->OptionalHeader.SizeOfImage);

	UnmapViewOfFile(dllinmem);
	CloseHandle(hMapping);
}

DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	return rva;
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

bool RebuildImportTable(void *BaseAddress, PIMAGE_NT_HEADERS pNtHeaders, PIMAGE_SECTION_HEADER pSecHeader)
{
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size <= 0)
		return true;	// no imports
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
														reinterpret_cast<DWORD_PTR>(BaseAddress) 
														+ Rva2Offset(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSecHeader, pNtHeaders)
												);
	while (pImportDescriptor->Name != NULL)
	{
		char *Library = reinterpret_cast<char *>(reinterpret_cast<DWORD_PTR>(BaseAddress) + Rva2Offset(pImportDescriptor->Name, pSecHeader, pNtHeaders));
		auto hLib = LoadLibrary(Library);
		if (!hLib)
			continue;
		PIMAGE_THUNK_DATA Name = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(BaseAddress) + Rva2Offset(pImportDescriptor->Characteristics, pSecHeader, pNtHeaders));
		PIMAGE_THUNK_DATA Symbol = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(BaseAddress) + Rva2Offset(pImportDescriptor->FirstThunk, pSecHeader, pNtHeaders));
		PIMAGE_THUNK_DATA Thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(BaseAddress) + Rva2Offset(pImportDescriptor->FirstThunk, pSecHeader, pNtHeaders));

		for (; Name->u1.AddressOfData; Name++, Symbol++, Thunk++)
		{
			if (Name->u1.AddressOfData & IMAGE_ORDINAL_FLAG)
				*(FARPROC *)Thunk = GetProcAddress(hLib, MAKEINTRESOURCE(Name->u1.AddressOfData));
			else
			{
				PIMAGE_IMPORT_BY_NAME ThunkData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<DWORD>(BaseAddress) + Rva2Offset(Name->u1.AddressOfData, pSecHeader, pNtHeaders));
				*(FARPROC *)Thunk = GetProcAddress(hLib, reinterpret_cast<CHAR*>(ThunkData->Name));
 			}
		}

		FreeLibrary(hLib);
		pImportDescriptor++;
	}

	return true;
}

bool Relocate(void *BaseAddress, PIMAGE_NT_HEADERS pNtHeaders, DWORD Delta)
{
	PIMAGE_BASE_RELOCATION pFirst = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<DWORD>(BaseAddress) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	PIMAGE_BASE_RELOCATION pLast = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<DWORD>(BaseAddress) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress 
																			+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
																			- sizeof(IMAGE_BASE_RELOCATION));
	for (; pFirst < pLast;)
	{
		WORD *reloc_item = reinterpret_cast<WORD*>(pFirst + 1);
		DWORD ItemCount = (pFirst->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (auto i = 0; i < ItemCount; i++, reloc_item++)
		{
			switch (*reloc_item >> 12)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*(DWORD_PTR*)(reinterpret_cast<DWORD>(BaseAddress) + pFirst->VirtualAddress + (*reloc_item & 0xFFF)) += Delta;
				break;
			default:
				return false;
			}
		}

		pFirst = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<DWORD_PTR>(pFirst) + pFirst->SizeOfBlock);
	}

	return true;
}

int main(int argc, char *argv[])
{
	auto TargetPid = atoi(argv[1]);
	auto dlldata = LoadResource();
	auto dllInMemory = MapDllIntoMemory(dlldata);
	auto hTargetProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,false, TargetPid);
	if (!hTargetProc)
	{
		std::cout << "openProcess() Failed " << GetLastError();
		return 1;
	}

	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllInMemory.data());
	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(dllInMemory.data()) + pDosHeader->e_lfanew);

	//::VirtualAllocEx(this->payload->hProcess, NULL, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	auto AddressInTargetProc = VirtualAllocEx(hTargetProc, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!AddressInTargetProc)
	{
		std::cout << "VirtaulAllocEx() Failed " << GetLastError();
		return 1;
	}

	PIMAGE_SECTION_HEADER  pSecHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	RebuildImportTable(&dllInMemory[0], pNtHeaders, pSecHeader);

	std::cout << "Successfully rebuilt import tabel \n ";
	auto delta = reinterpret_cast<DWORD>(AddressInTargetProc) - pNtHeaders->OptionalHeader.ImageBase;
	Relocate(&dllInMemory[0], pNtHeaders, delta);

	std::cout << "Successfully relocated \n ";

	if (!WriteProcessMemory(hTargetProc, AddressInTargetProc, dllInMemory.data(), pNtHeaders->OptionalHeader.SizeOfImage, nullptr))
	{
		std::cout << "WriteProcessMemory failed() " << GetLastError();
		return 1;
	}

	std::cout << "Successfully wroteprocessmemory \n ";

	auto EntryPoint = reinterpret_cast<DWORD>(AddressInTargetProc) + Rva2Offset(pNtHeaders->OptionalHeader.AddressOfEntryPoint, pSecHeader, pNtHeaders);
	DWORD dwThreadid;
	auto hThread = CreateRemoteThread(hTargetProc, nullptr, 1024*1024, reinterpret_cast<LPTHREAD_START_ROUTINE>(EntryPoint), nullptr, 0, &dwThreadid);
	if (!hThread)
	{
		std::cout << "CreateRemoteThread() failed " << GetLastError();
		return 1;
	}

	std::cout << "Created Thread : " << dwThreadid << "\n";
	char a;
	std::cout << "Waiting....";
	std::cin >> a;
	return 0;
}