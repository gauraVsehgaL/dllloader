#include<iostream>
#include<string>
#include<Windows.h>
/*
extern "C"
__declspec(dllexport) void JustCreateAFile(std::string FilePath)
{
	HANDLE File = CreateFile(FilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (NULL == File)
		std::cout << "Failed to create file: " << FilePath << std::endl;
	else
		std::cout << "Successfully created file: " << FilePath << std::endl;
}
*/
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, "Dll Loaded", "Info", MB_OK);
		//JustCreateAFile(R"(E:\\sim.wcry)");
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}