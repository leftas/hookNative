#include "Pattern.h"
#include "log.h"
#include "MinHook.h"

#pragma comment(lib,"libMinHook.x64.lib")

typedef __int64(__fastcall* tRETURN_NUMBER_OF_RUNNING_SCRIPT)(unsigned int hash);
tRETURN_NUMBER_OF_RUNNING_SCRIPT oRETURN_NUMBER_OF_RUNNING_SCRIPT = NULL;


__int64 __fastcall hkRETURN_NUMBER_OF_RUNNING_SCRIPT(unsigned int hash)
{
	if (hash == 0x5350ee84)
		return 1;
	else
		return oRETURN_NUMBER_OF_RUNNING_SCRIPT(hash);
}
 

DWORD64 funcToHookOn = 0;

void mainFunction()
{

	MODULEINFO moduleInfo;
	bool bSuccess;
	MH_STATUS status;

	Log::Init();
	
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &moduleInfo, sizeof(MODULEINFO));
	Log::Write(Log::Type::Debug, "Base address is at: %I64X", moduleInfo.lpBaseOfDll);

	funcToHookOn = Pattern::Scan(moduleInfo, "48 89 5C 24 ? 57 48 83 EC 20 44 0F B7 05 ? ? ? ? 33 D2");
	Log::Write(Log::Type::Debug, "The code is found at: %I64X", funcToHookOn);
	
	status = MH_Initialize();

	Log::Write(Log::Type::Debug, "MinHook intialization was: ", status != MH_STATUS::MH_OK ? "Not successful" : "Successful");

	status = MH_CreateHook((void*)funcToHookOn, hkRETURN_NUMBER_OF_RUNNING_SCRIPT, (void**)&oRETURN_NUMBER_OF_RUNNING_SCRIPT);

	Log::Write(Log::Type::Debug, "MinHook hook creation was: ", status != MH_STATUS::MH_OK ? "Not successful" : "Successful");
	
	status = MH_EnableHook((void*)funcToHookOn);

	Log::Write(Log::Type::Debug, "MinHook enable was: ", status != MH_STATUS::MH_OK ? "Not successful" : "Successful");
	
}

void Revert()
{
	MH_DisableHook((void*)funcToHookOn);
	MH_Uninitialize();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)mainFunction, NULL, 0, 0);
		return true;
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		Revert();
		return true;
	}
	return false;
}