#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <vector>
#include <deque>
#include <tuple>
#include <intrin.h>
#include <string>
#include "find_sig.h"

typedef BOOL(__stdcall* disable_thread_library_calls_t)(HMODULE);
disable_thread_library_calls_t orig_disable_thread_library_calls;

std::deque<std::tuple<uint32_t, const char*, uint32_t>> patch_offsets = {
	// Base 2c020000 Size 53d7000  51 56 8B F1 85 F6 74 68 83 BE 00 01 00 00 00
	std::make_tuple(0x2e4223, "51 56 8B F1 85 F6 74 68 83 BE 00 01 00 00 00", 0x0),
	//Base 2c260000 Size 53d7000  B0 01 83 FE 01 74 F0
	std::make_tuple(0x2fa561, "B0 01 83 FE 01 74 F0", 0x0),
	std::make_tuple(0x306150, "55 8B EC 83 E4 C0 83 EC 34 53 56 8B 75 08", 0x0),
	// Base 2c260000 Size 53d7000  55 8B EC 83 E4 F8 51 53 56 8B D9
	std::make_tuple(0x3358a0, "55 8B EC 83 E4 F8 51 53 56 8B D9", 0x0),
	std::make_tuple(0x340a05, "E8 ? ? ? ? 83 7D D8 00 7C 0F", 0x0),
	// Base 2c260000 Size 53d7000  A1 ?? ?? ?? ?? 74 38 85 C0 74 14 80 78 75 00
	std::make_tuple(0x3456e9, "A1 ? ? ? ? 74 38 85 C0 74 14 80 78 75 00", 0x0),
	// Base 2c260000 Size 53d7000  B9 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF 10 A1 ?? ?? ?? ?? B9 ?? ?? ?? ??
	std::make_tuple(0x349f59, "B9 ? ? ? ? A1 ? ? ? ? FF 10 A1 ? ? ? ? B9 ? ? ? ?", 0x0), // wildcards at the end idgaf
	std::make_tuple(0x34d7da, "85 C0 74 2D 83 7D 10 00", 0x0),
	std::make_tuple(0x372085, "B9 ? ? ? ? E8 ? ? ? ? 85 C0 74 0A 8B 10 8B C8 FF A2 AC 00 00 00", 0x0),
	// Base 2c260000 Size 53d7000  8B 35 ?? ?? ?? ?? FF 90 ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? FF 56 ?? 5E C3 CC CC CC CC CC CC CC
	std::make_tuple(0x37291d, "8B 35 ? ? ? ? FF 90 ? ? ? ? 50 B9 ? ? ? ? FF 56 ? 5E C3 CC CC CC CC CC CC CC", 0x0),
	// Base 2c260000 Size 53d7000  55 8B EC 83 EC 08 8B 15 ?? ?? ?? ?? 0F 57 C0 56
	std::make_tuple(0x388840, "55 8B EC 83 EC 08 8B 15 ? ? ? ? 0F 57 C0 56", 0x0),
	std::make_tuple(0x388897, "80 B9 ? ? ? ? ? 75 6C", 0x0),
	std::make_tuple(0x3948d0, "55 8B EC 83 E4 F8 81 EC ? ? ? ? 53 56 57 8B F9 BB", 0x0),
	//std::make_tuple(0x396748, "F3 0F 10 4C 24 ? 84 C0 74 12", 0x0),
	std::make_tuple(0x39c820, "55 8B EC 51 56 8B F1 80 BE ? ? ? ? ? 74 36", 0x0),
	std::make_tuple(0x39d220, "55 8B EC 56 8B F1 51 8D 4E FC", 0x0),
	std::make_tuple(0x39d266, "84 C0 75 0D F6 87", 0x0),
	std::make_tuple(0x39d284, "0F 84 ? ? ? ? 8B 88 ? ? ? ? 83 F9 FF 0F 84 ? ? ? ? 0F B7 C1 C1 E0 04 05 ? ? ? ? C1 E9 10 39 48 04 0F 85 ? ? ? ? 8B 18", 0x0),
	std::make_tuple(0x39dc60, "55 8B EC 83 E4 F8 81 EC ? ? ? ? 53 56 8B F1 57 89 74 24 1C", 0x0),
	// Base 2c260000 Size 53d7000  0F 44 C8 33 C0 5E 39 11
	std::make_tuple(0x39f605, "0F 44 C8 33 C0 5E 39 11", 0x0),
	// Base 2c260000 Size 53d7000  C7 00 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 08 8D 4E 74 8B C4
	std::make_tuple(0x3aa6ec, "C7 00 ? ? ? ? E8 ? ? ? ?? 83 EC 08 8D 4E 74 8B C4", 0x0),
	std::make_tuple(0x3aa6fa, "8D 4E 74 8B C4", 0x0),
	std::make_tuple(0x3b8993, "75 F3 8B 44 24 14", 0x0),
	std::make_tuple(0x3c29b2, "75 04 B0 01 5F", 0x0),
	// Base 2c260000 Size 53d7000  55 8B EC 51 56 8B 35 ?? ?? ?? ?? 57 83 BE 8C 00 00 00 02 73 65
	std::make_tuple(0x3d3900, "55 8B EC 51 56 8B 35 ? ? ? ? 57 83 BE 8C 00 00 00 02 73 65", 0x0),
	// Base 2c260000 Size 53d7000  83 3D ?? ?? ?? ?? ?? 57 8B F9 75 06 32 C0 5F C2 04 00
	std::make_tuple(0x3da8d0, "83 3D ? ? ? ? ? 57 8B F9 75 06 32 C0 5F C2 04 00", 0x0),
	//Base 2c260000 Size 53d7000  8B 35 ?? ?? ?? ?? FF 10 0F B7 C0 B9 ?? ?? ?? ?? 50 FF 56 ?? 85 C0
	std::make_tuple(0x3dd9c8, "8B 35 ? ? ? ? FF 10 0F B7 C0 B9 ? ? ? ? 50 FF 56 ? 85 C0", 0x0),
	std::make_tuple(0x3e9960, "56 6A 01 68 ? ? ? ? 8B F1", 0x0),
	// Base 2c260000 Size 53d7000  55 8B EC 83 E4 F8 83 EC 60 56 57 8B F9 89 7C 24 10
	std::make_tuple(0x3ea2e0, "55 8B EC 83 E4 F8 83 EC 60 56 57 8B F9 89 7C 24 10", 0x0),
	std::make_tuple(0x3ee5a0, "55 8B EC 83 E4 F8 83 EC 30 56 57 8B 3D", 0x0),
	std::make_tuple(0x3ee5e9, "84 C0 75 38 8B 0D ? ? ? ? 8B 01 8B 80", 0x0),
	std::make_tuple(0x3ee62f, "F3 0F 10 A6 ? ? ? ? F3 0F 11 64 24", 0x0),
	std::make_tuple(0x3da8d0, "E8 ? ? ? ? 84 C0 75 1C 8B CE", 0x0),
	std::make_tuple(0x5f56b5, "E8 ? ? ? ? 8B 4C 24 10 0F 57 D2", 0x0),
	std::make_tuple(0x5f8bfc, "83 BE ? ? ? ? ? 7F 67", 0x0),
	// Base 2c260000 Size 53d7000  E8 ?? ?? ?? ?? FF 76 0C 8D 48 04 E8 ?? ?? ?? ?? 89 44 24 14
	// 63 89 3B // unpatched
	// 93 89 3B // patched
	std::make_tuple(0x3b8963, "E8 ? ? ? ? FF 76 0C 8D 48 04 E8 ? ? ? ? 89 44 24 14", 0x0),
	std::make_tuple(0x690500, "55 8B EC 56 8B 35 ? ? ? ? 85 F6 0F 84 ? ? ? ? 81 C6", 0x0),
	//Base 2c260000 Size 53d7000  85 C0 75 30 38 86 AD 00 00 00 74 28 8B 0D ?? ?? ?? ?? 85 C9
	std::make_tuple(0x2c71af, "85 C0 75 30 38 86 AD 00 00 00 74 28 8B 0D ? ? ? ? 85 C9", 0x0),
	std::make_tuple(0x6e0150, "56 8B F1 8B 0D ? ? ? ? 57 8B 01 FF 76 70", 0x0),
	std::make_tuple(0x8c4bc0, "55 8B EC F3 0F 10 45 ? 56 6A 00", 0x0),
	// Base 2c260000 Size 53d7000  55 8B EC 53 8B 5D 08 56 57 8B F9 33 F6 39 77 28 7E 1E
	std::make_tuple(0x2a7190, "55 8B EC 53 8B 5D 08 56 57 8B F9 33 F6 39 77 28 7E 1E", 0x0),
};

BOOL __stdcall disable_lib_calls(HMODULE module)
{
	static bool diff = false;
	static bool did_once = false;

	const auto cheat_base = (DWORD)GetModuleHandle("onetap.dll");
	const auto ret = (DWORD)_ReturnAddress();

	auto patch_offset = [](DWORD location, DWORD offset)
	{
		DWORD old_protection = 0x0;
		VirtualProtect((LPVOID)location, 4, PAGE_READWRITE, &old_protection);
		*(DWORD*)location = offset;
		VirtualProtect((LPVOID)location, 4, old_protection, &old_protection);
	};

	if (ret >= cheat_base && ret <= cheat_base + 0x42FFF && !did_once)
	{
		did_once = true;

		const auto client_panorama_base = (DWORD)GetModuleHandle("client_panorama.dll");

		AllocConsole();
		freopen("CONIN$", "r", stdin);
		freopen("CONOUT$", "w", stdout);
		freopen("CONOUT$", "w", stderr);

		printf("> invoked from retaddress!\n");
		printf("> patching outdated offsets...\n\n");
		Sleep(1500);

		const auto offset_function = find_module_sig("onetap.dll",
			"55 8B EC 81 EC ? ? ? ? C7 85 ? ? ? ? ? ? ? ? C7 85 ? ? ? ? ? ? ? ? C7 85");

		const auto offset_start = offset_function + 0xF;

		for (auto traverse_function = offset_start; traverse_function < offset_start + 0x2E5; traverse_function += 0xA)
		{
			if (diff)
			{
				traverse_function -= 0x3;
			}

			auto current_offset = *(DWORD*)traverse_function;

			if (current_offset == 0x3C29B2)
				diff = true;

			for (uint32_t it = 0; it < patch_offsets.size(); it++)
			{
				const auto broken_offset = std::get<0>(patch_offsets[it]);
				const auto new_sig = std::get<1>(patch_offsets[it]);
				const auto sig_offset = std::get<2>(patch_offsets[it]);

				// same offset twice, patch the first one only.
				if (diff && broken_offset == 0x388840)
					continue;

				if (current_offset == broken_offset)
				{
					printf("0x%06X => ", current_offset);
					current_offset = (DWORD)find_module_sig("client_panorama.dll", new_sig) + sig_offset;
					current_offset -= client_panorama_base;

					patch_offset((DWORD)traverse_function, current_offset);
					
					printf("0x%06X\n", current_offset);
				}
			}
		}

		/*
		$+2E8    > C745 E8 C0528C00                  MOV DWORD PTR SS:[EBP-18],8C52C0
		$+2EF    > 50                                PUSH EAX
		$+2F0    > 8D4D FC                           LEA ECX,DWORD PTR SS:[EBP-4]
		$+2F3    > C745 EC 27912400                  MOV DWORD PTR SS:[EBP-14],249127
		$+2FA    > 51                                PUSH ECX
		$+2FB    > 8D95 A4FEFFFF                     LEA EDX,DWORD PTR SS:[EBP-15C]
		$+301    > C745 F0 889C1C00                  MOV DWORD PTR SS:[EBP-10],1C9C88
		$+308    > 52                                PUSH EDX
		$+309    > B9 A8EAF453                       MOV ECX,modified.53F4EAA8
		$+30E    > C745 F4 A0583300                  MOV DWORD PTR SS:[EBP-C],3358A0
		$+315    > C745 F8 E0221B00                  MOV DWORD PTR SS:[EBP-8],1B22E0
		*/

		auto offset = offset_function + 0x2E8 + 0x3;

		for (uint32_t remaining_offsets = 0; remaining_offsets < 5; remaining_offsets++)
		{
			if (remaining_offsets == 1)
				offset = offset_function + 0x2F3 + 0x3;
			else if (remaining_offsets == 2)
				offset = offset_function + 0x301 + 0x3;
			else if (remaining_offsets == 3)
				offset = offset_function + 0x30E + 0x3;
			else if (remaining_offsets == 4)
				offset = offset_function + 0x315 + 0x3;

			auto current_offset = *(DWORD*)offset;

			for (uint32_t it = 0; it < patch_offsets.size(); it++)
			{
				const auto broken_offset = std::get<0>(patch_offsets[it]);
				const auto new_sig = std::get<1>(patch_offsets[it]);
				const auto sig_offset = std::get<2>(patch_offsets[it]);

				if (current_offset == broken_offset)
				{
					printf("0x%06X => ", current_offset);
					current_offset = (DWORD)find_module_sig("client_panorama.dll", new_sig) + sig_offset;
					current_offset -= client_panorama_base;
					
					patch_offset((DWORD)offset, current_offset);

					printf("0x%06X\n", current_offset);
				}
			}
		}

		printf("\n> applying updated offsets...");

		// sub_1003F2A0
		// 55 8B EC 81 EC ? ? ? ? C7 85
		const auto reinit_offsets = (DWORD)find_module_sig("onetap.dll", "55 8B EC 81 EC ? ? ? ? C7 85");
		reinterpret_cast<int(__stdcall*)()>(reinit_offsets)();

		Sleep(1500);
		const auto window_handle = GetConsoleWindow();
		FreeConsole();
		PostMessage(window_handle, WM_CLOSE, 0, 0);
	}
}

DWORD __stdcall worker_thread(LPVOID parameter)
{
	auto detour_func = [](BYTE* src, const BYTE* dst, const int len)
	{
		BYTE* jmp = (BYTE*)malloc(len + 5);
		DWORD dwback;
		VirtualProtect(src, len, PAGE_READWRITE, &dwback);
		memcpy(jmp, src, len); jmp += len;
		jmp[0] = 0xE9;
		*(DWORD*)(jmp + 1) = (DWORD)(src + len - jmp) - 5;
		src[0] = 0xE9;
		*(DWORD*)(src + 1) = (DWORD)(dst - src) - 5;
		VirtualProtect(src, len, dwback, &dwback);
		return (jmp - len);
	};

	const auto lib_calls = (DWORD)GetProcAddress(GetModuleHandle("kernel32.dll"), 
		"DisableThreadLibraryCalls");

	if (!lib_calls)
		MessageBox(0, "Chinese super cracker is clueless, sorry.", "Error", 0);

	orig_disable_thread_library_calls = (disable_thread_library_calls_t)detour_func(
		(PBYTE)lib_calls, (PBYTE)disable_lib_calls, 5);

	char dll_path[MAX_PATH] = {};
	GetModuleFileNameA((HMODULE)parameter, dll_path, MAX_PATH);
	auto cheat_path = std::string(dll_path);
	const auto last_slash = std::string(dll_path);
	cheat_path = cheat_path.substr(0, cheat_path.find_last_of("\\/")) + "\\onetap.dll";
	
	LoadLibrary(cheat_path.c_str());

	return 0;
}

BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		HANDLE thread_handle = CreateThread(0, 0, worker_thread, hinstDLL, 0, 0);
		if (thread_handle)
			CloseHandle(thread_handle);
	}

	return TRUE;
}