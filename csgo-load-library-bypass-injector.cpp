#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>

HANDLE csgo_handle = 0;

DWORD get_module_base_address(DWORD process_id, const wchar_t* module_name)
{
	DWORD module_base_address = 0;
	HANDLE snap_shot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
	if (snap_shot_handle != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 module_entry;
		module_entry.dwSize = sizeof(module_entry);
		if (Module32First(snap_shot_handle, &module_entry))
		{
			do
			{
				if (!_wcsicmp(module_entry.szModule, module_name))
				{
					module_base_address = (DWORD)module_entry.modBaseAddr;
					break;
				}
			} while (Module32Next(snap_shot_handle, &module_entry));
		}
	}

	CloseHandle(snap_shot_handle);
	return module_base_address;
}

DWORD pattern_scan(DWORD start, const std::string& pattern)
{
	static auto pattern_to_byte = [](const char* pattern) -> std::vector<int>
	{
		auto bytes = std::vector<int>{};
		auto start = (char*)pattern;
		auto end = (char*)pattern + strlen(pattern);

		for (auto current = start; current < end; ++current)
		{
			if (*current == '?' || *current == '.')
			{
				++current;
				if (*current == '?' || *current == '.')
					++current;

				bytes.push_back(-1);
			}
			else
				bytes.push_back(strtoul(current, &current, 16));
		}

		return bytes;
	};

	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS nt_headers;

	DWORD bytes_read = 0;
	ReadProcessMemory(csgo_handle, (void*)start, &dos_header, sizeof(dos_header), &bytes_read);
	ReadProcessMemory(csgo_handle, (void*)(start + dos_header.e_lfanew), &nt_headers, sizeof(nt_headers), &bytes_read);

	uint8_t* local_image = new uint8_t[nt_headers.OptionalHeader.SizeOfImage];
	ReadProcessMemory(csgo_handle, (void*)start, local_image, nt_headers.OptionalHeader.SizeOfImage, &bytes_read);

	const auto pattern_bytes = pattern_to_byte(pattern.c_str());

	const auto s = pattern_bytes.size();
	const auto d = pattern_bytes.data();

	for (size_t i = 0; i < nt_headers.OptionalHeader.SizeOfImage - s; ++i)
	{
		bool found = true;
		for (auto j = 0ul; j < s; ++j)
		{
			if (local_image[i + j] != d[j] && d[j] != -1)
			{
				found = false;
				break;
			}
		}

		if (found)
		{
			delete[] local_image;
			return start + i;
		}
	}

	delete[] local_image;
	return 0;
}

int main()
{
	std::cout << "Dll name:\n";

	std::string dll_name = "";
	std::cin >> dll_name;

	char dll_path[MAX_PATH];
	GetFullPathNameA(dll_name.c_str(), MAX_PATH, dll_path, nullptr);

	HWND csgo_hwnd = FindWindowA(0, "Counter-Strike: Global Offensive");
	if (!csgo_hwnd)
		return 0;

	DWORD csgo_pid = 0;
	GetWindowThreadProcessId(csgo_hwnd, &csgo_pid);
	if (!csgo_pid)
		return 0;

	csgo_handle = OpenProcess(PROCESS_ALL_ACCESS, false, csgo_pid);
	if (!csgo_handle)
		return 0;

	DWORD csgo_base = get_module_base_address(csgo_pid, L"csgo.exe");
	if (!csgo_base)
		return 0;

	DWORD highest_trust_routine_index_address = pattern_scan(csgo_base, "39 05 ? ? ? ? 0F 8F");
	if (!highest_trust_routine_index_address)
		return 0;

	ReadProcessMemory(csgo_handle, (void*)(highest_trust_routine_index_address + 2), &highest_trust_routine_index_address, sizeof(highest_trust_routine_index_address), nullptr);
	if (!highest_trust_routine_index_address)
		return 0;

	int old_value = 0;

	// Bypassing LoadLibrary mechanism
	{
		int new_value = 5;
		ReadProcessMemory(csgo_handle, (void*)highest_trust_routine_index_address, &old_value, sizeof(old_value), nullptr);
		WriteProcessMemory(csgo_handle, (void*)highest_trust_routine_index_address, &new_value, sizeof(new_value), nullptr);
	}

	// Now continue normal LoadLibrary dll injection
	{
		void* dll_path_address_in_csgo = VirtualAllocEx(csgo_handle, 0, strlen(dll_path), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!dll_path_address_in_csgo)
			return 0;

		if (!WriteProcessMemory(csgo_handle, dll_path_address_in_csgo, dll_path, strlen(dll_path), nullptr))
			return 0;

		HMODULE kernel_base = GetModuleHandleA("kernel32.dll");
		if (!kernel_base)
			return 0;

		void* load_library_address = GetProcAddress(kernel_base, "LoadLibraryA");
		if (!load_library_address)
			return 0;

		HANDLE remote_thread = CreateRemoteThread(csgo_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)load_library_address, dll_path_address_in_csgo, 0, nullptr);
		if (!remote_thread)
			return 0;

		WaitForSingleObject(remote_thread, INFINITE);

		// Restoring LoadLibrary mechanism
		{
			WriteProcessMemory(csgo_handle, (void*)highest_trust_routine_index_address, &old_value, sizeof(old_value), nullptr);
		}

		CloseHandle(csgo_handle);
	}

	return 0;
}