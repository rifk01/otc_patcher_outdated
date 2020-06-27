#pragma once

#include <Windows.h>
#include <vector>

__forceinline uint8_t* find_sig(const uint32_t offset, const char* signature, const uint32_t range = 0u)
{
	static auto pattern_to_bytes = [](const char* pattern) -> std::vector<int> {
		auto bytes = std::vector<int32_t>{ };
		const auto start = const_cast<char*>(pattern);
		const auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				current++;

				if (*current == '?')
					current++;

				bytes.push_back(-1);
			}
			else
				bytes.push_back(static_cast<int32_t>(strtoul(current, &current, 0x10)));
		}

		return bytes;
	};

	const auto scan_bytes = reinterpret_cast<std::uint8_t*>(offset);
	auto pattern_bytes = pattern_to_bytes(signature);
	const auto s = pattern_bytes.size();
	const auto d = pattern_bytes.data();

	for (auto i = 0ul; i < range - s; ++i) {
		auto found = true;

		for (auto j = 0ul; j < s; ++j)
			if (scan_bytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}

		if (found)
			return &scan_bytes[i];
	}

	return nullptr;
}

__forceinline uint8_t* find_module_sig(const char* name, const char* signature)
{
	const auto module = (uint32_t)GetModuleHandle(name);

	if (module) {
		const auto dos_header = PIMAGE_DOS_HEADER(module);
		const auto nt_headers = PIMAGE_NT_HEADERS(reinterpret_cast<std::uint8_t*>(module) + dos_header->e_lfanew);
		const auto ret_value = find_sig(module, signature, nt_headers->OptionalHeader.SizeOfImage);
		if (!ret_value)
			MessageBox(0, "outdated sig!", "", 0);
		return ret_value;
	}

	return nullptr;
}