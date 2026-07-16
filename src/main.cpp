#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdarg>
#include <cstring>

namespace
{
    HMODULE g_sampDll = nullptr;

    void Log(const char* format, ...)
    {
        char message[1024]{};

        va_list args;
        va_start(args, format);
        std::vsnprintf(message, sizeof(message), format, args);
        va_end(args);

        OutputDebugStringA(message);
        OutputDebugStringA("\n");

        FILE* file = nullptr;
        if (fopen_s(&file, "VehiclesExtended.log", "a") == 0 && file)
        {
            std::fprintf(file, "%s\n", message);
            std::fclose(file);
        }
    }

    bool GetTextSection(HMODULE module, std::uint8_t*& textBase, std::size_t& textSize)
    {
        textBase = nullptr;
        textSize = 0;

        if (!module)
            return false;

        auto* moduleBase = reinterpret_cast<std::uint8_t*>(module);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);

        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        {
            Log("Invalid DOS header in samp.dll");
            return false;
        }

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(moduleBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            Log("Invalid PE header in samp.dll");
            return false;
        }

        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            Log("Unsupported samp.dll architecture; expected 32-bit");
            return false;
        }

        const std::size_t imageSize = nt->OptionalHeader.SizeOfImage;
        auto* sections = IMAGE_FIRST_SECTION(nt);

        for (unsigned int index = 0; index < nt->FileHeader.NumberOfSections; ++index)
        {
            if (std::memcmp(sections[index].Name, ".text", 5) != 0)
                continue;

            const std::size_t virtualAddress = sections[index].VirtualAddress;
            const std::size_t virtualSize = sections[index].Misc.VirtualSize;

            if (virtualSize == 0 || virtualAddress >= imageSize || virtualSize > imageSize - virtualAddress)
            {
                Log("Invalid .text section boundaries");
                return false;
            }

            textBase = moduleBase + virtualAddress;
            textSize = virtualSize;
            return true;
        }

        Log(".text section not found in samp.dll");
        return false;
    }

    const std::uint8_t* FindUniquePattern(
        const std::uint8_t* base,
        std::size_t size,
        const std::uint8_t* pattern,
        std::size_t patternSize,
        const char* mask,
        std::size_t& matchCount)
    {
        matchCount = 0;

        if (!base || !pattern || !mask || patternSize == 0)
            return nullptr;

        if (std::strlen(mask) != patternSize)
        {
            Log("Internal error: pattern and mask lengths do not match");
            return nullptr;
        }

        if (size < patternSize)
            return nullptr;

        const std::uint8_t* firstMatch = nullptr;

        for (std::size_t offset = 0; offset <= size - patternSize; ++offset)
        {
            bool matched = true;

            for (std::size_t index = 0; index < patternSize; ++index)
            {
                if (mask[index] == 'x' && base[offset + index] != pattern[index])
                {
                    matched = false;
                    break;
                }
            }

            if (!matched)
                continue;

            if (!firstMatch)
                firstMatch = base + offset;

            ++matchCount;
        }

        return firstMatch;
    }

    bool PatchVehicleIdLimit()
    {
        std::uint8_t* textBase = nullptr;
        std::size_t textSize = 0;

        if (!GetTextSection(g_sampDll, textBase, textSize))
            return false;

        // cmp eax, 400 / jl ... / cmp eax, 611 / jg ...
        // Relative jump offsets are wildcarded because they differ between SA-MP builds.
        static constexpr std::uint8_t pattern[] = {
            0x3D, 0x90, 0x01, 0x00, 0x00,
            0x0F, 0x8C, 0x00, 0x00, 0x00, 0x00,
            0x3D, 0x63, 0x02, 0x00, 0x00,
            0x0F, 0x8F, 0x00, 0x00, 0x00, 0x00
        };

        static constexpr char mask[] = "xxxxxxx????xxxxxxx????";
        static_assert(sizeof(pattern) == sizeof(mask) - 1, "Pattern/mask length mismatch");

        std::size_t matchCount = 0;
        const std::uint8_t* match = FindUniquePattern(
            textBase,
            textSize,
            pattern,
            sizeof(pattern),
            mask,
            matchCount);

        if (!match || matchCount == 0)
        {
            Log("Vehicle ID signature not found; no patch was applied");
            return false;
        }

        if (matchCount != 1)
        {
            Log("Vehicle ID signature is ambiguous (%zu matches); patch aborted safely", matchCount);
            return false;
        }

        auto* jgInstruction = const_cast<std::uint8_t*>(match + 16);

        if (jgInstruction < textBase || jgInstruction + 6 > textBase + textSize)
        {
            Log("Patch address is outside the .text section; patch aborted safely");
            return false;
        }

        if (jgInstruction[0] != 0x0F || jgInstruction[1] != 0x8F)
        {
            Log("Expected JG instruction was not found; patch aborted safely");
            return false;
        }

        DWORD oldProtection = 0;
        if (!VirtualProtect(jgInstruction, 6, PAGE_EXECUTE_READWRITE, &oldProtection))
        {
            Log("VirtualProtect failed with error %lu", GetLastError());
            return false;
        }

        std::memset(jgInstruction, 0x90, 6);
        FlushInstructionCache(GetCurrentProcess(), jgInstruction, 6);

        DWORD ignoredProtection = 0;
        VirtualProtect(jgInstruction, 6, oldProtection, &ignoredProtection);

        Log("Vehicle ID limit patch applied successfully");
        return true;
    }

    void RunPatchSafely()
    {
        DeleteFileA("VehiclesExtended.log");
        Log("VehiclesExtended safe build started");

        // ASI plugins may be loaded before samp.dll. Wait instead of patching too early.
        for (int attempt = 0; attempt < 300; ++attempt)
        {
            g_sampDll = GetModuleHandleA("samp.dll");
            if (g_sampDll)
                break;

            Sleep(100);
        }

        if (!g_sampDll)
        {
            Log("samp.dll was not loaded within 30 seconds; plugin stopped safely");
            return;
        }

        // Give SA-MP a little extra time to finish its initialization.
        Sleep(1500);
        PatchVehicleIdLimit();
    }

    DWORD WINAPI PatchThread(LPVOID)
    {
#ifdef _MSC_VER
        __try
        {
            RunPatchSafely();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Log(
                "An internal exception was caught (code 0x%08lX); game execution continues",
                GetExceptionCode());
        }
#else
        RunPatchSafely();
#endif
        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(instance);

        HANDLE thread = CreateThread(nullptr, 0, PatchThread, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
    }

    return TRUE;
}
