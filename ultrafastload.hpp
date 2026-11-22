#pragma once

// Startup profile and narrowly scoped VirtualProtect range restoration.
// The measured bottleneck is in this installation's compatibility runtime:
// it opens ~1-2 code pages, then restores all 232 MB of .rsrc to execute/read.
// Journal protection changes and restore only regions that differ. No code/data,
// game resource, loading-completion predicate, or access check is skipped.
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <atomic>
#include <share.h>
#include "addresses.h"
#include "minhook/include/MinHook.h"

namespace JC4UltraFastLoad {
using ProtectFn = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using NtProtectFn = LONG (NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
static ProtectFn OriginalProtect = nullptr;
static NtProtectFn OriginalNtProtect = nullptr;
static uintptr_t ImageBase = 0;
static uintptr_t RestoreBase = 0;
static SIZE_T RestoreSize = 0;
static uintptr_t RuntimeBase = 0;
static SRWLOCK RestoreLock = SRWLOCK_INIT;
static SRWLOCK LogLock = SRWLOCK_INIT;
static FILE* Profile = nullptr;
static LARGE_INTEGER Frequency = {};
static LARGE_INTEGER ClockOrigin = {};
static double OriginFromCreationMs = 0;
static std::atomic<LONGLONG> CurtainTick{0};
static std::atomic<bool> ReadyRecorded{false};
static std::atomic<unsigned long long> OptimizedRestores{0};
static std::atomic<unsigned long long> RegionQueries{0};
static std::atomic<unsigned long long> ChangedBytes{0};
static std::atomic<unsigned long long> LogicalBytes{0};
static std::atomic<unsigned long long> Fallbacks{0};
static bool Requested = false;
static bool Installed = false;
static constexpr size_t MaxPages = 0xdd5e;
static DWORD PageProtection[MaxPages] = {};
static uint64_t DirtyPages[(MaxPages + 63) / 64] = {};
static bool JournalValid = false; // protected by RestoreLock
static DWORD JournalAllocationType = MEM_IMAGE;
static std::atomic<unsigned long long> UntrackedEpoch{0};
static std::atomic<unsigned long> UntrackedActive{0};
static unsigned long long KnownEpoch = 0; // protected by RestoreLock

static void MarkPages(uintptr_t address, SIZE_T size, DWORD protection) {
    if (!size || address + size < address) { JournalValid = false; return; }
    const uintptr_t low = address < RestoreBase ? RestoreBase : address;
    const uintptr_t requestEnd = address + size;
    const uintptr_t regionEnd = RestoreBase + RestoreSize;
    const uintptr_t high = requestEnd < regionEnd ? requestEnd : regionEnd;
    if (low >= high) return;
    // PAGE_TARGETS_NO_UPDATE controls CFG bookkeeping; it is not a stored page
    // protection reported in MEMORY_BASIC_INFORMATION.Protect.
    protection &= ~DWORD(0x40000000);
    const size_t first = (low - RestoreBase) / 4096;
    const size_t last = (high - RestoreBase + 4095) / 4096;
    for (size_t i = first; i < last; ++i) {
        PageProtection[i] = protection;
        const uint64_t mask = uint64_t(1) << (i & 63);
        if (protection == PAGE_EXECUTE_READ) DirtyPages[i >> 6] &= ~mask;
        else DirtyPages[i >> 6] |= mask;
    }
}

// Take one live snapshot, then journal successful NtProtectVirtualMemory calls.
// Querying the entire large image on EVERY restore measured another ~9.5s.
// The native observer includes VirtualProtectEx and direct native API callers.
static bool SynchronizeJournal() {
    JournalValid = false;
    const auto epoch = UntrackedEpoch.load(std::memory_order_acquire);
    if (UntrackedActive.load(std::memory_order_acquire)) return false;
    if (!RestoreSize || RestoreSize / 4096 > MaxPages) return false;
    std::memset(DirtyPages, 0, sizeof(DirtyPages));
    const uintptr_t end = RestoreBase + RestoreSize;
    uintptr_t cursor = RestoreBase;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info = {};
        RegionQueries.fetch_add(1, std::memory_order_relaxed);
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info)) != sizeof(info) ||
            info.State != MEM_COMMIT || info.AllocationBase != reinterpret_cast<LPVOID>(ImageBase) ||
            info.Type != JournalAllocationType) return false;
        uintptr_t next = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
        if (next <= cursor) return false;
        if (next > end) next = end;
        MarkPages(cursor, next - cursor, info.Protect);
        cursor = next;
    }
    if (UntrackedActive.load(std::memory_order_acquire) ||
        UntrackedEpoch.load(std::memory_order_acquire) != epoch) return false;
    KnownEpoch = epoch;
    JournalValid = true;
    return true;
}

static bool ReadNativeRange(PVOID* address, PSIZE_T size, uintptr_t& base, SIZE_T& length) {
    SIZE_T read = 0;
    return ReadProcessMemory(GetCurrentProcess(), address, &base, sizeof(base), &read) && read == sizeof(base) &&
           ReadProcessMemory(GetCurrentProcess(), size, &length, sizeof(length), &read) && read == sizeof(length) &&
           length && base + length >= base;
}

static LONG NTAPI NtProtectObserver(HANDLE process, PVOID* address, PSIZE_T size, ULONG protection, PULONG old) {
    const DWORD entryError = GetLastError();
    uintptr_t base = 0;
    SIZE_T length = 0;
    if (!ReadNativeRange(address, size, base, length) || base >= RestoreBase + RestoreSize ||
        base + length <= RestoreBase) {
        SetLastError(entryError);
        return OriginalNtProtect(process, address, size, protection, old);
    }
    // Hook installers (including MinHook) suspend other threads. Never wait on
    // an owner they might have suspended: pass the real call through and mark
    // an epoch change so a future optimization first resynchronizes live state.
    if (!TryAcquireSRWLockExclusive(&RestoreLock)) {
        UntrackedActive.fetch_add(1, std::memory_order_acq_rel);
        UntrackedEpoch.fetch_add(1, std::memory_order_acq_rel);
        SetLastError(entryError);
        const LONG status = OriginalNtProtect(process, address, size, protection, old);
        UntrackedEpoch.fetch_add(1, std::memory_order_acq_rel);
        UntrackedActive.fetch_sub(1, std::memory_order_release);
        return status;
    }
    const auto epoch = UntrackedEpoch.load(std::memory_order_acquire);
    if (KnownEpoch != epoch || UntrackedActive.load(std::memory_order_acquire)) JournalValid = false;
    const bool current = process == GetCurrentProcess() || GetProcessId(process) == GetCurrentProcessId();
    if (current && !JournalValid) SynchronizeJournal();
    SetLastError(entryError);
    const LONG status = OriginalNtProtect(process, address, size, protection, old);
    const DWORD exitError = GetLastError();
    if (status >= 0) {
        if (current && JournalValid && ReadNativeRange(address, size, base, length)) {
            MarkPages(base, length, protection);
        } else {
            // An unqueryable process handle could refer to this process. Force
            // a live resynchronization before optimizing another bulk restore.
            JournalValid = false;
        }
    }
    if (UntrackedEpoch.load(std::memory_order_acquire) != epoch ||
        UntrackedActive.load(std::memory_order_acquire)) JournalValid = false;
    ReleaseSRWLockExclusive(&RestoreLock);
    SetLastError(exitError);
    return status;
}

// Called only for the fingerprinted runtime's bulk restore, under RestoreLock.
// Native calls below use the trampoline; their journal updates happen here.
static bool RestoreJournal(PDWORD oldProtection) {
    const auto epoch = UntrackedEpoch.load(std::memory_order_acquire);
    if (UntrackedActive.load(std::memory_order_acquire)) return false;
    if (KnownEpoch != epoch) JournalValid = false;
    if (!JournalValid && !SynchronizeJournal()) return false;
    MEMORY_BASIC_INFORMATION output = {};
    RegionQueries.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t out = reinterpret_cast<uintptr_t>(oldProtection);
    if (!oldProtection || VirtualQuery(oldProtection, &output, sizeof(output)) != sizeof(output) ||
        output.State != MEM_COMMIT || (output.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
        !(output.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ||
        out + sizeof(DWORD) < out ||
        out + sizeof(DWORD) > reinterpret_cast<uintptr_t>(output.BaseAddress) + output.RegionSize) return false;
    struct Change { uintptr_t base; SIZE_T size; DWORD old; };
    Change changes[128];
    size_t count = 0;
    const size_t pages = RestoreSize / 4096;
    for (size_t word = 0; word < (pages + 63) / 64; ++word) {
        uint64_t bits = DirtyPages[word];
        while (bits) {
            const size_t page = word * 64 + __builtin_ctzll(bits);
            bits &= bits - 1;
            if (page >= pages) break;
            const uintptr_t base = RestoreBase + page * 4096;
            const DWORD old = PageProtection[page];
            if (count && changes[count - 1].base + changes[count - 1].size == base && changes[count - 1].old == old) {
                changes[count - 1].size += 4096;
            } else {
                if (count == 128) return false;
                changes[count++] = {base, 4096, old};
            }
        }
    }
    DWORD firstProtection = PageProtection[0];
    unsigned long long changed = 0;
    for (size_t i = 0; i < count; ++i) {
        PVOID base = reinterpret_cast<PVOID>(changes[i].base);
        SIZE_T length = changes[i].size;
        ULONG ignored = 0;
        if (OriginalNtProtect(GetCurrentProcess(), &base, &length, PAGE_EXECUTE_READ, &ignored) < 0) {
            for (size_t j = 0; j < i; ++j) {
                base = reinterpret_cast<PVOID>(changes[j].base);
                length = changes[j].size;
                OriginalNtProtect(GetCurrentProcess(), &base, &length, changes[j].old, &ignored);
            }
            JournalValid = false;
            return false;
        }
        // The kernel clears PAGE_GUARD on access without a protection API
        // call. The journal remains conservatively dirty, but the native API's
        // actual old value is authoritative for the first page and rollback.
        if (changes[i].base == RestoreBase) firstProtection = ignored;
        changes[i].old = ignored;
        changed += changes[i].size;
    }
    if (UntrackedEpoch.load(std::memory_order_acquire) != epoch ||
        UntrackedActive.load(std::memory_order_acquire)) {
        PVOID base = reinterpret_cast<PVOID>(RestoreBase);
        SIZE_T length = RestoreSize;
        ULONG ignored = 0;
        const LONG status = OriginalNtProtect(GetCurrentProcess(), &base, &length, PAGE_EXECUTE_READ, &ignored);
        JournalValid = false;
        Fallbacks.fetch_add(1, std::memory_order_relaxed);
        if (status < 0) return false;
        *oldProtection = firstProtection;
        return true;
    }
    for (size_t i = 0; i < count; ++i) MarkPages(changes[i].base, changes[i].size, PAGE_EXECUTE_READ);
    *oldProtection = firstProtection;
    OptimizedRestores.fetch_add(1, std::memory_order_relaxed);
    LogicalBytes.fetch_add(RestoreSize, std::memory_order_relaxed);
    ChangedBytes.fetch_add(changed, std::memory_order_relaxed);
    return true;
}

// Compare complete, case-sensitive Windows arguments, excluding argv[0]. Use
// the OS parser rather than reinterpreting escaped or consecutive quote marks.
// Any parser/loader failure keeps the feature disabled. Never load EMP.dll.
static bool HasSwitch(const wchar_t* command, const wchar_t* flag) {
    if (!command || !flag) return false;
    HMODULE shell = GetModuleHandleW(L"shell32.dll");
    bool owned = false;
    if (!shell) {
        shell = LoadLibraryExW(L"shell32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        owned = shell != nullptr;
    }
    if (!shell) return false;
    using ParseFn = LPWSTR* (WINAPI*)(LPCWSTR, int*);
    const auto parse = reinterpret_cast<ParseFn>(GetProcAddress(shell, "CommandLineToArgvW"));
    int count = 0;
    LPWSTR* arguments = parse ? parse(command, &count) : nullptr;
    bool found = false;
    if (arguments) {
        for (int i = 1; i < count; ++i) {
            if (std::wcscmp(arguments[i], flag) == 0) { found = true; break; }
        }
        LocalFree(arguments);
    }
    if (owned) FreeLibrary(shell);
    return found;
}

static double ElapsedMs(LONGLONG tick) {
    return OriginFromCreationMs + double(tick - ClockOrigin.QuadPart) * 1000.0 / double(Frequency.QuadPart);
}

static void WriteRecord(const char* name, const char* details = "") {
    if (!Profile) return;
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    AcquireSRWLockExclusive(&LogLock);
    std::fprintf(Profile, "{\"event\":\"%s\",\"launch_ms\":%.3f%s}\n", name, ElapsedMs(now.QuadPart), details);
    std::fflush(Profile);
    ReleaseSRWLockExclusive(&LogLock);
}

#ifdef JC4_ULTRAFASTLOAD_TESTING
// Stateless reference used by the regression executable, not the shipped DLL.
// First inspect the WHOLE request: committed pages in the expected allocation.
// Keeping no protection cache means guard flags and changes by other software
// are read afresh on every call. On an unusual layout use the original API.
static BOOL RestoreReadExecute(LPVOID address, SIZE_T size, PDWORD oldProtection,
                               LPVOID allocation, DWORD expectedType = MEM_IMAGE) {
    if (!OriginalProtect || !size || !oldProtection)
        return OriginalProtect ? OriginalProtect(address, size, PAGE_EXECUTE_READ, oldProtection) : FALSE;
    const DWORD entryError = GetLastError();
    const uintptr_t begin = reinterpret_cast<uintptr_t>(address);
    if ((begin & 4095) || (size & 4095) || begin + size < begin)
        return OriginalProtect(address, size, PAGE_EXECUTE_READ, oldProtection);
    MEMORY_BASIC_INFORMATION outputInfo = {};
    const uintptr_t output = reinterpret_cast<uintptr_t>(oldProtection);
    if (VirtualQuery(oldProtection, &outputInfo, sizeof(outputInfo)) != sizeof(outputInfo) ||
        outputInfo.State != MEM_COMMIT || (outputInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
        !(outputInfo.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ||
        output + sizeof(DWORD) < output ||
        output + sizeof(DWORD) > reinterpret_cast<uintptr_t>(outputInfo.BaseAddress) + outputInfo.RegionSize) {
        SetLastError(entryError);
        return OriginalProtect(address, size, PAGE_EXECUTE_READ, oldProtection);
    }
    struct Region { uintptr_t address; SIZE_T size; DWORD protection; };
    Region changed[128];
    size_t count = 0;
    DWORD firstProtection = 0;
    const uintptr_t end = begin + size;
    uintptr_t cursor = begin;
    unsigned long long queries = 0;
    bool valid = true;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        ++queries;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi) ||
            mbi.State != MEM_COMMIT || mbi.AllocationBase != allocation || mbi.Type != expectedType) {
            valid = false;
            break;
        }
        const uintptr_t nextRegion = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (nextRegion <= cursor) { valid = false; break; }
        const uintptr_t next = nextRegion < end ? nextRegion : end;
        if (cursor == begin) firstProtection = mbi.Protect;
        if (mbi.Protect != PAGE_EXECUTE_READ) {
            if (count == 128) { valid = false; break; }
            changed[count++] = {cursor, next - cursor, mbi.Protect};
        }
        cursor = next;
    }
    RegionQueries.fetch_add(queries, std::memory_order_relaxed);
    if (!valid) {
        Fallbacks.fetch_add(1, std::memory_order_relaxed);
        SetLastError(entryError);
        return OriginalProtect(address, size, PAGE_EXECUTE_READ, oldProtection);
    }
    unsigned long long changedSize = 0;
    for (size_t i = 0; i < count; ++i) {
        DWORD ignored = 0;
        if (!OriginalProtect(reinterpret_cast<LPVOID>(changed[i].address), changed[i].size,
                             PAGE_EXECUTE_READ, &ignored)) {
            // Restore the pre-call state before falling back. Normally all these
            // pages belong to one committed PE section and cannot fail.
            for (size_t j = 0; j < i; ++j) {
                OriginalProtect(reinterpret_cast<LPVOID>(changed[j].address), changed[j].size,
                                changed[j].protection, &ignored);
            }
            Fallbacks.fetch_add(1, std::memory_order_relaxed);
            SetLastError(entryError);
            return OriginalProtect(address, size, PAGE_EXECUTE_READ, oldProtection);
        }
        changedSize += changed[i].size;
    }
    *oldProtection = firstProtection;
    OptimizedRestores.fetch_add(1, std::memory_order_relaxed);
    LogicalBytes.fetch_add(size, std::memory_order_relaxed);
    ChangedBytes.fetch_add(changedSize, std::memory_order_relaxed);
    SetLastError(entryError);
    return TRUE;
}
#endif

static BOOL WINAPI ProtectHook(LPVOID address, SIZE_T size, DWORD protection, PDWORD oldProtection) {
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    // Only this exact, fingerprinted runtime's restore call is optimized.
    // Other Win32 callers, modules, processes, and protection modes pass through.
    if (caller == RuntimeBase + 0x1ffb3 && reinterpret_cast<uintptr_t>(address) == RestoreBase &&
        size == RestoreSize && protection == PAGE_EXECUTE_READ) {
        const DWORD error = GetLastError();
        if (!TryAcquireSRWLockExclusive(&RestoreLock)) {
            Fallbacks.fetch_add(1, std::memory_order_relaxed);
            SetLastError(error);
            return OriginalProtect(address, size, protection, oldProtection);
        }
        const bool result = RestoreJournal(oldProtection);
        ReleaseSRWLockExclusive(&RestoreLock);
        SetLastError(error);
        if (result) return TRUE;
        Fallbacks.fetch_add(1, std::memory_order_relaxed);
    }
    return OriginalProtect(address, size, protection, oldProtection);
}

static void Initialize() {
    const wchar_t* command = GetCommandLineW();
    Requested = HasSwitch(command, L"-ultrafastload");
    const bool profiling = HasSwitch(command, L"-profileload");
    if (!Requested && !profiling) return;
    QueryPerformanceFrequency(&Frequency);
    FILETIME created, exited, kernel, user, now;
    GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user);
    GetSystemTimePreciseAsFileTime(&now);
    QueryPerformanceCounter(&ClockOrigin);
    const ULONGLONG createdTime = (ULONGLONG(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    const ULONGLONG currentTime = (ULONGLONG(now.dwHighDateTime) << 32) | now.dwLowDateTime;
    OriginFromCreationMs = double(currentTime - createdTime) / 10000.0;
    if (profiling) {
        wchar_t path[MAX_PATH] = {};
        if (GetModuleFileNameW(nullptr, path, MAX_PATH)) {
            wchar_t* slash = std::wcsrchr(path, L'\\');
            if (slash && (slash - path) < MAX_PATH - 48) {
                std::swprintf(slash + 1, MAX_PATH - size_t(slash + 1 - path),
                              L"ultrafastload-startup-%lu.jsonl", GetCurrentProcessId());
                Profile = _wfsopen(path, L"w", _SH_DENYNO);
            }
        }
        WriteRecord("profile_start", Requested ? ",\"requested\":true" : ",\"requested\":false");
    }
    if (!Requested) return;
    ImageBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    // Gate in this order. Epic/unknown builds must not even look up EMP.dll,
    // regardless of whether an unrelated DLL with that name is present.
    if (IdentifyJC4NativeBuild(ImageBase) != JC4NativeBuild::Steam) {
        WriteRecord("unsupported_build");
        return;
    }
    // Query only an already-loaded module. Never load or open EMP.dll here.
    HMODULE runtime = GetModuleHandleW(L"EMP.dll");
    if (!runtime) {
        WriteRecord("runtime_not_loaded");
        return;
    }
    if (reinterpret_cast<uintptr_t>(runtime) != 0x13000000) {
        WriteRecord("unsupported_runtime");
        return;
    }
    RuntimeBase = reinterpret_cast<uintptr_t>(runtime);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(runtime);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000) {
        WriteRecord("runtime_fingerprint_mismatch"); return;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(RuntimeBase + dos->e_lfanew);
    const uint8_t call[] = {0xb8,0x36,0x60,0x00,0x13,0xff,0x10};
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.TimeDateStamp != 0x5f12fd72 ||
        nt->OptionalHeader.SizeOfImage != 0x19f000 ||
        std::memcmp(reinterpret_cast<const void*>(RuntimeBase + 0x1ffac), call, sizeof(call)) != 0) {
        WriteRecord("runtime_fingerprint_mismatch"); return;
    }
    RestoreBase = ImageBase + 0x2e74000;
    RestoreSize = 0xdd5e000;
    // Both runtime globals must describe the exact section observed in the trace.
    if (*reinterpret_cast<const uintptr_t*>(RuntimeBase + 0x6e08) != RestoreBase ||
        *reinterpret_cast<const SIZE_T*>(RuntimeBase + 0x6e18) != RestoreSize) {
        WriteRecord("restore_range_mismatch"); return;
    }
    const auto* functionSlot = reinterpret_cast<const uintptr_t*>(RuntimeBase + 0x6036);
    void* target = reinterpret_cast<void*>(*functionSlot);
    void* expected = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect"));
    if (!target || target != expected) { WriteRecord("protect_target_mismatch"); return; }
    const MH_STATUS init = MH_Initialize();
    if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED) { WriteRecord("hook_init_failed"); return; }
    if (MH_CreateHook(target, reinterpret_cast<void*>(&ProtectHook), reinterpret_cast<void**>(&OriginalProtect)) != MH_OK) {
        WriteRecord("hook_create_failed"); return;
    }
    void* nativeTarget = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory"));
    if (!nativeTarget || MH_CreateHook(nativeTarget, reinterpret_cast<void*>(&NtProtectObserver),
                                       reinterpret_cast<void**>(&OriginalNtProtect)) != MH_OK) {
        MH_RemoveHook(target);
        WriteRecord("native_observer_failed"); return;
    }
    const bool queued = MH_QueueEnableHook(nativeTarget) == MH_OK && MH_QueueEnableHook(target) == MH_OK;
    if (!queued || MH_ApplyQueued() != MH_OK) {
        MH_DisableHook(target);
        MH_DisableHook(nativeTarget);
        MH_RemoveHook(target);
        MH_RemoveHook(nativeTarget);
        WriteRecord("hook_enable_failed"); return;
    }
    Installed = true;
    WriteRecord("patch_installed");
}

static void OnEvent(const char* name) {
    if (!Profile || !name) return;
    if (!std::strcmp(name, "loading_screen_start") || !std::strcmp(name, "game_loading_initiated")) {
        CurtainTick.store(0, std::memory_order_release);
        WriteRecord(name);
    } else if (!std::strcmp(name, "loading_screen_fully_lifted")) {
        LARGE_INTEGER tick;
        QueryPerformanceCounter(&tick);
        CurtainTick.store(tick.QuadPart, std::memory_order_release);
        WriteRecord(name);
    } else if (!std::strcmp(name, "on_gamestatefrontend_enter") ||
               !std::strcmp(name, "playerspawnpoint_loading_done") ||
               !std::strcmp(name, "loading_screen_end")) {
        WriteRecord(name);
    }
}

static void OnFrame(uintptr_t player) {
    if (!Profile || ReadyRecorded.load(std::memory_order_relaxed) || !player) return;
    const LONGLONG curtain = CurtainTick.load(std::memory_order_acquire);
    if (!curtain) return;
    uintptr_t character = 0;
    SIZE_T bytes = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(player + 0x68),
                           &character, sizeof(character), &bytes) || bytes != sizeof(character) || !character) return;
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    if (now.QuadPart - curtain < Frequency.QuadPart / 2) return;
    if (ReadyRecorded.exchange(true, std::memory_order_relaxed)) return;
    char details[512];
    std::snprintf(details, sizeof(details),
        ",\"curtain_launch_ms\":%.3f,\"patch_installed\":%s,\"optimized_restores\":%llu,"
        "\"region_queries\":%llu,\"logical_bytes\":%llu,\"changed_bytes\":%llu,\"fallbacks\":%llu",
        ElapsedMs(curtain), Installed ? "true" : "false", OptimizedRestores.load(), RegionQueries.load(),
        LogicalBytes.load(), ChangedBytes.load(), Fallbacks.load());
    WriteRecord("player_ready_confirmed", details);
}
} // namespace JC4UltraFastLoad
