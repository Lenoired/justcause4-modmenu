#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <fstream>
#include <string>
#include <cstring>

// Preferences only. Nothing here changes a live terrain allocation or shader.
// The existing mod's normal WriteConfig also serializes GetSavedWidth(), so
// saving an unrelated menu option cannot silently discard this preference.
namespace JC4TerrainSettings {

struct Snapshot {
    int savedWidth = 16;
    int startupWidth = 16;
    int activeWidth = 8;
    int overrideWidth = 0;
    bool savedAltitudeDetail = false;
    bool startupAltitudeDetail = false;
    int altitudeOverride = -1;
    bool altitudeSaveFailed = false;
    bool invalidFileValue = false;
    bool invalidEnvironment = false;
    bool pathError = false;
    bool saveFailed = false;
    DWORD saveError = ERROR_SUCCESS;
    char configPath[MAX_PATH]{};
};
enum class ReadResult { Missing, Valid, Invalid, IoError };
static INIT_ONCE g_Once = INIT_ONCE_STATIC_INIT;
static SRWLOCK g_Lock = SRWLOCK_INIT;
static SRWLOCK g_FileLock = SRWLOCK_INIT;
static Snapshot g_State;

inline bool IsSupported(int width) { return width == 8 || width == 16; }

inline std::string Trim(const std::string& text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
}

inline ReadResult ReadPreference(const char* path, const char* key, const char* low, const char* high, int& valueOut, int lowValue, int highValue) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        const DWORD attr = GetFileAttributesA(path);
        const DWORD error = GetLastError();
        if (attr == INVALID_FILE_ATTRIBUTES &&
            (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND))
            return ReadResult::Missing;
        return ReadResult::IoError;
    }
    char signature[2]{};
    file.read(signature, 2);
    if ((static_cast<unsigned char>(signature[0]) == 0xff && static_cast<unsigned char>(signature[1]) == 0xfe) ||
        (static_cast<unsigned char>(signature[0]) == 0xfe && static_cast<unsigned char>(signature[1]) == 0xff))
        return ReadResult::Invalid; // existing mod config parser is not UTF-16
    file.clear();
    file.seekg(0);
    std::string line, section;
    ReadResult found = ReadResult::Missing;
    bool firstLine = true;
    while (std::getline(file, line)) {
        if (line.find('\0') != std::string::npos) return ReadResult::Invalid;
        if (firstLine && line.compare(0, 3, "\xef\xbb\xbf") == 0) line.erase(0, 3);
        firstLine = false;
        line = Trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line.front() == '[' && line.back() == ']') {
            section = Trim(line.substr(1, line.size() - 2));
            continue;
        }
        const auto equals = line.find('=');
        if (equals == std::string::npos || _stricmp(section.c_str(), "Toggles") != 0 ||
            _stricmp(Trim(line.substr(0, equals)).c_str(), key) != 0)
            continue;
        const auto value = Trim(line.substr(equals + 1));
        if (value == low) { valueOut = lowValue; found = ReadResult::Valid; }
        else if (value == high) { valueOut = highValue; found = ReadResult::Valid; }
        else { found = ReadResult::Invalid; }
    }
    return file.bad() ? ReadResult::IoError : found;
}

inline ReadResult ReadWidth(const char* path, int& width) {
    return ReadPreference(path, "TerrainGridWidth", "8", "16", width, 8, 16);
}
inline ReadResult ReadAltitude(const char* path, int& value) {
    return ReadPreference(path, "TerrainAltitudeDetail", "0", "1", value, 0, 1);
}

inline BOOL CALLBACK InitializeOnce(PINIT_ONCE, PVOID, PVOID*) {
    // Same absolute file as the original mod's relative ReadConfig/WriteConfig
    // and TorIniPath(). A bare profile-API filename could select Windows\ instead.
    const DWORD length = GetFullPathNameA("modmenu_jc4.ini", MAX_PATH,
                                         g_State.configPath, nullptr);
    if (length == 0 || length >= MAX_PATH) {
        g_State.pathError = true;
        g_State.configPath[0] = '\0';
        g_State.savedWidth = 8;
    } else {
        int width = 16; // retain the previously validated expanded default
        const auto result = ReadWidth(g_State.configPath, width);
        if (result == ReadResult::Valid) g_State.savedWidth = width;
        else if (result == ReadResult::Invalid || result == ReadResult::IoError) {
            g_State.savedWidth = 8; // never interpret an unvalidated size as valid
            g_State.invalidFileValue = true;
        }
    }
    g_State.startupWidth = g_State.savedWidth;
    char overrideValue[8]{};
    const DWORD n = GetEnvironmentVariableA("JC4_TERRAIN_16X16", overrideValue, sizeof(overrideValue));
    if (n != 0) {
        if (n == 1 && overrideValue[0] == '1') g_State.overrideWidth = 16;
        else {
            g_State.overrideWidth = 8;
            g_State.invalidEnvironment = !(n == 1 && overrideValue[0] == '0');
        }
        g_State.startupWidth = g_State.overrideWidth;
    }
    int enabled = 0;
    g_State.savedAltitudeDetail = !g_State.pathError &&
        ReadAltitude(g_State.configPath, enabled) == ReadResult::Valid && enabled == 1;
    char altitudeValue[2]{};
    const DWORD altLen = GetEnvironmentVariableA("JC4_TERRAIN_ALTITUDE_DETAIL", altitudeValue, sizeof(altitudeValue));
    if (altLen) g_State.altitudeOverride = altLen == 1 && altitudeValue[0] == '1' ? 1 : 0;
    g_State.startupAltitudeDetail = g_State.startupWidth == 16 &&
        (g_State.altitudeOverride < 0 ? g_State.savedAltitudeDetail : g_State.altitudeOverride == 1);
    return TRUE;
}

inline void Initialize() {
    InitOnceExecuteOnce(&g_Once, InitializeOnce, nullptr, nullptr);
}
inline Snapshot GetSnapshot() {
    Initialize();
    AcquireSRWLockShared(&g_Lock);
    const Snapshot copy = g_State;
    ReleaseSRWLockShared(&g_Lock);
    return copy;
}
inline int GetSavedWidth() { return GetSnapshot().savedWidth; }
inline bool GetSavedAltitudeDetail() { return GetSnapshot().savedAltitudeDetail; }
inline int GetStartupWidth() { return GetSnapshot().startupWidth; }
class ConfigWriteGuard {
public:
    ConfigWriteGuard() { Initialize(); AcquireSRWLockExclusive(&g_FileLock); }
    ~ConfigWriteGuard() { ReleaseSRWLockExclusive(&g_FileLock); }
    ConfigWriteGuard(const ConfigWriteGuard&) = delete;
    ConfigWriteGuard& operator=(const ConfigWriteGuard&) = delete;
};
inline void MarkActive(int width) {
    Initialize();
    if (!IsSupported(width)) return;
    AcquireSRWLockExclusive(&g_Lock);
    g_State.activeWidth = width;
    ReleaseSRWLockExclusive(&g_Lock);
}

inline bool SaveRequestedWidth(int width) {
    Initialize();
    ConfigWriteGuard fileGuard; // same file -> state lock order as full WriteConfig
    AcquireSRWLockExclusive(&g_Lock);
    bool ok = false;
    DWORD error = ERROR_INVALID_PARAMETER;
    if (IsSupported(width) && !g_State.pathError) {
        const char* value = width == 16 ? "16" : "8";
        if (WritePrivateProfileStringA("Toggles", "TerrainGridWidth", value, g_State.configPath)) {
            // Force a disk readback, not a successful profile-cache query.
            WritePrivateProfileStringA(nullptr, nullptr, nullptr, g_State.configPath);
            int observed = 0;
            ok = ReadWidth(g_State.configPath, observed) == ReadResult::Valid && observed == width;
            error = ok ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
        } else {
            error = GetLastError();
            if (error == ERROR_SUCCESS) error = ERROR_WRITE_FAULT;
        }
    } else if (g_State.pathError) error = ERROR_BAD_PATHNAME;
    if (ok) {
        g_State.savedWidth = width;
        g_State.invalidFileValue = false;
    }
    g_State.saveFailed = !ok;
    g_State.saveError = error;
    // startupWidth and activeWidth are intentionally immutable through this UI.
    ReleaseSRWLockExclusive(&g_Lock);
    return ok;
}

inline bool SaveRequestedAltitudeDetail(bool enabled) {
    ConfigWriteGuard fileGuard;
    AcquireSRWLockExclusive(&g_Lock);
    bool ok = false;
    if (!g_State.pathError && WritePrivateProfileStringA("Toggles", "TerrainAltitudeDetail", enabled ? "1" : "0", g_State.configPath)) {
        WritePrivateProfileStringA(nullptr, nullptr, nullptr, g_State.configPath);
        int observed = 0;
        ok = ReadAltitude(g_State.configPath, observed) == ReadResult::Valid && observed == int(enabled);
    }
    if (ok) g_State.savedAltitudeDetail = enabled;
    g_State.altitudeSaveFailed = !ok;
    ReleaseSRWLockExclusive(&g_Lock);
    return ok;
}

} // namespace JC4TerrainSettings
