#include "terrain_expand.hpp"
#include <windows.h>
#include "addresses.h"
#include <cstdint>
#include <cmath>
#include <d3d11.h>
#include <dxgi.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <cstddef>   // offsetof (Tornado port ctx layout checks)
#include <cstdlib>   // strtoull (Tornado ini manual pointers)
#include <cstring>   // strrchr/memcmp (Tornado ini + signature checks)
#include <xmmintrin.h> // _mm_rsqrt_ss (Tornado smooth follow, rsqrtss-identical)
#include <atomic>

#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "minhook/include/MinHook.h"
#include "ultrafastload.hpp"


extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static LONG WINAPI ModCrashHandler(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    // Ignore routine, benign first-chance exceptions (thread naming, C++ throws, debug events)
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_STACK_OVERFLOW &&
        code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
        code != EXCEPTION_PRIV_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    uintptr_t rip = ep->ContextRecord->Rip;
    HMODULE hMod = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)rip, &hMod);
    char modName[MAX_PATH] = "Unknown";
    if (hMod) GetModuleFileNameA(hMod, modName, MAX_PATH);
    const char* pBaseName = strrchr(modName, '\\');
    if (pBaseName) pBaseName++; else pBaseName = modName;

    // Guarantee absolute path next to JustCause4.exe
    char logPath[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, logPath, MAX_PATH);
    char* pSlash = strrchr(logPath, '\\');
    if (pSlash) *(pSlash + 1) = '\0';
    strcat_s(logPath, "crash_dump.log");

    FILE* f = nullptr;
    fopen_s(&f, logPath, "w");
    if (f) {
        fprintf(f, "Exception Code: 0x%08lX\n", ep->ExceptionRecord->ExceptionCode);
        fprintf(f, "Fault Address : 0x%p (%s + 0x%llX)\n", 
                (void*)rip, pBaseName, (unsigned long long)(hMod ? (rip - (uintptr_t)hMod) : rip));
        fprintf(f, "RAX: 0x%016llX  RBX: 0x%016llX\n", ep->ContextRecord->Rax, ep->ContextRecord->Rbx);
        fprintf(f, "RCX: 0x%016llX  RDX: 0x%016llX\n", ep->ContextRecord->Rcx, ep->ContextRecord->Rdx);
        fprintf(f, "RSP: 0x%016llX  RBP: 0x%016llX\n", ep->ContextRecord->Rsp, ep->ContextRecord->Rbp);
        fclose(f);
    }

    std::cout << "\n\033[1;31m[CRASH DETECTED]\033[0m Exception 0x" << std::hex << ep->ExceptionRecord->ExceptionCode
              << " at " << pBaseName << " + 0x" << (hMod ? (rip - (uintptr_t)hMod) : rip) << std::dec << "\n" << std::flush;

    return EXCEPTION_CONTINUE_SEARCH;
}
// ============================================================================
// WINMM.DLL PROXY FORWARDING
// ============================================================================
// This module ships as "winmm.dll" next to JustCause4.exe. The game statically
// imports winmm (timeGetTime / timeBeginPeriod), and so do bink2w64,
// fmod_studio_F, rad_tm_win64(_d), steam_api64 and EOSSDK-Win64-Shipping. A
// static import is mapped during process initialisation, so we load earlier than
// the old dxgi.dll slot ever could -- and "winmm" is a name ReShade's installer
// never claims (it only installs as d3d9/d3d10/d3d11/d3d12/dxgi/opengl32/ddraw).
//
// All 180 winmm exports are forwarded by naked trampolines in winmm_proxy.S,
// bound to the real system functions by InitWinmmProxy(). We therefore no longer
// sit in the graphics chain at all: HookDX11_VMT() is the only graphics touch,
// and it hooks the shared driver Present vtable, so load order no longer matters.
// ============================================================================
void InitWinmmProxy();
void ShutdownWinmmProxy();

extern uintptr_t g_ExeBase; // Forward declare so FastWrite can see it

template <typename T>
static bool FastRead(uintptr_t address, T& outValue) {
    if (!address || address < 0x10000 || address > 0x7FFFFFFFFFFF) return false;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), &outValue, sizeof(T), NULL);
}

template <typename T>
static void FastWrite(uintptr_t address, T value) {
    if (!address || address < 0x10000 || address > 0x7FFFFFFFFFFF) return;

    // Safely unlock read-only .rdata / .text constants in JustCause4.exe (0x140000000 - 0x150C02000)
    if (g_ExeBase && address >= g_ExeBase && address < (g_ExeBase + g_Addr_10C02000)) {
        DWORD oldProtect;
        if (VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            *reinterpret_cast<volatile T*>(address) = value;
            VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &oldProtect);
            return;
        }
    }

    // Standard heap write
    *reinterpret_cast<volatile T*>(address) = value;
}

template <typename T>
static bool SafeReadMemory(uintptr_t address, T& outValue) {
    return FastRead<T>(address, outValue);
}

template <typename T>
static void SafeWriteMemory(uintptr_t address, T value) {
    FastWrite<T>(address, value);
}

static void SafePatchBytes(uintptr_t address, const uint8_t* bytes, size_t size) {
    DWORD oldProtect;
    if (VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(reinterpret_cast<void*>(address), bytes, size);
        VirtualProtect(reinterpret_cast<void*>(address), size, oldProtect, &oldProtect);
    }
}

// ============================================================================
// PLATFORM DETECTION (Steam vs Epic Games)
// Steam: steam_api64.dll is loaded (same signal g_IsSteam uses).
// Epic:  EOS SDK module loaded, or Epic launcher markers on the command line
//        (-epicapp= / -epicenv= / -EpicPortal). Anything else is Unknown.
// ============================================================================
enum class JC4Platform { Unknown = 0, Steam, Epic };

// Test hook (non-intrusive, opt-in): --spoof-platform=steam|epic|unknown
// forces the detected platform; any other value also yields Unknown.
// Parsed once and cached; when the flag is absent this is a single strstr
// and detection behaves exactly as before.
static bool GetPlatformSpoof(JC4Platform& out) {
    static int state = 0; // 0=unparsed, 1=no flag, 2=spoofed
    static JC4Platform spoofed = JC4Platform::Unknown;
    if (state == 0) {
        state = 1;
        const char* cmd = GetCommandLineA();
        static const char kFlag[] = "--spoof-platform=";
        const char* p = cmd ? strstr(cmd, kFlag) : nullptr;
        if (p) {
            p += strlen(kFlag);
            if (_strnicmp(p, "steam", 5) == 0)      spoofed = JC4Platform::Steam;
            else if (_strnicmp(p, "epic", 4) == 0)  spoofed = JC4Platform::Epic;
            else                                   spoofed = JC4Platform::Unknown;
            state = 2;
        }
    }
    if (state == 2) { out = spoofed; return true; }
    return false;
}

static JC4Platform DetectJC4Platform() {
    JC4Platform sp;
    if (GetPlatformSpoof(sp)) return sp;
    if (GetModuleHandleA("steam_api64.dll")) return JC4Platform::Steam;
    if (GetModuleHandleA("eossdk-win64-shipping.dll")) return JC4Platform::Epic;
    if (GetModuleHandleA("EOSSDK-Win64-Shipping_o.dll")) return JC4Platform::Epic;
    const char* cmd = GetCommandLineA();
    if (cmd && (strstr(cmd, "-epicapp=") || strstr(cmd, "-epicenv=") || strstr(cmd, "-EpicPortal")))
        return JC4Platform::Epic;
    return JC4Platform::Unknown;
}

static const char* GetPlatformName() {
    switch (DetectJC4Platform()) {
        case JC4Platform::Steam: return "Steam";
        case JC4Platform::Epic:  return "Epic";
        default:                 return "Unknown";
    }
}

// Mod menu version shown in the header banner. Bump on releases.
static const char* kModMenuVersion = "1.4";
typedef void(*SendEvent_t)(const char*, void*);
typedef void(__cdecl* report_gsfailure_t)(uintptr_t);
static report_gsfailure_t o_report_gsfailure = nullptr;

void __cdecl hk_report_gsfailure(uintptr_t cookie) {
    char logPath[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, logPath, MAX_PATH);
    char* pSlash = strrchr(logPath, '\\');
    if (pSlash) *(pSlash + 1) = '\0';
    strcat_s(logPath, "crash_dump.log");

    FILE* f = nullptr;
    fopen_s(&f, logPath, "w");

    std::cout << "\n\033[1;31m========================================================\033[0m\n";
    std::cout << "\033[1;31m[CRASH INTERCEPTED] STACK COOKIE CORRUPTION (__report_gsfailure)\033[0m\n";
    std::cout << "\033[1;33mCookie Value: 0x" << std::hex << cookie << std::dec << "\033[0m\n";
    std::cout << "Call Stack (Return Addresses):\n";

    if (f) {
        fprintf(f, "=== STACK COOKIE CORRUPTION DETECTED (__report_gsfailure) ===\n");
        fprintf(f, "Failed Cookie: 0x%llX\n", (unsigned long long)cookie);
        fprintf(f, "Call Stack Trace:\n");
    }

    uintptr_t stackProbe = 0;
    uintptr_t sp = (uintptr_t)&stackProbe;

    int depth = 0;
    // Probe 512 qwords up the stack for return addresses
    for (size_t i = 0; i < 512; i++) {
        uintptr_t addr = 0;
        if (ReadProcessMemory(GetCurrentProcess(), (void*)(sp + (i * 8)), &addr, sizeof(addr), NULL)) {
            if (g_ExeBase && addr >= g_ExeBase && addr < (g_ExeBase + g_Addr_10000000)) {
                uintptr_t rva = addr - g_ExeBase;
                // Filter out addresses inside __report_gsfailure itself
                if (rva >= 0x1AF9274 && rva <= 0x1AF9340) continue;

                std::cout << "  [" << depth << "] JustCause4.exe + 0x" << std::hex << rva << std::dec << "\n";
                if (f) fprintf(f, "  [%d] JustCause4.exe + 0x%llX\n", depth, (unsigned long long)rva);
                depth++;
                if (depth >= 16) break;
            }
        }
    }

    std::cout << "\033[1;31m========================================================\033[0m\n" << std::flush;
    if (f) fclose(f);

    Sleep(1500);
    o_report_gsfailure(cookie);
}
SendEvent_t o_SendEvent = nullptr;

typedef void(*Heat_Reset_t)(uintptr_t);
Heat_Reset_t o_Heat_Reset = nullptr;

// Native Heat System Function Pointers
typedef void(__fastcall* Heat_SetLevel_t)(uintptr_t heatMgr, uint32_t level);
typedef void(__fastcall* Heat_SetStatus_t)(uintptr_t heatMgr, int32_t status);
typedef void(__fastcall* Heat_AddHeatPoints_t)(uintptr_t heatMgr, int32_t points, bool p3, bool p4);
typedef void(__fastcall* Heat_ClearAllSets_t)(uintptr_t heatMgr, bool p1, bool p2, bool p3, bool p4);

static Heat_SetLevel_t o_Heat_SetLevel = nullptr;
static Heat_SetStatus_t o_Heat_SetStatus = nullptr;
static Heat_AddHeatPoints_t o_Heat_AddHeatPoints = nullptr;
static Heat_ClearAllSets_t o_Heat_ClearAllSets = nullptr;

typedef bool(__fastcall* Heat_ActivateSet_Worker_t)(uintptr_t heatMgr, uintptr_t pData, uint32_t minUnits, uint32_t weight, uint32_t cooldownMs, bool p5, uintptr_t pSpawner);
static Heat_ActivateSet_Worker_t o_Heat_ActivateSet = nullptr;

bool g_GodMode = false;
bool g_Noclip = false;
bool g_DisableDamageScreen = false;
bool g_DisableRagdoll = false;
bool g_AllVehiclesNitroJump = false;
bool g_InfiniteNitro = false;
bool g_InfiniteTurboJump = false;
bool g_TurboJumpAirHop = false;

// ============================================================================
// TIME & WORLD SYSTEM
// ============================================================================
typedef void(__fastcall* WorldTime_SetTime_t)(uintptr_t worldTime, float time, int mode);
static WorldTime_SetTime_t o_WorldTime_SetTime = nullptr;
static float g_TargetTime = 12.0f;
static float g_TimeScale = 1.0f;

// ============================================================================
// TELEPORT SYSTEM & SAVED LOCATIONS
// ============================================================================
typedef void(__fastcall* GameWorld_TeleportPlayer_t)(
    uintptr_t thisptr,
    float* worldMatrix,
    uint32_t* state,
    bool use_load_state,
    bool use_fade,
    float fade_in_time,
    float fade_out_time,
    uint32_t flags,
    void* callback,
    bool use_loading_screen,
    void* unknown
);

static float g_TeleportCoords[3] = { 0.0f, 0.0f, 0.0f };
static char g_TpNameBuf[64] = "";

struct SavedLocation {
    std::string name;
    float x, y, z;
};
static std::vector<SavedLocation> g_SavedLocations;

// ============================================================================
// HEAT REINFORCEMENT DISTANCES LOCK ENGINE
// ============================================================================
// Domains: 0 = Land (0xEC), 1 = Aircraft (0x12C), 2 = Sea (0x10C), 3 = Infantry (0x14C)
static const uintptr_t g_HeatDomainOffsets[4] = { 0xEC, 0x12C, 0x10C, 0x14C };
static const char* g_HeatDomainPrefixes[4] = { "Land", "Air", "Sea", "Infantry" };
static const char* g_HeatDistanceNames[8] = {
    "PursuitSpawnMin",
    "PursuitSpawnMax",
    "PursuitRecycleDist",
    "PursuitDespawnDist",
    "RoadblockSpawnMin",
    "RoadblockSpawnMax",
    "BlockDensityRange",
    "BlockDespawnDist"
};

bool g_HeatSystemActive = true;
static int g_CustomMaxHeatEntities = -1;
static int g_CustomMaxVisibilityDist = -1;
static float g_CustomDetectionRange = -1.0f;
static float g_CustomVisionThreshold = -1.0f;

static float g_HeatDistances[4][8] = { 0 };
static float g_DefHeatDistances[4][8] = { 0 };
static bool  g_HeatDistHasCustom[4][8] = { false };
static bool  g_HeatDistCaptured = false;
// ============================================================================
// GRAPPLING HOOK TUNING SETTINGS
// ============================================================================
struct GrappleSetting {
    bool overrideActive = false;
    float customVal = 0.0f;
    float defVal1 = 0.0f;
    float defVal2 = 0.0f;
    float defVal3 = 0.0f;
};

static GrappleSetting g_GrappleReach     = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static GrappleSetting g_GrappleFlight    = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static GrappleSetting g_GrappleReelSpd   = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static GrappleSetting g_GrappleReelAcc   = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static GrappleSetting g_TetherPullForce    = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static GrappleSetting g_TetherRetractSpeed = { false, 0.0f, 0.0f, 0.0f, 0.0f };

// Booster Settings
static GrappleSetting g_BoosterSpeed        = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static GrappleSetting g_BoosterForce        = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static GrappleSetting g_BoosterSpool        = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static bool           g_BoosterLockOnly30s  = false;

// Balloon (Air Lifter) Settings
static GrappleSetting g_BalloonAltitudeDelta = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static GrappleSetting g_BalloonSize          = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static GrappleSetting g_BalloonLiftForce     = { false, 0.0f, 0.0f, 0.0f, 0.0f };
static bool           g_BalloonExplosiveGas  = false;

// Tether Capacity Settings
static bool g_OverrideTethers  = false;
static bool g_UnlimitedTethers = false;
static int  g_MaxTethersCount  = 10;

static bool  g_TetherUnbreakable          = false;
static float g_DefTensionSnap              = 0.0f;
static float g_DefTensionTear              = 0.0f;
static float g_DefTensionTimer             = 0.0f;
static float g_DefTetherBreakScale         = 0.0f;
static float g_DefRetractHold[6]           = { 0 };
static float g_DefRetractTap[6]            = { 0 };
static float g_DefRetractSpeed[3]          = { 0 };
static float g_DefBoosterForce[3]          = { 0 };
static float g_DefBalloonForce[3]          = { 0 };
static bool g_NoclipPrevState = false;
static float g_NoclipPos[3] = { 0.0f, 0.0f, 0.0f };
static bool g_NoclipPosCaptured = false;
float g_NoclipSpeed = 35.0f;
float g_NoclipFastMult = 3.0f;

// Native CCharacter Physics & Position Function Pointers
typedef void(__fastcall* SetWorldAndPhysicsPosition_t)(uintptr_t character, float* pos_xyz);
typedef void(__fastcall* SetGhostMode_t)(uintptr_t character, uint8_t enable);
typedef void(__fastcall* SetCharacterGravity_t)(uintptr_t character, float gravity);

static SetWorldAndPhysicsPosition_t o_SetWorldAndPhysicsPosition = nullptr;
static SetGhostMode_t o_SetGhostMode = nullptr;
static SetCharacterGravity_t o_SetCharacterGravity = nullptr;

extern uintptr_t g_ExeBase;
extern bool g_ShowMenu;
extern SHORT(WINAPI* o_GetAsyncKeyState)(int);
static uintptr_t GetPlayerPtr();
static uintptr_t GetGraphicsCameraManager(); // Forward declaration
static void TriggerEvent(const char* eventName); // Forward declaration

struct CameraModifierPatch {
    uintptr_t rva;
    uint8_t origBytes[5];
    bool captured;
    const char* name;
};

static CameraModifierPatch g_NoclipCamPatches[] = {
    // 1. Auto-pitch downward while falling/airborne
    { 0x4E2190, {0}, false, "CAutoPitchModifier::ProcessCameraContext" },
    // 2. Clamping pitch to horizon (0.0 rad) in airborne/parachute states
    { 0x4E7340, {0}, false, "CLocalAngleLimitsModifier::ProcessCameraContext" },
    // 3. Direct angle limit worker function called during skydiving transitions
    { 0x4D1F30, {0}, false, "CLocalAngleLimitsModifier::ApplyLimits" },
    // 4. Dedicated skydiving pitch spline curve (clamps pitch to 0.0 horizon)
    { 0x4E9E60, {0}, false, "CSplineFuncOfPitchModifier::ProcessCameraContext" },
    // 5. Spherical coordinate framing limits in vertical descent
    { 0x4E9E10, {0}, false, "CSphericalCoordFramingModifier::ProcessCameraContext" },
    // 6. Pitch decay and reset when movement input is zero
    { 0x4E7980, {0}, false, "CMoveInputPitchModifier::ProcessCameraContext" },
    // 7. Forcing camera to face movement velocity vector
    { 0x4E1E30, {0}, false, "CAlignToVelocityModifier::ProcessCameraContext" },
    // 8. Clamping angles for target-relative cameras
    { 0x4EA470, {0}, false, "CTargetRelativeAngleLimitsModifier::ProcessCameraContext" },
    // 9. Parachute canopy hitbox colliding with camera
    { 0x4E7F50, {0}, false, "CParachuteCameraCollisionModifier::ProcessCameraContext" },
    // 10. Parachute harness orientation attachment lock
    { 0x4E7DD0, {0}, false, "CParachuteAttachmentModifier::ProcessCameraContext" },
    // 11. Camera collision fade (calls CCharacter::SetOpacity when camera inside player)
    { 0x4E2FC0, {0}, false, "CCameraCollisionModifier::ProcessCameraContext" },
    // 12. Player collision fade (calls CCharacter::SetOpacity when camera inside player)
    { 0x4E8620, {0}, false, "CPlayerCollisionModifier::ProcessCameraContext" }
};

static void ApplyNoclipCameraPatches(bool enable) {
    if (!g_ExeBase) return;
    static bool s_CamPatchesApplied = false;
    if (enable == s_CamPatchesApplied) return;

    static const uint8_t retPatch[5] = { 0xC3, 0x90, 0x90, 0x90, 0x90 }; // ret; nop; nop; nop; nop

    for (auto& p : g_NoclipCamPatches) {
        if (!JRVA_KNOWN(p.rva)) continue;
        uintptr_t addr = g_ExeBase + JRVA(p.rva);
        if (!p.captured) {
            if (ReadProcessMemory(GetCurrentProcess(), (void*)addr, p.origBytes, 5, NULL)) {
                p.captured = true;
            }
        }
        if (p.captured) {
            if (enable) {
                SafePatchBytes(addr, retPatch, 5);
            } else {
                SafePatchBytes(addr, p.origBytes, 5);
            }
        }
    }
    s_CamPatchesApplied = enable;
}

// ============================================================================
// VEHICLE FREECAM STABILIZER PATCHES
// ============================================================================
struct VehicleFreeCamPatch {
    uintptr_t rva;
    std::vector<uint8_t> patchBytes;
    std::vector<uint8_t> origBytes;
    bool captured;
    const char* name;
};

static VehicleFreeCamPatch g_VehicleFreeCamPatches[] = {
    // 1. In-air jump pitch blend (Forces m_InAirTransitionBlendRatio to 0.0f)
    { 0x4F2D00, { 0x0F, 0x57, 0xDB, 0x90, 0x90, 0x90, 0x90, 0x90 }, {}, false, "InAirJumpPitch" },

    // 2. Ground slope tracking (Cuts Slerp to ground normal)
    { 0x4F27E5, { 0x90, 0x90, 0x90, 0x90, 0x90 }, {}, false, "GroundSlopeSlerp" },

    // 3. Chassis pitch & roll blend (Zeroes chassis tilt weight)
    { 0x4F2C4A, { 0x45, 0x0F, 0x57, 0xD2, 0x90 }, {}, false, "ChassisRollPitchWeight" },

    // 4. Suspension UpCameraLag tilt (Zeroes UpCameraLag)
    { 0x4F5194, { 0x0F, 0x57, 0xC9, 0x90, 0x90, 0x90, 0x90, 0x90 }, {}, false, "UpCameraLag" },

    // 5. Suspension RightCameraLag tilt (Zeroes RightCameraLag)
    { 0x4F519C, { 0x0F, 0x57, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90 }, {}, false, "RightCameraLag" },

    // 6. Look-at target vertical displacement (Zeroes UpLookAtLag)
    { 0x4F66E4, { 0x0F, 0x57, 0xC9, 0x90, 0x90, 0x90, 0x90, 0x90 }, {}, false, "UpLookAtLag" },

    // 7. Look-at target lateral displacement (Zeroes RightLookAtLag)
    { 0x4F6740, { 0x0F, 0x57, 0xD2, 0x90, 0x90, 0x90, 0x90, 0x90 }, {}, false, "RightLookAtLag" },

    // 8. Lock Camera Up-Vector to World Vertical Y=1.0f (CGenericVehicleModifier::GetUserDesiredUp)
    { 0x824A840, { 
        0xC7, 0x02, 0x00, 0x00, 0x00, 0x00,             // mov dword ptr [rdx], 0
        0xC7, 0x42, 0x04, 0x00, 0x00, 0x80, 0x3F,       // mov dword ptr [rdx+4], (float)1
        0xC7, 0x42, 0x08, 0x00, 0x00, 0x00, 0x00,       // mov dword ptr [rdx+8], 0
        0x48, 0x89, 0xD0,                               // mov rax, rdx
        0xC3                                            // ret
    }, {}, false, "LockWorldUp" }
};

static void ApplyFreeCamVehiclePatches(bool enable) {
    if (!g_ExeBase) return;
    static bool s_VehiclePatchesApplied = false;
    if (enable == s_VehiclePatchesApplied) return;

    for (auto& p : g_VehicleFreeCamPatches) {
        if (!JRVA_KNOWN(p.rva)) continue;
        uintptr_t addr = g_ExeBase + JRVA(p.rva);
        size_t size = p.patchBytes.size();

        if (!p.captured) {
            p.origBytes.resize(size);
            if (ReadProcessMemory(GetCurrentProcess(), (void*)addr, p.origBytes.data(), size, NULL)) {
                p.captured = true;
            }
        }

        if (p.captured) {
            if (enable) {
                SafePatchBytes(addr, p.patchBytes.data(), size);
            } else {
                SafePatchBytes(addr, p.origBytes.data(), size);
            }
        }
    }
    s_VehiclePatchesApplied = enable;
}

bool g_FreeCam = false;
bool g_FreeCamLockPlayer = false;   // Disabled by default, not stored in ini
bool g_FreeCamLockMovement = false; // Disabled by default, not stored in ini
static bool g_FreeCamPrevState = false;
static float g_FreeCamPos[3] = { 0.0f, 0.0f, 0.0f };
static bool g_FreeCamPosCaptured = false;
float g_FreeCamSpeed = 35.0f;
float g_FreeCamFastMult = 3.0f;

int g_NoclipKey = 0;
int g_FreeCamKey = 0;
static bool g_AssigningNoclipKey = false;
static bool g_AssigningFreeCamKey = false;
static double g_NoclipKeyListenStart = 0.0;
static double g_FreeCamKeyListenStart = 0.0;

static float g_FreeCamPlayerPos[3] = { 0.0f, 0.0f, 0.0f };
static bool g_FreeCamPlayerPosCaptured = false;

extern bool g_FirstPerson;

typedef void(__thiscall* ProcessCameraContext_Orbit_t)(uintptr_t thisptr, uintptr_t pipeCtx, uintptr_t inCtx, uintptr_t outCtx);
static ProcessCameraContext_Orbit_t o_ProcessCameraContext_Orbit = nullptr;

void __fastcall hk_ProcessCameraContext_Orbit(uintptr_t thisptr, uintptr_t pipeCtx, uintptr_t inCtx, uintptr_t outCtx) {
    if ((g_Noclip || g_FreeCam) && pipeCtx) {
        // Disable pitch limits (bit 7 of field_0x268) and yaw limits (field_0x269) in CCameraPipelineContext
        FastWrite<uint8_t>(pipeCtx + 0x268, 0);
        FastWrite<uint8_t>(pipeCtx + 0x269, 0);
    } else if (g_FirstPerson && pipeCtx) {
        // Unlock yaw limits so Rico can look freely in vehicles/parachutes while keeping vertical pitch bounds
        FastWrite<uint8_t>(pipeCtx + 0x269, 0);
    }
    o_ProcessCameraContext_Orbit(thisptr, pipeCtx, inCtx, outCtx);
}

// ============================================================================
// FIRST PERSON MODE (render-synchronized mesh attachment, zero camera smoothing)
// ============================================================================
bool g_FirstPerson = false;
bool g_FpHideHead = true;
bool g_FpHideBody = true;
float g_FpForwardOffset = 0.12f;
float g_FpUpOffset = 0.06f;
float g_FpRightOffset = 0.0f;
int g_FirstPersonKey = 0;
static bool g_AssigningFirstPersonKey = false;
static double g_FirstPersonKeyListenStart = 0.0;

static constexpr uint32_t kFpBoneHashHead = 0xF625B09Eu;
static const void* g_FpLastHkaSkeleton = nullptr;
static std::vector<int> g_FpHeadDescendants;
static std::vector<int> g_FpBodyHideBones;
static bool g_FpHeadWasHidden = false;
static bool g_FpBodyWasHidden = false;
static bool g_FpWeaponsHidden = false;

typedef void(__thiscall* UpdateCameraContexts_t)(uintptr_t tree, uintptr_t ctrlCtx);
typedef void(__thiscall* UpdateRenderContexts_t)(uintptr_t tree, uintptr_t ctrlCtx);
typedef bool(__thiscall* CharacterUpdateRender_t)(uintptr_t ch, uintptr_t updateCtx);
typedef void(__thiscall* CharacterSetOpacity_t)(uintptr_t chOrGameObj, float opacity);
typedef void*(__thiscall* GetInterpolatedWorldTransform_t)(uintptr_t gameObj, float* outMat, float dtf);
typedef int(__thiscall* GetBoneIndexForNameHash_t)(uintptr_t ch, uint32_t hash);
typedef void(__thiscall* GetBoneMatrix_t)(uintptr_t animCtrl, int boneIdx, float* outMat);
typedef bool(__thiscall* IsInCinematicCamera_t)(uintptr_t camMgr);
typedef uintptr_t*(__thiscall* GetWieldingWeapon_t)(uintptr_t ch, uint8_t param1);
typedef void(__thiscall* WeaponSetVisible_t)(uintptr_t weapon, uint8_t visible, uint8_t forceShow, uint8_t forceUpdate);

static UpdateCameraContexts_t o_UpdateCameraContexts = nullptr;
static UpdateRenderContexts_t o_UpdateRenderContexts = nullptr;
static CharacterUpdateRender_t o_CharacterUpdateRender = nullptr;
static CharacterSetOpacity_t o_CharacterSetOpacity = nullptr;
static GetInterpolatedWorldTransform_t fn_GetInterpolatedWorldTransform = nullptr;
static GetBoneIndexForNameHash_t fn_GetBoneIndexForNameHash = nullptr;
static GetBoneMatrix_t fn_GetBoneMatrix = nullptr;
static GetBoneMatrix_t fn_GetPreviousBoneMatrix = nullptr;
static IsInCinematicCamera_t fn_IsInCinematicCamera = nullptr;
static GetWieldingWeapon_t fn_GetWieldingWeapon = nullptr;
static WeaponSetVisible_t fn_WeaponSetVisible = nullptr;

static uintptr_t ResolveJmpThunk(uintptr_t addr) {
    uint8_t op = 0;
    int32_t rel = 0;
    for (int hop = 0; hop < 3 && addr; hop++) {
        if (!FastRead<uint8_t>(addr, op)) break;
        if (op == 0xE9 && FastRead<int32_t>(addr + 1, rel)) {
            addr = addr + 5 + (intptr_t)rel;
        } else {
            break;
        }
    }
    return addr;
}

static uintptr_t GetLocalCharacterPtr() {
    uintptr_t player = GetPlayerPtr();
    if (!player) return 0;
    uintptr_t ch = 0;
    return (FastRead<uintptr_t>(player + 0x68, ch) && ch) ? ch : 0;
}

static bool IsFirstPersonActive(uintptr_t& outChar) {
    outChar = 0;
    if (!g_FirstPerson || g_FreeCam || !g_ExeBase) return false;
    uintptr_t ch = GetLocalCharacterPtr();
    if (!ch) return false;
    uint8_t inSeq = 0;
    if (FastRead<uint8_t>(ch + 0x2A30, inSeq) && inSeq) return false;
    uintptr_t camMgr = 0;
    if (!FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, camMgr) || !camMgr) return false;
    if (fn_IsInCinematicCamera && fn_IsInCinematicCamera(camMgr)) return false;
    float fov = 1.0f;
    if (FastRead<float>(camMgr + 0x5C0, fov) && fov < 0.32f) return false; // suspend during sniper zoom
    outChar = ch;
    return true;
}

static bool ReadFpBoneNameSafe(uintptr_t addr, char* buf, size_t maxLen) {
    if (!addr || !buf || maxLen == 0) return false;
    for (size_t i = 0; i + 1 < maxLen; i++) {
        char c = 0;
        if (!FastRead<char>(addr + i, c)) {
            buf[0] = '\0';
            return false;
        }
        buf[i] = c;
        if (c == '\0') return true;
    }
    buf[maxLen - 1] = '\0';
    return true;
}

static bool IsFpUtilityBoneName(const char* name) {
    if (!name || !name[0]) return false;
    static const char* kKeepSubstrs[] = {
        "Camera_RF", "Target_RF", "AimTarget_RF", "GrappleWire_RF",
        "IkTarget_RF", "IkOffset_RF", "HoverboardAttach"
    };
    for (const char* sub : kKeepSubstrs) {
        if (strstr(name, sub) != nullptr) return true;
    }
    return false;
}

static void ExpandFpBoneDescendants(const std::vector<int16_t>& parents, std::vector<uint8_t>& mark) {
    int n = (int)parents.size();
    bool changed = true;
    while (changed) {
        changed = false;
        for (int i = 0; i < n; i++) {
            int16_t p = parents[(size_t)i];
            if (!mark[(size_t)i] && p >= 0 && p < n && mark[(size_t)p]) {
                mark[(size_t)i] = 1;
                changed = true;
            }
        }
    }
}

static void RefreshFpBoneLists(uintptr_t ch, int headIdx) {
    uintptr_t animCtrl = 0, skinner = 0, poseT1 = 0, hkaSkel = 0;
    if (!FastRead<uintptr_t>(ch + 0x1D50, animCtrl) || !animCtrl) return;
    if (!FastRead<uintptr_t>(animCtrl + 0xE0, skinner) || !skinner) return;
    if (!FastRead<uintptr_t>(skinner + 0x30, poseT1) || !poseT1) return;
    if (!FastRead<uintptr_t>(poseT1 + 0x0, hkaSkel) || !hkaSkel) return;
    if ((const void*)hkaSkel == g_FpLastHkaSkeleton && !g_FpHeadDescendants.empty() && !g_FpBodyHideBones.empty()) return;

    uintptr_t parentData = 0, boneData = 0;
    int32_t parentCount = 0;
    if (!FastRead<uintptr_t>(hkaSkel + 32, parentData) || !parentData) return;
    if (!FastRead<int32_t>(hkaSkel + 40, parentCount) || parentCount <= 0 || parentCount > 1024) return;
    if (!FastRead<uintptr_t>(hkaSkel + 48, boneData) || !boneData) return;

    std::vector<int16_t> parents((size_t)parentCount);
    std::vector<uint8_t> rawBones((size_t)parentCount * 16);
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)parentData, parents.data(), (size_t)parentCount * sizeof(int16_t), NULL))
        return;
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)boneData, rawBones.data(), (size_t)parentCount * 16, NULL))
        return;

    std::vector<uint8_t> headMark((size_t)parentCount, 0);
    if (headIdx >= 0 && headIdx < parentCount) headMark[(size_t)headIdx] = 1;
    ExpandFpBoneDescendants(parents, headMark);

    std::vector<uint8_t> armMark((size_t)parentCount, 0);
    std::vector<uint8_t> utilMark((size_t)parentCount, 0);
    char bname[64];
    for (int i = 0; i < parentCount; i++) {
        uintptr_t namePtr = *(const uintptr_t*)(rawBones.data() + (size_t)i * 16);
        if (ReadFpBoneNameSafe(namePtr, bname, sizeof(bname))) {
            if (strcmp(bname, "L_UpperArm_01") == 0 || strcmp(bname, "R_UpperArm_01") == 0) {
                armMark[(size_t)i] = 1;
            }
            if (IsFpUtilityBoneName(bname)) {
                utilMark[(size_t)i] = 1;
            }
        }
    }
    ExpandFpBoneDescendants(parents, armMark);

    g_FpHeadDescendants.clear();
    g_FpBodyHideBones.clear();
    for (int i = 0; i < parentCount; i++) {
        if (headMark[(size_t)i]) g_FpHeadDescendants.push_back(i);
        // Keep root transforms (0..1), both arms/hands, and camera/IK/grapple reference bones unscaled
        if (i > 1 && !armMark[(size_t)i] && !utilMark[(size_t)i]) {
            g_FpBodyHideBones.push_back(i);
        }
    }
    g_FpLastHkaSkeleton = (const void*)hkaSkel;
}

static void SetPoseBonesScale(uintptr_t posePtr, const std::vector<int>& bones, float scale) {
    if (!posePtr || bones.empty()) return;
    uintptr_t dataPtr = 0;
    int32_t size = 0;
    if (!FastRead<uintptr_t>(posePtr + 0x18, dataPtr) || !dataPtr) return;
    if (!FastRead<int32_t>(posePtr + 0x20, size) || size <= 0) return;
    for (int idx : bones) {
        if (idx >= 0 && idx < size) {
            uintptr_t joint = dataPtr + (uintptr_t)idx * 48;
            FastWrite<float>(joint + 0x20, scale);
            FastWrite<float>(joint + 0x24, scale);
            FastWrite<float>(joint + 0x28, scale);
            FastWrite<float>(joint + 0x2C, 1.0f);
        }
    }
}

static void UpdateFpWeaponVisibility(uintptr_t ch, bool hideHolstered) {
    if (!fn_WeaponSetVisible) return;
    if (hideHolstered) {
        uintptr_t wield = 0;
        if (fn_GetWieldingWeapon) {
            uintptr_t* wp = fn_GetWieldingWeapon(ch, 0);
            if (wp) FastRead<uintptr_t>((uintptr_t)wp, wield);
        }
        for (int i = 0; i < 4; i++) {
            uintptr_t w = 0;
            if (!FastRead<uintptr_t>(ch + 0x9E0 + (uintptr_t)i * 16, w) || !w) continue;
            int32_t state = 0;
            if (FastRead<int32_t>(w + 0x4F4, state) && state == 5) continue; // skip mounted weapons
            fn_WeaponSetVisible(w, (w == wield) ? 1 : 0, 0, 0);
        }
        g_FpWeaponsHidden = true;
    } else if (g_FpWeaponsHidden) {
        for (int i = 0; i < 4; i++) {
            uintptr_t w = 0;
            if (!FastRead<uintptr_t>(ch + 0x9E0 + (uintptr_t)i * 16, w) || !w) continue;
            int32_t state = 0;
            if (FastRead<int32_t>(w + 0x4F4, state) && state == 5) continue;
            fn_WeaponSetVisible(w, 1, 0, 0);
        }
        g_FpWeaponsHidden = false;
    }
}

static bool ComputeFirstPersonEye(uintptr_t ch, float dtf, const float* camMat, float outEye[3]) {
    if (!fn_GetInterpolatedWorldTransform || !fn_GetBoneIndexForNameHash || !fn_GetBoneMatrix || !fn_GetPreviousBoneMatrix)
        return false;
    uintptr_t animCtrl = 0;
    if (!FastRead<uintptr_t>(ch + 0x1D50, animCtrl) || !animCtrl) return false;
    int headIdx = fn_GetBoneIndexForNameHash(ch, kFpBoneHashHead);
    if (headIdx < 0) return false;

    float charWorld[16] = {};
    float boneT0[16] = {}, boneT1[16] = {};
    fn_GetInterpolatedWorldTransform(ch + 0x10, charWorld, dtf);
    fn_GetPreviousBoneMatrix(animCtrl, headIdx, boneT0);
    fn_GetBoneMatrix(animCtrl, headIdx, boneT1);

    float lx = boneT0[12] + (boneT1[12] - boneT0[12]) * dtf;
    float ly = boneT0[13] + (boneT1[13] - boneT0[13]) * dtf;
    float lz = boneT0[14] + (boneT1[14] - boneT0[14]) * dtf;

    float wx = lx * charWorld[0] + ly * charWorld[4] + lz * charWorld[8]  + charWorld[12];
    float wy = lx * charWorld[1] + ly * charWorld[5] + lz * charWorld[9]  + charWorld[13];
    float wz = lx * charWorld[2] + ly * charWorld[6] + lz * charWorld[10] + charWorld[14];

    // Row 2 is -Forward in JC4 camera matrices; Row 1 is Up; Row 0 is Right.
    outEye[0] = wx - camMat[8] * g_FpForwardOffset + camMat[4] * g_FpUpOffset + camMat[0] * g_FpRightOffset;
    outEye[1] = wy - camMat[9] * g_FpForwardOffset + camMat[5] * g_FpUpOffset + camMat[1] * g_FpRightOffset;
    outEye[2] = wz - camMat[10] * g_FpForwardOffset + camMat[6] * g_FpUpOffset + camMat[2] * g_FpRightOffset;
    return true;
}

static void ApplyEyeToCameraContext(uintptr_t camCtxPtr, const float eye[3]) {
    FastWrite<float>(camCtxPtr + 0x30, eye[0]);
    FastWrite<float>(camCtxPtr + 0x34, eye[1]);
    FastWrite<float>(camCtxPtr + 0x38, eye[2]);
    // Keep m_ListenerTransform synced to Rico's ears
    FastWrite<float>(camCtxPtr + 0x80 + 0x30, eye[0]);
    FastWrite<float>(camCtxPtr + 0x80 + 0x34, eye[1]);
    FastWrite<float>(camCtxPtr + 0x80 + 0x38, eye[2]);
}

void __fastcall hk_UpdateCameraContexts(uintptr_t tree, uintptr_t ctrlCtx) {
    o_UpdateCameraContexts(tree, ctrlCtx);
    uintptr_t ch = 0;
    if (!ctrlCtx || !IsFirstPersonActive(ch)) return;
    uintptr_t simCtx = ctrlCtx + 0x170;
    float fov = 1.0f;
    if (FastRead<float>(simCtx + 0xC0, fov) && fov < 0.32f) return;
    float eye[3];
    if (ComputeFirstPersonEye(ch, 1.0f, (const float*)simCtx, eye)) {
        ApplyEyeToCameraContext(simCtx, eye);
    }
}

void __fastcall hk_UpdateRenderContexts(uintptr_t tree, uintptr_t ctrlCtx) {
    o_UpdateRenderContexts(tree, ctrlCtx);
    uintptr_t ch = 0;
    if (!ctrlCtx || !IsFirstPersonActive(ch)) return;
    uintptr_t rndCtx = ctrlCtx + 0x410;
    float fov = 1.0f;
    if (FastRead<float>(rndCtx + 0xC0, fov) && fov < 0.32f) return;
    float dtf = 1.0f;
    FastRead<float>(ctrlCtx + 0x08, dtf);
    if (dtf < 0.0f) dtf = 0.0f;
    if (dtf > 1.0f) dtf = 1.0f;
    float eye[3];
    if (ComputeFirstPersonEye(ch, dtf, (const float*)rndCtx, eye)) {
        ApplyEyeToCameraContext(rndCtx, eye);
    }
}

bool __fastcall hk_CharacterUpdateRender(uintptr_t ch, uintptr_t updateCtx) {
    uintptr_t localCh = GetLocalCharacterPtr();
    if (ch && ch == localCh) {
        uintptr_t fpChar = 0;
        int16_t charHp = 0;
        bool charAlive = FastRead<int16_t>(ch + 0x3AC, charHp) && charHp > 0;
        bool fpActive = charAlive && IsFirstPersonActive(fpChar);
        uintptr_t animCtrl = 0, skinner = 0;
        if (FastRead<uintptr_t>(ch + 0x1D50, animCtrl) && animCtrl &&
            FastRead<uintptr_t>(animCtrl + 0xE0, skinner) && skinner) {
            uintptr_t poseT0 = 0, poseT1 = 0;
            FastRead<uintptr_t>(skinner + 0x28, poseT0);
            FastRead<uintptr_t>(skinner + 0x30, poseT1);
            if (fpActive && (g_FpHideBody || g_FpHideHead)) {
                int headIdx = fn_GetBoneIndexForNameHash ? fn_GetBoneIndexForNameHash(ch, kFpBoneHashHead) : -1;
                RefreshFpBoneLists(ch, headIdx);
                if (g_FpHideBody) {
                    // Non-zero tiny positive scale avoids singular matrix NaN shader glare on hair/eyes
                    SetPoseBonesScale(poseT0, g_FpBodyHideBones, 0.001f);
                    SetPoseBonesScale(poseT1, g_FpBodyHideBones, 0.001f);
                    g_FpBodyWasHidden = true;
                    g_FpHeadWasHidden = true;
                } else {
                    if (g_FpBodyWasHidden) {
                        SetPoseBonesScale(poseT0, g_FpBodyHideBones, 1.0f);
                        SetPoseBonesScale(poseT1, g_FpBodyHideBones, 1.0f);
                        g_FpBodyWasHidden = false;
                    }
                    SetPoseBonesScale(poseT0, g_FpHeadDescendants, 0.001f);
                    SetPoseBonesScale(poseT1, g_FpHeadDescendants, 0.001f);
                    g_FpHeadWasHidden = true;
                }
            } else {
                if (g_FpBodyWasHidden) {
                    SetPoseBonesScale(poseT0, g_FpBodyHideBones, 1.0f);
                    SetPoseBonesScale(poseT1, g_FpBodyHideBones, 1.0f);
                    g_FpBodyWasHidden = false;
                    g_FpHeadWasHidden = false;
                } else if (g_FpHeadWasHidden) {
                    SetPoseBonesScale(poseT0, g_FpHeadDescendants, 1.0f);
                    SetPoseBonesScale(poseT1, g_FpHeadDescendants, 1.0f);
                    g_FpHeadWasHidden = false;
                }
            }
        }
        UpdateFpWeaponVisibility(ch, fpActive && g_FpHideBody);
    }
    return o_CharacterUpdateRender(ch, updateCtx);
}

void __fastcall hk_CharacterSetOpacity(uintptr_t chOrGameObj, float opacity) {
    uintptr_t localCh = 0;
    if (opacity < 0.99f && IsFirstPersonActive(localCh) &&
        (chOrGameObj == localCh || chOrGameObj == localCh + 0x10)) {
        opacity = 1.0f;
    }
    o_CharacterSetOpacity(chOrGameObj, opacity);
}

// NGraphicsEngine::CCamera::UpdateRender real body (FUN_1475c5e60, RVA 0x75C5E60).
// Entry hook: bumps T0/T1 BEFORE the game lerps them into m_FOV, so the projection
// rebuild consumes our value. Additive bump (live base + delta) preserves speed/ADS dynamics.
extern bool g_OverrideFOV;
extern bool g_FovWorldSettled;
extern int g_DesiredFOV;
extern float g_FovAnchorBase;
extern bool g_FovNeedAnchor;
typedef void(__fastcall* CameraUpdateRender_t)(uintptr_t thiz, uintptr_t p2, float t);
static CameraUpdateRender_t o_CameraUpdateRender = nullptr;

void __fastcall hk_CameraUpdateRender(uintptr_t thiz, uintptr_t p2, float t) {
    constexpr float kFovDeg2Rad = 0.01745329252f;
    static float s_Base = 0.0f; // game base FOV (rad) last seen
    static int s_Des = 0;
    static bool s_Have = false;
    static bool s_WasOverrideOn = false;

    // Override DISABLE edge: freeze the camera at its current FOV and drop ALL
    // tracking state. Previously s_Have was never cleared on disable, so the
    // disabled heal path kept policing m_FOV against the stale override value
    // for the whole session — whenever the game's live FOV passed near it
    // (nitro / speed kicks), the heal yanked the FOV to the stale base: the
    // "dips to ~0.96 then snap back" that only appeared after touching the
    // toggle. Freeze-at-current is the least intrusive restore: the engine's
    // own FOV effects simply take over from the current position.
    if (s_WasOverrideOn && !g_OverrideFOV) {
        if (s_Have && thiz && g_FovWorldSettled) {
            float cur = 0.0f;
            if (FastRead<float>(thiz + 0x588, cur) && cur > 0.1f && cur < 3.0f) {
                FastWrite<float>(thiz + 0x580, cur);
                FastWrite<float>(thiz + 0x584, cur);
                uint8_t flx = 0;
                if (FastRead<uint8_t>(thiz + 0x55E, flx)) {
                    flx |= 0x10;
                    FastWrite<uint8_t>(thiz + 0x55E, flx);
                }
            }
        }
        s_Have = false;
        s_Des = 0;
    }
    s_WasOverrideOn = g_OverrideFOV;

    // FOV applies only after the ACTIVATING MOD SETTINGS warmup (mirrors canApplyToggles).
    if (g_OverrideFOV && g_FovWorldSettled && thiz) {
        // Only after the 5s graphics-manager timeout: GetGraphicsCameraManager() returns 0
        // during loading/menu and resolves ~5s after entering the world, so the anchor below
        // always captures a settled in-world base instead of a boot transient.
        uintptr_t camMgr = GetGraphicsCameraManager();
        if (!camMgr) {
            o_CameraUpdateRender(thiz, p2, t);
            return;
        }
        // The hook fires for EVERY camera (cutscene/UI/pass cams included) — only
        // the active render camera may be touched. Others fail the dims guard by
        // design and have different layouts; writing them pollutes engine state.
        uintptr_t activeCam = 0;
        FastRead<uintptr_t>(camMgr + 0x5C0, activeCam);
        bool isRenderCam = (activeCam != 0 && thiz == activeCam);
        int32_t cw = 0, ch = 0;
        float t0 = 0.0f;
        bool dimsOk = FastRead<int32_t>(thiz + 0x5A8, cw) && FastRead<int32_t>(thiz + 0x5AC, ch) && cw > ch;
        bool t0Ok   = FastRead<float>(thiz + 0x580, t0) && t0 > 0.1f && t0 < 3.0f;
        // Epic: the dims fields may not hold width/height (layout shift) — for
        // the confirmed render camera the T0 range check alone is enough,
        // otherwise the bump silently never applies and the FOV falls back to
        // vanilla base (~0.96) whenever the dims check trips.
        if (t0Ok && (dimsOk || isRenderCam)) {
            if (g_FovNeedAnchor) {
                g_FovAnchorBase = t0; // capture live base, never assume it
                g_FovNeedAnchor = false;
                s_Have = false;
            }
            float deltaNow = (float)g_DesiredFOV * kFovDeg2Rad - g_FovAnchorBase;
            float deltaWas = (float)s_Des * kFovDeg2Rad - g_FovAnchorBase;
            if (!s_Have) {
                s_Base = t0;
            } else if (g_DesiredFOV == s_Des && fabsf(t0 - (s_Base + deltaWas)) > 0.002f) {
                s_Base = t0; // game moved its own base (car/ADS/transition)
            }
            // (desired changed -> keep s_Base; it still holds the true game base)
            float want = s_Base + deltaNow;
            FastWrite<float>(thiz + 0x580, want);
            FastWrite<float>(thiz + 0x584, want);
            uint8_t fl = 0;
            if (FastRead<uint8_t>(thiz + 0x55E, fl)) {
                fl |= 0x10; // DirtyProjection: force UpdateRender to rebuild now
                FastWrite<uint8_t>(thiz + 0x55E, fl);
            }
            s_Des = g_DesiredFOV;
            s_Have = true;
        } else if (s_Have && isRenderCam) {
            // GUARD MISS on the RENDER camera (Epic-only symptom): the width/
            // height or T0 sanity check transiently failed during a FOV-kick
            // event (nitro / high accel / wingsuit). Holding the last accepted
            // bump here instead of passing through is what stops the stock base
            // FOV (0.96 rad = 55) from leaking into m_FOV for a stretch of frames.
            float wantHold = s_Base + ((float)g_DesiredFOV * kFovDeg2Rad - g_FovAnchorBase);
            FastWrite<float>(thiz + 0x580, wantHold);
            FastWrite<float>(thiz + 0x584, wantHold);
            uint8_t flh = 0;
            if (FastRead<uint8_t>(thiz + 0x55E, flh)) {
                flh |= 0x10;
                FastWrite<uint8_t>(thiz + 0x55E, flh);
            }
        }
    }
    o_CameraUpdateRender(thiz, p2, t);
}

static void CheckAndApplyFreeCamMatrix(uintptr_t matPtr) {
    if (!g_FreeCam || !matPtr) return;

    uintptr_t cameraManager = 0;
    FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cameraManager);
    if (!cameraManager) return;

    // Check if the destination matrix is CGameCameraManager + 0x500
    if (matPtr == (cameraManager + 0x500)) {
        if (!g_FreeCamPosCaptured) {
            FastRead<float>(matPtr + 0x30, g_FreeCamPos[0]);
            FastRead<float>(matPtr + 0x34, g_FreeCamPos[1]);
            FastRead<float>(matPtr + 0x38, g_FreeCamPos[2]);
            g_FreeCamPosCaptured = true;
        }

        // Hijack camera coordinates directly at point of creation
        FastWrite<float>(matPtr + 0x30, g_FreeCamPos[0]);
        FastWrite<float>(matPtr + 0x34, g_FreeCamPos[1]);
        FastWrite<float>(matPtr + 0x38, g_FreeCamPos[2]);
    }
}

// Hook 1: CTransform::ToMatrix4 (FUN_1476014e0)
typedef uintptr_t(__fastcall* CameraToMatrix_t)(uintptr_t param_1, uintptr_t param_2);
static CameraToMatrix_t o_CameraToMatrix = nullptr;
uintptr_t __fastcall hk_CameraToMatrix(uintptr_t param_1, uintptr_t param_2) {
    uintptr_t ret = o_CameraToMatrix(param_1, param_2);
    static bool dbgFirst = false, dbgMatch = false;
    if (g_FreeCam) {
        uintptr_t cm = 0; FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cm);
        if (!dbgFirst) {
            dbgFirst = true;
            std::cout << "[FreeCam] first matPtr=0x" << std::hex << param_2
                      << " camMgr=0x" << cm << " camMgr+0x500=0x" << (cm + 0x500)
                      << (param_2 == cm + 0x500 ? "  MATCH" : "  NO-MATCH") << std::dec << "\n" << std::flush;
        }
        if (param_2 == cm + 0x500 && !dbgMatch) {
            dbgMatch = true;
            std::cout << "[FreeCam] MATCH camMgr+0x500 (hijack active)\n" << std::flush;
        }
    }
    CheckAndApplyFreeCamMatrix(param_2);
    return ret;
}

// Hook 2: Matrix3 to Matrix4 writer (FUN_147600060)
typedef void(__fastcall* CameraMatrix3To4_t)(uintptr_t param_1, uintptr_t param_2);
static CameraMatrix3To4_t o_CameraMatrix3To4 = nullptr;
void __fastcall hk_CameraMatrix3To4(uintptr_t param_1, uintptr_t param_2) {
    o_CameraMatrix3To4(param_1, param_2);
    CheckAndApplyFreeCamMatrix(param_2);
}

// Hook 3: Camera context transition copier (FUN_147b0c3d0)
typedef void(__fastcall* CameraContextCopy_t)(uintptr_t param_1, uintptr_t param_2, uintptr_t param_3);
static CameraContextCopy_t o_CameraContextCopy = nullptr;
void __fastcall hk_CameraContextCopy(uintptr_t param_1, uintptr_t param_2, uintptr_t param_3) {
    o_CameraContextCopy(param_1, param_2, param_3);
    CheckAndApplyFreeCamMatrix(param_3);
}

// Hook 4: Camera slerp/lerp transition (FUN_147b0b340)
typedef void(__fastcall* CameraSlerp_t)(uintptr_t param_1, uintptr_t param_2, uintptr_t param_3, float param_4, float param_5);
static CameraSlerp_t o_CameraSlerp = nullptr;
void __fastcall hk_CameraSlerp(uintptr_t param_1, uintptr_t param_2, uintptr_t param_3, float param_4, float param_5) {
    o_CameraSlerp(param_1, param_2, param_3, param_4, param_5);
    CheckAndApplyFreeCamMatrix(param_1);
}

// ============================================================================
// EPIC-ONLY freecam: the camera view matrix at camMgr+0x500 is built by these
// functions on the Epic build (found via write-watchpoint on camMgr+0x530):
//   0x247060  transform->matrix copier (dest = param_2)
//   0x23CB60  matrix copier
// After they run, re-pin the camera translation from g_FreeCamPos.
// ============================================================================
typedef uintptr_t(__fastcall* EpicCamWriter_t)(uintptr_t, uintptr_t);
static EpicCamWriter_t o_EpicCamWriter1 = nullptr;

static inline void PinFreeCamPos(uintptr_t matPtr) {
    if (!g_FreeCam || !matPtr) return;
    if (!g_FreeCamPosCaptured) {
        // capture the live camera position on the first writer call, before pinning
        FastRead<float>(matPtr + 0x30, g_FreeCamPos[0]);
        FastRead<float>(matPtr + 0x34, g_FreeCamPos[1]);
        FastRead<float>(matPtr + 0x38, g_FreeCamPos[2]);
        g_FreeCamPosCaptured = true;
        return;
    }
    FastWrite<float>(matPtr + 0x30, g_FreeCamPos[0]);
    FastWrite<float>(matPtr + 0x34, g_FreeCamPos[1]);
    FastWrite<float>(matPtr + 0x38, g_FreeCamPos[2]);
}

uintptr_t __fastcall hk_EpicCamWriter1(uintptr_t param_1, uintptr_t dest) {
    uintptr_t ret = o_EpicCamWriter1(param_1, dest);
    uintptr_t cm = 0; FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cm);
    if (cm && dest == cm + 0x500) PinFreeCamPos(dest);
    return ret;
}

static void ReleaseHeldMovementKeys() {
    if (!g_ExeBase || !g_IsSteam) return;
    uintptr_t inputMgr = 0;
    if (!FastRead<uintptr_t>(g_ExeBase + 0x2CE1AF0, inputMgr) || !inputMgr) return;
    uintptr_t fnGetKbAddr = g_ExeBase + 0xFC6140;
    uintptr_t fnProcKbAddr = g_ExeBase + 0xFF2BE0;
    uint8_t op0 = 0, op1 = 0;
    if (!FastRead<uint8_t>(fnGetKbAddr, op0) || op0 != 0xE9) return;
    if (!FastRead<uint8_t>(fnProcKbAddr, op1) || op1 != 0xE9) return;

    typedef void*(__fastcall* GetPrimaryKb_t)(void* mgr);
    typedef void(__fastcall* ProcessKbInput_t)(void* kb, const RAWKEYBOARD* rk, uint32_t ts);
    void* kb = ((GetPrimaryKb_t)fnGetKbAddr)((void*)inputMgr);
    if (!kb) return;

    struct KeyBreakDef { uint16_t vk; uint16_t sc; uint16_t flags; };
    static const KeyBreakDef kKeys[] = {
        { 'W',        0x11, RI_KEY_BREAK },
        { 'A',        0x1E, RI_KEY_BREAK },
        { 'S',        0x1F, RI_KEY_BREAK },
        { 'D',        0x20, RI_KEY_BREAK },
        { VK_SPACE,   0x39, RI_KEY_BREAK },
        { VK_SHIFT,   0x2A, RI_KEY_BREAK },
        { VK_SHIFT,   0x36, RI_KEY_BREAK },
        { VK_CONTROL, 0x1D, RI_KEY_BREAK },
        { VK_CONTROL, 0x1D, RI_KEY_BREAK | RI_KEY_E0 },
        { VK_UP,      0x48, RI_KEY_BREAK | RI_KEY_E0 },
        { VK_DOWN,    0x50, RI_KEY_BREAK | RI_KEY_E0 },
        { VK_LEFT,    0x4B, RI_KEY_BREAK | RI_KEY_E0 },
        { VK_RIGHT,   0x4D, RI_KEY_BREAK | RI_KEY_E0 },
    };
    DWORD ts = GetTickCount();
    auto fnProcKb = (ProcessKbInput_t)fnProcKbAddr;
    for (const auto& k : kKeys) {
        RAWKEYBOARD rk{};
        rk.MakeCode = k.sc;
        rk.Flags = k.flags;
        rk.VKey = k.vk;
        rk.Message = WM_KEYUP;
        fnProcKb(kb, &rk, ts);
    }
}

struct SavedCharPhysics {
    uintptr_t ch = 0;
    float gravity = -9.82f;
    int32_t proxyState = 6;
    bool wasParachute = false;
};

static SavedCharPhysics s_FreeCamSavedPhysics;
static SavedCharPhysics s_NoclipSavedPhysics;

static bool IsCharInParachute(uintptr_t ch) {
    uintptr_t ctrlParams = 0;
    uint64_t bits = 0;
    return ch && FastRead<uintptr_t>(ch + 0x2760, ctrlParams) && ctrlParams &&
           FastRead<uint64_t>(ctrlParams + 0xD0, bits) && ((bits & (1ULL << 0x23)) != 0);
}

static void CaptureCharPhysics(uintptr_t ch, SavedCharPhysics& out) {
    out = {};
    out.ch = ch;
    if (!ch) return;
    out.wasParachute = IsCharInParachute(ch);
    uintptr_t pfx = 0;
    if (FastRead<uintptr_t>(ch + 0x2208, pfx) && pfx) {
        float g = -9.82f;
        if (FastRead<float>(pfx + 0x1EC, g) && g != 0.0f) out.gravity = g;
        FastRead<int32_t>(pfx + 0x1B8, out.proxyState);
    }
}

static void RestoreCharPhysics(uintptr_t ch, SavedCharPhysics& saved, bool restoreGhostState) {
    const float grav = (saved.ch == ch && saved.gravity != 0.0f) ? saved.gravity : -9.82f;
    if (o_SetCharacterGravity) o_SetCharacterGravity(ch, grav);

    if (restoreGhostState) {
        if (o_SetGhostMode) o_SetGhostMode(ch, 0);
        // SetGhostMode(ch, 0) clears m_IsGameControledVelocity (+0x49) and resets m_ProxyState=6,
        // which strips parachute lift until OnEnter runs again; restore parachute physics state.
        uintptr_t pfx = 0;
        if (FastRead<uintptr_t>(ch + 0x2208, pfx) && pfx) {
            const bool inPara = IsCharInParachute(ch);
            if (inPara) {
                FastWrite<uint8_t>(pfx + 0x49, 1);
            }
            const int32_t wantProxy = inPara
                ? ((saved.ch == ch && saved.wasParachute && saved.proxyState >= 0) ? saved.proxyState : 8)
                : ((saved.ch == ch && !saved.wasParachute && saved.proxyState >= 0 && saved.proxyState != 6 && saved.proxyState != 7) ? saved.proxyState : -1);
            if (wantProxy >= 0) {
                uintptr_t pfxVtbl = 0, fnSetProxy = 0;
                if (FastRead<uintptr_t>(pfx, pfxVtbl) && pfxVtbl &&
                    FastRead<uintptr_t>(pfxVtbl + 0x108, fnSetProxy) && fnSetProxy) {
                    ((void(__fastcall*)(uintptr_t, int32_t))fnSetProxy)(pfx, wantProxy);
                }
            }
        }
    }
    saved = {};
}

void UpdateFreeCam(float dt) {
    static bool s_PrevLockMovement = false;
    bool lockMovementNow = g_FreeCam && g_FreeCamLockMovement;
    if (lockMovementNow && !s_PrevLockMovement) {
        ReleaseHeldMovementKeys();
    }
    s_PrevLockMovement = lockMovementNow;

    if (!g_ExeBase || (!g_FreeCam && !g_FreeCamPrevState)) return;

    uintptr_t cameraManager = 0;
    FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cameraManager);
    if (!cameraManager) return;

    uintptr_t playerPtr = GetPlayerPtr();
    uintptr_t characterPtr = 0;
    if (playerPtr) {
        FastRead<uintptr_t>(playerPtr + 0x68, characterPtr);
    }

    // 1. Handle Enable / Disable Transitions
    if (g_FreeCam != g_FreeCamPrevState) {
        g_FreeCamPrevState = g_FreeCam;
        std::cout << "[FreeCam] state -> " << (g_FreeCam ? "ON" : "OFF") << "\n" << std::flush;
        ApplyNoclipCameraPatches(g_FreeCam || g_Noclip);
        ApplyFreeCamVehiclePatches(g_FreeCam);

        if (g_FreeCam) {
            if (characterPtr && g_FreeCamLockPlayer) {
                FastRead<float>(characterPtr + 0x144, g_FreeCamPlayerPos[0]);
                FastRead<float>(characterPtr + 0x148, g_FreeCamPlayerPos[1]);
                FastRead<float>(characterPtr + 0x14C, g_FreeCamPlayerPos[2]);
                g_FreeCamPlayerPosCaptured = true;
                CaptureCharPhysics(characterPtr, s_FreeCamSavedPhysics);
                if (o_SetCharacterGravity) o_SetCharacterGravity(characterPtr, 0.0f);
            }
        } else {
            g_FreeCamPosCaptured = false;
            g_FreeCamPlayerPosCaptured = false;
            if (characterPtr && !g_Noclip && (g_FreeCamLockPlayer || s_FreeCamSavedPhysics.ch == characterPtr)) {
                RestoreCharPhysics(characterPtr, s_FreeCamSavedPhysics, false);
            } else {
                s_FreeCamSavedPhysics = {};
            }
        }
    }

    if (!g_FreeCam) return;

    // 2b. Freecam opacity: the game fades Rico to 0.5 (semi-opaque) via four
    // CPlayer floats (+0x3504/+0x3524/+0x3694/+0x36E4: 1.0 normal, 0.5 faded).
    // Aiming/parachute force them to 1.0 (hence normal there); freecam does
    // not, so force 1.0 every frame while freecam is active. Verified live:
    // aim=1.0, faded=0.5 at all four offsets (Epic). No capture/restore needed:
    // the game's own fade logic rewrites them when freecam is off.
    // Render opacity (what you actually see) lives in the render node at
    // player+0x6A8 -> +0x39C (1.0 opaque, 0.5 faded; isolated via
    // faded-vs-opaque target diff, single 0.5->1.0 hit in 1653 targets).
    // Raw CPlayer writes land but do not propagate, so force the render slot
    // through the pointer chain every frame (offsets stable, VAs resolved live).
    if (playerPtr) {
        FastWrite<float>(playerPtr + 0x3504, 1.0f);
        FastWrite<float>(playerPtr + 0x3524, 1.0f);
        FastWrite<float>(playerPtr + 0x3694, 1.0f);
        FastWrite<float>(playerPtr + 0x36E4, 1.0f);
        // Fade amount (0.0 normal, 0.5 faded): isolated via faded-vs-opaque
        // diff (7 other 0.5s constant in both states, only +0x255C flips).
        FastWrite<float>(playerPtr + 0x255C, 0.0f);
        uintptr_t renderNode = 0;
        if (FastRead<uintptr_t>(playerPtr + 0x6A8, renderNode) && renderNode) {
            FastWrite<float>(renderNode + 0x39C, 1.0f);
        }
    }

    // 2. Lock Player in Place every frame during Freecam (Optional Sub-feature)
    if (characterPtr && g_FreeCamLockPlayer) {
        if (!g_FreeCamPlayerPosCaptured) {
            FastRead<float>(characterPtr + 0x144, g_FreeCamPlayerPos[0]);
            FastRead<float>(characterPtr + 0x148, g_FreeCamPlayerPos[1]);
            FastRead<float>(characterPtr + 0x14C, g_FreeCamPlayerPos[2]);
            g_FreeCamPlayerPosCaptured = true;
            CaptureCharPhysics(characterPtr, s_FreeCamSavedPhysics);
        }

        if (o_SetCharacterGravity) o_SetCharacterGravity(characterPtr, 0.0f);

        uintptr_t pfxInstance = 0;
        if (FastRead<uintptr_t>(characterPtr + 0x2208, pfxInstance) && pfxInstance) {
            FastWrite<float>(pfxInstance + 0xD0, 0.0f);
            FastWrite<float>(pfxInstance + 0xD4, 0.0f);
            FastWrite<float>(pfxInstance + 0xD8, 0.0f);
            FastWrite<float>(pfxInstance + 0x1EC, 0.0f);
        }
        FastWrite<float>(characterPtr + 0x29C0, 0.0f);
        FastWrite<float>(characterPtr + 0x29C4, 0.0f);
        FastWrite<float>(characterPtr + 0x29C8, 0.0f);
        FastWrite<float>(characterPtr + 0x29CC, 0.0f);

        FastWrite<float>(characterPtr + 0x40, g_FreeCamPlayerPos[0]);
        FastWrite<float>(characterPtr + 0x44, g_FreeCamPlayerPos[1]);
        FastWrite<float>(characterPtr + 0x48, g_FreeCamPlayerPos[2]);
        FastWrite<float>(characterPtr + 0x144, g_FreeCamPlayerPos[0]);
        FastWrite<float>(characterPtr + 0x148, g_FreeCamPlayerPos[1]);
        FastWrite<float>(characterPtr + 0x14C, g_FreeCamPlayerPos[2]);

        if (o_SetWorldAndPhysicsPosition) {
            o_SetWorldAndPhysicsPosition(characterPtr, g_FreeCamPlayerPos);
        }
    } else if (characterPtr && !g_Noclip && g_FreeCamPlayerPosCaptured) {
        // If unticked mid-flight, restore saved gravity and clear captured state
        RestoreCharPhysics(characterPtr, s_FreeCamSavedPhysics, false);
        g_FreeCamPlayerPosCaptured = false;
    }

    // 3. Move Freecam
    float m[16] = { 0 };
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)(cameraManager + 0x500), m, sizeof(m), NULL)) return;

    if (!g_FreeCamPosCaptured) {
        g_FreeCamPos[0] = m[12];
        g_FreeCamPos[1] = m[13];
        g_FreeCamPos[2] = m[14];
        g_FreeCamPosCaptured = true;
    }

    HWND fg = GetForegroundWindow();
    DWORD fgPid = 0;
    if (fg) GetWindowThreadProcessId(fg, &fgPid);
    if (!g_ShowMenu && fgPid == GetCurrentProcessId()) {
        float rx = m[0],  ry = m[1],  rz = m[2];   // Camera Right
        float fx = -m[8], fy = -m[9], fz = -m[10]; // Camera Forward (3D Look Direction)

        auto GetKey = [](int vk) -> bool {
            return (o_GetAsyncKeyState ? o_GetAsyncKeyState(vk) : GetAsyncKeyState(vk)) & 0x8000;
        };

        float speed = g_FreeCamSpeed;
        if (GetKey(VK_SHIFT)) speed *= g_FreeCamFastMult;
        float moveDist = speed * dt;

        if (GetKey('W')) { g_FreeCamPos[0] += fx * moveDist; g_FreeCamPos[1] += fy * moveDist; g_FreeCamPos[2] += fz * moveDist; }
        if (GetKey('S')) { g_FreeCamPos[0] -= fx * moveDist; g_FreeCamPos[1] -= fy * moveDist; g_FreeCamPos[2] -= fz * moveDist; }
        if (GetKey('D')) { g_FreeCamPos[0] += rx * moveDist; g_FreeCamPos[1] += ry * moveDist; g_FreeCamPos[2] += rz * moveDist; }
        if (GetKey('A')) { g_FreeCamPos[0] -= rx * moveDist; g_FreeCamPos[1] -= ry * moveDist; g_FreeCamPos[2] -= rz * moveDist; }
        if (GetKey(VK_SPACE))   { g_FreeCamPos[1] += moveDist; }
        if (GetKey(VK_CONTROL)) { g_FreeCamPos[1] -= moveDist; }
    }

    // Direct write of the camera position each frame (the ToMatrix4 matrix hijack does not
    // catch the camera matrix on this build; noclip proves cameraManager+0x500 is valid).
    if (cameraManager) {
        FastWrite<float>(cameraManager + 0x530, g_FreeCamPos[0]);
        FastWrite<float>(cameraManager + 0x534, g_FreeCamPos[1]);
        FastWrite<float>(cameraManager + 0x538, g_FreeCamPos[2]);
    }
}

void UpdateNoclip(float dt) {
    if (!g_ExeBase || (!g_Noclip && !g_NoclipPrevState)) return;

    uintptr_t playerPtr = GetPlayerPtr();
    if (!playerPtr) {
        g_NoclipPosCaptured = false;
        s_NoclipSavedPhysics = {};
        ApplyNoclipCameraPatches(false);
        return;
    }

    uintptr_t characterPtr = 0;
    if (!FastRead<uintptr_t>(playerPtr + 0x68, characterPtr) || !characterPtr) {
        g_NoclipPosCaptured = false;
        s_NoclipSavedPhysics = {};
        ApplyNoclipCameraPatches(false);
        return;
    }

    // 1. Handle Enable / Disable Transitions
    if (g_Noclip != g_NoclipPrevState) {
        g_NoclipPrevState = g_Noclip;
        ApplyNoclipCameraPatches(g_Noclip);

        if (g_Noclip) {
            CaptureCharPhysics(characterPtr, s_NoclipSavedPhysics);
            if (o_SetGhostMode) o_SetGhostMode(characterPtr, 1); // Ghost Mode ON for true noclip
            if (o_SetCharacterGravity) o_SetCharacterGravity(characterPtr, 0.0f);

            FastRead<float>(characterPtr + 0x144, g_NoclipPos[0]);
            FastRead<float>(characterPtr + 0x148, g_NoclipPos[1]);
            FastRead<float>(characterPtr + 0x14C, g_NoclipPos[2]);
            g_NoclipPosCaptured = true;
        } else {
            RestoreCharPhysics(characterPtr, s_NoclipSavedPhysics, true);
            g_NoclipPosCaptured = false;
        }
    }

    if (!g_Noclip) return;

    // 2. Ensure initial position is captured
    if (!g_NoclipPosCaptured) {
        FastRead<float>(characterPtr + 0x144, g_NoclipPos[0]);
        FastRead<float>(characterPtr + 0x148, g_NoclipPos[1]);
        FastRead<float>(characterPtr + 0x14C, g_NoclipPos[2]);
        g_NoclipPosCaptured = true;
    }

    // 3. Continuous Anti-Gravity, Ghost Collision, & Velocity Freeze
    if (o_SetCharacterGravity) o_SetCharacterGravity(characterPtr, 0.0f);
    if (o_SetGhostMode) o_SetGhostMode(characterPtr, 1);

    uintptr_t pfxInstance = 0;
    if (FastRead<uintptr_t>(characterPtr + 0x2208, pfxInstance) && pfxInstance) {
        FastWrite<float>(pfxInstance + 0xD0, 0.0f);
        FastWrite<float>(pfxInstance + 0xD4, 0.0f);
        FastWrite<float>(pfxInstance + 0xD8, 0.0f);
        FastWrite<float>(pfxInstance + 0x1EC, 0.0f);
    }
    FastWrite<float>(characterPtr + 0x29C0, 0.0f);
    FastWrite<float>(characterPtr + 0x29C4, 0.0f);
    FastWrite<float>(characterPtr + 0x29C8, 0.0f);
    FastWrite<float>(characterPtr + 0x29CC, 0.0f);

    // 4. Calculate 3D Movement Displacement
    float dx = 0.0f, dy = 0.0f, dz = 0.0f;

    HWND fg = GetForegroundWindow();
    DWORD fgPid = 0;
    if (fg) GetWindowThreadProcessId(fg, &fgPid);
    if (!g_ShowMenu && fgPid == GetCurrentProcessId()) {
        uintptr_t cameraManager = 0;
        FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cameraManager);
        if (cameraManager) {
            float m[16] = { 0 };
            if (ReadProcessMemory(GetCurrentProcess(), (void*)(cameraManager + 0x500), m, sizeof(m), NULL)) {
                float rx = m[0],  ry = m[1],  rz = m[2];   // Camera Right
                float fx = -m[8], fy = -m[9], fz = -m[10]; // Camera Forward (3D Look Direction)

                auto GetKey = [](int vk) -> bool {
                    return (o_GetAsyncKeyState ? o_GetAsyncKeyState(vk) : GetAsyncKeyState(vk)) & 0x8000;
                };

                float speed = g_NoclipSpeed;
                if (GetKey(VK_SHIFT)) speed *= g_NoclipFastMult;
                float moveDist = speed * dt;

                if (GetKey('W')) { dx += fx * moveDist; dy += fy * moveDist; dz += fz * moveDist; }
                if (GetKey('S')) { dx -= fx * moveDist; dy -= fy * moveDist; dz -= fz * moveDist; }
                if (GetKey('D')) { dx += rx * moveDist; dy += ry * moveDist; dz += rz * moveDist; }
                if (GetKey('A')) { dx -= rx * moveDist; dy -= ry * moveDist; dz -= rz * moveDist; }
                if (GetKey(VK_SPACE))   { dy += moveDist; }
                if (GetKey(VK_CONTROL)) { dy -= moveDist; }
            }
        }
    }

    g_NoclipPos[0] += dx;
    g_NoclipPos[1] += dy;
    g_NoclipPos[2] += dz;

    // 5. Synchronize Position 1 (Base CGameObject / Camera & Weapon Attachment Root at +0x10)
    FastWrite<float>(characterPtr + 0x40, g_NoclipPos[0]);
    FastWrite<float>(characterPtr + 0x44, g_NoclipPos[1]);
    FastWrite<float>(characterPtr + 0x48, g_NoclipPos[2]);

    // 6. Synchronize Position 2 (Visual Character Mesh Matrix at +0x114)
    FastWrite<float>(characterPtr + 0x144, g_NoclipPos[0]);
    FastWrite<float>(characterPtr + 0x148, g_NoclipPos[1]);
    FastWrite<float>(characterPtr + 0x14C, g_NoclipPos[2]);

    // 7. Mark Transform Dirty Flag so bone sockets update child weapon attachments immediately
    uint8_t dirtyFlag = 0;
    FastRead<uint8_t>(characterPtr + 0x154, dirtyFlag);
    FastWrite<uint8_t>(characterPtr + 0x154, dirtyFlag | 1);

    // 8. Synchronize Havok Physics Capsule
    if (o_SetWorldAndPhysicsPosition) {
        o_SetWorldAndPhysicsPosition(characterPtr, g_NoclipPos);
    }
}

bool g_InfAmmo = false;
bool g_InfWeaponAmmo = false;
bool g_DisableRivers = false;
bool g_DisableFoliage = false;
int g_TerrainLODMode = 0; // 0 = Default (Vanilla), 1 = Force LOD 9 (Ultra High Res)

// ============================================================================
// GLOBAL WORLD & ALTITUDE OVERRIDES
// ============================================================================
extern uintptr_t g_ExeBase;
bool g_OverrideAltitudeLimit = false;
float g_LiveMaxAltitude = 7000.0f;
float g_LiveMinAltitude = -1000.0f;
float g_LiveBroadphaseSize = 8100.0f;

// Forward declarations so functions defined lower in the file can be called here
uintptr_t GetWorldSimManager();
static uintptr_t AllocateNear(uintptr_t target, size_t size);

// ============================================================================
// SPAWN LIMIT & SBUDGETRECORD ENGINE
// ============================================================================
bool g_OverrideSpawnLimits = false;
// True only once the warmup gate has actually pushed the overrides into the
// engine. The UI reads this instead of the raw toggle so the tab never claims a
// budget that hasn't been applied yet (i.e. no "0 / 1" during the warmup).
bool g_SpawnLimitsActive = false;

// Hardcoded genuine vanilla defaults (No zero initialization)
const int32_t g_DefSimBudget = 35; 
int32_t g_LiveSimBudget      = 35; // Default starts at 35
int     g_LiveSpawnDelayMs   = 5000; // Stock 5-second interval



// Resolves the real Vehicle SBudgetRecord (Hash 0xBC7DCD86) from CSpawnSystem (+0x58)
static uintptr_t GetVehicleBudgetRecord() {
    if (!g_ExeBase) return 0;
    uintptr_t spawnSystem = 0;
    if (!FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D20, spawnSystem) || !spawnSystem) return 0;
    uintptr_t bgn = 0, end = 0;
    if (!FastRead<uintptr_t>(spawnSystem + 0x58, bgn) || !FastRead<uintptr_t>(spawnSystem + 0x60, end)) return 0;
    // Reject uninitialized memory spans exceeding 64KB
    if (!bgn || end <= bgn || (end - bgn) > 0x10000) return 0;

    // Iterate SBudgetRecord array (0x150 stride) to find Land/Road Vehicles pool (0xBC7DCD86)
    for (uintptr_t cur = bgn; cur < end; cur += 0x150) {
        uint32_t hash = 0;
        if (FastRead<uint32_t>(cur, hash) && hash == 0xBC7DCD86) {
            return cur;
        }
    }
    return bgn; // Fallback
}

struct VerifiedPatch {
    const char* name;
    uintptr_t rva;
    std::vector<uint8_t> orig;
    std::vector<uint8_t> patch;
    bool applied = false;

    void Toggle(bool enable) {
        if (!g_ExeBase) return;
        if (!JRVA_KNOWN(rva)) return;
        uintptr_t target = g_ExeBase + JRVA(rva);
        if (enable) {
            if (applied) return;
            std::vector<uint8_t> cur(orig.size(), 0);
            if (!ReadProcessMemory(GetCurrentProcess(), (void*)target, cur.data(), orig.size(), NULL)) return;
            if (memcmp(cur.data(), orig.data(), orig.size()) != 0) return;
            SafePatchBytes(target, patch.data(), patch.size());
            applied = true;
        } else {
            if (applied) {
                SafePatchBytes(target, orig.data(), orig.size());
                applied = false;
            }
        }
    }
};

static VerifiedPatch s_SpawnPatches[] = {
    // 0. Air Spawner Bypasses
    { "AirStatusBypass",   0x471CDA, { 0x75, 0x07 }, { 0xEB, 0x07 } },
    { "AirInstantSpawn",   0x471EAF, { 0x48, 0x8B, 0x0D, 0x7A, 0xFE, 0x83, 0x02 }, { 0xEB, 0x20, 0x90, 0x90, 0x90, 0x90, 0x90 } },
    { "AirSpacing",        0x81E1519, { 0x8B, 0x85, 0xB8, 0x00, 0x00, 0x00 }, { 0xB8, 0x00, 0x00, 0xA0, 0x41, 0x90 } },

    // 1. Quotas, Express, & Cooldowns
    { "SlotCooldown",      0x49B60A, { 0x81, 0xC1, 0xEE, 0x02, 0x00, 0x00 }, { 0x81, 0xC1, 0x32, 0x00, 0x00, 0x00 } }, // 750ms -> 50ms slot cooldown
    { "SpawnExpress",      0x4936E8, { 0x44, 0x88, 0x4D, 0xD4 }, { 0xC6, 0x45, 0xD4, 0x01 } },
    { "TagIndexQuota",     0x49497D, { 0x74, 0x19 }, { 0xEB, 0x19 } },
    { "VehicleModelQuota", 0x4A6FE1, { 0x74, 0x09 }, { 0xEB, 0x09 } }, // Uncaps individual model instance limits (fixes 35 cap)
    { "DriverQuota",       0x4982BC, { 0x74, 0x09 }, { 0xEB, 0x09 } },

    // 2. Road Capacity & Headway (Uncaps Ground Density)
    { "RoadFraction",      0x49BA59, { 0x76, 0x5B }, { 0x90, 0x90 } },
    { "LaneHeadway1",      0x81DAD9E, { 0x72, 0x51 }, { 0x90, 0x90 } },
    { "LaneHeadway2",      0x81DADA6, { 0x72, 0x45 }, { 0x90, 0x90 } },
    { "TrafficEdgeCap",    0x81E1559, { 0xB9, 0x01, 0x00, 0x00, 0x00 }, { 0xB9, 0x10, 0x00, 0x00, 0x00 } }, // 1 -> 16 vehicles per segment

    // 3. Despawn Killers: Stops cars from disappearing in front of your eyes!
    { "DespawnLive",       0xBB52EF, { 0x7F, 0x05 }, { 0xEB, 0x4E } }, // Disables garbage collector that deletes cars in front of you
    { "RearDespawn",       0x4A74E3, { 0xE8, 0x58, 0xAD, 0x6D, 0x00 }, { 0x90, 0x90, 0x90, 0x90, 0x90 } }, // Disables immediate local despawner

    // 4. Uncap WorldSim Budget (NOPs cmovb eax, ebx to remove the 35 pool clamp)
    { "BudgetClamp",       0x46EF39, { 0x0F, 0x42, 0xC3 }, { 0x90, 0x90, 0x90 } },

    // 5. Bypass Factory Rank (FR_DESPAWN)
    { "FactoryRank",       0x9964A4C, { 0x7D, 0x1D }, { 0xEB, 0x29 } }
};

void ApplySpawnLimitOverrides(bool enable) {
    if (!g_ExeBase) return;

    // 1. Toggle Flow & Quota Bypasses
    for (auto& p : s_SpawnPatches) {
        p.Toggle(enable);
    }

    // 2. Dynamic Spawn Interval Delay (14046f2d5)
    uintptr_t intervalAddr = g_ExeBase + g_Addr_46F2D5;
    static const uint8_t origInterval[5] = { 0x05, 0x88, 0x13, 0x00, 0x00 }; // add eax, 5000ms
    if (enable) {
        uint8_t patch[5] = { 0x05, 0, 0, 0, 0 };
        int delay = (g_LiveSpawnDelayMs > 0) ? g_LiveSpawnDelayMs : 5000;
        memcpy(&patch[1], &delay, 4);
        SafePatchBytes(intervalAddr, patch, 5);
    } else {
        SafePatchBytes(intervalAddr, origInterval, 5);
    }

    // 3. Target Budget: Custom value when enabled, hardcoded 35 when disabled
    int32_t targetBudget = enable ? ((g_LiveSimBudget > 0) ? g_LiveSimBudget : 35) : 35;

    uintptr_t worldSim = 0;
    FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D98, worldSim);
    if (!worldSim && GetPlayerPtr()) worldSim = GetWorldSimManager();

    if (worldSim) {
            // Feed targetBudget to Vehicle simulation fields (Day, Night, Variety, Active)
            FastWrite<int32_t>(worldSim + 0x648, targetBudget);
            FastWrite<int32_t>(worldSim + 0x64C, targetBudget);
            FastWrite<int32_t>(worldSim + 0x650, enable ? targetBudget : 4);
            FastWrite<int32_t>(worldSim + 0x604, targetBudget);
        }

    // 4. Feed targetBudget to the real Vehicle SBudgetRecord (0xBC7DCD86)
    uintptr_t vRec = GetVehicleBudgetRecord();
    if (vRec) {
        FastWrite<int32_t>(vRec + 0xCC, targetBudget);
        FastWrite<int32_t>(vRec + 0x48, targetBudget);
    }
}

static float s_DefMaxAlt = 7000.0f, s_DefMinAlt = -1000.0f, s_DefBroadSize = 8100.0f;
static bool s_DefAltCaptured = false;
// OnBodyExitedBroadphase prologue (Steam+Epic identical): RET bypasses the
// hard-freeze on bounds exit; restoring re-enables streaming reloads.
static const uint8_t kExitOrigBytes[5]  = { 0x48, 0x89, 0x5C, 0x24, 0x10 };
static const uint8_t kExitPatchBytes[5] = { 0xC3, 0x90, 0x90, 0x90, 0x90 };

// ---------------------------------------------------------------------------
// Broadphase recenter decouple (the "20k/-5000 freezes WASD+grapple" fix).
//
// Verified at assembly level on BOTH builds:
// the LIVE broadphase AABB is built once at physics-world creation with
// half-height size/2 (vanilla: +-4050 m), and NPfx::RecenterWorldIfNeeded later
// re-centers that live box vertically at (s_BroadphaseMaxAltitude +
// s_BroadphaseMinAltitude)/2:
//
//   Steam RVA 0x10E8544 / Epic RVA 0x10EF594 (24 bytes, verified byte shape,
//   operand targets = each build's globals, 0.5f mul constant, and a branch
//   scan proved no jumps land inside the window on either build):
//     F3 0F 10 0D <disp>   movss xmm1, [s_BroadphaseMaxAltitude]
//     F3 0F 58 0D <disp>   addss xmm1, [s_BroadphaseMinAltitude]
//     F3 0F 59 0D <disp>   mulss xmm1, [0.5f]   -> Y lane -> shiftBroadPhase
//
//   Epic window: f3 0f 10 0d dc ad bf 01  f3 0f 58 0d 24 93 a0 01
//                f3 0f 59 0d 58 fc bb 00   (0.5f at Epic RVA 0x1CAF204)
//
// Vanilla invariant: (7000 + -1000)/2 = 3000 -> live box Y in [-1050, 7050],
// which contains the vanilla limits by design (size 8100 = span + 100).
// With custom 20000/-5000 the world recenter moves the box to center 7500
// -> live Y-range [3450, 11550] -> ground/grapple/character queries at
// y < 3450 cull everything: WASD dead + grapple dead (jump/fire survive).
// (The runtime s_BroadphaseSize write never resizes the LIVE box.)
//
// FIX (both builds): pin the recenter center to the vanilla 3000.0f while the
// override is on. 24-byte overwrite, lands exactly on instruction boundaries,
// position-independent, clobbers only EAX (dead across this window) and writes
// the intended XMM1; next original instruction at +0x18 is untouched.
//   mov eax, 0x453B8000 (3000.0f) ; movd xmm1, eax ; 15x NOP
// Restore = write back the 24-byte snapshot captured right before patching,
// so per-build displacements restore byte-perfectly.
// ---------------------------------------------------------------------------
static const uint8_t kRecenterPatchBytes[24] = {
    0xB8,0x00,0x80,0x3B,0x45,             // mov eax, 0x453B8000  (3000.0f)
    0x66,0x0F,0x6E,0xC8,                  // movd xmm1, eax
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,   // 15x NOP -> 24 bytes total
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90
};
static uint8_t s_RecenterSnapshot[24] = {0};
static bool    s_RecenterSnapValid = false;
// Site shape gate: the three 8-byte SSE ops with RIP-relative operands. Guards
// foreign/unknown builds even if the RVA table row above ever goes stale.
static bool RecenterSiteShapeOK(uintptr_t addr, uint8_t* out24) {
    for (int i = 0; i < 24; i++) {
        if (!FastRead<uint8_t>(addr + (uintptr_t)i, out24[i])) return false;
    }
    return out24[0]==0xF3 && out24[1]==0x0F && out24[2]==0x10 && out24[3]==0x0D &&
           out24[8]==0xF3 && out24[9]==0x0F && out24[10]==0x58 && out24[11]==0x0D &&
           out24[16]==0xF3 && out24[17]==0x0F && out24[18]==0x59 && out24[19]==0x0D;
}
static float BroadphaseSpanNeed() {
    float spanNeed = (g_LiveMaxAltitude - g_LiveMinAltitude) + 500.0f;
    if (spanNeed < 0.0f) spanNeed = 0.0f;
    return spanNeed;
}
static float EffectiveBroadphaseSize() {
    return BroadphaseSpanNeed();
}
// Push the computed span back into the menu variable so the Broadphase input
// shows the value actually written to Havok (e.g. 7000/-1000 -> 8500,
// 10000/-10000 -> 20500). Called on Max/Min edits and toggle-on.
static void SyncBroadphaseInputToSpan();
// Logs once per distinct auto-expanded value, from any write site (toggle,
// per-frame enforce, UI inputs) so edits that grow the span are visible.
static void LogAutoBroadphase(float boxToWrite) {
    static float s_LastLoggedBox = -1.0f;
    if (boxToWrite != s_LastLoggedBox) {
        s_LastLoggedBox = boxToWrite;
        std::cout << "[Altitude] broadphase auto-expanded to " << boxToWrite
                  << "m to contain [" << g_LiveMinAltitude << "," << g_LiveMaxAltitude << "].\n" << std::flush;
    }
}
static void SyncBroadphaseInputToSpan() {
    float spanNeed = BroadphaseSpanNeed();
    if (g_LiveBroadphaseSize != spanNeed) {
        g_LiveBroadphaseSize = spanNeed;
        LogAutoBroadphase(spanNeed);
    }
}
void ApplyAltitudeOverride(bool enable) {
    if (!g_ExeBase) return;

    uintptr_t addrMaxAlt    = g_ExeBase + g_Addr_2CE3F38; // s_BroadphaseMaxAltitude
    uintptr_t addrMinAlt    = g_ExeBase + g_Addr_2AF1E68; // s_BroadphaseMinAltitude
    uintptr_t addrBroadSize = g_ExeBase + g_Addr_2AF1E64; // s_BroadphaseSize
    uintptr_t addrExitHook  = g_ExeBase + g_Addr_F3660;   // CPhysicsSystem::OnBodyExitedBroadphase
    // NPfx::RecenterWorldIfNeeded center computation (Steam+Epic via addr table)
    uintptr_t addrRecenter  = g_ExeBase + g_Addr_10E8544;

    static const uint8_t* origExitBytes = kExitOrigBytes;
    static const uint8_t* patchExitBytes = kExitPatchBytes;

    // Recenter-decouple patch state (module-static so all apply paths share it)
    static bool s_RecenterPatched  = false;
    static bool s_RecenterSiteBad  = false;

    if (enable) {
        // 1. Bypass the exit callback so Havok doesn't hard-freeze the player
        // mid-air at the bounds (reinstated: without it you lock at exactly
        // the ceiling and cannot move; box enlargement alone does not stop
        // the exit path on this build).
        SafePatchBytes(addrExitHook, patchExitBytes, 5);

        // 1b. Pin the broadphase recenter Y-center to the vanilla 3000 m so the
        // live box never slides out from under the ground with custom min/max
        // pairs. Steam+Epic site via addr table, byte-shape-verified before
        // patching (foreign builds skip safely). Restored only on toggle-off.
        if (!s_RecenterPatched && !s_RecenterSiteBad) {
            if (!s_RecenterSnapValid) {
                if (RecenterSiteShapeOK(addrRecenter, s_RecenterSnapshot)) {
                    s_RecenterSnapValid = true;
                } else {
                    s_RecenterSiteBad = true;
                    std::cout << "[Altitude] RECENTER FIX: unexpected bytes at the recenter site, "
                                 "patch skipped on this build." << std::endl;
                }
            }
            if (s_RecenterSnapValid) {
                SafePatchBytes(addrRecenter, kRecenterPatchBytes, sizeof(kRecenterPatchBytes));
                s_RecenterPatched = true;
                std::cout << "[Altitude] recenter decouple patch ON (box center pinned to 3000m)." << std::endl;
            }
        }

        // 2. The broadphase box must contain [minAltitude, maxAltitude]:
        // flying above the box top culls raycasts (grapple indicator gone),
        // ground collision (WASD dead but shooting works), ragdoll wake-up,
        // and death respawn streaming (infinite loading). Auto-expand the box
        // to the altitude span + margin when the user's value is too small.
        SyncBroadphaseInputToSpan();
        float boxToWrite = EffectiveBroadphaseSize();
        LogAutoBroadphase(boxToWrite);
        // 2. Write live custom limits into Havok physics memory
        FastWrite<float>(addrMaxAlt, g_LiveMaxAltitude);
        FastWrite<float>(addrMinAlt, g_LiveMinAltitude);
        FastWrite<float>(addrBroadSize, boxToWrite);
    } else {
        // 1. Restore pristine game defaults captured pre-warmup (no hardcodes:
        // values are read off live memory on first world-ready, before any
        // patch lands).
        FastWrite<float>(addrMaxAlt, s_DefMaxAlt);
        FastWrite<float>(addrMinAlt, s_DefMinAlt);
        FastWrite<float>(addrBroadSize, s_DefBroadSize);
        // Refresh the (greyed-out) UI fields so they show defaults, not the
        // last custom values.
        g_LiveMaxAltitude = s_DefMaxAlt;
        g_LiveMinAltitude = s_DefMinAlt;
        g_LiveBroadphaseSize = s_DefBroadSize;

        // 2. Restore original function prologue
        SafePatchBytes(addrExitHook, origExitBytes, 5);

        // 3. Restore the recenter computation (only if we patched it; snapshot
        //    restores the exact per-build bytes)
        if (s_RecenterPatched && s_RecenterSnapValid) {
            SafePatchBytes(addrRecenter, s_RecenterSnapshot, sizeof(s_RecenterSnapshot));
            s_RecenterPatched = false;
            std::cout << "[Altitude] recenter decouple patch OFF (restored)." << std::endl;
        }
    }
}
// Standalone C++ Code Cave Pointer
uintptr_t g_CodeCave = 0;

// Forward declarations for helpers defined lower in the file
uintptr_t PatternScan(uintptr_t moduleBase, const char* signature);
static uintptr_t AllocateNear(uintptr_t target, size_t size);

// ============================================================================
// GROUND HEIGHTFIELD LOD ENGINE
// ============================================================================
bool g_ForceMaxGroundLOD = false;

struct TerrainPresetBackup {
    float lod1, lod2, tessRange, dispRange, midTessStart, midTessEnd, detailTex, fullTex;
};
// g_TerrainDetailSettings has exactly 5 entries (quality presets 0-4; sentinel 5
// in m_CurrentTerrainDetailConfiguration). Entry #6 does not exist: bytes at
// table+5*0x44 are string data ("TreeImpostor", ...).
static TerrainPresetBackup s_OrigTerrainPresets[5];
static bool s_TerrainDefaultsCaptured = false;

// Shared pristine snapshot of g_TerrainDetailSettings (exe+0x1CCB620).
// Must be captured before ANY terrain feature writes, and shared by all of them,
// otherwise a second feature would snapshot another feature's modified values.
static void EnsureTerrainDefaultsCaptured() {
    if (s_TerrainDefaultsCaptured || !g_ExeBase) return;
    uintptr_t baseArray = g_ExeBase + g_Addr_1CCB620;
    for (int i = 0; i < 5; i++) {
        uintptr_t preset = baseArray + (i * 0x44);
        FastRead<float>(preset + 0x14, s_OrigTerrainPresets[i].lod1);
        FastRead<float>(preset + 0x18, s_OrigTerrainPresets[i].lod2);
        FastRead<float>(preset + 0x0C, s_OrigTerrainPresets[i].tessRange);
        FastRead<float>(preset + 0x10, s_OrigTerrainPresets[i].dispRange);
        FastRead<float>(preset + 0x1C, s_OrigTerrainPresets[i].midTessStart);
        FastRead<float>(preset + 0x24, s_OrigTerrainPresets[i].midTessEnd);
        FastRead<float>(preset + 0x2C, s_OrigTerrainPresets[i].detailTex);
        FastRead<float>(preset + 0x30, s_OrigTerrainPresets[i].fullTex);
    }
    s_TerrainDefaultsCaptured = true;
}

// Defined below; the "Force ground meshes to max detail" toggle is a hard-wired 4x
// caller of the terrain detail-distance scaler.
void ApplyTerrainDetailScale(int factor);

// "Force ground meshes to max detail" — hard-pinned to 4x detail distance on ALL
// graphics presets. Enabling the toggle always scales by 4, disabling (factor 1)
// restores the pristine table. Both arms reuse EnsureTerrainDefaultsCaptured().
void ApplyGlobalGroundLOD(bool enable) {
    if (!g_ExeBase) return;
    EnsureTerrainDefaultsCaptured();
    if (!s_TerrainDefaultsCaptured) return;
    ApplyTerrainDetailScale(enable ? 4 : 1);
}

inline void ApplyGroundLOD(bool enable) { g_ForceMaxGroundLOD = enable; ApplyGlobalGroundLOD(enable); }

// ============================================================================
// TERRAIN DETAIL DISTANCE SCALE (2x / 4x)  — "better quality terrain, further"
// ============================================================================
// Multiplies the distance-driven fields of all five STerrainDetailSettings
// quality presets (g_TerrainDetailSettings, 5 x 0x44B @ exe+0x1CCB620).
// The detail/near/far quad bucketing runs on the GPU in TerrainClassifyQuads
// against these floats, which TerrainPatchSystemUpdate copies into the terrain
// system EVERY FRAME — so live .data edits take effect immediately with zero
// code patching. Scaled fields:
//   +0x0C m_DetailTessellationRange, +0x10 m_DetailDisplacementRange,
//   +0x14 m_Lod1Range (engine side clamps it >= TessRange), +0x18 m_Lod2Range,
//   +0x1C/+0x24 m_MidTessellation(Start|End)Range, +0x2C/+0x30 Detail/FullTex.
// NOT scaled by design:
//   +0x08 m_DetailTessellationMax (a tess factor, not a distance),
//   +0x34..0x40 budget ints (SetDetailLevel sizes buffers from them only on
//   preset switch; total resident quad count is unchanged — only the distance
//   distribution of existing quads shifts).
// Residency ceiling: no finer detail exists past the LOD-9 ring (+-2048 m), and
// displacement texels past ~+-256 m (LOD-12 ring) — values beyond are wasted
// but harmless (displacement additionally clamped below to 256 m to be strict).
// Called by "Force ground meshes to max detail" with factor 4 (enable) / 1 (disable);
// factor 1 multiplies the pristine snapshot by 1.0, writing the original values back.
// ----------------------------------------------------------------------------
void ApplyTerrainDetailScale(int factor) {
    if (!g_ExeBase) return;
    EnsureTerrainDefaultsCaptured();
    if (!s_TerrainDefaultsCaptured) return;

    const float f = (float)((factor == 2 || factor == 4) ? factor : 1);
    uintptr_t baseArray = g_ExeBase + g_Addr_1CCB620; // g_TerrainDetailSettings
    for (int i = 0; i < 5; i++) {
        const TerrainPresetBackup& o = s_OrigTerrainPresets[i];
        uintptr_t preset = baseArray + (i * 0x44);
        FastWrite<float>(preset + 0x0C, o.tessRange * f);    // m_DetailTessellationRange
        float disp = o.dispRange * f;                        // m_DetailDisplacementRange:
        if (disp > 256.0f) disp = 256.0f;                    //   LOD-12 data ends ~+-256 m
        FastWrite<float>(preset + 0x10, disp);
        FastWrite<float>(preset + 0x14, o.lod1 * f);         // m_Lod1Range
        FastWrite<float>(preset + 0x18, o.lod2 * f);         // m_Lod2Range
        FastWrite<float>(preset + 0x1C, o.midTessStart * f); // m_MidTessellationStartRange
        FastWrite<float>(preset + 0x24, o.midTessEnd * f);   // m_MidTessellationEndRange
        FastWrite<float>(preset + 0x2C, o.detailTex * f);    // m_DetailTextureRange
        FastWrite<float>(preset + 0x30, o.fullTex * f);      // m_FullTextureRange
    }
}
// Individual Vehicle Boost Properties State
// Vehicle Boost Properties State
float g_BoostTorque = 1.0f;
float g_BoostGrip = 1.0f;
float g_BoostTopSpeed = 1.0f;
float g_BoostJumpHeight = 1.0f;
DWORD g_LastBoostReadTime = 0;

// ============================================================================
// CURRENT VEHICLE — BASE ENGINE (NO NITRO) — live tuning state
// Forward declarations for vehicle resolver helpers defined below
static bool IsLikelyGameObject(uintptr_t obj);
static uintptr_t GetPlayerVehiclePtr();
static std::string GetESPClassName(uintptr_t objPtr);
// ----------------------------------------------------------------------------
// Provenance (Ghidra /JustCause4.exe, Steam build, PDB types):
//   CVehicle.m_PfxVehicle            @ 0x13DE8 -> CPfxCar* (shared_ptr + raw)
//   CVehicle.m_LocalPlayerSeat       @ 0x1063C (int32; -1 = on foot, >=0 = Rico in car)
//   CPfxCar.m_LandVehicleEngine      @ 0x2990 (10640) -> CPfxLandVehicleEngine*
//   CPfxCar.m_LandVehicleTransmission @ 0x2998 (10648)
//   CPfxCar.m_EngineTorque (live)    @ 0x29A4 (10660)  <- Torque hook 0x77BDE85 writes here every tick
//   CPfxCar.m_EngineRPM (live)       @ 0x29A8 (10664)
//   CPfxCar.m_TransmissionRPM (live) @ 0x2A0C (10764)
//   CPfxCar.m_NitroCurrentForce      @ 0x2AC0 (10944)
//   CPfxCar.m_TopSpeedKmph (live cap)@ 0x2AC4 (10948) <- derived by RecomputeTopSpeed()
//   CPfxCar.m_CustomLandGlobal       @ 0x2A78 (10872) -> SCustomLandGlobal* (nitro_boost lives here)
//   CPfxLandVehicleEngine:
//     m_EngineRevs 0x1C,
//     m_minRPM 0x40, m_optRPM 0x44, m_maxRPM 0x48, m_maxTorque 0x4C,
//     m_torqueFactorAtMinRPM 0x50, m_torqueFactorAtMaxRPM 0x54,
//     m_resistanceFactorAtMinRPM 0x58, m_resistanceFactorAtOptRPM 0x5C,
//     m_resistanceFactorAtMaxRPM 0x60, m_clutchSlipRPM 0x64
//   STransmissionConstant:
//     m_MaxTransmissionRPM 0x2C, m_ForwardTorqueRatio 0x24,
//     m_SteeringTorqueSplitRatio 0x4C, m_primaryTransmissionRatio 0x58
//   STransmissionState: m_TransmissionRPM 0x18, m_currentGear 0x65
// Key decompiles:
//   CPfxCar::GetMaxRPM returns m_LandVehicleEngine->m_maxRPM
//   CPfxCar::GetRPMRange fills (m_minRPM, m_maxRPM)
//   CPfxCar::GetVehicleTorqueOnWheel = m_maxTorque * steeringSplit * currentRatio + ...
//   CPfxCar::RecomputeTopSpeed: m_TopSpeedKmph = (m_maxRPM / primaryRatio)*0.10466667*radius*3.6
//   CPfxCar::GetCurrentNitrousParams returns &m_CustomLandGlobal->m_arcade.m_nitro_boost[_upgraded]
//     -> SPerformanceBoost { +0x0 torque_mult, +0x4 grip_mult, +0x8 push_force,
//                            +0xC blend_time, +0x10 extra_top_speed }
//     -> only consumed while IsNitrousActive / UpdatePreSim_Nitrous (m_NitrousInput>0.2, bar>0)
//   Torque hook bytes at 0x77BDE85: F3 0F 59 09 / F3 0F 11 8E A4 29 00 00
//     = mulss xmm1,[rcx] ; movss [rsi+0x29A4],xmm1  (unconditional base-torque store)
//   Grip hook at 0x77BE81D sits right after CALL GetCurrentNitrousParams (nitro grip path)
//   MaxSpeed hook at 0x77BCBDD scales [m_CustomLandGlobal+0xAC/0xC0] = nitro extra_top_speed
//     (0xAC = arcade+36 = nitro_boost.extra_top_speed, 0xC0 = nitro_boost_upgraded.extra_top_speed)
// Hence: PushForce/BlendTime + Grip/Speed multipliers only bite while boosting.
// Base power without nitro = write the engine/transmission/top-speed fields below every frame.
// ============================================================================
struct VehBaseField {
    bool overrideActive = false;
    float customVal = 0.0f;
    float defVal = 0.0f;
    bool captured = false;
};
static VehBaseField g_VehBaseMaxTorque      = {};
static VehBaseField g_VehBaseMaxRPM         = {};
static VehBaseField g_VehBaseMinRPM         = {};
static VehBaseField g_VehBaseOptRPM         = {};
static VehBaseField g_VehBaseTopSpeed       = {};
static VehBaseField g_VehBasePrimaryRatio   = {};
// --- Base GRIP: static config + live per-wheel, enforced per-frame ---
static VehBaseField g_VehGripFriction  = {};
static VehBaseField g_VehGripDownforce = {};
static VehBaseField g_VehDriftMaxTorque = {};
static DWORD g_LastVehBaseReadTime = 0;
// Live readouts (never written, display only)
static float g_VehLiveTorque = 0.0f;
static float g_VehLiveRPM = 0.0f;
static float g_VehLiveTransRPM = 0.0f;
static float g_VehLiveTopSpeed = 0.0f;
static float g_VehLiveNitroForce = 0.0f;
static int   g_VehLiveGear = -1;
static uintptr_t g_VehLiveVeh = 0, g_VehLivePfx = 0, g_VehLiveEng = 0, g_VehLiveTrans = 0;
static std::string g_VehLiveClass = "";

// Seat-based Rico vehicle resolver (robust vs camera-proximity heuristic).
// Returns the CVehicle* whose m_LocalPlayerSeat (>=0) proves Rico sits in it.
// Falls back to 0 when on foot / loading.
static uintptr_t GetRicoVehicleSeatBased() {
    if (!g_ExeBase) return 0;
    static const bool is_steam = (GetModuleHandleA("steam_api64.dll") != nullptr);
    uintptr_t gameObjectsAddr = g_ExeBase + (g_Addr_2CB1938);
    uintptr_t myFirst = 0, myLast = 0;
    if (!FastRead<uintptr_t>(gameObjectsAddr + 0x0, myFirst) ||
        !FastRead<uintptr_t>(gameObjectsAddr + 0x8, myLast) ||
        !myFirst || myLast <= myFirst) return 0;
    size_t count = (myLast - myFirst) / 8;
    if (count == 0 || count > 2000) return 0;
    for (size_t i = 0; i < count; i++) {
        uintptr_t veh = 0;
        if (!FastRead<uintptr_t>(myFirst + (i * 8), veh) || !veh) continue;
        if (!IsLikelyGameObject(veh)) continue;
        int32_t seat = -1;
        if (!FastRead<int32_t>(veh + 0x1063C, seat) || seat < 0) continue; // not Rico's
        uintptr_t pfx = 0;
        if (!FastRead<uintptr_t>(veh + 0x13DE8, pfx) || !pfx) continue;   // needs physics
        return veh;
    }
    return 0;
}
// Resolves veh -> pfxCar -> engine + transmission. Returns false when any link is dead.
// veh: CVehicle*, pfx: CPfxCar*, eng: CPfxLandVehicleEngine*, trans: CPfxLandVehicleTransmission*
static bool GetRicoVehiclePhysics(uintptr_t& vehOut, uintptr_t& pfxOut, uintptr_t& engOut, uintptr_t& transOut) {
    vehOut = pfxOut = engOut = transOut = 0;
    // STRICT: only the vehicle Rico sits in (seat index >= 0). No closest-vehicle fallback.
    uintptr_t veh = GetRicoVehicleSeatBased();
    if (!veh || !IsLikelyGameObject(veh)) return false;
    uintptr_t pfx = 0;
    if (!FastRead<uintptr_t>(veh + 0x13DE8, pfx) || !pfx || pfx < 0x10000) return false;
    uintptr_t eng = 0, trans = 0;
    FastRead<uintptr_t>(pfx + 0x2990, eng);
    FastRead<uintptr_t>(pfx + 0x2998, trans);
    // Engine/trans may be null on boats/helis (non-car PFX). Still return veh+pfx so UI shows *something*.
    vehOut = veh; pfxOut = pfx; engOut = eng; transOut = trans;
    return true;
}
static void CaptureVehBaseField(VehBaseField& f, float liveVal) {
    if (!f.captured) { f.defVal = liveVal; f.customVal = liveVal; f.captured = true; }
    else { f.defVal = f.defVal; } // keep first-seen pristine default (per archetype changes, see below)
}
// Captures pristine defaults for the CURRENT engine/trans/pfx triple.
// Uses per-address maps so switching cars does not poison other archetypes' defaults.
static std::map<uintptr_t, float> g_PristineEngMaxTorque,
    g_PristineEngMaxRPM, g_PristineEngMinRPM, g_PristineEngOptRPM,
    g_PristineTopSpeed, g_PristinePrimaryRatio,
    g_PristineGripFriction, g_PristineGripDownforce, g_PristineDriftMaxTorque;
static void CaptureVehBaseDefaults(uintptr_t eng, uintptr_t trans, uintptr_t pfx) {
    if (!eng && !trans && !pfx) return;
    auto cap = [](std::map<uintptr_t,float>& m, uintptr_t key, float v, VehBaseField& f) {
        if (!key) return;
        auto it = m.find(key);
        if (it == m.end()) m[key] = v;
        float pristine = m[key];
        if (!f.captured) {
            // First live read ever: seed from the game.
            f.defVal = pristine; f.customVal = pristine; f.captured = true;
        }
        else {
            f.defVal = pristine; // refresh stock to current car
            if (!f.overrideActive) f.customVal = pristine; // unticked rows mirror live stock
        }
    };
    float v = 0;
    if (eng) {
        if (FastRead<float>(eng + 0x4C, v)) cap(g_PristineEngMaxTorque, eng, v, g_VehBaseMaxTorque);
        if (FastRead<float>(eng + 0x48, v)) cap(g_PristineEngMaxRPM, eng, v, g_VehBaseMaxRPM);
        if (FastRead<float>(eng + 0x40, v)) cap(g_PristineEngMinRPM, eng, v, g_VehBaseMinRPM);
        if (FastRead<float>(eng + 0x44, v)) cap(g_PristineEngOptRPM, eng, v, g_VehBaseOptRPM);
    }
    if (trans) {
        if (FastRead<float>(trans + 0x58, v)) cap(g_PristinePrimaryRatio, trans, v, g_VehBasePrimaryRatio);
    }
    if (pfx) {
        if (FastRead<float>(pfx + 0x2AC4, v)) cap(g_PristineTopSpeed, pfx, v, g_VehBaseTopSpeed);
        // Grip static config: capture BOTH axles (they can differ per car)
        uintptr_t frontProps = 0, rearProps = 0;
        FastRead<uintptr_t>(pfx + 0x1C20, frontProps);
        FastRead<uintptr_t>(pfx + 0x1C28, rearProps);
        bool gotFriction = false;
        if (frontProps && FastRead<float>(frontProps + 0x14, v)) {
            cap(g_PristineGripFriction, frontProps + 0x14, v, g_VehGripFriction);
            gotFriction = true;
        }
        if (rearProps && FastRead<float>(rearProps + 0x14, v)) {
            // store rear pristine under its own key; UI def shows front (or first seen)
            auto it = g_PristineGripFriction.find(rearProps + 0x14);
            if (it == g_PristineGripFriction.end()) g_PristineGripFriction[rearProps + 0x14] = v;
            gotFriction = true;
        }
        if (!gotFriction) {
            // Fallback: first live wheel m_WheelFrictionMultiplier (+0x17C)
            uintptr_t wData = 0; int wCount = 0;
            if (FastRead<uintptr_t>(pfx + 0x1BE0, wData) && wData &&
                FastRead<int>(pfx + 0x1BE0 + 0x8, wCount) && wCount > 0 &&
                FastRead<float>(wData + 0x17C, v))
                cap(g_PristineGripFriction, wData + 0x17C, v, g_VehGripFriction);
        }
        if (frontProps && FastRead<float>(frontProps + 0x1C, v))
            cap(g_PristineGripDownforce, frontProps + 0x1C, v, g_VehGripDownforce);
        if (rearProps && FastRead<float>(rearProps + 0x1C, v)) {
            auto it = g_PristineGripDownforce.find(rearProps + 0x1C);
            if (it == g_PristineGripDownforce.end()) g_PristineGripDownforce[rearProps + 0x1C] = v;
        }
        // Drift: SCustomLandGlobal.m_drift (custom+52, 84B SDrift)
        // +0 entry slip, +20 max torque (DENOMINATOR), +36 yaw damp
        uintptr_t custom = 0;
        if (FastRead<uintptr_t>(pfx + 0x2A78, custom) && custom) {
            if (FastRead<float>(custom + 52 + 20, v))
                cap(g_PristineDriftMaxTorque, custom + 72, v, g_VehDriftMaxTorque);
        }
    }
}
// Unticked rows mirror live stock; with no vehicle there is no stock, so show 0.
static void ZeroUntickedVehFields() {
    VehBaseField* fs[] = {
        &g_VehBaseMaxTorque, &g_VehBaseMaxRPM, &g_VehBaseMinRPM,
        &g_VehBaseOptRPM, &g_VehBaseTopSpeed, &g_VehBasePrimaryRatio,
        &g_VehGripFriction, &g_VehGripDownforce, &g_VehDriftMaxTorque
    };
    for (auto* f : fs) {
        if (f && !f->overrideActive) { f->customVal = 0.0f; f->defVal = 0.0f; }
    }
    g_VehLiveTorque = g_VehLiveRPM = g_VehLiveTransRPM = 0.0f;
}
// Per-frame enforcer. Call from hkPresent (render thread) when playerPtr != 0.
// STRICT RULE: only WRITES fields whose overrideActive is true. Everything else is READ-ONLY.
static void ApplyVehBaseTuning() {
    if (!g_ExeBase) return;
    uintptr_t veh = 0, pfx = 0, eng = 0, trans = 0;
    if (!GetRicoVehiclePhysics(veh, pfx, eng, trans) || !pfx) { ZeroUntickedVehFields(); return; }
    CaptureVehBaseDefaults(eng, trans, pfx);
    // Never write a value we have not actually read from the game yet.
    if (eng) {
        if (g_VehBaseMaxTorque.overrideActive && g_VehBaseMaxTorque.captured)      FastWrite<float>(eng + 0x4C, g_VehBaseMaxTorque.customVal);
        if (g_VehBaseMaxRPM.overrideActive && g_VehBaseMaxRPM.captured)         FastWrite<float>(eng + 0x48, g_VehBaseMaxRPM.customVal);
        if (g_VehBaseMinRPM.overrideActive && g_VehBaseMinRPM.captured)         FastWrite<float>(eng + 0x40, g_VehBaseMinRPM.customVal);
        if (g_VehBaseOptRPM.overrideActive && g_VehBaseOptRPM.captured)         FastWrite<float>(eng + 0x44, g_VehBaseOptRPM.customVal);
    }
    if (trans && g_VehBasePrimaryRatio.overrideActive && g_VehBasePrimaryRatio.captured) {
        float r = g_VehBasePrimaryRatio.customVal;
        if (r > 0.001f && r < 200.0f) FastWrite<float>(trans + 0x58, r);
    }
    if (pfx && g_VehBaseTopSpeed.overrideActive && g_VehBaseTopSpeed.captured) {
        float s = g_VehBaseTopSpeed.customVal;
        if (s > 1.0f && s < 20000.0f) FastWrite<float>(pfx + 0x2AC4, s);
    }
    // --- Base GRIP: static SLandWheel + live SWheelInfo + SDrift ---
    if (pfx && (g_VehGripFriction.overrideActive || g_VehGripDownforce.overrideActive || g_VehDriftMaxTorque.overrideActive)) {
        uintptr_t frontProps = 0, rearProps = 0, custom = 0;
        FastRead<uintptr_t>(pfx + 0x1C20, frontProps);
        FastRead<uintptr_t>(pfx + 0x1C28, rearProps);
        FastRead<uintptr_t>(pfx + 0x2A78, custom);
        if (g_VehGripFriction.overrideActive && g_VehGripFriction.captured) {
            float g = g_VehGripFriction.customVal;
            if (g < 0.01f) g = 0.01f; if (g > 50.0f) g = 50.0f;
            if (frontProps) FastWrite<float>(frontProps + 0x14, g);
            if (rearProps) FastWrite<float>(rearProps + 0x14, g);
            uintptr_t wData = 0; int wCount = 0;
            if (FastRead<uintptr_t>(pfx + 0x1BE0, wData) && wData &&
                FastRead<int>(pfx + 0x1BE0 + 0x8, wCount) && wCount > 0 && wCount <= 16) {
                for (int i = 0; i < wCount; i++)
                    FastWrite<float>(wData + (uintptr_t)i * 0x210 + 0x17C, g);
            }
        }
        if (g_VehGripDownforce.overrideActive && g_VehGripDownforce.captured) {
            float d = g_VehGripDownforce.customVal;
            if (d < 0.0f) d = 0.0f; if (d > 100.0f) d = 100.0f;
            if (frontProps) FastWrite<float>(frontProps + 0x1C, d);
            if (rearProps) FastWrite<float>(rearProps + 0x1C, d);
            uintptr_t wData = 0; int wCount = 0;
            if (FastRead<uintptr_t>(pfx + 0x1BE0, wData) && wData &&
                FastRead<int>(pfx + 0x1BE0 + 0x8, wCount) && wCount > 0 && wCount <= 16) {
                for (int i = 0; i < wCount; i++)
                    FastWrite<float>(wData + (uintptr_t)i * 0x210 + 0x18C, d);
            }
        }
        if (g_VehDriftMaxTorque.overrideActive && g_VehDriftMaxTorque.captured && custom) {
            float t = g_VehDriftMaxTorque.customVal;
            if (t < 1.0f) t = 1.0f; if (t > 100000000.0f) t = 100000000.0f;
            FastWrite<float>(custom + 52 + 20, t);
        }
    }
    // NOTE: we deliberately do NOT call CPfxCar::RecomputeTopSpeed() here.
    // It derives m_TopSpeedKmph from (maxRPM/primaryRatio)*radius, but it runs on the
    // physics thread during module changes and would race our write. Per-frame direct
    // write to m_TopSpeedKmph wins without a call, and changing maxRPM/ratio still
    // changes acceleration/gear behavior immediately because StepVehicle reads them live.
}
static void ResetVehBaseTuning() {
    uintptr_t veh = 0, pfx = 0, eng = 0, trans = 0;
    GetRicoVehiclePhysics(veh, pfx, eng, trans);
    // Prefer map pristine when present, else fall back to live-captured defVal.
    // defVal is refreshed to the CURRENT archetype on every UI tick via CaptureVehBaseDefaults,
    // so writing defVal is always correct even after switching cars (map may miss).
    if (eng) {
        auto rst = [](std::map<uintptr_t,float>& m, uintptr_t key, uintptr_t addr, float fallback) {
            auto it = m.find(key);
            if (it != m.end()) FastWrite<float>(addr, it->second);
            else FastWrite<float>(addr, fallback);
        };
        rst(g_PristineEngMaxTorque, eng, eng + 0x4C, g_VehBaseMaxTorque.defVal);
        rst(g_PristineEngMaxRPM, eng, eng + 0x48, g_VehBaseMaxRPM.defVal);
        rst(g_PristineEngMinRPM, eng, eng + 0x40, g_VehBaseMinRPM.defVal);
        rst(g_PristineEngOptRPM, eng, eng + 0x44, g_VehBaseOptRPM.defVal);
    }
    if (trans) {
        auto it = g_PristinePrimaryRatio.find(trans);
        FastWrite<float>(trans + 0x58, (it != g_PristinePrimaryRatio.end()) ? it->second : g_VehBasePrimaryRatio.defVal);
    }
    if (pfx) {
        auto it = g_PristineTopSpeed.find(pfx);
        FastWrite<float>(pfx + 0x2AC4, (it != g_PristineTopSpeed.end()) ? it->second : g_VehBaseTopSpeed.defVal);
        // Restore grip static (BOTH axles) + live wheels + drift from defVal (current archetype)
        uintptr_t frontProps = 0, rearProps = 0, custom = 0;
        FastRead<uintptr_t>(pfx + 0x1C20, frontProps);
        FastRead<uintptr_t>(pfx + 0x1C28, rearProps);
        FastRead<uintptr_t>(pfx + 0x2A78, custom);
        auto rstAddrDef = [](std::map<uintptr_t,float>& m, uintptr_t addrKey, float defFallback) {
            auto it2 = m.find(addrKey);
            FastWrite<float>(addrKey, (it2 != m.end()) ? it2->second : defFallback);
        };
        if (frontProps) {
            rstAddrDef(g_PristineGripFriction, frontProps + 0x14, g_VehGripFriction.defVal);
            rstAddrDef(g_PristineGripDownforce, frontProps + 0x1C, g_VehGripDownforce.defVal);
        }
        if (rearProps) {
            // Rear may share front's value on some cars; map lookup first, else front def.
            auto itR = g_PristineGripFriction.find(rearProps + 0x14);
            if (itR != g_PristineGripFriction.end()) FastWrite<float>(rearProps + 0x14, itR->second);
            else FastWrite<float>(rearProps + 0x14, g_VehGripFriction.defVal);
            auto itRD = g_PristineGripDownforce.find(rearProps + 0x1C);
            if (itRD != g_PristineGripDownforce.end()) FastWrite<float>(rearProps + 0x1C, itRD->second);
            else FastWrite<float>(rearProps + 0x1C, g_VehGripDownforce.defVal);
        }
        if (custom) {
            rstAddrDef(g_PristineDriftMaxTorque, custom + 72, g_VehDriftMaxTorque.defVal);
        }
        // Live wheels: restore each wheel from defVal (not stale heap addresses)
        uintptr_t wData = 0; int wCount = 0;
        if (FastRead<uintptr_t>(pfx + 0x1BE0, wData) && wData &&
            FastRead<int>(pfx + 0x1BE0 + 0x8, wCount) && wCount > 0 && wCount <= 16) {
            for (int i = 0; i < wCount; i++) {
                FastWrite<float>(wData + (uintptr_t)i * 0x210 + 0x17C, g_VehGripFriction.defVal);
                FastWrite<float>(wData + (uintptr_t)i * 0x210 + 0x18C, g_VehGripDownforce.defVal);
            }
        }
    }
    g_VehBaseMaxTorque.overrideActive = false;
    g_VehBaseMaxRPM.overrideActive = g_VehBaseMinRPM.overrideActive = g_VehBaseOptRPM.overrideActive = false;
    g_VehBaseTopSpeed.overrideActive = g_VehBasePrimaryRatio.overrideActive = false;
    g_VehGripFriction.overrideActive = g_VehGripDownforce.overrideActive = g_VehDriftMaxTorque.overrideActive = false;
    // Re-seed custom=def from LIVE so UI shows true current values (fixes stale UI after reset/car switch)
    if (eng) {
        float v = 0;
        if (FastRead<float>(eng + 0x4C, v)) { g_VehBaseMaxTorque.customVal = g_VehBaseMaxTorque.defVal = v; }
        if (FastRead<float>(eng + 0x48, v)) { g_VehBaseMaxRPM.customVal = g_VehBaseMaxRPM.defVal = v; }
        if (FastRead<float>(eng + 0x40, v)) { g_VehBaseMinRPM.customVal = g_VehBaseMinRPM.defVal = v; }
        if (FastRead<float>(eng + 0x44, v)) { g_VehBaseOptRPM.customVal = g_VehBaseOptRPM.defVal = v; }
    }
    float r = 0; if (trans && FastRead<float>(trans + 0x58, r)) { g_VehBasePrimaryRatio.customVal = g_VehBasePrimaryRatio.defVal = r; }
    float s = 0; if (pfx && FastRead<float>(pfx + 0x2AC4, s)) { g_VehBaseTopSpeed.customVal = g_VehBaseTopSpeed.defVal = s; }
    if (pfx) {
        uintptr_t fP = 0, c = 0; float v = 0;
        FastRead<uintptr_t>(pfx + 0x1C20, fP);
        FastRead<uintptr_t>(pfx + 0x2A78, c);
        if (fP && FastRead<float>(fP + 0x14, v)) { g_VehGripFriction.customVal = g_VehGripFriction.defVal = v; }
        else {
            uintptr_t wD = 0; int wC = 0;
            if (FastRead<uintptr_t>(pfx + 0x1BE0, wD) && wD && FastRead<int>(pfx + 0x1BE0 + 0x8, wC) && wC > 0 && FastRead<float>(wD + 0x17C, v))
                { g_VehGripFriction.customVal = g_VehGripFriction.defVal = v; }
        }
        if (fP && FastRead<float>(fP + 0x1C, v)) { g_VehGripDownforce.customVal = g_VehGripDownforce.defVal = v; }
        if (c && FastRead<float>(c + 72, v)) { g_VehDriftMaxTorque.customVal = g_VehDriftMaxTorque.defVal = v; }
    }
}

// Oxygen Supply Toggles & Real-time Tracking
float g_OxygenValue = 100.0f;
bool g_LockOxygen = false;
DWORD g_LastOxygenReadTime = 0;

// Health Toggles & Real-time Tracking
int g_HealthValue = 800;
int g_MaxHealthValue = 800;
bool g_LockHealth = false;
DWORD g_LastHealthReadTime = 0;

// Desired FOV in degrees (used only while g_OverrideFOV is on; 60 = vanilla stock)
int g_DesiredFOV = 60;
// FOV override state. The bump is always derived from live reads (anchor captured on
// enable, base re-tracked on transitions) — no FOV value is hardcoded.
bool g_OverrideFOV = false;
bool g_FovWorldSettled = false; // mirrors canApplyToggles: world ready + warmup done
float g_FovAnchorBase = 0.0f; // live game base (rad) captured by the detour on enable
bool g_FovNeedAnchor = true;  // request detour to (re)capture anchor + reset tracking

// Custom Ocean Wave Overrides
float g_CustomWaveAmplitude = -1.0f; // -1.0f means inactive (use game default)
float g_CustomWindSpeed = -1.0f;
float g_CustomChoppyScale = -1.0f;
float g_CustomSmallWaveFraction = -1.0f;

// Live Parameter Diagnostic Tracking
uintptr_t g_ActiveNvWaveWorkSimulation = 0;
float g_LiveWaveAmplitude = 0.0f;
float g_LiveWindSpeed = 0.0f;
float g_LiveChoppyScale = 0.0f;
float g_LiveSmallWaveFraction = 0.0f;
bool g_ForceWaveWorksUpdate = false;

// Custom Game Speed Override (literal game speed via CSlowMotionManager)
float g_CustomGameSpeed = -1.0f; // -1.0f means inactive (use game default)
float g_LiveGameSpeed = 1.0f;

typedef void(__thiscall* UpdateSimulationProperties_t)(uintptr_t thisptr, uintptr_t param_1, uintptr_t param_2, bool param_3);
UpdateSimulationProperties_t o_UpdateSimulationProperties = nullptr;

void hk_UpdateSimulationProperties(uintptr_t thisptr, uintptr_t param_1, uintptr_t param_2, bool param_3) {
    g_ActiveNvWaveWorkSimulation = thisptr;
    o_UpdateSimulationProperties(thisptr, param_1, param_2, param_3);
}

typedef void(__thiscall* SetMagazineAmmo_t)(uintptr_t thisptr, int ammo);

uintptr_t GetWingsuitWeaponPtr(); // defined later: resolves Rico's wingsuit CWeapon* (0 when unavailable)

// True when this firing module belongs to the wingsuit missile system (same owner
// comparison the missile filter uses). Exempts wingsuit missiles from infinite ammo:
// with full-auto holding fire, a never-empty mag would fire forever from a single click.
static bool IsWingsuitFiringModule(uintptr_t module) {
    if (!module) return false;
    uintptr_t owner = 0; // CFiringModule::m_Owner (CWeapon*) at +0x310 (PDB layout + disasm agree)
    if (!FastRead<uintptr_t>(module + 0x310, owner) || !owner) return false;
    uintptr_t wingsuitWeapon = GetWingsuitWeaponPtr();
    return wingsuitWeapon && (owner == wingsuitWeapon);
}
SetMagazineAmmo_t o_SetMagazineAmmo = nullptr;

void hk_SetMagazineAmmo(uintptr_t thisptr, int ammo) {
    if (g_InfWeaponAmmo && !IsWingsuitFiringModule(thisptr)) {
        ammo = 999;
    }
    o_SetMagazineAmmo(thisptr, ammo);
}

// Subclass overrides the base hook misses (virtual dispatch bypasses 0x761BE0):
// CFiringModulePinner::SetMagazineAmmo (0x761C30) and CFiringModuleRPG::SetMagazineAmmo (0x761CE0).
// Same 999 logic, each calling its own original so the rocket/projectile visuals keep working.
SetMagazineAmmo_t o_SetMagazineAmmoPinner = nullptr;
SetMagazineAmmo_t o_SetMagazineAmmoRPG = nullptr;

void hk_SetMagazineAmmoPinner(uintptr_t thisptr, int ammo) {
    if (g_InfWeaponAmmo && !IsWingsuitFiringModule(thisptr)) {
        ammo = 999;
    }
    o_SetMagazineAmmoPinner(thisptr, ammo);
}

void hk_SetMagazineAmmoRPG(uintptr_t thisptr, int ammo) {
    if (g_InfWeaponAmmo && !IsWingsuitFiringModule(thisptr)) {
        ammo = 999;
    }
    o_SetMagazineAmmoRPG(thisptr, ammo);
}

typedef int(*UpdateProperties_t)(uintptr_t sim, uintptr_t settings, uintptr_t params);
UpdateProperties_t o_UpdateProperties = nullptr;

int hk_UpdateProperties(uintptr_t sim, uintptr_t settings, uintptr_t params) {
    if (params) {
        // Intercepting WaveWorks parameter block before it is processed by the engine
        // Offset 0x00: wave_amplitude (float)
        // Offset 0x0C: wind_speed (float)
        // Offset 0x14: choppy_scale (float)
        // Offset 0x18: small_wave_fraction (float)
        if (g_CustomWaveAmplitude >= 0.0f) {
            *reinterpret_cast<float*>(params + 0x00) = g_CustomWaveAmplitude;
        }
        if (g_CustomWindSpeed >= 0.0f) {
            *reinterpret_cast<float*>(params + 0x0C) = g_CustomWindSpeed;
        }
        if (g_CustomChoppyScale >= 0.0f) {
            *reinterpret_cast<float*>(params + 0x14) = g_CustomChoppyScale;
        }
        if (g_CustomSmallWaveFraction >= 0.0f) {
            *reinterpret_cast<float*>(params + 0x18) = g_CustomSmallWaveFraction;
        }
    }
    return o_UpdateProperties(sim, settings, params);
}
bool g_DisableOcean = false;
bool g_ShowSpeedometer = false;
bool g_SpeedoReplaceGameHUD = false; // TrueKMH: feed real speed into stock HUD dials.
bool g_ShowHeatStatus = false;
bool g_AlwaysShowHeatStatus = false; // Disabled by default, not saved to .ini
bool g_HideUI = false;
void ApplyHideUI(bool enable);

// ============================================================================
// HUD RESIZE MODE STATE & PERSISTED LAYOUT
// ============================================================================
enum ResizeTarget { RESIZE_NONE = 0, RESIZE_SPEEDOMETER, RESIZE_HEAT, RESIZE_VEHICLE_ESP };
static ResizeTarget g_ResizeMode = RESIZE_NONE;

// Speedometer layout (-1.0f = use default right-bottom anchor)
static float g_SpeedoPosX   = -1.0f;
static float g_SpeedoPosY   = -1.0f;
static float g_SpeedoWidth  = 210.0f;
static float g_SpeedoHeight = 68.0f;

// Heat Status layout
static float g_HeatOffsetX  = 505.0f;
static float g_HeatOffsetY  = 55.0f;
static float g_HeatScale    = 1.0f;

// Vehicle ESP diagnostic panel layout
static float g_VehicleESPPanelX = 10.0f;
static float g_VehicleESPPanelY = 10.0f;
static float g_VehicleESPPanelW = 670.0f;
static float g_VehicleESPPanelH = 280.0f;

// Dragging / Resizing runtime tracking
static bool  g_ResizeDragging = false;
static bool  g_ResizeResizing = false;
static float g_ResizeDragOffX = 0.0f;
static float g_ResizeDragOffY = 0.0f;

// Cached screen bounding boxes for resize handles
static float s_SpeedoBounds[4] = { 0 }; // x1, y1, x2, y2
static float s_HeatBounds[4]   = { 0 }; // x1, y1, x2, y2

extern float g_UIScale;
bool WriteConfig();

// Reference resolution tracking for DPI & resolution adaptation
static float g_HUDRefW = 0.0f;
static float g_HUDRefH = 0.0f;
static float s_LastDisplayW = 0.0f;
static float s_LastDisplayH = 0.0f;
static bool  g_ConfigNeedsRefResSave = false;

static void UpdateHUDResolutionScaling() {
    ImGuiIO& io = ImGui::GetIO();
    float curW = io.DisplaySize.x;
    float curH = io.DisplaySize.y;
    if (curW <= 100.0f || curH <= 100.0f) return;

    // 1. Initial adaptation from saved config reference resolution
    if (s_LastDisplayW <= 0.0f || s_LastDisplayH <= 0.0f) {
        if (g_HUDRefW > 100.0f && g_HUDRefH > 100.0f &&
            (fabsf(curW - g_HUDRefW) > 1.0f || fabsf(curH - g_HUDRefH) > 1.0f)) {
            float initScaleX = curW / g_HUDRefW;
            float initScaleY = curH / g_HUDRefH;
            if (g_SpeedoPosX >= 0.0f) g_SpeedoPosX *= initScaleX;
            if (g_SpeedoPosY >= 0.0f) g_SpeedoPosY *= initScaleY;
            g_SpeedoWidth      *= initScaleX;
            g_SpeedoHeight     *= initScaleY;
            g_VehicleESPPanelX *= initScaleX;
            g_VehicleESPPanelY *= initScaleY;
            g_VehicleESPPanelW *= initScaleX;
            g_VehicleESPPanelH *= initScaleY;
            g_HeatOffsetX      *= initScaleX;
            g_HeatOffsetY      *= initScaleY;
            g_HeatScale        *= initScaleY;
        }
        s_LastDisplayW = curW;
        s_LastDisplayH = curH;
        g_HUDRefW = curW;
        g_HUDRefH = curH;

        if (g_ConfigNeedsRefResSave) {
            WriteConfig();
            g_ConfigNeedsRefResSave = false;
        }
        return;
    }

    // 2. Dynamic adaptation when resolution or display size changes mid-game
    if (fabsf(curW - s_LastDisplayW) > 1.0f || fabsf(curH - s_LastDisplayH) > 1.0f) {
        float scaleX = curW / s_LastDisplayW;
        float scaleY = curH / s_LastDisplayH;

        if (g_SpeedoPosX >= 0.0f) g_SpeedoPosX *= scaleX;
        if (g_SpeedoPosY >= 0.0f) g_SpeedoPosY *= scaleY;
        g_SpeedoWidth      *= scaleX;
        g_SpeedoHeight     *= scaleY;
        g_VehicleESPPanelX *= scaleX;
        g_VehicleESPPanelY *= scaleY;
        g_VehicleESPPanelW *= scaleX;
        g_VehicleESPPanelH *= scaleY;
        g_HeatOffsetX      *= scaleX;
        g_HeatOffsetY      *= scaleY;
        g_HeatScale        *= scaleY;

        s_LastDisplayW = curW;
        s_LastDisplayH = curH;
        g_HUDRefW = curW;
        g_HUDRefH = curH;
    }

    // 3. Safety clamps: prevent HUD elements from drifting outside screen boundaries
    float sW = g_SpeedoWidth * g_UIScale;
    float sH = g_SpeedoHeight * g_UIScale;
    if (g_SpeedoPosX >= 0.0f) {
        if (g_SpeedoPosX > curW - sW) g_SpeedoPosX = (curW > sW) ? (curW - sW) : 0.0f;
        if (g_SpeedoPosX < 0.0f) g_SpeedoPosX = 0.0f;
    }
    if (g_SpeedoPosY >= 0.0f) {
        if (g_SpeedoPosY > curH - sH) g_SpeedoPosY = (curH > sH) ? (curH - sH) : 0.0f;
        if (g_SpeedoPosY < 0.0f) g_SpeedoPosY = 0.0f;
    }

    if (g_VehicleESPPanelX > curW - g_VehicleESPPanelW)
        g_VehicleESPPanelX = (curW > g_VehicleESPPanelW) ? (curW - g_VehicleESPPanelW) : 0.0f;
    if (g_VehicleESPPanelX < 0.0f) g_VehicleESPPanelX = 0.0f;
    if (g_VehicleESPPanelY > curH - g_VehicleESPPanelH)
        g_VehicleESPPanelY = (curH > g_VehicleESPPanelH) ? (curH - g_VehicleESPPanelH) : 0.0f;
    if (g_VehicleESPPanelY < 0.0f) g_VehicleESPPanelY = 0.0f;
}

// ============================================================================
// REAL GLOBAL SPEEDOMETER HUD (Bottom-Right Overlay)
// ============================================================================
extern uintptr_t g_ExeBase;
extern HWND g_HWnd;
extern float g_UIScale;
static uintptr_t GetPlayerPtr();

static float g_DisplayedSpeedMS = 0.0f;
static DWORD g_LastSpeedDisplayTime = 0;

void DrawSpeedometerHUD() {
    if (!g_ShowSpeedometer || !g_ExeBase || !g_HWnd) return;

    DWORD now = GetTickCount();
    uintptr_t playerPtr = GetPlayerPtr();
    float currentSpeedMS = 0.0f;

    if (playerPtr) {
        uintptr_t characterPtr = 0;
        if (FastRead<uintptr_t>(playerPtr + 0x68, characterPtr) && characterPtr) {
            // 1. Primary: Read Avalanche's native measured world speed (+0x29CC)
            FastRead<float>(characterPtr + 0x29CC, currentSpeedMS);

            // 2. Fallback: If 0, compute magnitude from measured world velocity (+0x29C0)
            if (currentSpeedMS <= 0.0f) {
                float vx = 0.0f, vy = 0.0f, vz = 0.0f;
                if (FastRead<float>(characterPtr + 0x29C0, vx) &&
                    FastRead<float>(characterPtr + 0x29C4, vy) &&
                    FastRead<float>(characterPtr + 0x29C8, vz)) {
                    currentSpeedMS = std::sqrt(vx * vx + vy * vy + vz * vz);
                }
            }

            // 3. Fallback: Havok cached linear velocity (+0xD0)
            if (currentSpeedMS <= 0.0f) {
                uintptr_t pfxInstance = 0;
                if (FastRead<uintptr_t>(characterPtr + 0x2208, pfxInstance) && pfxInstance) {
                    float vx = 0.0f, vy = 0.0f, vz = 0.0f;
                    if (FastRead<float>(pfxInstance + 0xD0, vx) &&
                        FastRead<float>(pfxInstance + 0xD4, vy) &&
                        FastRead<float>(pfxInstance + 0xD8, vz)) {
                        currentSpeedMS = std::sqrt(vx * vx + vy * vy + vz * vz);
                    }
                }
            }
        }
    }

    // Refresh UI display text every 0.25s (250ms) for clean reading without flicker
    if (now - g_LastSpeedDisplayTime >= 250) {
        g_DisplayedSpeedMS = currentSpeedMS;
        g_LastSpeedDisplayTime = now;
    }

    // --- RENDER HUD (Position & Height) ---
    ImGuiIO& io = ImGui::GetIO();
    float screenW = io.DisplaySize.x;
    float screenH = io.DisplaySize.y;
    if (screenW <= 100.0f || screenH <= 100.0f) return;

    float boxW = g_SpeedoWidth * g_UIScale;
    float boxH = g_SpeedoHeight * g_UIScale;
    float posX, posY;

    if (g_SpeedoPosX >= 0.0f) {
        posX = g_SpeedoPosX;
        posY = g_SpeedoPosY;
    } else {
        posX = screenW - boxW - (20.0f * g_UIScale);
        posY = screenH - boxH - (380.0f * g_UIScale);
    }

    if (posX > screenW - boxW) posX = (screenW > boxW) ? (screenW - boxW) : 0.0f;
    if (posX < 0.0f) posX = 0.0f;
    if (posY > screenH - boxH) posY = (screenH > boxH) ? (screenH - boxH) : 0.0f;
    if (posY < 0.0f) posY = 0.0f;

    // Cache bounds for resize mode
    s_SpeedoBounds[0] = posX;
    s_SpeedoBounds[1] = posY;
    s_SpeedoBounds[2] = posX + boxW;
    s_SpeedoBounds[3] = posY + boxH;

    ImDrawList* dl = ImGui::GetForegroundDrawList();

    // Dark sleek background panel with JC4 turquoise accent
    dl->AddRectFilled(ImVec2(posX, posY), ImVec2(posX + boxW, posY + boxH), IM_COL32(12, 16, 22, 210), 8.0f * g_UIScale);
    dl->AddRect(ImVec2(posX, posY), ImVec2(posX + boxW, posY + boxH), IM_COL32(0, 210, 220, 180), 8.0f * g_UIScale, 0, 1.5f);

    ImFont* font = ImGui::GetFont();

    // Scale text based on BOTH width and height so it never exceeds the box
    float scaleW = boxW / (210.0f * g_UIScale);
    float scaleH = boxH / (68.0f * g_UIScale);
    float fontScale = (scaleW < scaleH) ? scaleW : scaleH;
    if (fontScale < 0.2f) fontScale = 0.2f;
    if (fontScale > 6.0f) fontScale = 6.0f;

    float padX = 12.0f * g_UIScale * fontScale;
    float fontSizeTitle = 11.0f * g_UIScale * fontScale;
    float fontSizeMain  = 20.0f * g_UIScale * fontScale;
    float fontSizeSub   = 13.0f * g_UIScale * fontScale;

    // Distribute spacing vertically inside whatever height the user selected
    float totalTextH = fontSizeTitle + fontSizeMain + fontSizeSub;
    float gapY = (boxH - totalTextH) / 4.0f;
    if (gapY < 2.0f) gapY = 2.0f;

    float yTitle = posY + gapY;
    float yMain  = yTitle + fontSizeTitle + gapY;
    float ySub   = yMain + fontSizeMain + gapY;

    float speedMS = g_DisplayedSpeedMS;
    float speedKMH = speedMS * 3.6f;
    float speedKMS = speedMS / 1000.0f;

    char bufMain[64];
    char bufSub[64];
    snprintf(bufMain, sizeof(bufMain), "%.1f m/s", speedMS);
    snprintf(bufSub, sizeof(bufSub), "%.1f km/h  (%.2f km/s)", speedKMH, speedKMS);

    // Hardware-accelerated clip rect so text is strictly prevented from bleeding out
    dl->PushClipRect(ImVec2(posX, posY), ImVec2(posX + boxW, posY + boxH), true);

    dl->AddText(font, fontSizeTitle, ImVec2(posX + padX, yTitle), IM_COL32(0, 225, 235, 255), "REAL GLOBAL SPEED");
    dl->AddText(font, fontSizeMain,  ImVec2(posX + padX, yMain),  IM_COL32(255, 255, 255, 255), bufMain);
    dl->AddText(font, fontSizeSub,   ImVec2(posX + padX, ySub),   IM_COL32(160, 230, 240, 220), bufSub);

    dl->PopClipRect();
}

// ============================================================================
// TrueKMH - Feed REAL global speed into the stock vehicle HUD dials
// ----------------------------------------------------------------------------
// Stock CUISpeedometerController::Update (RVA 0xEB4D00) derives its number
// from CVehicle::GetSpeedDialSpeedMs (wheel/transmission RPM or forward
// projection) then *3.6 (cars) / *1.94384 (boats) + needle smoothing.
// That reads low when drifting, sliding, airborne or wheel-spinning.
// This hook runs the original Update, then overwrites m_CurrentSpeed (+0x30)
// and m_CurrentNeedleSpeed (+0x2C) with our true speed in the same unit
// the game chose (+0x28): knots for boats, km/h otherwise.
// Gated by g_SpeedoReplaceGameHUD; installed once at startup.
// ============================================================================
static float ReadTrueSpeedMS_ForHUD() {
    float ms = 0.0f;
    uintptr_t playerPtr = GetPlayerPtr();
    if (!playerPtr || !g_ExeBase) return 0.0f;
    uintptr_t characterPtr = 0;
    if (!FastRead<uintptr_t>(playerPtr + 0x68, characterPtr) || !characterPtr) return 0.0f;
    // 1. Primary: Avalanche native measured world speed (+0x29CC)
    FastRead<float>(characterPtr + 0x29CC, ms);
    // 2. Fallback: magnitude of measured world velocity (+0x29C0)
    if (ms <= 0.0f) {
        float vx = 0.0f, vy = 0.0f, vz = 0.0f;
        if (FastRead<float>(characterPtr + 0x29C0, vx) &&
            FastRead<float>(characterPtr + 0x29C4, vy) &&
            FastRead<float>(characterPtr + 0x29C8, vz)) {
            ms = std::sqrt(vx * vx + vy * vy + vz * vz);
        }
    }
    // 3. Fallback: Havok cached linear velocity (+0xD0)
    if (ms <= 0.0f) {
        uintptr_t pfxInstance = 0;
        if (FastRead<uintptr_t>(characterPtr + 0x2208, pfxInstance) && pfxInstance) {
            float vx = 0.0f, vy = 0.0f, vz = 0.0f;
            if (FastRead<float>(pfxInstance + 0xD0, vx) &&
                FastRead<float>(pfxInstance + 0xD4, vy) &&
                FastRead<float>(pfxInstance + 0xD8, vz)) {
                ms = std::sqrt(vx * vx + vy * vy + vz * vz);
            }
        }
    }
    return ms;
}

typedef void(__fastcall* CUISpeedoUpdate_t)(uintptr_t thisptr, float p1, float p2);
static CUISpeedoUpdate_t o_SpeedoUpdate = nullptr;

void __fastcall hk_SpeedoUpdate(uintptr_t thisptr, float p1, float p2) {
    if (o_SpeedoUpdate) o_SpeedoUpdate(thisptr, p1, p2);
    if (!g_SpeedoReplaceGameHUD || !thisptr) return;
    int unit = 1;
    FastRead<int>(thisptr + 0x28, unit);
    float trueMS = ReadTrueSpeedMS_ForHUD();
    // m_CurrentSpeed (+0x30) + needle (+0x2C) in the game's own unit:
    // knots for boats, km/h for everything else. Unit (+0x28) left alone.
    float v = (unit == 0) ? (trueMS * 1.9438444f) : (trueMS * 3.6f);
    FastWrite<float>(thisptr + 0x30, v);
    FastWrite<float>(thisptr + 0x2C, v);
}

// ============================================================================
// REAL-TIME IN-GAME HEAT STATUS HUD (Low-CPU Throttled Text HUD)
// ============================================================================
void DrawHeatStatusHUD() {
    if (!g_ShowHeatStatus || !g_ExeBase || !g_HWnd) return;

    // Static cache: Preserves state between frames without repeating syscalls
    static int32_t  s_HeatStatus = 0;
    static uint32_t s_HeatLevel = 0;
    static uint32_t s_ThreatScore = 0;
    static DWORD    s_LastPollTime = 0;

    static char   s_LvlBuf[32] = "LVL 0";
    static char   s_PtsBuf[32] = "0 PTS";
    static ImVec2 s_LvlSz = ImVec2(0.0f, 0.0f);
    static ImVec2 s_PtsSz = ImVec2(0.0f, 0.0f);

    DWORD now = GetTickCount();

    // CPU THROTTLE: Read memory & calculate text bounds only every 100ms (10 Hz)
    if (now - s_LastPollTime >= 100) {
        s_LastPollTime = now;

        uintptr_t heatManager = 0;
        if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D38, heatManager) && heatManager) {
            FastRead<int32_t>(heatManager + 0x00, s_HeatStatus);
            FastRead<uint32_t>(heatManager + 0x04, s_HeatLevel);
            FastRead<uint32_t>(heatManager + 0x28, s_ThreatScore);

            snprintf(s_LvlBuf, sizeof(s_LvlBuf), "LVL %u", s_HeatLevel);
            snprintf(s_PtsBuf, sizeof(s_PtsBuf), "%u PTS", s_ThreatScore);

            ImFont* font = ImGui::GetFont();
            if (font) {
                float fontSzLvl = 22.0f * g_UIScale;
                float fontSzPts = 13.0f * g_UIScale;
                s_LvlSz = font->CalcTextSizeA(fontSzLvl, FLT_MAX, 0.0f, s_LvlBuf);
                s_PtsSz = font->CalcTextSizeA(fontSzPts, FLT_MAX, 0.0f, s_PtsBuf);
            }
        }
    }

    // Visibility filter: If "Always show" is disabled, hide completely when calm (unless in resize mode)
    bool hasHeat = (s_HeatLevel >= 1);
    if (!g_AlwaysShowHeatStatus && !hasHeat && g_ResizeMode != RESIZE_HEAT) return;

    ImGuiIO& io = ImGui::GetIO();
    float screenW = io.DisplaySize.x;
    float screenH = io.DisplaySize.y;
    if (screenW <= 100.0f || screenH <= 100.0f) return;

    // ========================================================================
    // POSITIONING CONTROLS:
    // ========================================================================
    float hudOffsetX = g_HeatOffsetX;
    float hudOffsetY = g_HeatOffsetY;

    float centerX = screenW - (hudOffsetX * g_UIScale);
    float centerY = hudOffsetY * g_UIScale;
    if (centerY < 10.0f * g_UIScale) centerY = 10.0f * g_UIScale;
    if (centerY > screenH - (60.0f * g_UIScale)) centerY = screenH - (60.0f * g_UIScale);

    ImDrawList* dl = ImGui::GetForegroundDrawList();

    // Dynamic alert color matching current heat level
    ImU32 heatCol;
    float pulse = 0.0f;

    switch (s_HeatLevel) {
        case 0:
            heatCol = IM_COL32(140, 160, 180, 255); // Slate Gray (Calm)
            break;
        case 1:
            heatCol = IM_COL32(90, 235, 130, 255);  // Bright Green
            break;
        case 2:
            heatCol = IM_COL32(255, 215, 50, 255);  // Alert Yellow
            break;
        case 3:
            heatCol = IM_COL32(255, 140, 30, 255);  // Vibrant Orange
            break;
        case 4:
            heatCol = IM_COL32(255, 50, 50, 255);   // Vivid Red
            break;
        case 5:
        default:
            pulse = (sinf((float)ImGui::GetTime() * 9.0f) + 1.0f) * 0.5f;
            heatCol = IM_COL32(255, (int)(40 * pulse), (int)(40 * pulse), 255); // Pulsing Crimson
            break;
    }

    ImFont* font = ImGui::GetFont();
    float fontSizeLevel  = 22.0f * g_UIScale * g_HeatScale;
    float fontSizePoints = 13.0f * g_UIScale * g_HeatScale;

    // Recalculate text size using live scale
    if (font) {
        s_LvlSz = font->CalcTextSizeA(fontSizeLevel, FLT_MAX, 0.0f, s_LvlBuf);
        s_PtsSz = font->CalcTextSizeA(fontSizePoints, FLT_MAX, 0.0f, s_PtsBuf);
    }

    float lineWidth = (s_LvlSz.x > s_PtsSz.x ? s_LvlSz.x : s_PtsSz.x) + (16.0f * g_UIScale * g_HeatScale);
    if (lineWidth < 52.0f * g_UIScale * g_HeatScale) lineWidth = 52.0f * g_UIScale * g_HeatScale;

    float lvlX = centerX - (s_LvlSz.x * 0.5f);
    float lvlY = centerY;

    float lineY  = lvlY + s_LvlSz.y + (2.0f * g_UIScale * g_HeatScale);
    float lineX1 = centerX - (lineWidth * 0.5f);
    float lineX2 = centerX + (lineWidth * 0.5f);

    float ptsX = centerX - (s_PtsSz.x * 0.5f);
    float ptsY = lineY + (4.0f * g_UIScale * g_HeatScale);

    // Subtle dark translucent backing plate
    float padX = 8.0f * g_UIScale * g_HeatScale;
    float padY = 5.0f * g_UIScale * g_HeatScale;
    float bgX1 = lineX1 - padX;
    float bgX2 = lineX2 + padX;
    float bgY1 = lvlY - padY;
    float bgY2 = ptsY + s_PtsSz.y + padY;

    // Cache bounds for resize mode
    s_HeatBounds[0] = bgX1;
    s_HeatBounds[1] = bgY1;
    s_HeatBounds[2] = bgX2;
    s_HeatBounds[3] = bgY2;

    dl->AddRectFilled(ImVec2(bgX1, bgY1), ImVec2(bgX2, bgY2), IM_COL32(8, 10, 14, 185), 5.0f * g_UIScale);
    ImU32 borderCol = (heatCol & 0x00FFFFFF) | ((s_HeatLevel >= 4) ? 0x80000000 : 0x40000000);
    dl->AddRect(ImVec2(bgX1, bgY1), ImVec2(bgX2, bgY2), borderCol, 5.0f * g_UIScale, 0, 1.2f);

    // 8-way high-contrast outline rendering
    auto DrawOutlinedText = [&](float x, float y, float size, ImU32 col, const char* str) {
        float d = 1.6f * g_UIScale * g_HeatScale;
        dl->AddText(font, size, ImVec2(x - d, y),     IM_COL32(0, 0, 0, 255), str);
        dl->AddText(font, size, ImVec2(x + d, y),     IM_COL32(0, 0, 0, 255), str);
        dl->AddText(font, size, ImVec2(x, y - d),     IM_COL32(0, 0, 0, 255), str);
        dl->AddText(font, size, ImVec2(x, y + d),     IM_COL32(0, 0, 0, 255), str);
        dl->AddText(font, size, ImVec2(x - d, y - d), IM_COL32(0, 0, 0, 255), str);
        dl->AddText(font, size, ImVec2(x + d, y - d), IM_COL32(0, 0, 0, 255), str);
        dl->AddText(font, size, ImVec2(x - d, y + d), IM_COL32(0, 0, 0, 255), str);
        dl->AddText(font, size, ImVec2(x + d, y + d), IM_COL32(0, 0, 0, 255), str);
        dl->AddText(font, size, ImVec2(x, y), col, str);
    };

    // 1. "LVL <num>"
    DrawOutlinedText(lvlX, lvlY, fontSizeLevel, heatCol, s_LvlBuf);

    // 2. Separator line
    dl->AddLine(ImVec2(lineX1, lineY), ImVec2(lineX2, lineY), IM_COL32(0, 0, 0, 255), 3.8f * g_UIScale);
    dl->AddLine(ImVec2(lineX1, lineY), ImVec2(lineX2, lineY), heatCol, 1.8f * g_UIScale);

    // 3. "<points> PTS"
    DrawOutlinedText(ptsX, ptsY, fontSizePoints, heatCol, s_PtsBuf);
}
// Forward declaration of WriteConfig
bool WriteConfig();

void UpdateResizeMode() {
    if (g_ResizeMode == RESIZE_NONE || !g_HWnd) return;

    ImGuiIO& io = ImGui::GetIO();
    float screenW = io.DisplaySize.x;
    float screenH = io.DisplaySize.y;
    if (screenW <= 100.0f || screenH <= 100.0f) return;

    float* targetX1 = nullptr;
    float* targetY1 = nullptr;
    float* targetX2 = nullptr;
    float* targetY2 = nullptr;
    const char* targetName = "";

    float tempBounds[4] = { 0 };

    if (g_ResizeMode == RESIZE_SPEEDOMETER) {
        targetName = "Speedometer HUD";
        if (g_SpeedoPosX < 0.0f) {
            g_SpeedoPosX = s_SpeedoBounds[0];
            g_SpeedoPosY = s_SpeedoBounds[1];
        }
        targetX1 = &s_SpeedoBounds[0];
        targetY1 = &s_SpeedoBounds[1];
        targetX2 = &s_SpeedoBounds[2];
        targetY2 = &s_SpeedoBounds[3];
    }
    else if (g_ResizeMode == RESIZE_HEAT) {
        targetName = "Heat Status HUD";
        targetX1 = &s_HeatBounds[0];
        targetY1 = &s_HeatBounds[1];
        targetX2 = &s_HeatBounds[2];
        targetY2 = &s_HeatBounds[3];
    }
    else if (g_ResizeMode == RESIZE_VEHICLE_ESP) {
        targetName = "Vehicle ESP Diagnostic Panel";
        tempBounds[0] = g_VehicleESPPanelX;
        tempBounds[1] = g_VehicleESPPanelY;
        tempBounds[2] = g_VehicleESPPanelX + g_VehicleESPPanelW;
        tempBounds[3] = g_VehicleESPPanelY + g_VehicleESPPanelH;
        targetX1 = &tempBounds[0];
        targetY1 = &tempBounds[1];
        targetX2 = &tempBounds[2];
        targetY2 = &tempBounds[3];
    }

    if (!targetX1) return;

    float x1 = *targetX1, y1 = *targetY1, x2 = *targetX2, y2 = *targetY2;
    float handleSize = 18.0f * g_UIScale;

    ImVec2 mouse = io.MousePos;
    bool isMouseDown = io.MouseDown[0];
    bool isMouseClicked = io.MouseClicked[0];

    bool inCorner = (mouse.x >= x2 - handleSize && mouse.x <= x2 + 4.0f &&
                     mouse.y >= y2 - handleSize && mouse.y <= y2 + 4.0f);
    bool inBox = (mouse.x >= x1 && mouse.x <= x2 && mouse.y >= y1 && mouse.y <= y2);

    if (inCorner) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNWSE);
    } else if (inBox) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeAll);
    }

    if (isMouseClicked) {
        if (inCorner) {
            g_ResizeResizing = true;
            g_ResizeDragging = false;
        } else if (inBox) {
            g_ResizeDragging = true;
            g_ResizeResizing = false;
            g_ResizeDragOffX = mouse.x - x1;
            g_ResizeDragOffY = mouse.y - y1;
        }
    }

    if (!isMouseDown) {
        g_ResizeDragging = false;
        g_ResizeResizing = false;
    }

    // --- Process Drag Movement ---
    if (g_ResizeDragging) {
        float newX = mouse.x - g_ResizeDragOffX;
        float newY = mouse.y - g_ResizeDragOffY;

        if (g_ResizeMode == RESIZE_SPEEDOMETER) {
            g_SpeedoPosX = newX;
            g_SpeedoPosY = newY;
        } else if (g_ResizeMode == RESIZE_HEAT) {
            float curW = x2 - x1;
            float newCenterX = newX + (curW * 0.5f);
            g_HeatOffsetX = (screenW - newCenterX) / g_UIScale;
            g_HeatOffsetY = (newY + (5.0f * g_UIScale * g_HeatScale)) / g_UIScale;
        } else if (g_ResizeMode == RESIZE_VEHICLE_ESP) {
            g_VehicleESPPanelX = newX;
            g_VehicleESPPanelY = newY;
        }
    }

    // --- Process Corner Resize ---
    if (g_ResizeResizing) {
        if (g_ResizeMode == RESIZE_SPEEDOMETER) {
            float newW = (mouse.x - x1) / g_UIScale;
            float newH = (mouse.y - y1) / g_UIScale;
            if (newW >= 140.0f) g_SpeedoWidth  = newW;
            if (newH >= 45.0f)  g_SpeedoHeight = newH;
        } else if (g_ResizeMode == RESIZE_HEAT) {
            float curH = mouse.y - y1;
            float baseH = 50.0f * g_UIScale; // Reference height at 1.0 scale
            float newScale = curH / baseH;
            if (newScale >= 0.45f && newScale <= 3.0f) {
                g_HeatScale = newScale;
            }
        } else if (g_ResizeMode == RESIZE_VEHICLE_ESP) {
            float newW = mouse.x - g_VehicleESPPanelX;
            float newH = mouse.y - g_VehicleESPPanelY;
            if (newW >= 220.0f) g_VehicleESPPanelW = newW;
            if (newH >= 90.0f)  g_VehicleESPPanelH = newH;
        }
    }

    // --- Draw Glowing Selection Border & Corner Handle ---
    ImDrawList* dl = ImGui::GetForegroundDrawList();
    float pulse = (sinf((float)ImGui::GetTime() * 7.0f) + 1.0f) * 0.5f;
    ImU32 borderCol = IM_COL32(255, (int)(180 + 70 * pulse), 30, 255);

    dl->AddRect(ImVec2(x1 - 3, y1 - 3), ImVec2(x2 + 3, y2 + 3), borderCol, 4.0f * g_UIScale, 0, 2.5f);

    // Corner handle triangle
    ImVec2 ptA(x2 - handleSize, y2);
    ImVec2 ptB(x2, y2 - handleSize);
    ImVec2 ptC(x2, y2);
    dl->AddTriangleFilled(ptA, ptB, ptC, borderCol);
    dl->AddTriangle(ptA, ptB, ptC, IM_COL32(255, 255, 255, 255), 1.5f);

    // --- Top Control Banner ---
    ImGui::SetNextWindowPos(ImVec2(screenW * 0.5f, 25.0f * g_UIScale), ImGuiCond_Always, ImVec2(0.5f, 0.0f));
    ImGuiWindowFlags bannerFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                                   ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav;

    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.08f, 0.10f, 0.14f, 0.94f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1.0f, 0.75f, 0.2f, 0.8f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.5f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.0f * g_UIScale);

    bool exitResize = false;
    if (ImGui::Begin("##ResizeTopBanner", nullptr, bannerFlags)) {
        ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.25f, 1.0f), "RESIZE MODE: %s", targetName);
        ImGui::SameLine();
        ImGui::TextDisabled("| Drag box to move | Drag corner to resize |");
        ImGui::SameLine();
        if (ImGui::Button("Done & Save (ESC or Ctrl+F12)")) {
            exitResize = true;
        }
    }
    ImGui::End();

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);

    // Multi-key detection: handles CTRL+F12, ESCAPE, and ENTER across all keyboard layouts & overlays
    bool isCtrlDown = (GetAsyncKeyState(VK_CONTROL) & 0x8000) || (GetAsyncKeyState(VK_LCONTROL) & 0x8000) || 
                      (GetAsyncKeyState(VK_RCONTROL) & 0x8000) || io.KeyCtrl;
    bool isF12Down  = (GetAsyncKeyState(VK_F12) & 0x8000) || ImGui::IsKeyPressed(ImGuiKey_F12, false);
    bool isEscDown  = (GetAsyncKeyState(VK_ESCAPE) & 0x8000) || ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    bool isEnterDown = (GetAsyncKeyState(VK_RETURN) & 0x8000) || ImGui::IsKeyPressed(ImGuiKey_Enter, false);

    static bool s_ExitKeyWasDown = false;
    bool exitKeyDown = (isCtrlDown && isF12Down) || isEscDown || isEnterDown;

    if (exitKeyDown && !s_ExitKeyWasDown) {
        exitResize = true;
    }
    s_ExitKeyWasDown = exitKeyDown;

    if (exitResize) {
        g_ResizeMode = RESIZE_NONE;
        g_ResizeDragging = false;
        g_ResizeResizing = false;
        WriteConfig();
        g_ShowMenu = true;
    }
}
bool g_OceanSubVisuals = false;
bool g_OceanSubStates = false;
bool g_OceanSubCamera = false;
bool g_OceanSubPhysics = false;
bool g_OceanSubEntry = false;
bool g_MoonGravity = false;
bool g_NeverWanted = false;
bool g_PirateSkin = false;
static char g_CustomEventBuf[256] = "";

// ============================================================================
// WINGSUIT MISSILE PHYSICS & AUTO-FIRE STATE
// ============================================================================
uintptr_t g_LastMissilePtr = 0;
float g_MissileSpeedMult = 1.0f;
bool g_FullAutoMissiles = false;

// Captured genuine game defaults from live missile memory
float g_DefMissileStage0Time  = 0.0f;
float g_DefMissileStage1Time  = 0.0f;
float g_DefMissileStage0Speed = 0.0f;
float g_DefMissileStage1Speed = 0.0f;
float g_DefMissileTurnSpeed   = 0.0f;
float g_DefMissileTurnDelay   = 0.0f;
bool g_MissileDefaultsCaptured = false;

// User editable live values (initialized to -1 to detect if config loaded them)
float g_LiveMissileStage0Time  = -1.0f;
float g_LiveMissileStage1Time  = -1.0f;
float g_LiveMissileStage0Speed = -1.0f;
float g_LiveMissileStage1Speed = -1.0f;
float g_LiveMissileTurnSpeed   = -1.0f;
float g_LiveMissileTurnDelay   = -1.0f;

void ApplyMissileSpeedHook();
void ToggleFullAutoMissiles(bool enable);

void EnforceMissileProperties(uintptr_t missilePtr) {
    if (!missilePtr) return;
    if (g_LiveMissileStage0Time >= 0.0f)  FastWrite<float>(missilePtr + 0x5AC, g_LiveMissileStage0Time);
    if (g_LiveMissileStage1Time >= 0.0f)  FastWrite<float>(missilePtr + 0x5B0, g_LiveMissileStage1Time);
    if (g_LiveMissileStage0Speed >= 0.0f) FastWrite<float>(missilePtr + 0x5B4, g_LiveMissileStage0Speed);
    if (g_LiveMissileStage1Speed >= 0.0f) FastWrite<float>(missilePtr + 0x5B8, g_LiveMissileStage1Speed);
    if (g_LiveMissileTurnSpeed >= 0.0f)   FastWrite<float>(missilePtr + 0x5BC, g_LiveMissileTurnSpeed);
    if (g_LiveMissileTurnDelay >= 0.0f)   FastWrite<float>(missilePtr + 0x5C0, g_LiveMissileTurnDelay);
}
// ============================================================================
// WINGSUIT MISSILE WEAPON RESOLVER
// ============================================================================
static uintptr_t GetPlayerPtr();
static uintptr_t GetPlayerCharacterPtr();

uintptr_t g_ActiveWingsuitWeapon = 0;

uintptr_t GetWingsuitWeaponPtr() {
    if (!g_ExeBase) return 0;
    uintptr_t character = GetPlayerCharacterPtr();
    if (!character) {
        g_ActiveWingsuitWeapon = 0;
        return 0;
    }

    // Read Rico's m_Components array (CCharacter + 0x180 to +0x188)
    uintptr_t compBegin = 0, compEnd = 0;
    if (!FastRead<uintptr_t>(character + 0x180, compBegin) ||
        !FastRead<uintptr_t>(character + 0x188, compEnd) ||
        !compBegin || compEnd <= compBegin) {
        g_ActiveWingsuitWeapon = 0;
        return 0;
    }

    size_t count = (compEnd - compBegin) / 16;
    if (count > 64) count = 64; // Sanity boundary against corrupted lists

    uintptr_t typeId = g_ExeBase + g_Addr_1D25450; // CBoneAttachedInventory::TYPE_ID
    typedef bool (__fastcall* IsTypeFn)(uintptr_t thisptr, uintptr_t typeId);
    typedef uintptr_t (__fastcall* GetAnyWeaponFn)(uintptr_t thisptr);
    static GetAnyWeaponFn fnGetAnyWeapon = (GetAnyWeaponFn)(g_ExeBase + g_Addr_53D7B0);

    for (size_t i = 0; i < count; i++) {
        uintptr_t comp = 0;
        if (!FastRead<uintptr_t>(compBegin + (i * 16), comp) || !comp || comp < 0x10000) continue;

        uintptr_t vtable = 0;
        if (!FastRead<uintptr_t>(comp, vtable) || !vtable || vtable < g_ExeBase) continue;

        // Virtual method index 2 (vtable + 0x10) is IsType()
        uintptr_t fnIsType = 0;
        if (!FastRead<uintptr_t>(vtable + 0x10, fnIsType) || !fnIsType || fnIsType < g_ExeBase) continue;

        if (((IsTypeFn)fnIsType)(comp, typeId)) {
            uintptr_t weapon = fnGetAnyWeapon(comp);
            if (weapon && weapon > 0x10000) {
                g_ActiveWingsuitWeapon = weapon;
                return weapon;
            }
        }
    }

    g_ActiveWingsuitWeapon = 0;
    return 0;
}
extern "C" void HookMissileInit(uintptr_t missile) {
    if (!missile) return;

    // 1. Must be fired by the local player (m_IsPlayer flag bit 0 at +0x78)
    uint8_t flags = 0;
    if (!FastRead<uint8_t>(missile + 0x78, flags) || (flags & 1) == 0) {
        return; // Rejects all enemy & NPC missiles
    }

    // 2. Must be fired directly by Rico's character (rejects vehicles, tanks, jets, attack choppers)
    uintptr_t shooter = 0;
    uintptr_t rico = GetPlayerCharacterPtr();
    if (!FastRead<uintptr_t>(missile + 0x38, shooter) || !shooter || !rico || (shooter - 0x10) != rico) {
        return; // Rejects all vehicle-mounted weapons
    }

    // 3. Resolve the wingsuit weapon and compare against the missile's launching weapon (+0x48)
    uintptr_t wingsuitWeapon = GetWingsuitWeaponPtr();
    uintptr_t missileWeapon = 0;
    if (!FastRead<uintptr_t>(missile + 0x48, missileWeapon) || !missileWeapon) {
        return;
    }

    if (!wingsuitWeapon || missileWeapon != wingsuitWeapon) {
        return; // Rejects handheld RPGs, AT3-X, Fire Leach, Bloodhound, Javelin, etc.
    }

    // --- At this point, this missile is 100% guaranteed to be a Wingsuit missile ---
    g_LastMissilePtr = missile;

    if (!g_MissileDefaultsCaptured) {
        FastRead<float>(missile + 0x5AC, g_DefMissileStage0Time);
        FastRead<float>(missile + 0x5B0, g_DefMissileStage1Time);
        FastRead<float>(missile + 0x5B4, g_DefMissileStage0Speed);
        FastRead<float>(missile + 0x5B8, g_DefMissileStage1Speed);
        FastRead<float>(missile + 0x5BC, g_DefMissileTurnSpeed);
        FastRead<float>(missile + 0x5C0, g_DefMissileTurnDelay);

        // Auto-sync live values to captured defaults on the first wingsuit shot
        if (g_LiveMissileStage0Time  < 0.0f) g_LiveMissileStage0Time  = g_DefMissileStage0Time;
        if (g_LiveMissileStage1Time  < 0.0f) g_LiveMissileStage1Time  = g_DefMissileStage1Time;
        if (g_LiveMissileStage0Speed < 0.0f) g_LiveMissileStage0Speed = g_DefMissileStage0Speed;
        if (g_LiveMissileStage1Speed < 0.0f) g_LiveMissileStage1Speed = g_DefMissileStage1Speed;
        if (g_LiveMissileTurnSpeed   < 0.0f) g_LiveMissileTurnSpeed   = g_DefMissileTurnSpeed;
        if (g_LiveMissileTurnDelay   < 0.0f) g_LiveMissileTurnDelay   = g_DefMissileTurnDelay;

        g_MissileDefaultsCaptured = true;
    }

    // Enforce custom properties ONLY on confirmed wingsuit missiles
    EnforceMissileProperties(missile);
}

// Helper to dynamically resolve the local player (CPlayer) address
extern uintptr_t g_ExeBase; // Forward declare so this helper can see it
static uintptr_t GetPlayerPtr() {
    if (!g_ExeBase) return 0;
    static const bool is_steam = (GetModuleHandleA("steam_api64.dll") != nullptr);
    uintptr_t playerManagerAddr = g_ExeBase + (g_Addr_2CB2388);
    uintptr_t playerManager = 0;
    if (!FastRead<uintptr_t>(playerManagerAddr, playerManager) || !playerManager) return 0;

    uintptr_t localPlayer = 0;
    if (!FastRead<uintptr_t>(playerManager + 0x30, localPlayer) || !localPlayer) return 0;
    return localPlayer;
}

// Verifies Rico is physically spawned and his damage/weapon components are ready
static uintptr_t GetPlayerCharacterPtr() {
    uintptr_t player = GetPlayerPtr();
    if (!player) return 0;
    uintptr_t character = 0;
    if (!FastRead<uintptr_t>(player + 0x68, character) || !character || character < 0x10000) return 0;
    return character;
}


static uintptr_t AllocateNear(uintptr_t target, size_t size) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    uintptr_t base = target & ~(gran - 1);

    // Search OUTWARD from the target so every hook stays comfortably inside rel32.
    for (uintptr_t step = gran; step < 0x40000000; step += gran) {
        uintptr_t hi = base + step;
        if (hi < (uintptr_t)si.lpMaximumApplicationAddress) {
            void* a = VirtualAlloc((void*)hi, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (a) return (uintptr_t)a;
        }
        if (base > step + (uintptr_t)si.lpMinimumApplicationAddress) {
            uintptr_t lo = base - step;
            void* a = VirtualAlloc((void*)lo, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (a) return (uintptr_t)a;
        }
    }
    return 0;
}

static struct { uintptr_t addr; std::vector<uint8_t> orig; } g_HookBackups[8];
static int g_HookBackupCount = 0;

// [addr, addr+len) must be committed, executable, and INSIDE JustCause4.exe's image.
static bool VH_IsExeCode(uintptr_t addr, size_t len) {
    if (!g_ExeBase || !addr) return false;
    auto dos = (IMAGE_DOS_HEADER*)g_ExeBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (IMAGE_NT_HEADERS64*)(g_ExeBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (addr < g_ExeBase || addr + len > g_ExeBase + nt->OptionalHeader.SizeOfImage) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    const DWORD exec = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & exec)) return false;
    return (addr + len) <= ((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
}

static void VH_Dump(const char* name, uintptr_t addr, size_t len) {
    char line[256];
    int n = snprintf(line, sizeof(line), "[VH] %s RVA 0x%llX actual:", name,
                     (unsigned long long)(addr - g_ExeBase));
    for (size_t i = 0; i < len && n > 0 && n < (int)sizeof(line) - 4; i++)
        n += snprintf(line + n, sizeof(line) - n, " %02X", ((uint8_t*)addr)[i]);
    std::cout << line << "\n";
}

void UninstallVehicleHooks() {
    for (int i = 0; i < g_HookBackupCount; i++)
        SafePatchBytes(g_HookBackups[i].addr, g_HookBackups[i].orig.data(), g_HookBackups[i].orig.size());
    g_HookBackupCount = 0;
    Sleep(200);                       // let any thread still inside the cave leave
    if (g_CodeCave) { VirtualFree((void*)g_CodeCave, 0, MEM_RELEASE); g_CodeCave = 0; }
}

void InstallVehicleHooks() {
    if (!g_ExeBase) return;
    
    // Allocate 1024 bytes close to the physics functions to support relative jumps
    g_CodeCave = AllocateNear(g_ExeBase + g_Addr_77BCA70, 1024);
    if (!g_CodeCave) return;

    // Multiplier / constant block at cave+0x00 (16-byte aligned by VirtualAlloc)
    //  +0x00 Torque   +0x04 Grip   +0x08 Speed   +0x0C Jump Height
    //  +0x10 Jump impulse hard ceiling (Inf/NaN firewall)
    float initialMultipliers[8] = { g_BoostTorque, g_BoostGrip, g_BoostTopSpeed, g_BoostJumpHeight, 1.0e7f, 0.0f, 0.0f, 0.0f };
    memcpy((void*)g_CodeCave, initialMultipliers, sizeof(initialMultipliers));

    auto WriteJump = [](uintptr_t from, uintptr_t to) -> bool {
        int64_t delta = (int64_t)to - (int64_t)(from + 5);
        if (delta < INT32_MIN || delta > INT32_MAX) return false; // NEVER patch a truncated jump
        uint8_t bytes[5];
        bytes[0] = 0xE9; // JMP rel32
        int32_t rel = (int32_t)delta;
        memcpy(&bytes[1], &rel, 4);
        SafePatchBytes(from, bytes, 5);
        return true;
    };

    uintptr_t offset = 0x40; // Skip 64 bytes of variables space
    auto AssembleHook = [&](uintptr_t hookAddress, std::vector<uint8_t> hookCode, size_t overwriteSize,
                            std::vector<uint8_t> expected, const char* name) {
        if (g_HookBackupCount >= 8) return;
        if (!VH_IsExeCode(hookAddress, overwriteSize)) {
            std::cout << "[VH] SKIP " << name << " : address is NOT inside JustCause4.exe executable code.\n";
            return;
        }
        if (expected.size() != overwriteSize ||
            memcmp((void*)hookAddress, expected.data(), overwriteSize) != 0) {
            std::cout << "[VH] SKIP " << name << " : original-byte signature mismatch (wrong build/address).\n";
            VH_Dump(name, hookAddress, overwriteSize);
            return;
        }
        std::cout << "[VH] OK   " << name << "\n";
        uintptr_t caveLoc = g_CodeCave + offset;
        offset += 0x60;
        
        g_HookBackups[g_HookBackupCount].addr = hookAddress;
        g_HookBackups[g_HookBackupCount].orig.assign((uint8_t*)hookAddress, (uint8_t*)hookAddress + overwriteSize);
        g_HookBackupCount++;

        SafePatchBytes(caveLoc, hookCode.data(), hookCode.size());
        if (!WriteJump(caveLoc + hookCode.size(), hookAddress + overwriteSize)) return; // cave too far
        if (!WriteJump(hookAddress, caveLoc)) return;                                   // leave code intact
        if (overwriteSize > 5) {
            std::vector<uint8_t> nops(overwriteSize - 5, 0x90);
            SafePatchBytes(hookAddress + 5, nops.data(), nops.size());
        }
    };

    // Hook 1: Engine Torque (RVA 0x77BDE85, 12 bytes)
    std::vector<uint8_t> code_torque = {
        0x50,                                      // push rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, g_CodeCave (index 3-10)
        0xF3, 0x0F, 0x59, 0x09,                    // mulss xmm1, [rcx]
        0xF3, 0x0F, 0x59, 0x08,                    // mulss xmm1, [rax]
        0x58,                                      // pop rax
        0xF3, 0x0F, 0x11, 0x8E, 0xA4, 0x29, 0x00, 0x00 // movss [rsi+0x29a4], xmm1
    };
    memcpy(&code_torque[3], &g_CodeCave, 8);
    AssembleHook(g_ExeBase + g_Addr_77BDE85, code_torque, 12,
        {0xF3,0x0F,0x59,0x09, 0xF3,0x0F,0x11,0x8E,0xA4,0x29,0x00,0x00}, "Torque");

    // Hook 2: Wheel Grip (Steam 0x77BE81D = 10 bytes r14-base; Epic = 9 bytes rcx-base)
    std::vector<uint8_t> code_grip = { 0x50, 0x48, 0xB8, 0,0,0,0,0,0,0,0 };
    if (g_IsSteam) {
        const uint8_t o[] = {0xF3,0x41,0x0F,0x59,0x84,0x3E,0x84,0x01,0x00,0x00}; // mulss xmm0,[r14+rdi*1+0x184]
        code_grip.insert(code_grip.end(), o, o + sizeof(o));
    } else {
        const uint8_t o[] = {0xF3,0x0F,0x59,0x84,0x39,0x84,0x01,0x00,0x00};       // mulss xmm0,[rcx+rdi*1+0x184]
        code_grip.insert(code_grip.end(), o, o + sizeof(o));
    }
    { const uint8_t t[] = {0xF3,0x0F,0x59,0x40,0x04,0x58}; code_grip.insert(code_grip.end(), t, t + sizeof(t)); } // mulss [rax+4]; pop rax
    memcpy(&code_grip[3], &g_CodeCave, 8);
    AssembleHook(g_ExeBase + g_Addr_77BE81D, code_grip, g_IsSteam ? 10 : 9,
        g_IsSteam ? std::vector<uint8_t>{0xF3,0x41,0x0F,0x59,0x84,0x3E,0x84,0x01,0x00,0x00}
                  : std::vector<uint8_t>{0xF3,0x0F,0x59,0x84,0x39,0x84,0x01,0x00,0x00}, "Grip");



    // Hook 3: Max Speed (RVA 0x77BCBDD, 6 bytes)
    std::vector<uint8_t> code_speed = {
        0x48, 0x83, 0xEC, 0x10,                    // sub rsp, 16 safely
        0x0F, 0x11, 0x04, 0x24,                    // movups [rsp], xmm0 (unaligned-safe)
        0xF3, 0x0F, 0x10, 0x04, 0x01,              // movss xmm0, [rcx+rax*1] (uses original RAX index first!)
        0x50,                                      // push rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, g_CodeCave (index 16-23)
        0xF3, 0x0F, 0x59, 0x40, 0x08,              // mulss xmm0, [rax+8]
        0x58,                                      // pop rax
        0xF3, 0x44, 0x0F, 0x58, 0xE8,              // addss xmm13, xmm0
        0x0F, 0x10, 0x04, 0x24,                    // movups xmm0, [rsp] (unaligned-safe)
        0x48, 0x83, 0xC4, 0x10                     // add rsp, 16 safely
    };
    memcpy(&code_speed[16], &g_CodeCave, 8);
    AssembleHook(g_ExeBase + g_Addr_77BCBDD, code_speed, 6,
        g_IsSteam ? std::vector<uint8_t>{0xF3,0x44,0x0F,0x58,0x2C,0x01}
                  : std::vector<uint8_t>{0xF3,0x44,0x0F,0x58,0x24,0x01}, "MaxSpeed");

    // Hook 4: Body Push (RVA 0x77BE4A6, 5 bytes)
    std::vector<uint8_t> code_jump = {
        0x50,                                      // push rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, g_CodeCave (index 3-10)
        0xF3, 0x0F, 0x59, 0x69, 0x0C,              // mulss xmm5, [rcx+0xc]
        0xF3, 0x0F, 0x59, 0x68, 0x0C,              // mulss xmm5, [rax+0x0C]
        0xF3, 0x0F, 0x5D, 0x68, 0x10,              // minss xmm5, [rax+0x10] <-- clamp + NaN kill
        0x58                                       // pop rax
    };
    memcpy(&code_jump[3], &g_CodeCave, 8);
    AssembleHook(g_ExeBase + g_Addr_77BE4A6, code_jump, 5,
        {0xF3,0x0F,0x59,0x69,0x0C}, "BodyPush");

    // Hook 5: Front Wheels (RVA 0x77BE2FE, 8 bytes)
    std::vector<uint8_t> code_front = { 0x50, 0x48, 0xB8, 0,0,0,0,0,0,0,0 };
    if (g_IsSteam) { const uint8_t o[] = {0x49,0x8B,0x7F,0x10}; code_front.insert(code_front.end(), o, o + sizeof(o)); } // mov rdi,[r15+0x10]
    else           { const uint8_t o[] = {0x49,0x8B,0x7E,0x10}; code_front.insert(code_front.end(), o, o + sizeof(o)); } // mov rdi,[r14+0x10]
    { const uint8_t t[] = {0xF3,0x0F,0x59,0x03, 0xF3,0x0F,0x59,0x40,0x0C, 0xF3,0x0F,0x5D,0x40,0x10, 0x58};            // mulss [rbx]; mulss [rax+0xC]; minss [rax+0x10]; pop rax
      code_front.insert(code_front.end(), t, t + sizeof(t)); }
    memcpy(&code_front[3], &g_CodeCave, 8);
    AssembleHook(g_ExeBase + g_Addr_77BE2FE, code_front, 8,
        g_IsSteam ? std::vector<uint8_t>{0x49,0x8B,0x7F,0x10, 0xF3,0x0F,0x59,0x03}
                  : std::vector<uint8_t>{0x49,0x8B,0x7E,0x10, 0xF3,0x0F,0x59,0x03}, "FrontWheels");

    // Hook 6: Rear Wheels (RVA 0x77BE5A5, 8 bytes)
    std::vector<uint8_t> code_rear = {
        0x50,                                      // push rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, g_CodeCave (index 3-10)
        0xF3, 0x0F, 0x59, 0xC7,                    // mulss xmm0, xmm7
        0xF3, 0x0F, 0x59, 0x40, 0x0C,              // mulss xmm0, [rax+0x0C]
        0xF3, 0x0F, 0x5D, 0x40, 0x10,              // minss xmm0, [rax+0x10] <-- clamp + NaN kill
        0x58,                                      // pop rax
        0x48, 0x89, 0x45, 0xA8                     // mov [rbp+local_470], rax
    };
    memcpy(&code_rear[3], &g_CodeCave, 8);
    AssembleHook(g_ExeBase + g_Addr_77BE5A5, code_rear, 8,
        {0xF3,0x0F,0x59,0xC7, 0x48,0x89,0x45,0xA8}, "RearWheels");
}

// ============================================================================
// TORNADO SYSTEM
// ----------------------------------------------------------------------------
// Absolute (preferred base 0x140000000) -> RVA:
//   hook1  0x148FEEF70 -> 0x8FEEF70 (11 bytes: sub rsp,0x28 ; mov rcx,[0x142CAFA50])
//   hook2  0x1407FE8CC -> 0x7FE8CC  (5 bytes: addss xmm14, xmm6)
//   GetLocalPlayer 0x148380070 -> 0x8380070     ResetToStart 0x1407EAC10 -> 0x7EAC10
//   HideObject     0x1407F6290 -> 0x7F6290      CWeather     0x142CADA68 -> 0x2CADA68
//   Time           0x142C846B0 -> 0x2C846B0     PlayerMgr    0x142CB2388 -> 0x2CB2388
//   Camera         0x142CB1D90 -> 0x2CB1D90     CTRL vtable  0x141D7DF98 -> 0x1D7DF98
//   OBJ vtable     0x141D7E0E8 -> 0x1D7E0E8
// ============================================================================

struct TorReqFlags { volatile bool forceSpawn, fadeSpawn, forceDespawn, fadeDespawn; };
static_assert(sizeof(TorReqFlags) == 4, "hook1 stub reads these 4 bytes as one dword");
static TorReqFlags g_TorReq = {};
static uintptr_t g_TorController = 0;
static uintptr_t g_TorObject = 0;
static bool  g_TorSpawnAtCrosshair = false;
static bool  g_TorUseCustomCoords  = false;
static float g_TorCustomSpawn[3]   = {0.0f, 0.0f, 0.0f};
static bool  g_TorAimGuide         = false;
static bool  g_TorTeleportToAim    = false;
static bool  g_TorFreezeInPlace    = false;
static bool  g_TorSmoothSpawn      = false;
static bool  g_TorInstantSpawn     = true;
static float g_TorManualSpeed        = 30.0f;
static float g_TorAimDistance        = 150.0f;
static float g_TorFrontSpawnDistance = 60.0f;
static float g_TorFadeSpawnDuration   = 10.0f;           // default 10s
static float g_TorFadeDespawnDuration = 10.0f;           // default 10s
static float g_TorDeadzone           = 25.0f;
static float g_TorCurPos[3]      = {0.0f, 0.0f, 0.0f};
static float g_TorDefaultSpawn[3] = {0.0f, 0.0f, 0.0f};  // pristine [controller+0x23C] captured at locate time
static bool  g_TorDefaultCaptured = false;               // +0x23C is overwritten by every spawn;
                                                         // lock the first non-zero read so "default location"
                                                         // stays the game's configured origin
static uintptr_t g_TorManualController = 0;              // optional ini override
static uintptr_t g_TorManualObject     = 0;              // optional ini override
// Cached vtable scan candidates for on-demand pair healing.
static uintptr_t g_TorCtrlCands[8] = {};                 // CTRL-vtable hits (writer: locate thread)
static size_t    g_TorCtrlCandCount = 0;                 // count written AFTER data (x86 store order)
static uintptr_t g_TorObjCands[8]  = {};                 // OBJ-vtable hits
static size_t    g_TorObjCandCount = 0;
static volatile bool g_TorWantPair = false;              // set by TorDoSpawn: locate NOW
static uintptr_t g_TorForcedObj = 0;                     // object linked into +0x1F0 (one-shot:
                                                         // never link twice; cleared when the game's own
                                                         // pair appears; doesn't count as "linked")
static bool g_TorAllowForceLink = true;                  // false = heal only (disable force-linking)

// ---- hook2 stub <-> C++ shared context (offsets are hardcoded in the stub) ----
struct TorH2Ctx {
    uintptr_t ctrl;     // +0x00  rdi (controller) at the hook
    float x, y, z;      // +0x08/+0x0C/+0x10  xmm14/xmm15/xmm13 after the original addss
    float dt;           // +0x14  delta time ([rsp+0x20] at hook site)
    uintptr_t vel;      // +0x18  velocity pointer ([rsp+0x40], 3 dwords zeroed on neutralize)
    float nx, ny, nz;   // +0x20/+0x24/+0x28  new xmm14/xmm15/xmm13 (vel is 8 bytes: 0x18-0x1F)
    uintptr_t savedRsp; // +0x30  stub-internal
};
static_assert(offsetof(TorH2Ctx, ctrl)     == 0x00, "stub offset");
static_assert(offsetof(TorH2Ctx, x)        == 0x08, "stub offset");
static_assert(offsetof(TorH2Ctx, dt)       == 0x14, "stub offset");
static_assert(offsetof(TorH2Ctx, vel)      == 0x18, "stub offset");
static_assert(offsetof(TorH2Ctx, nx)       == 0x20, "stub offset");
static_assert(offsetof(TorH2Ctx, savedRsp) == 0x30, "stub offset");
static TorH2Ctx g_TorH2Ctx = {};
static uintptr_t g_TorH1SaveRsp = 0;

// [0x142CB2388] -> +0x30 (local player)
static uintptr_t TorLocalPlayer() {
    uintptr_t mgr = 0;
    if (!FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB2388, mgr) || !mgr) return 0;
    uintptr_t p = 0;
    if (!FastRead<uintptr_t>(mgr + 0x30, p) || !p) return 0;
    return p;
}
static bool GetCrosshairAimPosition(float& outX, float& outY, float& outZ) {
    uintptr_t player = GetPlayerPtr();
    if (!player) return false;

    uintptr_t character = 0;
    if (!FastRead<uintptr_t>(player + 0x68, character) || !character) return false;

    uintptr_t aimControl = 0;
    if (!FastRead<uintptr_t>(player + 0x1C0, aimControl) || !aimControl) return false;

    // 1. Get Camera Position and Forward Vector
    uintptr_t cameraManager = 0;
    FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cameraManager);
    if (!cameraManager) return false;

    float m[16] = { 0 };
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)(cameraManager + 0x500), m, sizeof(m), NULL)) return false;

    float fx = -m[8], fy = -m[9], fz = -m[10]; // Camera Forward
    float cx =  m[12], cy =  m[13], cz =  m[14]; // Camera Position

    // 2. Uncap all engine aim and raycast limits to 3000m across all slots
    FastWrite<float>(aimControl + 0x3C0, 3000.0f); // Active direct raycast max distance
    FastWrite<float>(aimControl + 0x3C4, 3000.0f); // Primary weapon range
    FastWrite<float>(aimControl + 0x3C8, 3000.0f); // Secondary range
    FastWrite<float>(aimControl + 0x3CC, 3000.0f); // Grapple range (uncapped from 100m to 3000m)
    FastWrite<float>(aimControl + 0x3D4, 3000.0f); // Heavy weapon (RPG/Launcher) range
    FastWrite<float>(aimControl + 0x3D8, 3000.0f); // Special weapon range
    FastWrite<float>(aimControl + 0x3DC, 3000.0f); // Lock-on range
    FastWrite<float>(aimControl + 0x3E0, 3000.0f); // Engine raycast override distance

    // Check if position is a genuine world collision hit and NOT the 0m camera artifact
    auto IsValidWorldHit = [&](float x, float y, float z) -> bool {
        if (std::isnan(x) || std::isnan(y) || std::isnan(z)) return false;
        if (std::abs(x) < 0.01f && std::abs(y) < 0.01f && std::abs(z) < 0.01f) return false;

        // When a raycast misses, the engine writes (CamPos - CamForward * 0.1f).
        // Distance to the camera lens is ~0.1m. We reject only that missed-ray artifact:
        float dx = x - cx, dy = y - cy, dz = z - cz;
        float distToCamSq = dx * dx + dy * dy + dz * dz;
        if (distToCamSq < (1.5f * 1.5f)) return false; // Rejects camera-origin artifact

        // Allow hits up to our 3000m limit (+100m tolerance buffer)
        if (distToCamSq > (3100.0f * 3100.0f)) return false;

        return true;
    };

    // Reads unmagnetized direct physics raycast hit: aimControl + 0x1E4 + (slot * 0xC)
    auto TryReadDirectHit = [&](int slotIdx, float& rx, float& ry, float& rz) -> bool {
        uintptr_t directPosAddr = aimControl + 0x1E4 + (slotIdx * 0xC);
        if (FastRead<float>(directPosAddr + 0x0, rx) &&
            FastRead<float>(directPosAddr + 0x4, ry) &&
            FastRead<float>(directPosAddr + 0x8, rz)) {
            return IsValidWorldHit(rx, ry, rz);
        }
        return false;
    };

    // 3. Determine the primary channel based on active weapon
    // character + 0x27D8: 3 = Heavy (AT3-X, RPG, Launchers), 1 = Sidearm, 0 = Primary Rifle
    int32_t activeWeaponSlot = 0;
    FastRead<int32_t>(character + 0x27D8, activeWeaponSlot);

    int primaryChannel = (activeWeaponSlot == 3) ? 4 : (activeWeaponSlot == 1 ? 1 : 0);

    // Try active weapon channel first (Channel 4 for Launchers, Channel 0 for Rifles)
    if (TryReadDirectHit(primaryChannel, outX, outY, outZ)) return true;

    // If active channel missed, check Channel 0 (Rifle direct hit)
    if (primaryChannel != 0 && TryReadDirectHit(0, outX, outY, outZ)) return true;

    // If still no hit, check Channel 4 (Heavy direct hit)
    if (primaryChannel != 4 && TryReadDirectHit(4, outX, outY, outZ)) return true;

    // Check Channel 2 (Direct collision raycast hit — NOT the magnetized target)
    if (TryReadDirectHit(2, outX, outY, outZ)) return true;

    // 4. Sky / Open Air Fallback (when aiming above terrain or into the clouds)
    // Projects 3000m along camera forward vector.
    // Clamped below 3500m altitude so it stays well below Havok's 7000m broadphase ceiling
    outX = cx + fx * 3000.0f;
    outY = cy + fy * 3000.0f;
    outZ = cz + fz * 3000.0f;

    if (outY > 3500.0f) outY = 3500.0f;

    return true;
}

static bool TorCrosshairHit(float& hx, float& hy, float& hz) {
    return GetCrosshairAimPosition(hx, hy, hz);
}
// [0x142CB1D90] camera: pos +0x530/534/538, forward +0x520/528
static bool TorCamFallback(float& cx, float& cy, float& cz, float& fx, float& fz) {
    uintptr_t cam = 0;
    if (!FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cam) || !cam) return false;
    if (!FastRead<float>(cam + 0x530, cx) || !FastRead<float>(cam + 0x534, cy) || !FastRead<float>(cam + 0x538, cz)) return false;
    if (!FastRead<float>(cam + 0x520, fx) || !FastRead<float>(cam + 0x528, fz)) return false;
    return true;
}
// [vtable+0x20](obj, onOff)
static void TorVtEnable(uintptr_t obj, uint32_t onOff) {
    uintptr_t vt = 0, fn = 0;
    if (!FastRead<uintptr_t>(obj, vt) || !vt) return;
    if (!FastRead<uintptr_t>(vt + 0x20, fn) || !fn) return;
    ((void(__fastcall*)(uintptr_t, uint32_t))fn)(obj, onOff);
}
// ---- deep liveness validation -------------------------------------------------
// free() does NOT scrub the vtable pointer, so "vtable still matches" is NOT proof of life:
// a recycled block passes vt == OBJ_VT with torn-down internals, and ResetToStart /
// [vtable+0x20] on it walks garbage pointers -> the crash. These check INTERNAL
// consistency of the containers/fields the allocator scrambles.
static bool TorPtrOK(uintptr_t p) { return p == 0 || (p > 0x10000 && p < 0x7FFFFFFFFFFF); }
static bool TorVecSane(uintptr_t obj, uintptr_t off) {   // std::vector triple: begin/end/cap
    uintptr_t b = 0, e = 0, c = 0;
    if (!FastRead<uintptr_t>(obj + off, b) || !FastRead<uintptr_t>(obj + off + 8, e) ||
        !FastRead<uintptr_t>(obj + off + 0x10, c)) return false;
    if (b == 0 && e == 0 && c == 0) return true;        // never-populated vector: fine
    if (!TorPtrOK(b) || !TorPtrOK(e) || !TorPtrOK(c)) return false;
    if (e < b || c < e) return false;
    return (e - b) < 0x100000;                          // < 1 MB span
}
static bool TorMapSane(uintptr_t obj, uintptr_t off) {   // 16-byte map: head ptr + size
    uintptr_t root = 0, sz = 0;
    if (!FastRead<uintptr_t>(obj + off, root) || !FastRead<uintptr_t>(obj + off + 8, sz)) return false;
    return TorPtrOK(root) && sz < 0x10000;
}
static bool TorObjLooksAlive(uintptr_t o) {
    if (!TorVecSane(o, 0x3E0)) return false;            // m_FxOffsetModifiers
    uintptr_t s = 0;
    if (!FastRead<uintptr_t>(o + 0x2D0, s) || !TorPtrOK(s)) return false;  // m_FunnelShape
    if (!FastRead<uintptr_t>(o + 0x2D8, s) || !TorPtrOK(s)) return false;  // m_DestructiveVolumeShape
    float mnY = 0.0f, mxY = 0.0f;                       // m_RenderingAABB: min.Y <= max.Y, not NaN
    if (FastRead<float>(o + 0x40C, mnY) && FastRead<float>(o + 0x418, mxY))
        if (!(mnY <= mxY)) return false;                // NaN or inverted -> torn-down block
    return true;
}
static bool TorCtrlLooksAlive(uintptr_t c) {
    if (!TorVecSane(c, 0x1F8)) return false;            // m_PathObjects
    if (!TorVecSane(c, 0x210)) return false;            // m_TriggerObjects
    if (!TorMapSane(c, 0x1D0)) return false;            // m_BezierPathSearchTree
    if (!TorMapSane(c, 0x1E0)) return false;            // m_TraveledDistances
    return true;
}

// Re-validate cached candidates at spawn time (frame-thread safe) and, when
// nothing is linked anywhere, force-link a spare CTornadoObject into controller+0x1F0.
static bool TorHealPair() {
    if (!g_ExeBase) return false;
    const uintptr_t CTRL_VT = g_ExeBase + g_Addr_1D7DF98;
    const uintptr_t OBJ_VT  = g_ExeBase + g_Addr_1D7E0E8;
    size_t nCtrl = (g_TorCtrlCandCount < 8) ? g_TorCtrlCandCount : 8;
    size_t nObj  = (g_TorObjCandCount  < 8) ? g_TorObjCandCount  : 8;
    uintptr_t liveCtrl = 0;                             // first valid, unlinked controller
    for (size_t i = 0; i < nCtrl; i++) {
        uintptr_t cc = g_TorCtrlCands[i], vt = 0, o = 0;
        if (!FastRead<uintptr_t>(cc, vt) || vt != CTRL_VT) continue;   // freed / recycled block
        if (FastRead<uintptr_t>(cc + 0x1F0, o) && o) {
            uintptr_t ovt = 0;
            if (FastRead<uintptr_t>(o, ovt) && ovt == OBJ_VT) {        // real linked pair
                if (g_TorController != cc || g_TorObject != o)
                    std::cout << "[Tornado] healed live pair: ctrl 0x" << std::hex << cc
                              << "  obj 0x" << o << std::dec << "\n";
                g_TorController = cc;
                g_TorObject = o;
                g_TorForcedObj = 0;                     // the game's own pair supersedes ours
                return true;
            }
            continue;                                                  // linked to something else - leave it
        }
        if (!liveCtrl) liveCtrl = cc;
    }
    if (!liveCtrl && g_TorController) {
        uintptr_t vt = 0, cur = 0;
        if (FastRead<uintptr_t>(g_TorController, vt) && vt == CTRL_VT &&
            (!FastRead<uintptr_t>(g_TorController + 0x1F0, cur) || !cur))
            liveCtrl = g_TorController;
    }
    if (!liveCtrl) return false;
    if (g_TorForcedObj || !g_TorAllowForceLink) return false;  // ONE-SHOT + kill-switch: a second
                                                              // attempt only races the game and
                                                              // multiplies the crash window
    if (!TorCtrlLooksAlive(liveCtrl)) {                // dead controller: vtable calls WILL crash
        static uintptr_t s_LastRefused = 0;            // once per address (each deferred retry re-runs heal)
        if (liveCtrl != s_LastRefused) {
            s_LastRefused = liveCtrl;
            std::cout << "[Tornado] force-link refused: controller 0x" << std::hex << liveCtrl
                      << std::dec << " failed deep validation\n";
        }
        return false;
    }
    for (size_t i = 0; i < nObj; i++) {                // nothing linked anywhere: force-link
        uintptr_t cand = g_TorObjCands[i];
        if (cand == liveCtrl) continue;                // skip recycled block aliasing controller
        uintptr_t vt = 0;
        if (!FastRead<uintptr_t>(cand, vt) || vt != OBJ_VT) continue;   // freed / recycled block
        if (!TorObjLooksAlive(cand)) continue;         // vtable matches but internals torn down
        FastWrite<uintptr_t>(liveCtrl + 0x1F0, cand);
        g_TorController = liveCtrl;
        g_TorObject = cand;
        g_TorForcedObj = cand;
        std::cout << "[Tornado] force-linked spare object 0x" << std::hex << cand
                  << std::dec << " into controller+0x1F0 (deep-validated)\n";
        return true;
    }
    return false;
}

static void TorDoSpawn(bool fadeMode) {
    static DWORD s_DeferDeadline = 0;
    uintptr_t rbx = g_TorController;
    uintptr_t rdi = 0;
    if (rbx && FastRead<uintptr_t>(rbx + 0x1F0, rdi) && rdi) {
        uintptr_t vt = 0;                              // recycled-block vtable guard
        if (!FastRead<uintptr_t>(rdi, vt) || vt != g_ExeBase + g_Addr_1D7E0E8) rdi = 0;
    }
    if (!rbx || !rdi) {
        TorHealPair();                                 // cached candidates only, NO heap scan
        rbx = g_TorController;
        rdi = 0;
        if (rbx) FastRead<uintptr_t>(rbx + 0x1F0, rdi);
    }
    if (!rbx || !rdi) {
        // Still nothing linked: keep the request armed for 15s while TorLocateThread rescans.
        DWORD now = GetTickCount();
        if (s_DeferDeadline == 0) {
            s_DeferDeadline = now + 15000;
            std::cout << "[Tornado] spawn deferred: controller+0x1F0 not linked yet - healing pointers\n";
        }
        if ((int32_t)(now - s_DeferDeadline) < 0) {
            if (fadeMode) g_TorReq.fadeSpawn = true; else g_TorReq.forceSpawn = true; // retry next frame
            g_TorWantPair = true;                      // wake TorLocateThread for a fresh scan
        } else {
            s_DeferDeadline = 0;
            std::cout << "[Tornado] spawn skipped: no tornado object exists yet\n";
        }
        return;
    }
    s_DeferDeadline = 0;
    g_TorObject = rdi;

    float x = 0.0f, y = 0.0f, z = 0.0f;
    bool have = false;
    if (g_TorUseCustomCoords) {
        x = g_TorCustomSpawn[0]; y = g_TorCustomSpawn[1]; z = g_TorCustomSpawn[2];
        have = true;
    } else if (g_TorSpawnAtCrosshair) {
        float hx, hy, hz;
        if (TorCrosshairHit(hx, hy, hz)) {
            x = hx; y = hy; z = hz;
            have = true;
        }
    }
    if (!have) return;

    // Deep-validate BEFORE calling any game function on the pair. A matching vtable is not
    // proof of life (free() keeps it); ResetToStart / [vtable+0x20] on a recycled block crashes.
    if (!TorCtrlLooksAlive(rbx) || !TorObjLooksAlive(rdi)) {
        std::cout << "[Tornado] spawn aborted: pair failed deep validation (ctrl 0x"
                  << std::hex << rbx << "  obj 0x" << rdi << std::dec << ")\n";
        if (g_TorForcedObj == rdi) g_TorForcedObj = 0; // allow exactly one retry, not a loop
        return;
    }
    FastWrite<float>(rbx + 0x23C, x);                  // 1. overwrite controller Havok origin
    FastWrite<float>(rbx + 0x240, y);
    FastWrite<float>(rbx + 0x244, z);
    FastWrite<uint8_t>(rdi + 0x423, 0);                // 2. clear visual guard so the 3D mesh (0x8E4CD781) activates
    TorVtEnable(rbx, 1);                               // 3. enable CTornadoController ([vtable+0x20], edx=1)
    ((void(__fastcall*)(uintptr_t))(g_ExeBase + g_Addr_7EAC10))(rbx); // 4. ResetToStart (0x1407EAC10)
    FastWrite<uint32_t>(rbx + 0x230, 0);               // 5. zero velocity (no initial sideways kick)
    FastWrite<uint32_t>(rbx + 0x234, 0);
    FastWrite<uint32_t>(rbx + 0x238, 0);
    uintptr_t timePtr = 0;                             // 6. sync LastTickTime with current time (Alt-Tab dt spike)
    if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2C846B0, timePtr) && timePtr) {
        uint32_t cur = 0;
        if (FastRead<uint32_t>(timePtr + 0x60, cur)) FastWrite<uint32_t>(rbx + 0x260, cur);
    }
    FastWrite<uint32_t>(rbx + 0x228, 1);               //    State = 1 (Active Roaming)
    FastWrite<uint32_t>(rbx + 0x22C, 2);               //    Steering = 2 (Target Steering)
    FastWrite<float>(rbx + 0x264, 100.0f);             //    Mass = 100.0f (stable default)
    FastWrite<float>(rbx + 0x270, 7.0f);               //    MovementSpeed = 7.0f (natural speed)
    if (fadeMode) {                                    // set_fade_timers
        FastWrite<float>(rbx + 0x280, g_TorFadeSpawnDuration);
        FastWrite<float>(rbx + 0x284, g_TorFadeSpawnDuration);
        FastWrite<float>(rdi + 0x780, 0.0f);           // start intensity at 0.0f
    } else {                                           // instant spawn intensity
        FastWrite<float>(rbx + 0x280, 0.0f);
        FastWrite<float>(rdi + 0x780, 1.0f);
    }
    // sync_spawn_registers
    FastWrite<float>(rbx + 0x248, x); FastWrite<float>(rbx + 0x24C, y); FastWrite<float>(rbx + 0x250, z);
    FastWrite<float>(rbx + 0x254, x); FastWrite<float>(rbx + 0x258, y); FastWrite<float>(rbx + 0x25C, z);
    FastWrite<float>(rdi + 0x134, x); FastWrite<float>(rdi + 0x138, y); FastWrite<float>(rdi + 0x13C, z);
    FastWrite<float>(rdi + 0x790, x); FastWrite<float>(rdi + 0x794, y); FastWrite<float>(rdi + 0x798, z);
    g_TorCurPos[0] = x; g_TorCurPos[1] = y; g_TorCurPos[2] = z;
    std::cout << "[Tornado] spawned (" << (fadeMode ? "fade" : "instant") << ") at "
              << x << ", " << y << ", " << z << "\n";
}

// ---- do_instant_despawn & cloud purge ----
static void TorInstantDespawn() {
    uintptr_t rbx = g_TorController;
    if (!rbx) return;
    uintptr_t rdi = 0;
    if (!FastRead<uintptr_t>(rbx + 0x1F0, rdi) || !rdi) return;
    {
        uintptr_t vt = 0;                              // refuse game calls on a dead object
        if (!FastRead<uintptr_t>(rdi, vt) || vt != g_ExeBase + g_Addr_1D7E0E8) return;
        if (!TorObjLooksAlive(rdi)) return;
    }

    ((void(__fastcall*)(uintptr_t, int))(g_ExeBase + g_Addr_7F6290))(rdi, 0); // 1. hide object (edx=0)
    FastWrite<float>(rdi + 0x780, 0.0f);                //    Intensity = 0.0f

    uintptr_t weather = 0;                              // 2. clear CWeather volumetrics
    if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CADA68, weather) && weather) {
        uint16_t idx = 0;
        if (FastRead<uint16_t>(rdi + 0x3F8, idx) && idx < 0x10) { // force-linked objects may carry a garbage index
            uintptr_t list = 0;
            if (FastRead<uintptr_t>(weather + 0xAF0, list) && list) {
                FastWrite<uint8_t>(list + (uintptr_t)idx * 0x110 + 0x104, 0); // STornado.m_Visible = 0
            }
        }
    }
    TorVtEnable(rbx, 0);                                // 3. disable controller (edx=0)
    FastWrite<uint32_t>(rbx + 0x228, 5);                // 4. State = 5 (Inactive)
    FastWrite<float>(rbx + 0x264, 0.0f);
    FastWrite<float>(rbx + 0x270, 0.0f);
    FastWrite<float>(rbx + 0x280, 0.0f);
    FastWrite<uint32_t>(rbx + 0x230, 0);
    FastWrite<uint32_t>(rbx + 0x234, 0);
    FastWrite<uint32_t>(rbx + 0x238, 0);
    FastWrite<float>(rbx + 0x24C, -5000.0f);            // 5. move 5000m underground (skybox clouds)
    FastWrite<float>(rbx + 0x258, -5000.0f);
    FastWrite<float>(rdi + 0x138, -5000.0f);
    FastWrite<float>(rdi + 0x794, -5000.0f);
}

// ---- do_fade_despawn ----
static void TorFadeDespawn() {
    uintptr_t rbx = g_TorController;
    if (!rbx) return;
    FastWrite<uint32_t>(rbx + 0x228, 4);                // State = 4 (Dissipating)
    FastWrite<float>(rbx + 0x280, g_TorFadeDespawnDuration);
    FastWrite<float>(rbx + 0x284, g_TorFadeDespawnDuration);
}

// ---- hook 1 dispatcher (spawn_hook_code) ----
static void TorFrameC() {
    if      (g_TorReq.forceSpawn)   { g_TorReq.forceSpawn = false; g_TorReq.fadeSpawn = false; TorDoSpawn(false); }
    else if (g_TorReq.fadeSpawn)    { g_TorReq.fadeSpawn  = false; g_TorReq.forceSpawn = false; TorDoSpawn(true);  }
    else if (g_TorReq.forceDespawn) { g_TorReq.forceDespawn = false; TorInstantDespawn(); }
    else if (g_TorReq.fadeDespawn)  { g_TorReq.fadeDespawn  = false; TorFadeDespawn(); }
}

// ---- hook 2: neutralize_velocity ----
static void TorNeutralize(uintptr_t ctrl, float x, float y, float z) {
    if (g_TorH2Ctx.vel) {                               // mov dword [rsp+0x40..0x48], 0
        FastWrite<uint32_t>(g_TorH2Ctx.vel + 0, 0);
        FastWrite<uint32_t>(g_TorH2Ctx.vel + 4, 0);
        FastWrite<uint32_t>(g_TorH2Ctx.vel + 8, 0);
    }
    FastWrite<float>(ctrl + 0x248, x); FastWrite<float>(ctrl + 0x24C, y); FastWrite<float>(ctrl + 0x250, z);
    FastWrite<float>(ctrl + 0x254, x); FastWrite<float>(ctrl + 0x258, y); FastWrite<float>(ctrl + 0x25C, z);
    uintptr_t obj = 0;
    if (FastRead<uintptr_t>(ctrl + 0x1F0, obj) && obj) {
        FastWrite<float>(obj + 0x134, x); FastWrite<float>(obj + 0x138, y); FastWrite<float>(obj + 0x13C, z);
        FastWrite<float>(obj + 0x790, x); FastWrite<float>(obj + 0x794, y); FastWrite<float>(obj + 0x798, z);
    }
    FastWrite<uint32_t>(ctrl + 0x230, 0);
    FastWrite<uint32_t>(ctrl + 0x234, 0);
    FastWrite<uint32_t>(ctrl + 0x238, 0);
}

static void TorHook2C() {
    uintptr_t rdi = g_TorH2Ctx.ctrl;
    // Accept rdi as the tornado controller ONLY if its vtable matches 0x141D7DF98.
    if (rdi > 0x10000) {
        uintptr_t vt = 0;
        if (FastRead<uintptr_t>(rdi, vt) && vt == g_ExeBase + g_Addr_1D7DF98) {
            static bool s_Hook2Logged = false;
            if (!s_Hook2Logged) {
                s_Hook2Logged = true;
                std::cout << "[Tornado] hook2 captured live controller: 0x" << std::hex << rdi << std::dec << "\n";
            }
            g_TorController = rdi;
            uintptr_t o = 0;
            if (FastRead<uintptr_t>(rdi + 0x1F0, o)) g_TorObject = o;
            // Fallback capture of the "default location" origin if the locate scan never
            // filled it (only while still 0,0,0; if a tornado is already active this
            // records its current spot rather than the pristine origin - still better
            // than the rico-forward fallback).
            if (!g_TorDefaultCaptured) {                // same lock as TornadoAutoLocate
                float fx = 0.0f, fy = 0.0f, fz = 0.0f;
                if (FastRead<float>(rdi + 0x23C, fx) && FastRead<float>(rdi + 0x240, fy) &&
                    FastRead<float>(rdi + 0x244, fz) && (fx != 0.0f || fy != 0.0f || fz != 0.0f)) {
                    g_TorDefaultSpawn[0] = fx; g_TorDefaultSpawn[1] = fy; g_TorDefaultSpawn[2] = fz;
                    g_TorDefaultCaptured = true;
                }
            }
        }
    }
    float x = g_TorH2Ctx.x, y = g_TorH2Ctx.y, z = g_TorH2Ctx.z;

    if (g_TorTeleportToAim) {                           // do_teleport_to_aim
        float hx, hy, hz;
        if (TorCrosshairHit(hx, hy, hz)) {              // apply_instant_aim_teleport
            x = hx; y = hy; z = hz;
        } else {                                        // use_cam_fallback_teleport
            float cx, cy, cz, fwx, fwz;
            if (!TorCamFallback(cx, cy, cz, fwx, fwz)) {
                g_TorH2Ctx.nx = x; g_TorH2Ctx.ny = y; g_TorH2Ctx.nz = z;
                return;
            }
            x = cx + (-fwx) * g_TorAimDistance;         // xorps fSignBit -> -Fwd
            y = cy;                                     // Cam Y, unmodified
            z = cz + (-fwz) * g_TorAimDistance;
        }
        g_TorCurPos[0] = x; g_TorCurPos[1] = y; g_TorCurPos[2] = z;
        TorNeutralize(rdi, x, y, z);
    }
    else if (g_TorAimGuide) {
        float tx = 0.0f, tz = 0.0f;
        bool hasTarget = false;
        float hx = 0.0f, hy = 0.0f, hz = 0.0f;
        if (GetCrosshairAimPosition(hx, hy, hz)) {
            tx = hx; tz = hz; hasTarget = true;
        }
        if (!hasTarget) {
            float cx, cy, cz, fwx, fwz;
            if (!TorCamFallback(cx, cy, cz, fwx, fwz)) {
                g_TorH2Ctx.nx = x; g_TorH2Ctx.ny = y; g_TorH2Ctx.nz = z;
                return;
            }
            tx = cx + (-fwx) * g_TorAimDistance;
            tz = cz + (-fwz) * g_TorAimDistance;
        }
        float dx = tx - x;                              // subss xmm0, xmm14
        float dz = tz - z;                              // subss xmm1, xmm13
        float d2 = dx * dx + dz * dz;
        if (!(d2 > g_TorDeadzone)) {                    // ucomiss [fDeadzone]; jbe neutralize_velocity
            TorNeutralize(rdi, x, y, z);
        } else {
            float dist = std::sqrt(d2);                                     // sqrtss xmm4
            float rinv = _mm_cvtss_f32(_mm_rsqrt_ss(_mm_set_ss(d2)));       // rsqrtss xmm3
            dx *= rinv; dz *= rinv;
            float spd = g_TorManualSpeed * g_TorH2Ctx.dt;                   // mulss xmm5,[rsp+0x20]
            spd = (spd < dist) ? spd : dist;                                // minss xmm5, xmm4 (NaN -> dist)
            x += dx * spd;                                                  // addss xmm14, xmm0
            z += dz * spd;                                                  // addss xmm13, xmm1
            g_TorCurPos[0] = x; g_TorCurPos[1] = y; g_TorCurPos[2] = z;
            TorNeutralize(rdi, x, y, z);
        }
    }
    else if (g_TorFreezeInPlace) {                      // do_freeze
        x = g_TorCurPos[0]; y = g_TorCurPos[1]; z = g_TorCurPos[2];
        TorNeutralize(rdi, x, y, z);
    }
    else {                                              // no flags: only track position
        g_TorCurPos[0] = x; g_TorCurPos[1] = y; g_TorCurPos[2] = z;
    }
    g_TorH2Ctx.nx = x; g_TorH2Ctx.ny = y; g_TorH2Ctx.nz = z;
}

// ---- AUTO-LOCATE (qword heap scan) ----
static bool TorInExeImage(uintptr_t a) {
    if (!g_ExeBase) return false;
    auto dos = (IMAGE_DOS_HEADER*)g_ExeBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (IMAGE_NT_HEADERS64*)(g_ExeBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    return a >= g_ExeBase && a < g_ExeBase + nt->OptionalHeader.SizeOfImage;
}
// Scan committed writable non-image memory, sorted 8-aligned-first then ascending.
static void TorScanValue(uintptr_t value, std::vector<uintptr_t>& hits) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end  = (uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    std::vector<uint8_t> scanBuf(0x1000000); // 16 MB reusable scan buffer (per TorScanValue call)
    const size_t torChunk = scanBuf.size();
    while (addr < end && VirtualQuery((void*)addr, &mbi, sizeof(mbi))) {
        uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        // Committed, writable, non-copy-on-write, non-image memory. The controller lives
        // in a MEM_MAPPED RW section on this engine (MEM_PRIVATE-only misses it).
        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE &&
            !(mbi.Protect & PAGE_GUARD) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            // Chunked with 8-byte slice overlap so a qword straddling a boundary is still
            // found; first-byte memchr prefilter instead of a memcmp per qword.
            const uint8_t first = (uint8_t)(value & 0xFF);
            for (uintptr_t off = 0; off < mbi.RegionSize; off += (torChunk - 8)) {
                size_t n = (size_t)((mbi.RegionSize - off < torChunk) ? (mbi.RegionSize - off) : torChunk);
                if (!ReadProcessMemory(GetCurrentProcess(), (void*)((uintptr_t)mbi.BaseAddress + off), scanBuf.data(), n, NULL)) continue;
                uint8_t* p = scanBuf.data();
                size_t base = 0; // slice-relative index of p
                while (n - base >= 8) {
                    void* hit = memchr(p, first, n - base - 7);
                    if (!hit) break;
                    size_t idx = base + (size_t)((uint8_t*)hit - p);
                    if (memcmp(hit, &value, 8) == 0) hits.push_back((uintptr_t)mbi.BaseAddress + off + idx);
                    p = (uint8_t*)hit + 1;
                    base = idx + 1;
                }
            }
        }
        addr = regionEnd;
    }
    std::sort(hits.begin(), hits.end(), [](uintptr_t a, uintptr_t b) {
        int aa = (a % 8 == 0) ? 0 : 1, ab = (b % 8 == 0) ? 0 : 1;
        if (aa != ab) return aa < ab;
        return a < b;
    });
}
static bool TornadoAutoLocate() {
    if (!g_ExeBase) return false;
    if (g_TorManualController) {                        // manual ini override path
        g_TorController = g_TorManualController;
        if (g_TorManualObject) g_TorObject = g_TorManualObject;
        else { uintptr_t o = 0; if (FastRead<uintptr_t>(g_TorManualController + 0x1F0, o)) g_TorObject = o; }
        return true;
    }
    const uintptr_t CTRL_VTABLE = g_ExeBase + g_Addr_1D7DF98; // 0x141D7DF98
    const uintptr_t OBJ_VTABLE  = g_ExeBase + g_Addr_1D7E0E8; // 0x141D7E0E8

    // Sanity: the CTRL vtable's first entry must be a code pointer inside the exe.
    uintptr_t vtProbe = 0;
    if (!FastRead<uintptr_t>(CTRL_VTABLE, vtProbe) || vtProbe < g_ExeBase || vtProbe > g_ExeBase + g_Addr_10000000) {
        std::cout << "[Tornado] auto-locate FAILED: CTRL vtable RVA 0x1D7DF98 does not hold a code pointer (wrong build?).\n";
        return false;
    }

    std::vector<uintptr_t> ctrls;
    TorScanValue(CTRL_VTABLE, ctrls);
    for (size_t i = 0; i < ctrls.size() && i < 8; i++) g_TorCtrlCands[i] = ctrls[i]; // cache for TorHealPair
    g_TorCtrlCandCount = (ctrls.size() < 8) ? ctrls.size() : 8;                     // count written last
    static int s_TorLocateFails = 0;
    if (ctrls.empty() && (++s_TorLocateFails % 10 == 1)) {
        std::cout << "[Tornado] auto-locate: 0 heap hits for CTRL vtable (attempt " << s_TorLocateFails << "; CE requires being in-game)\n";
    }
    uintptr_t controller = 0, object = 0;
    for (uintptr_t cc : ctrls) {
        uintptr_t vt0 = 0;
        if (!FastRead<uintptr_t>(cc, vt0) || vt0 != CTRL_VTABLE) continue;  // ctrl itself freed/recycled
        uintptr_t o = 0;
        if (FastRead<uintptr_t>(cc + 0x1F0, o) && o) {
            uintptr_t vt = 0;
            if (FastRead<uintptr_t>(o, vt) && vt == OBJ_VTABLE &&
                TorObjLooksAlive(o) && TorCtrlLooksAlive(cc)) {
                controller = cc; object = o; break;
            }
        }
    }
    if (!controller && !ctrls.empty()) {
        // Fallback: no candidate passed the +0x1F0 object validation - take the first
        static size_t s_LastCtrlN = (size_t)-1;   // rescans repeat now - log only on change
        if (ctrls.size() != s_LastCtrlN) { s_LastCtrlN = ctrls.size();
            std::cout << "[Tornado] auto-locate: " << ctrls.size() << " CTRL candidate(s), none validated via +0x1F0 - using first as fallback\n"; }
        controller = ctrls[0];
        std::vector<uintptr_t> objs;
        TorScanValue(OBJ_VTABLE, objs);
        for (size_t i = 0; i < objs.size() && i < 8; i++) g_TorObjCands[i] = objs[i]; // cache for the force-link
        g_TorObjCandCount = (objs.size() < 8) ? objs.size() : 8;
        object = objs.empty() ? 0 : objs[0];
        static size_t s_LastObjN = (size_t)-1;
        if (objs.size() != s_LastObjN) { s_LastObjN = objs.size();
            std::cout << "[Tornado] fallback object scan: " << objs.size() << " OBJ vtable hit(s)\n"; }
    }
    if (!controller) {                                  // auto-locate failed (not in game yet)
        return false;
    }
    g_TorController = controller;
    g_TorObject = object;
    if (!g_TorDefaultCaptured) {                        // re-scans must NOT pick up spawn-overwritten values
        float fx = 0.0f, fy = 0.0f, fz = 0.0f;
        if (FastRead<float>(controller + 0x23C, fx) && FastRead<float>(controller + 0x240, fy) &&
            FastRead<float>(controller + 0x244, fz) && (fx != 0.0f || fy != 0.0f || fz != 0.0f)) {
            g_TorDefaultSpawn[0] = fx; g_TorDefaultSpawn[1] = fy; g_TorDefaultSpawn[2] = fz;
            g_TorDefaultCaptured = true;
        }
    }
    static uintptr_t s_LastC = 1, s_LastO = 1;   // rescans repeat now - print only on change
    if (controller != s_LastC || object != s_LastO) {
        s_LastC = controller; s_LastO = object;
        std::cout << "[TornadoMaster] Controller = 0x" << std::hex << controller
                  << "   Object = 0x" << object << std::dec << "\n";
    }
    return true;
}

// Retry locate on its own thread, gated on the player existing (no scan at main menu),
// so neither the key-polling thread nor the render thread stalls behind a heap scan.
static volatile bool g_TorForceRelocate = false; // set by the tab's Re-locate button
// "Linked" = controller+0x1F0 points at an object with the CTornadoObject vtable.
// Keep healing in the background until the game links a real pair.
static bool TorPairLinked() {
    if (!g_TorController || !g_ExeBase) return false;
    uintptr_t o = 0;
    if (!FastRead<uintptr_t>(g_TorController + 0x1F0, o) || !o) return false;
    if (g_TorForcedObj && o == g_TorForcedObj) return false;   // OUR link doesn't count - keep
    uintptr_t vt = 0;                                          // hunting for the game's real pair
    if (!FastRead<uintptr_t>(o, vt) || vt != g_ExeBase + g_Addr_1D7E0E8) return false;
    return TorObjLooksAlive(o);                        // vtable match alone is not proof of life
}
static DWORD WINAPI TorLocateThread(LPVOID) {
    DWORD lastScan = 0;
    while (true) {
        if (g_ExeBase && GetPlayerPtr()) {
            bool linked = TorPairLinked();
            if (linked) g_TorWantPair = false;
            if (g_TorForceRelocate || (!linked && (g_TorWantPair || GetTickCount() - lastScan > 30000))) {
                g_TorForceRelocate = false;
                lastScan = GetTickCount();
                TornadoAutoLocate();
            } else {
                g_TorForceRelocate = false;
            }
        }
        Sleep(1000);
    }
    return 0;
}

// ---- code cave hooks (same technique as the vehicle hooks above) ----
static uint8_t  g_TorOrig1[11]; static uintptr_t g_TorHook1Addr = 0; static uintptr_t g_TorCave1 = 0;
static uint8_t  g_TorOrig2[5];  static uintptr_t g_TorHook2Addr = 0; static uintptr_t g_TorCave2 = 0;

// Hook 1: RVA 0x8FEEF70 (11 bytes) — sub rsp,0x28 ; mov rcx,[0x142CAFA50]
static bool TorBuildHook1() {
    uintptr_t h1 = g_ExeBase + g_Addr_8FEEF70;
    if (!VH_IsExeCode(h1, 11)) { std::cout << "[Tornado] SKIP hook1: address is NOT inside JustCause4.exe code.\n"; return false; }
    memcpy(g_TorOrig1, (void*)h1, 11);
    if (memcmp(g_TorOrig1, "\x48\x83\xEC\x28\x48\x8B\x0D", 7) != 0) {
        std::cout << "[Tornado] SKIP hook1: original-byte signature mismatch at RVA 0x8FEEF70.\n"; return false;
    }
    int32_t rel; memcpy(&rel, g_TorOrig1 + 7, 4);
    if ((uintptr_t)((int64_t)h1 + 11 + rel) != g_ExeBase + g_Addr_2CAFA50) {
        std::cout << "[Tornado] SKIP hook1: mov rcx,[0x142CAFA50] target mismatch.\n"; return false;
    }
    g_TorCave1 = AllocateNear(h1, 0x200);
    if (!g_TorCave1) return false;

    std::vector<uint8_t> c;
    auto b = [&](std::initializer_list<uint8_t> xs) { for (uint8_t x : xs) c.push_back(x); };
    size_t pReq=0, pSave=0, pFn=0, pSave2=0, pJz=0, pOrigRel=0, pBack=0, pJmpTail=0;

    b({0x9C});                                          // pushfq
    b({0x50});                                          // push rax
    b({0x48,0xB8}); pReq = c.size(); b({0,0,0,0,0,0,0,0}); // mov rax, &g_TorReq
    b({0x8B,0x00});                                     // mov eax, [rax]
    b({0x85,0xC0});                                     // test eax, eax
    b({0x58});                                          // pop rax (pop does not touch flags)
    b({0x0F,0x84}); pJz = c.size(); b({0,0,0,0});       // jz idle
    // ---- active: full register save, call C++ ----
    b({0x50,0x51,0x52});                                // push rax, rcx, rdx
    b({0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53});      // push r8, r9, r10, r11
    b({0x48,0x83,0xEC,0x60});                           // sub rsp, 0x60 (xmm0-5 save area)
    b({0xF3,0x0F,0x11,0x04,0x24});                      // movups [rsp+0x00], xmm0
    b({0xF3,0x0F,0x11,0x4C,0x24,0x10});                 // movups [rsp+0x10], xmm1
    b({0xF3,0x0F,0x11,0x54,0x24,0x20});                 // movups [rsp+0x20], xmm2
    b({0xF3,0x0F,0x11,0x5C,0x24,0x30});                 // movups [rsp+0x30], xmm3
    b({0xF3,0x0F,0x11,0x64,0x24,0x40});                 // movups [rsp+0x40], xmm4
    b({0xF3,0x0F,0x11,0x6C,0x24,0x50});                 // movups [rsp+0x50], xmm5
    b({0x48,0xB8}); pSave = c.size(); b({0,0,0,0,0,0,0,0});  // mov rax, &g_TorH1SaveRsp
    b({0x48,0x89,0x20});                                // mov [rax], rsp
    b({0x48,0x83,0xE4,0xF0});                           // and rsp, -16
    b({0x48,0x83,0xEC,0x20});                           // sub rsp, 0x20 (shadow space)
    b({0x48,0xB8}); pFn = c.size(); b({0,0,0,0,0,0,0,0});    // mov rax, TorFrameC
    b({0xFF,0xD0});                                     // call rax
    b({0x48,0xB8}); pSave2 = c.size(); b({0,0,0,0,0,0,0,0}); // mov rax, &g_TorH1SaveRsp
    b({0x48,0x8B,0x20});                                // mov rsp, [rax]
    b({0xF3,0x0F,0x10,0x04,0x24});                      // movups xmm0, [rsp+0x00]
    b({0xF3,0x0F,0x10,0x4C,0x24,0x10});                 // movups xmm1, [rsp+0x10]
    b({0xF3,0x0F,0x10,0x54,0x24,0x20});                 // movups xmm2, [rsp+0x20]
    b({0xF3,0x0F,0x10,0x5C,0x24,0x30});                 // movups xmm3, [rsp+0x30]
    b({0xF3,0x0F,0x10,0x64,0x24,0x40});                 // movups xmm4, [rsp+0x40]
    b({0xF3,0x0F,0x10,0x6C,0x24,0x50});                 // movups xmm5, [rsp+0x50]
    b({0x48,0x83,0xC4,0x60});                           // add rsp, 0x60
    b({0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58});      // pop r11, r10, r9, r8
    b({0x5A,0x59,0x58});                                // pop rdx, rcx, rax
    b({0x9D});                                          // popfq
    // ---- spawn_hook_orig: the two original instructions, rebased into the cave ----
    b({0x48,0x83,0xEC,0x28});                           // sub rsp, 0x28
    b({0x48,0x8B,0x0D}); pOrigRel = c.size(); b({0,0,0,0}); // mov rcx, [rip+rel32] -> 0x142CAFA50
    b({0xE9}); pBack = c.size(); b({0,0,0,0});          // jmp 0x148FEEF7B
    // ---- idle: nothing touched, restore flags and enter the tail ----
    b({0x9D});                                          // popfq
    b({0xE9}); pJmpTail = c.size(); b({0,0,0,0});       // jmp tail (sub rsp,0x28)

    uintptr_t v64 = (uintptr_t)&g_TorReq; memcpy(&c[pReq], &v64, 8);
    v64 = (uintptr_t)&g_TorH1SaveRsp; memcpy(&c[pSave], &v64, 8); memcpy(&c[pSave2], &v64, 8);
    v64 = (uintptr_t)&TorFrameC; memcpy(&c[pFn], &v64, 8);
    int32_t r32 = (int32_t)((int64_t)(c.size() - 6) - (int64_t)(pJz + 4));       // jz -> idle popfq (idle = popfq + jmp = 6 bytes)
    memcpy(&c[pJz], &r32, 4);
    r32 = (int32_t)((int64_t)(g_ExeBase + g_Addr_2CAFA50) - (int64_t)(g_TorCave1 + pOrigRel + 4));
    memcpy(&c[pOrigRel], &r32, 4);
    r32 = (int32_t)((int64_t)(h1 + 11) - (int64_t)(g_TorCave1 + pBack + 4));     // jmp back
    memcpy(&c[pBack], &r32, 4);
    r32 = (int32_t)((int64_t)(g_TorCave1 + pOrigRel - 7) - (int64_t)(g_TorCave1 + pJmpTail + 4)); // idle -> tail
    memcpy(&c[pJmpTail], &r32, 4);

    SafePatchBytes(g_TorCave1, c.data(), c.size());
    uint8_t j[11] = { 0xE9 };                           // jmp cave + 6x nop (11 bytes)
    int64_t d = (int64_t)g_TorCave1 - (int64_t)(h1 + 5);
    if (d < INT32_MIN || d > INT32_MAX) return false;
    int32_t jr = (int32_t)d; memcpy(&j[1], &jr, 4);
    for (int i = 5; i < 11; i++) j[i] = 0x90;
    SafePatchBytes(h1, j, 11);
    g_TorHook1Addr = h1;
    return true;
}

// Hook 2: RVA 0x7FE8CC (5 bytes) — addss xmm14, xmm6
static bool TorBuildHook2() {
    uintptr_t h2 = g_ExeBase + g_Addr_7FE8CC;
    if (!VH_IsExeCode(h2, 5)) { std::cout << "[Tornado] SKIP hook2: address is NOT inside JustCause4.exe code.\n"; return false; }
    memcpy(g_TorOrig2, (void*)h2, 5);
    static const uint8_t expected[5] = { 0xF3, 0x44, 0x0F, 0x58, 0xF6 }; // addss xmm14, xmm6
    if (memcmp(g_TorOrig2, expected, 5) != 0) {
        std::cout << "[Tornado] SKIP hook2: original-byte signature mismatch at RVA 0x7FE8CC.\n"; return false;
    }
    g_TorCave2 = AllocateNear(h2, 0x200);
    if (!g_TorCave2) return false;

    std::vector<uint8_t> c;
    auto b = [&](std::initializer_list<uint8_t> xs) { for (uint8_t x : xs) c.push_back(x); };
    size_t pCtx1=0, pFn=0, pCtx2=0, pBack=0;

    b({0xF3,0x44,0x0F,0x58,0xF6});                      // addss xmm14, xmm6   (ORIGINAL)
    b({0x9C});                                          // pushfq
    b({0x50,0x51,0x52});                                // push rax, rcx, rdx
    b({0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53});      // push r8, r9, r10, r11
    b({0x48,0x83,0xEC,0x60});                           // sub rsp, 0x60 (xmm0-5 save area)
    b({0xF3,0x0F,0x11,0x04,0x24});                      // movups [rsp+0x00], xmm0
    b({0xF3,0x0F,0x11,0x4C,0x24,0x10});                 // movups [rsp+0x10], xmm1
    b({0xF3,0x0F,0x11,0x54,0x24,0x20});                 // movups [rsp+0x20], xmm2
    b({0xF3,0x0F,0x11,0x5C,0x24,0x30});                 // movups [rsp+0x30], xmm3
    b({0xF3,0x0F,0x11,0x64,0x24,0x40});                 // movups [rsp+0x40], xmm4
    b({0xF3,0x0F,0x11,0x6C,0x24,0x50});                 // movups [rsp+0x50], xmm5
    b({0x48,0xB8}); pCtx1 = c.size(); b({0,0,0,0,0,0,0,0}); // mov rax, &g_TorH2Ctx
    b({0x48,0x89,0x60,0x30});                           // mov [rax+0x30], rsp   (savedRsp)
    b({0x48,0x89,0x38});                                // mov [rax+0x00], rdi   (ctrl)
    b({0xF3,0x44,0x0F,0x11,0x70,0x08});                 // movss [rax+0x08], xmm14
    b({0xF3,0x44,0x0F,0x11,0x78,0x0C});                 // movss [rax+0x0C], xmm15
    b({0xF3,0x44,0x0F,0x11,0x68,0x10});                 // movss [rax+0x10], xmm13
    b({0xF3,0x0F,0x10,0x8C,0x24,0xC0,0x00,0x00,0x00});  // movss xmm1, [rsp+0xC0]  (dt)
    b({0xF3,0x0F,0x11,0x48,0x14});                      // movss [rax+0x14], xmm1
    b({0x48,0x8D,0x94,0x24,0xE0,0x00,0x00,0x00});       // lea rdx, [rsp+0xE0]     (vel)
    b({0x48,0x89,0x50,0x18});                           // mov [rax+0x18], rdx
    b({0x48,0x83,0xE4,0xF0});                           // and rsp, -16
    b({0x48,0x83,0xEC,0x20});                           // sub rsp, 0x20 (shadow space)
    b({0x48,0xB8}); pFn = c.size(); b({0,0,0,0,0,0,0,0});   // mov rax, TorHook2C
    b({0xFF,0xD0});                                     // call rax
    b({0x48,0xB8}); pCtx2 = c.size(); b({0,0,0,0,0,0,0,0}); // mov rax, &g_TorH2Ctx
    b({0xF3,0x44,0x0F,0x10,0x70,0x20});                 // movss xmm14, [rax+0x20]
    b({0xF3,0x44,0x0F,0x10,0x78,0x24});                 // movss xmm15, [rax+0x24]
    b({0xF3,0x44,0x0F,0x10,0x68,0x28});                 // movss xmm13, [rax+0x28]
    b({0x48,0x8B,0x48,0x30});                           // mov rcx, [rax+0x30]    (savedRsp)
    b({0xF3,0x0F,0x10,0x01});                           // movups xmm0, [rcx+0x00]
    b({0xF3,0x0F,0x10,0x49,0x10});                      // movups xmm1, [rcx+0x10]
    b({0xF3,0x0F,0x10,0x51,0x20});                      // movups xmm2, [rcx+0x20]
    b({0xF3,0x0F,0x10,0x59,0x30});                      // movups xmm3, [rcx+0x30]
    b({0xF3,0x0F,0x10,0x61,0x40});                      // movups xmm4, [rcx+0x40]
    b({0xF3,0x0F,0x10,0x69,0x50});                      // movups xmm5, [rcx+0x50]
    b({0x48,0x89,0xCC});                                // mov rsp, rcx
    b({0x48,0x83,0xC4,0x60});                           // add rsp, 0x60
    b({0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58});      // pop r11, r10, r9, r8
    b({0x5A,0x59,0x58});                                // pop rdx, rcx, rax
    b({0x9D});                                          // popfq
    b({0xE9}); pBack = c.size(); b({0,0,0,0});          // jmp 0x1407FE8D1

    uintptr_t v64 = (uintptr_t)&g_TorH2Ctx; memcpy(&c[pCtx1], &v64, 8); memcpy(&c[pCtx2], &v64, 8);
    v64 = (uintptr_t)&TorHook2C; memcpy(&c[pFn], &v64, 8);
    int64_t d = (int64_t)(h2 + 5) - (int64_t)(g_TorCave2 + pBack + 4);
    if (d < INT32_MIN || d > INT32_MAX) return false;
    int32_t r32 = (int32_t)d; memcpy(&c[pBack], &r32, 4);

    SafePatchBytes(g_TorCave2, c.data(), c.size());
    uint8_t j[5] = { 0xE9 };                            // jmp cave (5 bytes)
    d = (int64_t)g_TorCave2 - (int64_t)(h2 + 5);
    if (d < INT32_MIN || d > INT32_MAX) return false;
    r32 = (int32_t)d; memcpy(&j[1], &r32, 4);
    SafePatchBytes(h2, j, 5);
    g_TorHook2Addr = h2;
    return true;
}

void InstallTornadoHooks() {
    if (!g_ExeBase || g_TorHook1Addr) return;
    if (!TorBuildHook1()) {
        if (g_TorCave1) { VirtualFree((void*)g_TorCave1, 0, MEM_RELEASE); g_TorCave1 = 0; }
        return;
    }
    if (!TorBuildHook2()) {
        if (g_TorCave2) { VirtualFree((void*)g_TorCave2, 0, MEM_RELEASE); g_TorCave2 = 0; }
        SafePatchBytes(g_TorHook1Addr, g_TorOrig1, 11); // roll back hook 1
        g_TorHook1Addr = 0;
        if (g_TorCave1) { VirtualFree((void*)g_TorCave1, 0, MEM_RELEASE); g_TorCave1 = 0; }
        return;
    }
    std::cout << "[Tornado] hooks installed: RVA 0x8FEEF70 (11 bytes) + 0x7FE8CC (5 bytes)\n";
    // Run auto-locate on a dedicated thread so a full heap scan never blocks
    // the key-polling thread (which handles the F2 menu toggle) or the render thread.
    static HANDLE sLocateThread = NULL;
    if (!sLocateThread) sLocateThread = CreateThread(NULL, 0, TorLocateThread, NULL, 0, NULL);
}
void UninstallTornadoHooks() {
    if (g_TorHook1Addr) { SafePatchBytes(g_TorHook1Addr, g_TorOrig1, 11); g_TorHook1Addr = 0; } // sub rsp,0x28; mov rcx,[...]
    if (g_TorHook2Addr) { SafePatchBytes(g_TorHook2Addr, g_TorOrig2, 5);  g_TorHook2Addr = 0; } // addss xmm14, xmm6
    Sleep(200);
    if (g_TorCave1) { VirtualFree((void*)g_TorCave1, 0, MEM_RELEASE); g_TorCave1 = 0; }
    if (g_TorCave2) { VirtualFree((void*)g_TorCave2, 0, MEM_RELEASE); g_TorCave2 = 0; }
}

// ---- INI: keybinds (saved the instant they change; old INIs get missing keys written) ----
static const char* TorIniPath() {
    static char path[MAX_PATH] = "";
    if (!path[0]) {
        // Resolve against the current working directory — the exact same file your
        // WriteConfig()/ReadConfig() open with ("modmenu_jc4.ini"). A bare filename
        // would make the profile APIs look in the Windows directory instead.
        GetFullPathNameA("modmenu_jc4.ini", MAX_PATH, path, nullptr);
    }
    return path;
}
enum TorBindId {
    TB_SPAWN_DEFAULT, TB_SPAWN_CROSSHAIR, TB_FOLLOW, TB_TELEPORT, TB_FREEZE,
    TB_SPAWN_SMOOTH, TB_SPAWN_INSTANT, TB_DESPAWN_NOW, TB_DESPAWN_FADE, TB_COUNT
};
struct TorBind { int vk; int def; const char* ini; };
static TorBind g_TorBinds[TB_COUNT] = {
    // F2 = menu toggle (g_ToggleKey) and F3 = favorite vehicle spawn (g_SpawnFavoriteKey)
    // are already taken by this mod, so the tornado defaults run F4..F12.
    { VK_F4,  VK_F4,  "KeySpawnDefaultLocation" },
    { VK_F5,  VK_F5,  "KeySpawnAtCrosshair" },
    { VK_F6,  VK_F6,  "KeyFollowCrosshairSmooth" },
    { VK_F7,  VK_F7,  "KeyTeleportToCrosshair" },
    { VK_F8,  VK_F8,  "KeyFreezeInPlace" },
    { VK_F9,  VK_F9,  "KeySpawnSmoothly" },
    { VK_F10, VK_F10, "KeySpawnInstantly" },
    { VK_F11, VK_F11, "KeyDespawnInstant" },
    { VK_F12, VK_F12, "KeyDespawnFade" },
};
static bool g_TorBindsLoaded = false;
static int  s_TorCapture = -1;
static double g_TorListenStart = 0.0;  // arm delay before listening (mirrors g_FavoriteKeyListenStart)
extern int g_ToggleKey;                // defined later in GLOBAL STATE (int g_ToggleKey = VK_F2)
static bool g_TorPrevDown[TB_COUNT] = {};
static void TorSaveBind(int i) {
    char v[16]; snprintf(v, sizeof(v), "%d", g_TorBinds[i].vk);
    WritePrivateProfileStringA("Tornado", g_TorBinds[i].ini, v, TorIniPath());
}
static uintptr_t TorIniReadU64(const char* key, uintptr_t def) {
    char buf[64] = "";
    GetPrivateProfileStringA("Tornado", key, "", buf, sizeof(buf), TorIniPath());
    if (!buf[0]) return def;
    return (uintptr_t)strtoull(buf, nullptr, 0);
}
static void TorLoadBinds() {
    g_TorBindsLoaded = true;
    char v[16];
    for (int i = 0; i < TB_COUNT; i++) {
        g_TorBinds[i].vk = (int)GetPrivateProfileIntA("Tornado", g_TorBinds[i].ini, g_TorBinds[i].def, TorIniPath());
        snprintf(v, sizeof(v), "%d", g_TorBinds[i].vk);   // write back: populates missing keys (old-ini migration)
        WritePrivateProfileStringA("Tornado", g_TorBinds[i].ini, v, TorIniPath());
    }
    g_TorManualController = TorIniReadU64("ManualController", 0);
    g_TorManualObject     = TorIniReadU64("ManualObject", 0);
    snprintf(v, sizeof(v), "%llu", (unsigned long long)g_TorManualController);
    WritePrivateProfileStringA("Tornado", "ManualController", v, TorIniPath());
    snprintf(v, sizeof(v), "%llu", (unsigned long long)g_TorManualObject);
    WritePrivateProfileStringA("Tornado", "ManualObject", v, TorIniPath());
}

// ---- actions (single integration point for buttons AND keybinds) ----
static void TorAction(int id) {
    switch (id) {
    case TB_SPAWN_DEFAULT:      // spawn at the controller's pristine configured origin (game default = zona tres)
        g_TorCustomSpawn[0] = g_TorDefaultSpawn[0];
        g_TorCustomSpawn[1] = g_TorDefaultSpawn[1];
        g_TorCustomSpawn[2] = g_TorDefaultSpawn[2];
        g_TorUseCustomCoords = true;
        g_TorSpawnAtCrosshair = false;
        if (g_TorSmoothSpawn) g_TorReq.fadeSpawn = true; else g_TorReq.forceSpawn = true;
        break;
    case TB_SPAWN_CROSSHAIR:
        g_TorSpawnAtCrosshair = true;
        g_TorUseCustomCoords = false;
        if (g_TorSmoothSpawn) g_TorReq.fadeSpawn = true; else g_TorReq.forceSpawn = true;
        break;
    case TB_FOLLOW:     g_TorAimGuide = !g_TorAimGuide;      if (g_TorAimGuide)    g_TorTeleportToAim = false; break;
    case TB_TELEPORT:   g_TorTeleportToAim = !g_TorTeleportToAim; if (g_TorTeleportToAim) g_TorAimGuide = false;  break;
    case TB_FREEZE:     g_TorFreezeInPlace = !g_TorFreezeInPlace; break;
    case TB_SPAWN_SMOOTH:  g_TorSmoothSpawn = true;  g_TorInstantSpawn = false; break;
    case TB_SPAWN_INSTANT: g_TorInstantSpawn = true; g_TorSmoothSpawn = false;  break;
    case TB_DESPAWN_NOW:  g_TorReq.forceDespawn = true; break;
    case TB_DESPAWN_FADE: g_TorReq.fadeDespawn  = true; break;
    }
}

// ---- keybind capture widget (click [key], press a key; ESC clears) ----
extern SHORT(WINAPI* o_GetAsyncKeyState)(int); // defined later in KEYBOARD POLL HOOKS
static SHORT TorRawKeyState(int vk) {
    return o_GetAsyncKeyState ? o_GetAsyncKeyState(vk) : GetAsyncKeyState(vk);
}
static const char* TorVkName(int vk) {
    static char buf[32];
    if (vk <= 0) { snprintf(buf, sizeof(buf), "None"); return buf; }
    // Same OS-level name lookup the spawn tab uses (falls through to our table below on failure)
    UINT sc = MapVirtualKeyA((UINT)vk, MAPVK_VK_TO_VSC);
    if (sc != 0 && GetKeyNameTextA((LONG)(sc << 16), buf, (int)sizeof(buf)) && buf[0] != '\0') return buf;
    if ((vk >= '0' && vk <= '9') || (vk >= 'A' && vk <= 'Z')) { snprintf(buf, sizeof(buf), "%c", (char)vk); return buf; }
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) { snprintf(buf, sizeof(buf), "NUM %d", vk - VK_NUMPAD0); return buf; }
    if (vk >= VK_F1 && vk <= VK_F24) { snprintf(buf, sizeof(buf), "F%d", vk - VK_F1 + 1); return buf; }
    switch (vk) {
        case VK_INSERT: return "INSERT"; case VK_HOME: return "HOME";   case VK_END: return "END";
        case VK_PRIOR:  return "PGUP";   case VK_NEXT:  return "PGDN";   case VK_DELETE: return "DELETE";
        case VK_BACK:   return "BACKSPACE"; case VK_TAB: return "TAB";  case VK_RETURN: return "ENTER";
        case VK_SHIFT:  return "SHIFT";  case VK_CONTROL: return "CTRL"; case VK_MENU: return "ALT";
        case VK_SPACE:  return "SPACE";  case VK_CAPITAL: return "CAPS";
    }
    snprintf(buf, sizeof(buf), "VK 0x%02X", vk);
    return buf;
}
static void TorKeybindWidget(const char* idStr, int bindIdx) {
    ImGui::PushID(idStr);
    ImGui::SameLine();
    char lbl[48];
    if (s_TorCapture == bindIdx) snprintf(lbl, sizeof(lbl), "[ press key ]");
    else snprintf(lbl, sizeof(lbl), "[%s]", TorVkName(g_TorBinds[bindIdx].vk));
    if (ImGui::SmallButton(lbl)) {
        s_TorCapture = (s_TorCapture == bindIdx) ? -1 : bindIdx;
        g_TorListenStart = ImGui::GetTime(); // arm delay, same 0.25s as the spawn tab's key listener
    }
    if (s_TorCapture == bindIdx && ImGui::GetTime() - g_TorListenStart > 0.25f) {
        if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
            g_TorBinds[bindIdx].vk = 0; TorSaveBind(bindIdx); s_TorCapture = -1;
        } else {
            for (int vk = 0x08; vk <= 0xFE; vk++) {      // skip mouse buttons 0x01-0x07
                if (vk == g_ToggleKey) continue;         // never bind the menu toggle key (same guard as the spawn tab)
                if (TorRawKeyState(vk) & 0x8000) {
                    g_TorBinds[bindIdx].vk = vk;
                    TorSaveBind(bindIdx);                // saved to ini the instant it changes
                    g_TorPrevDown[bindIdx] = true;       // require release before it can trigger
                    s_TorCapture = -1;
                    break;
                }
            }
        }
    }
    ImGui::PopID();
}

// ---- per-frame keybind polling + lazy install + auto-locate retry ----
extern bool g_ShowMenu;     // defined in GLOBAL STATE
extern bool g_ImGuiInited;  // defined in GLOBAL STATE
// Refreshed by hkPresent on the RENDER thread; read here on the polling thread.
// (Never call ImGui functions from KeyPollingThread - it is not the ImGui thread.)
bool g_TorUiTyping = false;
void TornadoHandleKeys() {
    if (!g_ExeBase) return;
    if (!g_TorBindsLoaded) {
        // Lazy fallback only - MainThread calls TorLoadBinds() right after ReadConfig().
        // The 3s delay guarantees we never race ReadConfig's ini rewrite on first launch.
        static DWORD s_FirstTick = GetTickCount();
        if (GetTickCount() - s_FirstTick < 3000) return;
        TorLoadBinds();
    }
    if (s_TorCapture != -1 && !g_ShowMenu) s_TorCapture = -1; // menu closed mid-capture -> cancel it
    static bool s_TriedInstall = false;
    if (!s_TriedInstall) { s_TriedInstall = true; InstallTornadoHooks(); }
    // (auto-locate retries moved to TorLocateThread - a heap scan here froze the menu toggle key)
    // Keybind guard: do not trigger while the mod menu is open
    if (g_ShowMenu) return;
    for (int i = 0; i < TB_COUNT; i++) {
        int vk = g_TorBinds[i].vk;
        bool now = vk > 0 && (GetAsyncKeyState(vk) & 0x8000) != 0;
        if (now && !g_TorPrevDown[i] && s_TorCapture == -1) TorAction(i);
        g_TorPrevDown[i] = now;
    }
}

// ============================================================================
// TORNADO LIVE FIELD BROWSER — CTornadoObject / CTornadoController 
// ----------------------------------------------------------------------------
//  * Values are READ live every 1s. NOTHING is written or preset on startup.
//  * A field writes to memory ONLY when you edit it.
//  * A field whose data has not been successfully read yet ("still recollecting")
//    is BLOCKED (disabled) so a zero/stale cache can never be written back.
//  * While you interact with a field, its 1s refresh is suspended (no clobbering).
// ============================================================================
extern float g_UIScale;

enum TorKind { TK_F, TK_I, TK_U, TK_B, TK_U16, TK_V3, TK_PTR, TK_U64, TK_VECNT };
struct TorField { const char* grp; uintptr_t off; int kind; const char* name; const char* note; };
struct TorLiveCell {
    float   f[3];
    int64_t i;
    bool    valid;   // false = still recollecting -> widget BLOCKED
    bool    hold;    // true = user interacting as of last frame -> skip refresh tick
};

static const TorField TOR_CTRL_FIELDS[] = {
    {"Identity", 0x0, TK_PTR, "vtable (implicit)", "CTornadoController vtable (RVA 0x1D7DF98)"},
    {"Core / State", 0x228, TK_U, "m_State", "ETornadoState (1=Active Roaming, 4=Dissipating, 5=Inactive)"},
    {"Core / State", 0x22C, TK_U, "m_Movement", "ETornadoMovement (2=Target Steering)"},
    {"Core / State", 0x1F0, TK_PTR, "m_TornadoObject", "CTornadoObject instance pointer"},
    {"Core / State", 0x260, TK_U, "m_PrevTime", "Timestamp tracking for simulation step"},
    {"Position & Velocity", 0x230, TK_V3, "m_Velocity", "CVector3f - Velocity vector"},
    {"Position & Velocity", 0x23C, TK_V3, "m_StartPosition", "CVector3f - Initial spawn origin"},
    {"Position & Velocity", 0x248, TK_V3, "m_PrevPosition", "CVector3f - Previous frame position"},
    {"Position & Velocity", 0x254, TK_V3, "m_ReachPoint", "CVector3f"},
    {"Physics & Movement", 0x264, TK_F, "m_TornadoMass", "Physical simulation mass (Default: 100.0)"},
    {"Physics & Movement", 0x268, TK_F, "m_DragCoefficient", ""},
    {"Physics & Movement", 0x26C, TK_F, "m_WindCrossSectionalArea", ""},
    {"Physics & Movement", 0x270, TK_F, "m_MovementSpeed", "Movement speed (Default: 7.0)"},
    {"Physics & Movement", 0x274, TK_F, "m_SplineGlueForce", ""},
    {"Physics & Movement", 0x278, TK_F, "m_StayAheadDistance", ""},
    {"Physics & Movement", 0x27C, TK_F, "m_StayAheadForce", ""},
    {"Buildup / Timing", 0x280, TK_F, "m_BuildupTimeLeft", "Remaining buildup / fade duration"},
    {"Buildup / Timing", 0x284, TK_F, "m_BuildupTimeTotal", "Total buildup / fade duration"},
    {"Buildup / Timing", 0x288, TK_F, "m_ReachPointETAScale", ""},
    {"Containers & Maps", 0x1D0, TK_U64, "m_BezierPathSearchTree (map, raw)", "std::map 16B - raw qwords, internal layout opaque"},
    {"Containers & Maps", 0x1D8, TK_U64, "m_BezierPathSearchTree +8 (raw)", ""},
    {"Containers & Maps", 0x1E0, TK_U64, "m_TraveledDistances (map, raw)", "std::map 16B - raw qwords"},
    {"Containers & Maps", 0x1E8, TK_U64, "m_TraveledDistances +8 (raw)", ""},
    {"Containers & Maps", 0x1F8, TK_VECNT, "m_PathObjects (vector)", "vector<CBezierPathObject*> - span/8 = element count"},
    {"Containers & Maps", 0x210, TK_VECNT, "m_TriggerObjects (vector)", "vector<CTornadoTrigger*> - span/8 = element count"},
    {"Event Objects (raw)", 0x290, TK_U64, "m_ResetEvent", "CReceiveEvent - raw"},
    {"Event Objects (raw)", 0x298, TK_U64, "m_EnterEvent", "CReceiveEvent<uint,uint> - raw"},
    {"Event Objects (raw)", 0x2A0, TK_U64, "m_ExitEvent", "CReceiveEvent<uint,uint> - raw"},
    {"Event Objects (raw)", 0x2A8, TK_U64, "m_StopEvent", "raw"},
    {"Event Objects (raw)", 0x2B0, TK_U64, "m_DisapperEvent", "raw"},
    {"Event Objects (raw)", 0x2B8, TK_U64, "m_AppearEvent", "raw"},
    {"Event Objects (raw)", 0x2C0, TK_U64, "m_ResumeEvent", "raw"},
    {"Event Objects (raw)", 0x2C8, TK_U64, "m_MovementSystemicEvent", "raw"},
    {"Event Objects (raw)", 0x2D0, TK_U64, "m_MovementFollowSplineEvent", "raw"},
    {"Event Objects (raw)", 0x2D8, TK_U64, "m_MovementStayAheadEvent", "raw"},
    {"Event Objects (raw)", 0x2E0, TK_U64, "m_MovementReachPointEvent", "raw"},
    {"Event Objects (raw)", 0x2E8, TK_U64, "m_TeleportToCrosshairEvent", "raw"},
    {"Event Objects (raw)", 0x2F0, TK_U64, "m_OnTornadoStoppedEvent", "CSendEvent<uint,uint> - raw"},
    {"Event Objects (raw)", 0x2F8, TK_U64, "m_OnTornadoDisappearedEvent", "CSendEvent<> - raw"},
};

static const TorField TOR_OBJ_FIELDS[] = {
    {"Identity", 0x0, TK_PTR, "vtable (implicit)", "CTornadoObject vtable (RVA 0x1D7E0E8)"},
    {"Position & Transform", 0x134, TK_V3, "[obj+0x134]", "Spawn position coordinates"},
    {"Havok Shapes", 0x2D0, TK_PTR, "m_FunnelShape", "hknpCompoundShape*"},
    {"Havok Shapes", 0x2D8, TK_PTR, "m_DestructiveVolumeShape", "hknpCompoundShape*"},
    {"Havok Shapes", 0x2E0, TK_PTR, "m_FunnelCapsuleShapes[0]", "hknpConvexShape*"},
    {"Havok Shapes", 0x2E8, TK_PTR, "m_FunnelCapsuleShapes[1]", ""},
    {"Havok Shapes", 0x2F0, TK_PTR, "m_FunnelCapsuleShapes[2]", ""},
    {"Havok Shapes", 0x2F8, TK_PTR, "m_FunnelCapsuleShapes[3]", ""},
    {"Havok Shapes", 0x300, TK_PTR, "m_FunnelCapsuleShapes[4]", ""},
    {"Havok Shapes", 0x308, TK_PTR, "m_FunnelCapsuleShapes[5]", ""},
    {"Havok Shapes", 0x310, TK_PTR, "m_FunnelCapsuleShapes[6]", ""},
    {"Havok Shapes", 0x318, TK_PTR, "m_FunnelCapsuleShapes[7]", ""},
    {"Havok Shapes", 0x320, TK_PTR, "m_FunnelCapsuleShapes[8]", ""},
    {"Havok Shapes", 0x328, TK_PTR, "m_FunnelCapsuleShapes[9]", ""},
    {"Havok Shapes", 0x330, TK_PTR, "m_DestructiveVolumeCapsuleShapes[0]", "hknpConvexShape*"},
    {"Havok Shapes", 0x338, TK_PTR, "m_DestructiveVolumeCapsuleShapes[1]", ""},
    {"Havok Shapes", 0x340, TK_PTR, "m_DestructiveVolumeCapsuleShapes[2]", ""},
    {"Havok Shapes", 0x348, TK_PTR, "m_DestructiveVolumeCapsuleShapes[3]", ""},
    {"Havok Shapes", 0x350, TK_PTR, "m_DestructiveVolumeCapsuleShapes[4]", ""},
    {"Havok Shapes", 0x358, TK_PTR, "m_DestructiveVolumeCapsuleShapes[5]", ""},
    {"Havok Shapes", 0x360, TK_PTR, "m_DestructiveVolumeCapsuleShapes[6]", ""},
    {"Havok Shapes", 0x368, TK_PTR, "m_DestructiveVolumeCapsuleShapes[7]", ""},
    {"Havok Shapes", 0x370, TK_PTR, "m_DestructiveVolumeCapsuleShapes[8]", ""},
    {"Havok Shapes", 0x378, TK_PTR, "m_DestructiveVolumeCapsuleShapes[9]", ""},
    {"Curve Derivatives", 0x380, TK_V3, "m_BottomControlCurveFirstDerivative.m_v1", "Vector3"},
    {"Curve Derivatives", 0x390, TK_V3, "m_BottomControlCurveFirstDerivative.m_v2", ""},
    {"Curve Derivatives", 0x3A0, TK_V3, "m_BottomControlCurveFirstDerivative.m_v3", ""},
    {"Curve Derivatives", 0x3B0, TK_V3, "m_TopControlCurveFirstDerivative.m_v1", ""},
    {"Curve Derivatives", 0x3C0, TK_V3, "m_TopControlCurveFirstDerivative.m_v2", ""},
    {"Curve Derivatives", 0x3D0, TK_V3, "m_TopControlCurveFirstDerivative.m_v3", ""},
    {"Render & Damage", 0x3F8, TK_U16, "m_RenderHandle", "ushort - Volumetric weather handle index"},
    {"Render & Damage", 0x400, TK_PTR, "m_AOVolume", "CAOVolumeInstance*"},
    {"Render & Damage", 0x420, TK_B, "m_Initialized", "bool"},
    {"Render & Damage", 0x421, TK_B, "m_ShowGizmo", "bool"},
    {"Render & Damage", 0x422, TK_B, "m_IsUpdateActive", "bool"},
    {"Render & Damage", 0x423, TK_B, "m_Visible", "bool - Mesh rendering toggle"},
    {"Render & Damage", 0x424, TK_I, "m_DamagePerSecond", "int"},
    {"Render & Damage", 0x428, TK_I, "m_DamagePerSecondToPlayers", "int"},
    {"Render & Damage", 0x42C, TK_F, "m_MaxDamageImpulse", "float"},
    {"Render & Damage", 0x430, TK_F, "m_DestructiveWindMargin", "float"},
    {"Render & Damage", 0x434, TK_F, "m_DmgTic", "float"},
    {"Rendering AABB", 0x408, TK_V3, "m_RenderingAABB.m_Min", "CAABox"},
    {"Rendering AABB", 0x414, TK_V3, "m_RenderingAABB.m_Max", "CAABox"},
    {"Control Orbit - Low (0x440)", 0x440, TK_PTR, "m_LowControlOrbit.m_Tornado", "CTornadoObject*"},
    {"Control Orbit - Low (0x440)", 0x450, TK_V3, "m_LowControlOrbit.m_ControlPointPosition", "Point3"},
    {"Control Orbit - Low (0x440)", 0x460, TK_F, "m_LowControlOrbit.m_OrbitRadius", ""},
    {"Control Orbit - Low (0x440)", 0x464, TK_F, "m_LowControlOrbit.m_RotationOffset", ""},
    {"Control Orbit - Low (0x440)", 0x468, TK_F, "m_LowControlOrbit.m_Phase", ""},
    {"Control Orbit - Low (0x440)", 0x46C, TK_F, "m_LowControlOrbit.m_RotationsPerMinute", ""},
    {"Control Orbit - Low (0x440)", 0x470, TK_F, "m_LowControlOrbit.m_HeightRatio", ""},
    {"Control Orbit - Low (0x440)", 0x474, TK_B, "m_LowControlOrbit.m_RotatesAroundBottomTopAxis", ""},
    {"Control Orbit - Mid (0x480)", 0x480, TK_PTR, "m_MidControlOrbit.m_Tornado", "CTornadoObject*"},
    {"Control Orbit - Mid (0x480)", 0x490, TK_V3, "m_MidControlOrbit.m_ControlPointPosition", "Point3"},
    {"Control Orbit - Mid (0x480)", 0x4A0, TK_F, "m_MidControlOrbit.m_OrbitRadius", ""},
    {"Control Orbit - Mid (0x480)", 0x4A4, TK_F, "m_MidControlOrbit.m_RotationOffset", ""},
    {"Control Orbit - Mid (0x480)", 0x4A8, TK_F, "m_MidControlOrbit.m_Phase", ""},
    {"Control Orbit - Mid (0x480)", 0x4AC, TK_F, "m_MidControlOrbit.m_RotationsPerMinute", ""},
    {"Control Orbit - Mid (0x480)", 0x4B0, TK_F, "m_MidControlOrbit.m_HeightRatio", ""},
    {"Control Orbit - Mid (0x480)", 0x4B4, TK_B, "m_MidControlOrbit.m_RotatesAroundBottomTopAxis", ""},
    {"Control Orbit - High (0x4C0)", 0x4C0, TK_PTR, "m_HighControlOrbit.m_Tornado", "CTornadoObject*"},
    {"Control Orbit - High (0x4C0)", 0x4D0, TK_V3, "m_HighControlOrbit.m_ControlPointPosition", "Point3"},
    {"Control Orbit - High (0x4C0)", 0x4E0, TK_F, "m_HighControlOrbit.m_OrbitRadius", ""},
    {"Control Orbit - High (0x4C0)", 0x4E4, TK_F, "m_HighControlOrbit.m_RotationOffset", ""},
    {"Control Orbit - High (0x4C0)", 0x4E8, TK_F, "m_HighControlOrbit.m_Phase", ""},
    {"Control Orbit - High (0x4C0)", 0x4EC, TK_F, "m_HighControlOrbit.m_RotationsPerMinute", ""},
    {"Control Orbit - High (0x4C0)", 0x4F0, TK_F, "m_HighControlOrbit.m_HeightRatio", ""},
    {"Control Orbit - High (0x4C0)", 0x4F4, TK_B, "m_HighControlOrbit.m_RotatesAroundBottomTopAxis", ""},
    {"Wind Field Speeds", 0x518, TK_F, "m_MaxRadialWindSpeed", ""},
    {"Wind Field Speeds", 0x51C, TK_F, "m_MaxTangentialWindSpeed", ""},
    {"Wind Field Speeds", 0x520, TK_F, "m_MaxVerticalWindSpeed", ""},
    {"Wind Field Speeds", 0x524, TK_F, "m_MaxAngularWindSpeed", ""},
    {"Wind Field Speeds", 0x528, TK_F, "m_MaxRadialWindSpeedStart", ""},
    {"Wind Field Speeds", 0x52C, TK_F, "m_MaxTangentialWindSpeedStart", ""},
    {"Wind Field Speeds", 0x530, TK_F, "m_MaxVerticalWindSpeedStart", ""},
    {"Wind Field Speeds", 0x534, TK_F, "m_MaxRadialWindSpeedGrowth", ""},
    {"Wind Field Speeds", 0x538, TK_F, "m_MaxTangentialWindSpeedGrowth", ""},
    {"Wind Field Speeds", 0x53C, TK_F, "m_MaxVerticalWindSpeedGrowth", ""},
    {"Bottom Control Curve (0x540)", 0x540, TK_V3, "m_BottomControlCurve.m_P0", "SCubicBezierCurve3D"},
    {"Bottom Control Curve (0x540)", 0x550, TK_V3, "m_BottomControlCurve.m_P1", ""},
    {"Bottom Control Curve (0x540)", 0x560, TK_V3, "m_BottomControlCurve.m_P2", ""},
    {"Bottom Control Curve (0x540)", 0x570, TK_V3, "m_BottomControlCurve.m_P3", ""},
    {"Top Control Curve (0x580)", 0x580, TK_V3, "m_TopControlCurve.m_P0", "SCubicBezierCurve3D"},
    {"Top Control Curve (0x580)", 0x590, TK_V3, "m_TopControlCurve.m_P1", ""},
    {"Top Control Curve (0x580)", 0x5A0, TK_V3, "m_TopControlCurve.m_P2", ""},
    {"Top Control Curve (0x580)", 0x5B0, TK_V3, "m_TopControlCurve.m_P3", ""},
    {"Prev Bottom Control Curve (0x5C0)", 0x5C0, TK_V3, "m_PreviousBottomControlCurve.m_P0", ""},
    {"Prev Bottom Control Curve (0x5C0)", 0x5D0, TK_V3, "m_PreviousBottomControlCurve.m_P1", ""},
    {"Prev Bottom Control Curve (0x5C0)", 0x5E0, TK_V3, "m_PreviousBottomControlCurve.m_P2", ""},
    {"Prev Bottom Control Curve (0x5C0)", 0x5F0, TK_V3, "m_PreviousBottomControlCurve.m_P3", ""},
    {"Prev Top Control Curve (0x600)", 0x600, TK_V3, "m_PreviousTopControlCurve.m_P0", ""},
    {"Prev Top Control Curve (0x600)", 0x610, TK_V3, "m_PreviousTopControlCurve.m_P1", ""},
    {"Prev Top Control Curve (0x600)", 0x620, TK_V3, "m_PreviousTopControlCurve.m_P2", ""},
    {"Prev Top Control Curve (0x600)", 0x630, TK_V3, "m_PreviousTopControlCurve.m_P3", ""},
    {"Wind AABBs (0x640)", 0x640, TK_V3, "m_WindAabbWorld[0].m_Min", "CAABox[5]"},
    {"Wind AABBs (0x640)", 0x64C, TK_V3, "m_WindAabbWorld[0].m_Max", ""},
    {"Wind AABBs (0x640)", 0x658, TK_V3, "m_WindAabbWorld[1].m_Min", ""},
    {"Wind AABBs (0x640)", 0x664, TK_V3, "m_WindAabbWorld[1].m_Max", ""},
    {"Wind AABBs (0x640)", 0x670, TK_V3, "m_WindAabbWorld[2].m_Min", ""},
    {"Wind AABBs (0x640)", 0x67C, TK_V3, "m_WindAabbWorld[2].m_Max", ""},
    {"Wind AABBs (0x640)", 0x688, TK_V3, "m_WindAabbWorld[3].m_Min", ""},
    {"Wind AABBs (0x640)", 0x694, TK_V3, "m_WindAabbWorld[3].m_Max", ""},
    {"Wind AABBs (0x640)", 0x6A0, TK_V3, "m_WindAabbWorld[4].m_Min", ""},
    {"Wind AABBs (0x640)", 0x6AC, TK_V3, "m_WindAabbWorld[4].m_Max", ""},
    {"Wind Activation AABBs (0x6B8)", 0x6B8, TK_V3, "m_WindActivationAabbWorld[0].m_Min", "CAABox[5]"},
    {"Wind Activation AABBs (0x6B8)", 0x6C4, TK_V3, "m_WindActivationAabbWorld[0].m_Max", ""},
    {"Wind Activation AABBs (0x6B8)", 0x6D0, TK_V3, "m_WindActivationAabbWorld[1].m_Min", ""},
    {"Wind Activation AABBs (0x6B8)", 0x6DC, TK_V3, "m_WindActivationAabbWorld[1].m_Max", ""},
    {"Wind Activation AABBs (0x6B8)", 0x6E8, TK_V3, "m_WindActivationAabbWorld[2].m_Min", ""},
    {"Wind Activation AABBs (0x6B8)", 0x6F4, TK_V3, "m_WindActivationAabbWorld[2].m_Max", ""},
    {"Wind Activation AABBs (0x6B8)", 0x700, TK_V3, "m_WindActivationAabbWorld[3].m_Min", ""},
    {"Wind Activation AABBs (0x6B8)", 0x70C, TK_V3, "m_WindActivationAabbWorld[3].m_Max", ""},
    {"Wind Activation AABBs (0x6B8)", 0x718, TK_V3, "m_WindActivationAabbWorld[4].m_Min", ""},
    {"Wind Activation AABBs (0x6B8)", 0x724, TK_V3, "m_WindActivationAabbWorld[4].m_Max", ""},
    {"Shape & Dimensions", 0x730, TK_F, "m_DesiredHeight", ""},
    {"Shape & Dimensions", 0x734, TK_F, "m_Height", ""},
    {"Shape & Dimensions", 0x738, TK_F, "m_BottomWindFieldRadius", ""},
    {"Shape & Dimensions", 0x73C, TK_F, "m_BottomWindFieldRadiusGrowth", ""},
    {"Shape & Dimensions", 0x740, TK_F, "m_BottomWindFieldRadiusStart", ""},
    {"Shape & Dimensions", 0x744, TK_F, "m_BottomInnerWallRatio", ""},
    {"Shape & Dimensions", 0x748, TK_F, "m_BottomInnerWallRatioGrowth", ""},
    {"Shape & Dimensions", 0x74C, TK_F, "m_BottomInnerWallRatioStart", ""},
    {"Shape & Dimensions", 0x750, TK_F, "m_ControlCurveJunctionHeightRatio", ""},
    {"Shape & Dimensions", 0x754, TK_F, "m_PreviousControlCurveJunctionHeightRatio", ""},
    {"Shape & Dimensions", 0x758, TK_F, "m_FlaringExponent", ""},
    {"Shape & Dimensions", 0x75C, TK_F, "m_FlaringScale", ""},
    {"Shape & Dimensions", 0x760, TK_F, "m_FlaringExponentGrowth", ""},
    {"Shape & Dimensions", 0x764, TK_F, "m_FlaringScaleGrowth", ""},
    {"Shape & Dimensions", 0x768, TK_F, "m_FlaringExponentStart", ""},
    {"Shape & Dimensions", 0x76C, TK_F, "m_FlaringScaleStart", ""},
    {"Shape & Dimensions", 0x770, TK_F, "m_BottomVerticalOffset", ""},
    {"Shape & Dimensions", 0x774, TK_F, "m_TopDistanceLagOnStart", ""},
    {"Shape & Dimensions", 0x778, TK_F, "m_TopHorizontalLagHalfLife", ""},
    {"Shape & Dimensions", 0x77C, TK_F, "m_TopVerticalLagHalfLife", ""},
    {"Formation & Growth", 0x780, TK_F, "m_FormationRatio", "Visual intensity (1.0 = instant, 0.0 = fade)"},
    {"Formation & Growth", 0x784, TK_F, "m_GrowthPercentage", ""},
    {"Key Points", 0x790, TK_V3, "m_TornadoOrigin", "Point3 - Anchor origin"},
    {"Key Points", 0x7A0, TK_V3, "m_PreviousTornadoOrigin", "Point3"},
    {"Key Points", 0x7B0, TK_V3, "m_TornadoBottom", "Point3"},
    {"Key Points", 0x7C0, TK_V3, "m_TornadoTop", "Point3"},
    {"VFX", 0x7D0, TK_F, "m_VfxRadiusMin", ""},
    {"VFX", 0x7D4, TK_F, "m_VfxRadiusMax", ""},
    {"VFX", 0x7D8, TK_F, "m_VfxRotationalWindSpeed", ""},
    {"VFX", 0x7DC, TK_F, "m_VfxOutwardWindSpeed", ""},
    {"VFX", 0x7E0, TK_F, "m_VfxUpwardWindSpeed", ""},
    {"VFX", 0x7E4, TK_F, "m_VfxFalloffExponent", ""},
    {"Ambient Occlusion", 0x7E8, TK_F, "m_AORadiusMultiplier", ""},
    {"Ambient Occlusion", 0x7EC, TK_F, "m_AOHeightMeters", ""},
    {"Ambient Occlusion", 0x7F0, TK_F, "m_AOFalloff", ""},
    {"Ambient Occlusion", 0x7F4, TK_F, "m_AOMaxShadows", ""},
    {"Ambient Occlusion", 0x7F8, TK_F, "m_AOVerticalOffset", ""},
    {"Destruction", 0x7FC, TK_F, "m_DestructionT_Buildings", ""},
    {"Destruction", 0x800, TK_F, "m_DestructionT_Vegetation", ""},
    {"Containers & Refs", 0x3E0, TK_VECNT, "m_FxOffsetModifiers (vector)", "element size unknown - byte span shown"},
    {"Containers & Refs", 0x500, TK_U64, "m_PointOnFunnelClosestToPlayerAtSameHeight", "TGameObjectRef (24B) - raw first qword"},
};

// Tornado VFX globals: exe .data statics (base = g_ExeBase, off = RVA).
// Values are read live; nothing is preset on startup.
static const TorField TOR_VFX_FIELDS[] = {
    {"Funnel Shape", 0x2AD4384, TK_F, "TornadoFunnelTwist", "Spiral twist rate of the vortex mesh (default ~12.0)"},
    {"Dust Cloud", 0x2AD439C, TK_F, "DustBottomRadiusScale", "Ground dust ring width multiplier (default ~1.3)"},
    {"Dust Cloud", 0x2AD43A0, TK_F, "DustTopRadiusScale", "Upper debris cloud width multiplier (default ~2.5)"},
    {"Cap Flare", 0x2AD43B4, TK_F, "CapFlaringExponent", "Shape curve of the top cloud flare (default ~3.0)"},
    {"Cap Flare", 0x2AD43B8, TK_F, "CapFlaringScale", "Top cloud flare width where the funnel enters the sky (default ~6.0)"},
    {"Funnel Wobble", 0x2AD43BC, TK_F, "FunnelDisplaceScale", "Funnel wobble / turbulent displacement width (default ~1.3)"},
};
static const size_t TOR_CTRL_N = sizeof(TOR_CTRL_FIELDS) / sizeof(TOR_CTRL_FIELDS[0]);
static const size_t TOR_OBJ_N  = sizeof(TOR_OBJ_FIELDS)  / sizeof(TOR_OBJ_FIELDS[0]);
static const size_t TOR_VFX_N  = sizeof(TOR_VFX_FIELDS)  / sizeof(TOR_VFX_FIELDS[0]);
static TorLiveCell s_TorCtrlCells[TOR_CTRL_N] = {};
static TorLiveCell s_TorObjCells[TOR_OBJ_N]  = {};
static TorLiveCell s_TorVfxCells[TOR_VFX_N]  = {};

// 1s live read. NEVER writes. Cells on hold (user editing) skip the tick.
static void TorCellsRefresh(uintptr_t base, const TorField* fld, TorLiveCell* cells, size_t n) {
    for (size_t k = 0; k < n; k++) {
        TorLiveCell& c = cells[k];
        if (c.hold) continue;                              // user interacting: block refresh for this cell
        uintptr_t a = base + fld[k].off;
        switch (fld[k].kind) {
            case TK_F:   c.valid = FastRead<float>(a, c.f[0]); break;
            case TK_I:   { int v = 0; c.valid = FastRead<int>(a, v); if (c.valid) c.i = v; } break;
            case TK_U:   { uint32_t v = 0; c.valid = FastRead<uint32_t>(a, v); if (c.valid) c.i = v; } break;
            case TK_B:   { uint8_t v = 0; c.valid = FastRead<uint8_t>(a, v); if (c.valid) c.i = v; } break;
            case TK_U16: { uint16_t v = 0; c.valid = FastRead<uint16_t>(a, v); if (c.valid) c.i = v; } break;
            case TK_V3:  c.valid = FastRead<float>(a, c.f[0]) && FastRead<float>(a + 4, c.f[1]) && FastRead<float>(a + 8, c.f[2]); break;
            case TK_PTR: case TK_U64: { uintptr_t v = 0; c.valid = FastRead<uintptr_t>(a, v); if (c.valid) c.i = (int64_t)v; } break;
            case TK_VECNT: {
                uintptr_t bgn = 0, end = 0;
                c.valid = FastRead<uintptr_t>(a, bgn) && FastRead<uintptr_t>(a + 8, end);
                if (c.valid) c.i = (int64_t)(end - bgn);   // byte span only (element size not always known)
            } break;
        }
    }
}

// Renders one field table with per-group dropdowns. Writes ONLY on explicit edit.
static void TorFieldWidgets(const TorField* fld, size_t n, TorLiveCell* cells, uintptr_t base, bool doRefresh) {
    if (!base) { ImGui::TextDisabled("Not located yet - all fields stay blocked until the object is found."); return; }
    if (doRefresh) TorCellsRefresh(base, fld, cells, n);
    const char* grp = nullptr;
    bool grpOpen = false;
    for (size_t k = 0; k < n; k++) {
        if (!grp || strcmp(fld[k].grp, grp) != 0) {
            grp = fld[k].grp;
            ImGui::Spacing();
            if (k == 0) ImGui::SetNextItemOpen(true, ImGuiCond_Once);
            grpOpen = ImGui::CollapsingHeader(grp);        // dropdown per group
        }
        if (!grpOpen) continue;

        TorLiveCell& c = cells[k];
        uintptr_t a = base + fld[k].off;
        ImGui::PushID((int)k);
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(fld[k].name);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("+0x%03X%s%s", (unsigned)fld[k].off,
                              (fld[k].note && fld[k].note[0]) ? "\n" : "",
                              (fld[k].note && fld[k].note[0]) ? fld[k].note : "");
        ImGui::SameLine(250.0f * g_UIScale);
        ImGui::SetNextItemWidth(-80.0f * g_UIScale);

        if (!c.valid) {
            // Still recollecting: BLOCKED - no widget, no possible write (corruption guard)
            ImGui::BeginDisabled();
            ImGui::TextDisabled("[ collecting ]");
            ImGui::EndDisabled();
        } else switch (fld[k].kind) {
            case TK_F:
                if (ImGui::InputFloat("##v", &c.f[0], 0.0f, 0.0f, "%.3f")) FastWrite<float>(a, c.f[0]);
                break;
            case TK_V3:
                if (ImGui::InputFloat3("##v", c.f, "%.3f")) {
                    FastWrite<float>(a, c.f[0]); FastWrite<float>(a + 4, c.f[1]); FastWrite<float>(a + 8, c.f[2]);
                }
                break;
            case TK_I: {
                int v = (int)c.i;
                if (ImGui::InputInt("##v", &v, 0, 0)) { c.i = v; FastWrite<int>(a, v); }
                break; }
            case TK_U: {
                int v = (int)c.i; if (v < 0) v = 0;
                if (ImGui::InputInt("##v", &v, 0, 0)) { if (v < 0) v = 0; c.i = v; FastWrite<uint32_t>(a, (uint32_t)v); }
                break; }
            case TK_U16: {
                int v = (int)c.i; if (v < 0) v = 0; if (v > 0xFFFF) v = 0xFFFF;
                if (ImGui::InputInt("##v", &v, 0, 0)) {
                    if (v < 0) v = 0; if (v > 0xFFFF) v = 0xFFFF;
                    c.i = v; FastWrite<uint16_t>(a, (uint16_t)v);
                }
                break; }
            case TK_B: {
                bool b = (c.i != 0);
                if (ImGui::Checkbox("##v", &b)) { c.i = b ? 1 : 0; FastWrite<uint8_t>(a, (uint8_t)c.i); }
                break; }
            case TK_PTR: case TK_U64:
                ImGui::TextDisabled("0x%016llX", (unsigned long long)c.i);
                break;
            case TK_VECNT: {
                uintptr_t bgn = 0, end = 0;
                if (FastRead<uintptr_t>(a, bgn) && FastRead<uintptr_t>(a + 8, end))
                    ImGui::TextDisabled("span %lld B  (0x%llX -> 0x%llX)", (long long)c.i,
                                        (unsigned long long)bgn, (unsigned long long)end);
                else
                    ImGui::TextDisabled("span %lld B", (long long)c.i);
                break; }
        }
        if (fld[k].kind != TK_PTR && fld[k].kind != TK_U64 && fld[k].kind != TK_VECNT && c.valid)
            c.hold = ImGui::IsItemActive();                // suspend this cell's refresh while typing
        ImGui::SameLine();
        ImGui::TextDisabled("+0x%03X", (unsigned)fld[k].off);
        ImGui::PopID();
    }
}

// Raw hex dump: covers EVERY "??" unnamed byte region (obj 0x000-0x2CF, 0x438-0x43F,
// 0x788-0x78F, 0x804-0x80F; ctrl 0x000-0x1CF). Read-only, 1s refresh, never written.
static void TorRawHexDump(int slot, uintptr_t base, size_t len) {
    static uint8_t   buf[2][0x820];
    static DWORD     last[2]   = {0, 0};
    static bool      ok[2]     = {false, false};
    static uintptr_t cached[2] = {0, 0};
    if (base && (base != cached[slot] || GetTickCount() - last[slot] >= 1000)) {
        cached[slot] = base;
        last[slot] = GetTickCount();
        ok[slot] = (ReadProcessMemory(GetCurrentProcess(), (void*)base, buf[slot], len, NULL) != FALSE);
    }
    if (!base || !ok[slot]) { ImGui::TextDisabled("    no data yet"); return; }
    ImGui::BeginChild(slot ? "torRawObj" : "torRawCtrl", ImVec2(0.0f, 260.0f * g_UIScale), true);
    char line[96];
    for (size_t row = 0; row < len; row += 16) {
        size_t nn = (len - row < 16) ? (len - row) : 16;
        int p = snprintf(line, sizeof(line), "%04X  ", (unsigned)row);
        if (p < 0 || p >= (int)sizeof(line) - 1) continue;
        for (size_t j = 0; j < 16; j++) {
            if (p >= (int)sizeof(line) - 4) break;
            if (j < nn) p += snprintf(line + p, sizeof(line) - p, "%02X ", buf[slot][row + j]);
            else        p += snprintf(line + p, sizeof(line) - p, "   ");
            if (p < 0 || p >= (int)sizeof(line) - 4) { p = (int)sizeof(line) - 4; break; }
        }
        if (p < (int)sizeof(line) - 2) line[p++] = ' ';
        if (p < (int)sizeof(line) - 2) line[p++] = '|';
        for (size_t j = 0; j < nn && p < (int)sizeof(line) - 2; j++) {
            uint8_t ch = buf[slot][row + j];
            line[p++] = (ch >= 0x20 && ch < 0x7F) ? (char)ch : '.';
        }
        if (p < (int)sizeof(line) - 2) line[p++] = '|';
        line[p] = '\0';
        ImGui::TextUnformatted(line);
    }
    ImGui::EndChild();
}

// ---- Simple mode: end-user quick controls (shown when advanced mode is OFF) ----
// live 1s read, writes only on edit, blocked until
// first successful read, editing suspends the refresh. Extra per-field LOCK re-applies
// the locked value on every 1s tick (oxygen-lock pattern) because the game's formation/growth
// system rewrites several of these fields continuously.
static bool g_TorAdvancedMode = false;               // "Show all variables (advanced mode)"
static float s_TorSizeMult = 1.0f;                   // relative size multiplier (no baseline captured)

struct TorSimpleCell { float val; bool valid, hold, lock; };
enum {
    TSS_STATE, TSS_MOVEMENT, TSS_SPEED, TSS_HEIGHT, TSS_WIDTH, TSS_FLARE, TSS_PULL, TSS_SPIN, TSS_UPDRAFT,
    TSS_INTENSITY, TSS_DMG, TSS_DMGPLY, TSS_COUNT
};
static const struct { int base; uintptr_t off; bool is_int; const char* label; const char* pdb; const char* note; } TOR_SIMPLE[] = {
    {0, 0x228, true,  "Tornado State / Status",       "State",             "1 = Active Roaming, 4 = Dissipating, 5 = Inactive"},
    {0, 0x22C, true,  "Tornado Movement Mode",        "Movement",          "Movement mode (2 = Target Steering)"},
    {0, 0x270, false, "Movement speed",               "MovementSpeed",     "How fast the tornado roams the map."},
    {1, 0x730, false, "Height (target)",              "TargetHeight",      "Target funnel height in meters; the game eases toward it."},
    {1, 0x738, false, "Funnel width / pull radius",   "FunnelRadius",      "Base radius of the funnel and its wind field."},
    {1, 0x75C, false, "Top flare width",              "FlareScale",        "How much wider the funnel flares out at the top."},
    {1, 0x518, false, "Pull force (suction)",         "SuctionSpeed",      "Inward wind speed toward the core."},
    {1, 0x51C, false, "Spin force",                   "TangentialSpeed",   "Tangential rotational wind speed."},
    {1, 0x520, false, "Updraft force",                "VerticalSpeed",     "Vertical lift wind speed."},
    {1, 0x780, false, "Formation Ratio",             "VisualIntensity",   "Formation ratio (0.0 to 1.0)."},
    {1, 0x424, false, "Damage per second",            "EntityDamage",      "Damage dealt to objects inside the funnel."},
    {1, 0x428, false, "Damage to players",            "PlayerDamage",      "Damage dealt to the player inside the funnel."},
};
static TorSimpleCell s_TorSimple[TSS_COUNT] = {};

// Relative size multiplier: scales the CURRENT live values by the slider delta, so 1.00x
// always means "whatever the game has right now". No baseline is captured, nothing is
// written on startup or when a tornado (re)spawns.
static void TorApplySizeMultiplier(float oldM, float newM) {
    if (!g_TorObject || oldM <= 0.0f || newM <= 0.0f || oldM == newM) return;
    const uintptr_t offs[] = { 0x730, 0x734, 0x738, 0x75C, 0x7D0, 0x7D4 }; // height x2, base radius, flare, vfx radii
    float k = newM / oldM;
    for (uintptr_t o : offs) {
        float v = 0.0f;
        if (FastRead<float>(g_TorObject + o, v)) FastWrite<float>(g_TorObject + o, v * k);
    }
}

static void TorSimplePanel(bool doRefresh) {
    if (!g_TorController || !g_TorObject) {
        ImGui::TextDisabled("Controls appear once the tornado controller/object are located (in-game).");
        return;
    }
    // Re-located pair = new instance: reset cells AND locks so a stale value is never
    // written into the new object. The multiplier also resets (new reference size).
    static uintptr_t s_SimpleCtrl = 1, s_SimpleObj = 1;
    if (g_TorController != s_SimpleCtrl || g_TorObject != s_SimpleObj) {
        s_SimpleCtrl = g_TorController;
        s_SimpleObj = g_TorObject;
        memset(s_TorSimple, 0, sizeof(s_TorSimple));
        s_TorSizeMult = 1.0f;
    }

    // --- size multiplier (relative scaling; live values, no hardcoded baseline) ---
    float m = s_TorSizeMult;
    ImGui::SetNextItemWidth(-100.0f * g_UIScale);
    if (ImGui::SliderFloat("Size multiplier", &m, 0.25f, 4.0f, "%.2fx")) {
        TorApplySizeMultiplier(s_TorSizeMult, m);
        s_TorSizeMult = m;
    }
    ImGui::TextDisabled("    Scales the size of the whole tornado. ");
    ImGui::TextDisabled("    Warning: May introduce effect glitches, tweak with caution. ");
    ImGui::TextDisabled("    It's recommended to set its size by increasing 'Funnel width / Pull Radius' instead.");
    ImGui::Spacing();

    for (int k = 0; k < TSS_COUNT; k++) {
        TorSimpleCell& c = s_TorSimple[k];
        uintptr_t base = TOR_SIMPLE[k].base ? g_TorObject : g_TorController;
        uintptr_t a = base + TOR_SIMPLE[k].off;
        if (doRefresh) {
            if (c.lock && !c.hold) {
                if (TOR_SIMPLE[k].is_int) FastWrite<uint32_t>(a, (uint32_t)c.val);
                else FastWrite<float>(a, c.val);
            }
            else if (!c.hold) {
                if (TOR_SIMPLE[k].is_int) {
                    uint32_t iv = 0;
                    c.valid = FastRead<uint32_t>(a, iv);
                    if (c.valid) c.val = (float)iv;
                } else {
                    c.valid = FastRead<float>(a, c.val);
                }
            }
        }
        ImGui::PushID(k);
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(TOR_SIMPLE[k].label);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", TOR_SIMPLE[k].note);
        ImGui::SameLine(270.0f * g_UIScale);
        ImGui::SetNextItemWidth(-110.0f * g_UIScale);
        if (!c.valid) {
            ImGui::BeginDisabled();
            ImGui::TextDisabled("[ collecting ]");
            ImGui::EndDisabled();
        } else {
            if (TOR_SIMPLE[k].is_int) {
                int iv = (int)c.val;
                if (ImGui::InputInt("##v", &iv, 1, 1)) {
                    c.val = (float)iv;
                    FastWrite<uint32_t>(a, (uint32_t)iv);
                }
            } else {
                if (ImGui::InputFloat("##v", &c.val, 0.0f, 0.0f, "%.2f")) FastWrite<float>(a, c.val);
            }
            c.hold = ImGui::IsItemActive();
            ImGui::SameLine();
            if (ImGui::Checkbox("Lock", &c.lock) && c.lock) {
                if (TOR_SIMPLE[k].is_int) FastWrite<uint32_t>(a, (uint32_t)c.val);
                else FastWrite<float>(a, c.val);
            }
        }
        ImGui::PopID();
    }
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.85f, 0.75f, 0.40f, 1.0f));
    ImGui::TextWrapped("Note: If the tornado gets stuck, stops moving, or refuses to follow controls, set both 'Tornado State / Status' and 'Tornado Movement Mode' to 4, check 'Lock', then despawn and spawn the tornado again. Warning: this will make the tornado go into a straight line.");
    ImGui::PopStyleColor();
}

// ---- the Tornado tab ----
static void DrawSectionHeader(const char* title); // defined later in UI HELPERS
void DrawTornadoTab() {
    if (!g_TorBindsLoaded) TorLoadBinds();

    ImGui::Text("Hooks: %s", (g_TorHook1Addr && g_TorHook2Addr) ? "installed" : "not installed");
    ImGui::Text("Controller: %s   Object: %s",
                g_TorController ? "found" : "not found", g_TorObject ? "found" : "not found");
    ImGui::SameLine();
    if (ImGui::SmallButton("Re-locate")) g_TorForceRelocate = true; // runs on TorLocateThread, not the render thread
    ImGui::Text("Tornado position: %.1f  %.1f  %.1f", g_TorCurPos[0], g_TorCurPos[1], g_TorCurPos[2]);

    DrawSectionHeader("Spawn Mode");

    // --- non-mutual spawn-mode toggles (instant = default true) ---
    bool inst = g_TorInstantSpawn;
    if (ImGui::Checkbox("Make tornadoes spawn instantly", &inst)) { g_TorInstantSpawn = inst; g_TorSmoothSpawn = !inst; }
    TorKeybindWidget("kb_spawn_instant", TB_SPAWN_INSTANT);
    bool smooth = g_TorSmoothSpawn;
    if (ImGui::Checkbox("Make tornadoes spawn smoothly", &smooth)) { g_TorSmoothSpawn = smooth; g_TorInstantSpawn = !smooth; }
    TorKeybindWidget("kb_spawn_smooth", TB_SPAWN_SMOOTH);
    DrawSectionHeader("Crosshair Control");

    // --- non-mutual crosshair modes (both default false) ---
    bool follow = g_TorAimGuide;
    if (ImGui::Checkbox("Make tornado follow smoothly the player's crosshair", &follow)) {
        g_TorAimGuide = follow; if (follow) g_TorTeleportToAim = false;
    }
    TorKeybindWidget("kb_follow", TB_FOLLOW);
    bool tp = g_TorTeleportToAim;
    if (ImGui::Checkbox("Make tornado teleport instantly to player's crosshair", &tp)) {
        g_TorTeleportToAim = tp; if (tp) g_TorAimGuide = false;
    }
    TorKeybindWidget("kb_teleport", TB_TELEPORT);
    bool frz = g_TorFreezeInPlace;
    if (ImGui::Checkbox("Freeze tornado in place", &frz)) g_TorFreezeInPlace = frz;
    TorKeybindWidget("kb_freeze", TB_FREEZE);
    ImGui::SameLine();
    ImGui::TextDisabled("[ ? ]");
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Game-object-level position freeze (hook 2): if the crosshair modes above\n"
                          "are off, the tornado's position is pinned to its last known spot.");
    DrawSectionHeader("Actions");

    // --- buttons ---
    if (ImGui::Button("Spawn tornado at default location (zona tres)")) TorAction(TB_SPAWN_DEFAULT);
    TorKeybindWidget("kb_spawn_default", TB_SPAWN_DEFAULT);
    if (ImGui::Button("Spawn tornado at player crosshair")) TorAction(TB_SPAWN_CROSSHAIR);
    TorKeybindWidget("kb_spawn_crosshair", TB_SPAWN_CROSSHAIR);
    if (ImGui::Button("Despawn tornado instantly")) TorAction(TB_DESPAWN_NOW);
    TorKeybindWidget("kb_despawn_now", TB_DESPAWN_NOW);
    if (ImGui::Button("Despawn tornado smoothly (fade)")) TorAction(TB_DESPAWN_FADE);
    TorKeybindWidget("kb_despawn_fade", TB_DESPAWN_FADE);
    DrawSectionHeader("Fade Durations");

    // --- fade durations (defaults 10s) ---
    ImGui::InputFloat("Tornado spawn fade duration", &g_TorFadeSpawnDuration);
    ImGui::TextDisabled("    Duration in seconds for the spawn formation animation");
    ImGui::InputFloat("Tornado despawn fade duration", &g_TorFadeDespawnDuration);
    ImGui::TextDisabled("    Duration in seconds for the dissipation animation");
    DrawSectionHeader("Navigation & Follow Settings");

    ImGui::InputFloat("fManualSpeed", &g_TorManualSpeed);
    ImGui::TextDisabled("    Speed of the smooth crosshair follow");
    ImGui::InputFloat("fAimDistance", &g_TorAimDistance);
    ImGui::TextDisabled("    Distance used when falling back to the camera aim");
    ImGui::InputFloat("fFrontSpawnDistance", &g_TorFrontSpawnDistance);
    ImGui::TextDisabled("    Distance in front of the player used by the fallback spawn");
    ImGui::InputFloat("fDeadzone", &g_TorDeadzone);
    ImGui::TextDisabled("    Stop-distance threshold for the smooth follow");
    ImGui::InputFloat3("vCustomSpawnCoords", g_TorCustomSpawn);
    ImGui::TextDisabled("    Custom spawn coordinates (used by custom-coords spawn path)");
        DrawSectionHeader("Tornado Controls");

    // Advanced-mode toggle: OFF = friendly quick controls; ON = full field browser.
    ImGui::Checkbox("Show all variables (advanced mode)", &g_TorAdvancedMode);
    ImGui::Spacing();

    // 1s live refresh. Cells with no data yet are BLOCKED; cells being edited skip the tick.
    static DWORD s_TorFieldTick = 0;
    bool doRefresh = (GetTickCount() - s_TorFieldTick >= 1000);
    if (doRefresh) s_TorFieldTick = GetTickCount();

    if (!g_TorAdvancedMode) {
        TorSimplePanel(doRefresh);                    // end-user quick controls
        return;
    }

    // If the pair was healed / re-located, drop ALL cached cells so every field returns to
    // the blocked "collecting" state until it is re-read from the NEW object (no stale writes).
    static uintptr_t s_CellsCtrlBase = 0, s_CellsObjBase = 0;
    if (g_TorController != s_CellsCtrlBase) { s_CellsCtrlBase = g_TorController; memset(s_TorCtrlCells, 0, sizeof(s_TorCtrlCells)); }
    if (g_TorObject     != s_CellsObjBase)  { s_CellsObjBase  = g_TorObject;     memset(s_TorObjCells,  0, sizeof(s_TorObjCells));  }

    if (ImGui::CollapsingHeader("CTornadoController (live, 1s refresh)")) {
        TorFieldWidgets(TOR_CTRL_FIELDS, TOR_CTRL_N, s_TorCtrlCells, g_TorController, doRefresh);
        if (ImGui::CollapsingHeader("Controller Raw Hex Dump (0x000 - 0x2FF)"))
            TorRawHexDump(0, g_TorController, 0x300);
    }
    if (ImGui::CollapsingHeader("CTornadoObject (live, 1s refresh)")) {
        TorFieldWidgets(TOR_OBJ_FIELDS, TOR_OBJ_N, s_TorObjCells, g_TorObject, doRefresh);
        if (ImGui::CollapsingHeader("Object Raw Hex Dump (0x000 - 0x80F)"))
            TorRawHexDump(1, g_TorObject, 0x810);
    }
    if (ImGui::CollapsingHeader("Tornado VFX Globals (Live 1s Refresh)")) {
        TorFieldWidgets(TOR_VFX_FIELDS, TOR_VFX_N, s_TorVfxCells, g_ExeBase, doRefresh);
    }
}

// A real game object has a vtable pointer that lives inside JustCause4.exe.
// Freed / non-vehicle / streamed-out objects will fail this almost every time.
static bool IsLikelyGameObject(uintptr_t obj) {
    if (!g_ExeBase) return false;
    if (obj < 0x10000 || (obj & 0x7) != 0) return false;           // must be 8-byte aligned
    uintptr_t vtbl = 0;
    if (!FastRead<uintptr_t>(obj, vtbl)) return false;             // unmapped -> bail
    if (vtbl < g_ExeBase || vtbl >= g_ExeBase + g_Addr_10000000) return false;
    uintptr_t firstFn = 0;
    if (!FastRead<uintptr_t>(vtbl, firstFn)) return false;
    return (firstFn >= g_ExeBase && firstFn < g_ExeBase + g_Addr_10000000);
}

static uintptr_t GetPlayerVehiclePtr() {
    if (!g_ExeBase) return 0;
    
    // 1. Get Camera Position (Render Camera) to find the closest vehicle
    uintptr_t cameraManager = 0;
    FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cameraManager);
    if (!cameraManager) return 0;
    
    float m[16] = {0};
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)(cameraManager + 0x500), m, sizeof(m), NULL)) return 0;
    float cx = m[12], cy = m[13], cz = m[14];
    
    // 2. Iterate through simulated vehicles vector
    uintptr_t m_GameObjects_Addr = g_ExeBase + g_Addr_2CB1938;
    uintptr_t myFirst = 0, myLast = 0;
    if (!FastRead<uintptr_t>(m_GameObjects_Addr + 0x0, myFirst) || 
        !FastRead<uintptr_t>(m_GameObjects_Addr + 0x8, myLast) || 
        !myFirst || myLast < myFirst) return 0;
        
    size_t count = (myLast - myFirst) / 8;
    if (count > 2000) count = 2000;
    
    uintptr_t closestVehicle = 0;
    float minDistance = 15.0f; // Must be within 15 meters of camera to be player's car
    
    for (size_t i = 0; i < count; i++) {
            uintptr_t vehiclePtr = 0;
            if (!FastRead<uintptr_t>(myFirst + (i * 8), vehiclePtr) || !vehiclePtr) continue;
            if (!IsLikelyGameObject(vehiclePtr)) continue; // skip freed / non-object entries
        
        float vx = 0, vy = 0, vz = 0;
        if (!FastRead<float>(vehiclePtr + 0x644, vx) ||
            !FastRead<float>(vehiclePtr + 0x648, vy) ||
            !FastRead<float>(vehiclePtr + 0x64C, vz)) continue;
            
        float dx = vx - cx;
        float dy = vy - cy;
        float dz = vz - cz;
        float dist = std::sqrt(dx*dx + dy*dy + dz*dz);
        
        if (dist < minDistance) {
            minDistance = dist;
            closestVehicle = vehiclePtr;
        }
    }
    return closestVehicle;
}

static std::string GetESPClassName(uintptr_t objPtr); // Forward declaration

// Helper to safely send events by copying the string literal to a writable buffer
static void TriggerEvent(const char* eventName) {
    if (!o_SendEvent) return;
    char buf[256];
    strncpy_s(buf, eventName, sizeof(buf));
    o_SendEvent(buf, nullptr);
}
// ============================================================================
// AOB PATTERN SCANNER
// ============================================================================
uintptr_t PatternScan(uintptr_t moduleBase, const char* signature) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
    DWORD sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

    auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + strlen(pattern);
        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?') ++current;
                bytes.push_back(-1);
            } else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    auto patternBytes = pattern_to_byte(signature);
    uint8_t* scanBytes = reinterpret_cast<uint8_t*>(moduleBase);
    size_t s = patternBytes.size();
    int* d = patternBytes.data();

    for (size_t i = 0; i < sizeOfImage - s; ++i) {
        bool found = true;
        for (size_t j = 0; j < s; ++j) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) { found = false; break; }
        }
        if (found) return reinterpret_cast<uintptr_t>(&scanBytes[i]);
    }
    return 0;
}

// ============================================================================
// WINGSUIT FIELD DEFINITIONS (std::map = auto alphabetical sort)
// ============================================================================
struct WingsuitField {
    uintptr_t offset;
    int num_values;          // 1, 2, 3, or 5
    bool is_u32;
    float defaults[5];
    float current[5];
    uint32_t current_u32;
    uint32_t default_u32;
};

static std::map<std::string, WingsuitField> g_WingsuitSettings;
static bool g_WingsuitInitialized = false;
// ============================================================================
// WEATHER FIELD DEFINITIONS
// ============================================================================
struct WeatherVar {
    uintptr_t offset;
    enum Type { Float, Bool, Int, UInt } type;
    float f_def, f_cur;
    bool b_def, b_cur;
    int i_def, i_cur;
    bool modified = false;
};

static std::map<std::string, WeatherVar> g_WeatherSettings;
static bool g_WeatherInitialized = false;

void InitWeatherSettings() {
    if (g_WeatherInitialized) return;
    g_WeatherInitialized = true;

    auto addF = [](const char* name, uintptr_t off, float def) {
        WeatherVar v = {}; v.offset = JRVA(off); v.type = WeatherVar::Float; v.f_def = def; v.f_cur = def; g_WeatherSettings[name] = v;
    };
    auto addB = [](const char* name, uintptr_t off, bool def) {
        WeatherVar v = {}; v.offset = JRVA(off); v.type = WeatherVar::Bool; v.b_def = def; v.b_cur = def; g_WeatherSettings[name] = v;
    };
    auto addI = [](const char* name, uintptr_t off, int def) {
        WeatherVar v = {}; v.offset = JRVA(off); v.type = WeatherVar::Int; v.i_def = def; v.i_cur = def; g_WeatherSettings[name] = v;
    };
    auto addU = [](const char* name, uintptr_t off, uint32_t def) {
        WeatherVar v = {}; v.offset = JRVA(off); v.type = WeatherVar::UInt; v.i_def = def; v.i_cur = def; g_WeatherSettings[name] = v;
    };

    // === SUN SHADOW CASCADE & DISTANCE PARAMETERS ===
    // Vanilla m_SunOriginalShadowRadius (0x142AE9720): [3.0, 18.0, 110.0, 800.0, 1200.0, 4000.0]
    addF("Shadow_Cascade0_Radius", 0x2AE9720, 3.0f);
    addF("Shadow_Cascade1_Radius", 0x2AE9724, 18.0f);
    addF("Shadow_Cascade2_Radius", 0x2AE9728, 110.0f);
    addF("Shadow_Cascade3_Radius", 0x2AE972C, 800.0f);
    addF("Shadow_Cascade4_Radius (Far)", 0x2AE9730, 1200.0f);
    addF("Shadow_Cascade5_Radius", 0x2AE9734, 4000.0f);

    addF("Shadow_SunDepth", 0x2AE9780, 1250.0f);
    addF("Shadow_SunDepthTarget", 0x2AE9784, 1600.0f);

    addF("Shadow_Cascade0_FOVScale", 0x2AE9768, 1.0f);
    addF("Shadow_Cascade1_FOVScale", 0x2AE976C, 1.0f);
    addF("Shadow_Cascade2_FOVScale", 0x2AE9770, 1.0f);
    addF("Shadow_Cascade3_FOVScale", 0x2AE9774, 1.0f);
    addF("Shadow_Cascade4_FOVScale", 0x2AE9778, 1.0f);

    addB("Shadow_EnableBillboardShadows", 0x2AD0FD0, true);
    addB("Shadow_EnableLayer0", 0x2CAD8BA, true);

    addB("WeatherSimEnabled", 0x2AD4410, true);
    addB("TornadoEnabled", 0x2AD4365, true);
    addF("CloudDensityMultiplier", 0x2AD4584, 1.0f);
    addB("CloudShadowEnabled", 0x2AD44C0, true);
    addF("SunIntensity", 0x2AD4434, 120.0f);
    addF("MoonIntensity", 0x2AD4438, 0.053f);
    addF("AerialPerspectiveScale", 0x2AD4440, 2.0f);
    addF("AerialPerspectiveStartDistance", 0x2AD4444, 0.0f);
    addF("HeightFogDensity", 0x2AD444C, 1.0f);
    addF("HeightFogForwardScatteringModulator", 0x2AD4450, 0.742949f);
    addF("HeightFogFalloffScale", 0x2AD4454, 5.40804f);
    addF("HeightFogInscatteringMultiplier", 0x2AD4458, 0.399358f);
    addF("HeightFogExtinctionMultiplier", 0x2AD445C, 0.015f);
    addF("HeightFogHorizonScatteringBlendScale", 0x2AD4460, 0.836265f);
    addF("SunDiskAngularRadius", 0x2AD4470, 0.545f);
    addF("SunDiskIntensity", 0x2AD4474, 120000.0f);
    addF("MoonlightScatteringFadeInAngle", 0x2AD4484, 0.05f);
    addF("MoonlightScatteringFullContributionAngle", 0x2AD4488, 0.12f);
    addF("MoonlightScatteringSunPosToEnableAngle", 0x2AD448C, -0.1f);
    addB("EnableMoonlightScattering", 0x2AD4490, true);
    addB("EnableSunMoonTransitionTuning", 0x2AD4491, true);
    addB("EnableAPHorizonMap", 0x2AD449C, true);
    addB("EnableAerialPerspective", 0x2AD449D, true);
    addF("RayleighMultiplier", 0x2AD44A4, 1.0f);
    addF("MieMultiplier", 0x2AD44A8, 1.0f);
    addF("OzoneLevel", 0x2AD44AC, 1.0f);
    addF("RayleighHeightScaleMultiplier", 0x2AD44B0, 1.0f);
    addF("MieHeightScaleMultiplier", 0x2AD44B4, 1.0f);
    addF("TweakMieForwardScatteringFactor", 0x2AD44B8, 0.8f);
    addF("DebugBrightnessAdjustment", 0x2AD44F0, 1.0f);
    addF("WeatherMapCoverageMultiplier", 0x2AD44F4, 1.0f);
    addF("WeatherMapCloudTypeMultiplier", 0x2AD44F8, 1.0f);
    addF("WeatherMapPrecipitationMultiplier", 0x2AD44FC, 1.0f);
    addB("EnableRandomizedCoverageTest", 0x2AD4501, true);
    addB("EnableRandomizedCloudTypeTest", 0x2AD4502, true);
    addB("EnableRandomizedPrecipitationTest", 0x2AD4503, true);
    addB("EnableHorizonClipping", 0x2AD4504, true);
    addB("EnableSeaLevelAltitudeAdjustment", 0x2AD4505, true);
    addB("EnablePreMultipliedAlphaBlending", 0x2AD4506, true);
    addB("EnableNewDetailErosion", 0x2AD4507, true);
    addB("EnableDetailErosion", 0x2AD4508, true);
    addB("EnableCurlTurbulence", 0x2AD4509, true);
    addB("EnableLightConeSampling", 0x2AD450A, true);
    addB("EnableFarDistShadowSampling", 0x2AD450B, true);
    addB("EnableTwoLobePhaseFunc", 0x2AD450C, true);
    addB("EnableViewDependentSampleCount", 0x2AD450D, true);
    addB("EnableBilateralUpsampling", 0x2AD450E, true);
    addB("EnableFadeDistance", 0x2AD450F, true);
    addB("EnableMaxRayMarchDistance", 0x2AD4510, true);
    addB("EnableMaxRayMarchDistanceClamp", 0x2AD4511, true);
    addB("EnableRayMarchDistanceAutoAdjustment", 0x2AD4512, true);
    addB("EnablePowderTerm", 0x2AD4513, true);
    addB("EnableLowTransmittanceSnapping", 0x2AD4514, true);
    addB("EnableMinMaxBounds", 0x2AD4515, true);
    addB("EnableTransmittanceBuffer", 0x2AD4516, true);
    addB("EnableCloudReflections", 0x2AD4517, true);
    addF("TransmittanceBuffer_DensityMultiplier", 0x2AD451C, 4.0f);
    addF("MaxLightConeDistance", 0x2AD457C, 200.0f);
    addF("CloudscapeFadeDistance", 0x2AD4580, 35000.0f);
    addF("PlanetRadiusScale", 0x2AD458C, 0.2f);
    addF("ScatteringCoeff", 0x2AD4590, 0.125f);
    addF("ExtinctionCoeff", 0x2AD4594, 0.055f);
    addF("LowTransmittanceSnapThreshold", 0x2AD4598, 0.1f);
    addB("EnableMultipleScattering", 0x2AD459C, true);
    addF("CloudShadowMaxRayMarchDistance", 0x2AD45A4, 1000.0f);
    addF("CloudShadowDensityMultiplier", 0x2AD45A8, 1.2f);
    addF("HighAltitudeWindOffset", 0x2AD45B8, 900.0f);
    addF("MagicSilverLiningIntensity", 0x2AD45BC, 1.0f);
    addF("MagicSilverLiningSpread", 0x2AD45C0, 0.5f);
    addF("WindGustStrengthMin", 0x2AD43F8, 1.0f);
    addF("WindGustStrengthMax", 0x2AD43FC, 10.0f);
    addF("EnvironmentWindGustStrengthMin", 0x2AD4400, 0.5f);
    addF("EnvironmentWindGustStrengthMax", 0x2AD4404, 1.0f);
    addF("WindStrength", 0x2AD441C, 3.0f);
    addF("EventRadius", 0x2AD4424, 0.1f);
    addF("WeatherWindClamp", 0x2AD4428, 30.0f);
    addF("WeatherWindScale", 0x2AD442C, 0.1f);
    addU("PhasesPerFrame", 0x2AD4430, 1);
    addF("MaxLightningDurationSeconds", 0x2AD4324, 0.1f);
    addB("LightningBoltGenerateBranches", 0x2AD4328, true);
    addF("LightningSpawnRadiusMultiplier", 0x2AD432C, 7.0f);
    addF("MaxLightningSpawnTime", 0x2AD4330, 1.0f);
    addF("LightningPointlightCullingDistance", 0x2AD4334, 500.0f);
    addF("LightningPointlightRadius", 0x2AD4338, 200.0f);
    addB("LightningPointlightEnabled", 0x2AD433C, true);
    addB("LightningSpotlightEnabled", 0x2AD433D, true);
    addB("LightningEnableAmbient", 0x2AD433E, true);
    addB("LightningEnableBolts", 0x2AD433F, true);
    addF("LightningCloudRadius", 0x2AD4348, 1500.0f);
    addF("LightningCloudRadiusVariance", 0x2AD434C, 150.0f);
    addF("LightningPointlightScale", 0x2AD4350, 100000.0f);
    addF("LightningEmissiveScale", 0x2AD4354, 5000.0f);
    addU("TornadoManagerClearFrames", 0x2AD4358, 0);
    addF("Weather_Blend_Time_Max", 0x2AD435C, 1.0f);
    addB("tornado_use_height_as_parameter_and_y", 0x2AD4364, true);
    addF("TimeScale", 0x2AD4368, 1.0f);
    addU("Sides", 0x2AD436C, 32);
    addU("HeightDivisions", 0x2AD4370, 96);
    addU("TornadoRaymarchMeshSides", 0x2AD4374, 32);
    addU("TornadoCachePointCount", 0x2AD4378, 32);
    addF("TornadoRaymarchMeshNormaliz", 0x2AD437C, 1.0f);
    addB("TornadoWriteDepth", 0x2AD4380, true);
    addF("TornadoFunnelTwist", 0x2AD4384, 12.0f);
    addF("GrowthTimeScale", 0x2AD4388, 0.55f);
    addB("Fullscreen_Raymarch", 0x2AD438C, false);
    addB("EnableTornadoVoxelization", 0x2AD438D, true);
    addB("ShowTornadoFunnel", 0x2AD438E, true);
    addB("ShowTornadoDust", 0x2AD438F, true);
    addU("TornadoCapCullingFace", 0x2AD4390, 2);
    addB("UseFullscreenHighRes", 0x2AD4394, true);
    addF("DustHeight", 0x2AD4398, 35.0f);
    addF("DustBottomRadiusScale", 0x2AD439C, 1.3f);
    addF("DustTopRadiusScale", 0x2AD43A0, 2.5f);
    addF("DustShapePower", 0x2AD43A4, 1.8f);
    addI("DustAlbedoRed", 0x2AD43A8, 104);
    addI("DustAlbedoGreen", 0x2AD43AC, 92);
    addI("DustAlbedoBlue", 0x2AD43B0, 66);
    addF("CapFlaringExponent", 0x2AD43B4, 3.0f);
    addF("CapFlaringScale", 0x2AD43B8, 6.0f);
    addF("FunnelDisplaceScale", 0x2AD43BC, 1.3f);
    addF("TornadoLightModifier", 0x2AD43C0, 2.0f);
    addF("TornadoMotionBlurMultiplier", 0x2AD43C4, 1.0f);
    addF("TornadoMotionBlurMultiplier2", 0x2AD43C8, 8.0f);
    addF("TornadoVelocityOpacityThres", 0x2AD43CC, 0.69f);
    addF("TornadoVelocityOpacityThres2", 0x2AD43D0, 0.8f);
    addF("TornadoVelocityDistanceMin", 0x2AD43D4, 10.0f);
    addF("TornadoVelocityDistanceMax", 0x2AD43D8, 1000.0f);
    addF("UpsampleBlendMultiplier", 0x2AD43DC, 1000.0f);
    addB("EnableBilateralUpsampling_Tornado", 0x2AD43E0, true);
    addF("TornadoTileSize", 0x2AD43E4, 8.0f);
}

// Capture live game values on startup to use as defaults
extern uintptr_t g_ExeBase; // Forward declare so this helper can see it
void CaptureWeatherDefaults() {
    if (!g_ExeBase) return;
    for (auto& [name, v] : g_WeatherSettings) {
        if (v.modified) continue; // Don't capture defaults for variables the user has manually changed!
        uintptr_t addr = g_ExeBase + v.offset;
        if (v.type == WeatherVar::Float) {
            float val = 0.0f;
            if (FastRead<float>(addr, val)) { v.f_def = val; v.f_cur = val; }
        } else if (v.type == WeatherVar::Bool) {
            uint8_t val = 0;
            if (FastRead<uint8_t>(addr, val)) { v.b_def = (val != 0); v.b_cur = v.b_def; }
        } else if (v.type == WeatherVar::UInt) {
            uint32_t val = 0;
            if (FastRead<uint32_t>(addr, val)) { v.i_def = (int)val; v.i_cur = v.i_def; }
        } else if (v.type == WeatherVar::Int) {
            int32_t val = 0;
            if (FastRead<int32_t>(addr, val)) { v.i_def = val; v.i_cur = v.i_def; }
        }
    }
}

// Helper to render weather rows
extern uintptr_t g_ExeBase; // Forward declare so this helper can see it
static void RenderWeatherField(const std::string& name, WeatherVar& v) {
    ImGui::PushID(name.c_str());
    ImGui::TableNextRow();

    ImGui::TableSetColumnIndex(0);
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(name.c_str());

    ImGui::TableSetColumnIndex(1);
    ImGui::SetNextItemWidth(-1);
    bool changed = false;

    if (v.type == WeatherVar::Float) {
        changed = ImGui::InputFloat("##v", &v.f_cur, 0.0f, 0.0f, "%.3f");
        if (changed) { FastWrite<float>(g_ExeBase + v.offset, v.f_cur); v.modified = true; }
    } else if (v.type == WeatherVar::Bool) {
        changed = ImGui::Checkbox("##v", &v.b_cur);
        if (changed) { FastWrite<uint8_t>(g_ExeBase + v.offset, v.b_cur ? 1 : 0); v.modified = true; }
    } else {
        changed = ImGui::InputInt("##v", &v.i_cur, 0, 0);
        if (changed) {
            v.modified = true;
            if (v.type == WeatherVar::UInt) FastWrite<uint32_t>(g_ExeBase + v.offset, (uint32_t)v.i_cur);
            else FastWrite<int32_t>(g_ExeBase + v.offset, v.i_cur);
        }
    }

    ImGui::TableSetColumnIndex(2);
    if (ImGui::SmallButton("R")) {
        v.modified = false; // Clear modified flag on reset
        if (v.type == WeatherVar::Float) { v.f_cur = v.f_def; FastWrite<float>(g_ExeBase + v.offset, v.f_cur); }
        else if (v.type == WeatherVar::Bool) { v.b_cur = v.b_def; FastWrite<uint8_t>(g_ExeBase + v.offset, v.b_cur ? 1 : 0); }
        else { 
            v.i_cur = v.i_def; 
            if (v.type == WeatherVar::UInt) FastWrite<uint32_t>(g_ExeBase + v.offset, (uint32_t)v.i_cur);
            else FastWrite<int32_t>(g_ExeBase + v.offset, v.i_cur);
        }
    }
    ImGui::PopID();
}
void InitWingsuitSettings() {
    if (g_WingsuitInitialized) return;
    g_WingsuitInitialized = true;

    auto add = [](const char* name, uintptr_t off, int n,
                  float v0=0, float v1=0, float v2=0, float v3=0, float v4=0) {
        WingsuitField f = {};
        f.offset = off;
        f.num_values = n;
        f.is_u32 = false;
        f.defaults[0]=v0; f.current[0]=v0;
        f.defaults[1]=v1; f.current[1]=v1;
        f.defaults[2]=v2; f.current[2]=v2;
        f.defaults[3]=v3; f.current[3]=v3;
        f.defaults[4]=v4; f.current[4]=v4;
        g_WingsuitSettings[name] = f;
    };

    add("AnimInputSpringX",              0x8BC, 3, 1.0f, 2.0f, 0.5f);
    add("AnimInputSpringY",              0x8C8, 3, 2.0f, 2.4f, 1.5f);
    add("CenterYawPitchRoll",            0x898, 3, 0.0f, 0.0f, 0.0f);
    add("ClampVelocitySpeed",            0x7C4, 1, 22.0f);
    add("DragInputSpring",               0x8B0, 3, 2.0f, 3.9f, 0.9f);
    add("DragX",                         0x7D4, 3, 0.0f, 0.01f, 0.12f);
    add("DragY",                         0x7E0, 3, 0.0f, 0.01f, 0.12f);
    add("DragZ",                         0x7EC, 3, 0.0f, 0.01f, 0.1f);
    { WingsuitField f = {}; f.offset=0x810; f.num_values=1; f.is_u32=true;
      f.current_u32=0; f.default_u32=0; g_WingsuitSettings["DrawDebugLines"]=f; }
    add("Gravity",                       0x7B8, 1, -9.82f);
    add("Lift",                          0x7C8, 3, -1.0f, 0.24f, 0.7f);
    add("LiftInputSpring",               0x8A4, 3, 2.0f, 4.0f, 0.9f);
    add("LiftPoint",                     0x7F8, 3, 0.0f, 0.0f, 0.0f);
    add("LookSteerAimingDeadZone",       0x910, 2, 0.0f, 0.0f);
    add("LookSteerAimingExponential",    0x92C, 2, 0.5f, 2.0f);
    add("LookSteerAimingMaxPitch",       0x924, 2, -45.0f, 45.0f);
    add("LookSteerAimingMaxSpeed",       0x918, 2, 0.3f, 0.0f);
    add("LookSteerAimingMaxYaw",         0x920, 1, 45.0f);
    add("LookSteerDeadZone",             0x8EC, 2, 0.0f, 0.0f);
    add("LookSteerExponential",          0x908, 2, 2.0f, 2.0f);
    add("LookSteerMaxPitch",             0x900, 2, -45.0f, 45.0f);
    add("LookSteerMaxSpeed",             0x8F4, 2, 1.0f, 1.0f);
    add("LookSteerMaxYaw",               0x8FC, 1, 45.0f);
    add("MaxVelocity",                   0x7BC, 1, 75.0f);
    add("MaxVelocityXZ",                 0x7C0, 1, 40.0f);
    add("NearGroundLiftDecayMax",        0x8E0, 1, 4.0f);
    add("NearGroundLiftDecayMultiplier", 0x8E4, 1, 2.0f);
    add("NearGroundLiftDistance",        0x8D4, 1, 3.5f);
    add("NearGroundLiftExponent",        0x8DC, 1, 0.5f);
    add("NearGroundLiftRecoverRate",     0x8E8, 1, 1.0f);
    add("NearGroundMaxLift",             0x8D8, 1, 20.0f);
    add("PersistYawPitchRoll",           0x88C, 3, 1.0f, 0.2f, 0.3f);
    add("PitchInputSpring",              0x82C, 3, 1.0f, 2.0f, 1.0f);
    add("PitchLimit",                    0x804, 2, -85.0f, 85.0f);
    add("RetractSlingshotSettings",      0x968, 5, 0.25f, 0.25f, 50.0f, 80.0f, 80.0f);
    add("RollInputSpring",               0x844, 3, 1.5f, 2.0f, 0.4f);
    add("RotateCharPitchToVelocity",     0x820, 3, 4.0f, 2.0f, 0.9f);
    add("RotateCharYawToSlingshot",      0x880, 3, 1.0f, 0.7f, 0.5f);
    add("RotateCharYawToVelocity",       0x814, 3, 4.0f, 2.0f, 0.9f);
    add("SlingshotBreakDistance",        0x964, 1, 5.0f);
    add("SlingshotBreakPitch",           0x954, 1, -1.3f);
    add("SlingshotBreakYawBlendTime",    0x960, 1, 2.0f);
    add("SlingshotBreakYawEnd",          0x95C, 1, 0.5f);
    add("SlingshotBreakYawStart",        0x958, 1, -0.2f);
    add("SlingshotDirectAccel",          0x93C, 1, 30.0f);
    add("SlingshotDragXYZAdjust",        0x948, 3, 0.0f, 0.0f, 0.0f);
    add("SlingshotExtraLift",            0x938, 1, 0.1f);
    add("SlingshotForwardAccel",         0x940, 1, 0.0f);
    add("SlingshotMaxSpeedAdjust",       0x944, 1, 10.0f);
    add("SlingshotPitchAdjust",          0x934, 1, 0.0f);
    add("XInputYawPitchRollAmount",      0x850, 3, 20.0f, 0.0f, -60.0f);
    add("XLookYawPitchRollAmount",       0x868, 3, 0.0f, 0.0f, 0.0f);
    add("YInputYawPitchRollAmount",      0x85C, 3, 0.0f, 45.0f, 0.0f);
    add("YLookYawPitchRollAmount",       0x874, 3, 0.0f, 0.0f, 0.0f);
    add("YawInputSpring",                0x838, 3, 0.1f, 1.0f, 0.8f);
    add("YawSteerAmount",                0x80C, 1, 0.5f);
}

// ============================================================================
// CONFIG FILE SYSTEM
// ============================================================================
extern float g_UIScale;
extern bool g_FreezeGame;
extern int g_ToggleKey;
extern bool g_InfBoost;
extern bool g_InfMissiles;
extern float g_Thrust;
extern float g_Floor;
extern float g_MaxSpeed;
extern float g_HavokMaxSpeed;
extern float g_HavokMaxAccel;
extern float default_havok_max_speed;
extern float default_havok_max_accel;
extern bool g_OpenMenuOnStart;
extern bool g_ShowSpeedometer;
extern int g_SpawnFavoriteKey;
extern int g_SpawnChaosKey;
extern std::string g_FavoriteVehicle;
void ToggleInfBoost(bool enable);
void ToggleInfMissiles(bool enable);
extern bool g_VehiclesInvincible;
extern bool g_VehiclesInvinciblePlayerOnly; // sub-option of the above
void ToggleVehiclesInvincible(bool enable);
void ToggleAllVehiclesNitroJump(bool enable);
void ToggleInfiniteNitro(bool enable);
void ToggleInfiniteTurboJump(bool enable, bool allowAirHop);
extern bool g_DebugNoLogin;
void ToggleNoLogin(bool enable);
bool g_MissionsSpoilerAccepted = false;

// Forward declarations for settings defined lower down in the file
extern bool g_RainbowVehicles;
extern bool g_RainbowPlayerOnly;
extern int  g_RainbowSpeed;
extern bool g_RainEverywhere;
extern bool g_VehicleESP;
extern bool g_CarSplineESP;
extern bool g_DisableDistanceFog;
extern bool g_DisableGroundHaze;
extern bool g_DisableAtmosphericScattering;
extern bool g_DisableClouds;
extern bool g_DisableSSReflections;
extern bool g_DisableMotionBlur;
extern bool g_DisableRadialBlur;
extern bool g_DisableVelocityReprojection;
extern bool g_DisableEdgeStencil;
extern bool g_DisableWaterReflections;
extern bool g_DisableShadows;
extern bool g_DisableMountainShadows;
extern bool g_DisableOcean;
extern bool g_OceanSubVisuals;
extern bool g_OceanSubStates;
extern bool g_OceanSubCamera;
extern bool g_OceanSubPhysics;
extern bool g_OceanSubEntry;
extern bool g_DisableRivers;
extern bool g_DisableFoliage;
extern bool g_ForceMaxGroundLOD;
extern bool g_HeatBypassCaps;
extern bool g_HeatBypassCooldowns;
extern bool g_HeatBypassQuotas;
extern uintptr_t g_CodeCave;

void ToggleMountainShadows(bool enable);
extern int g_ShadowResolution;          // 0 = follow the game's own setting; else atlas side in px
void UpdateShadowResolutionDriver();    // per-frame: pins the engine tables + fires the native settings applier
void ToggleDisableRivers(bool enable);
void UpdateOceanPatches();
void ApplyGlobalGroundLOD(bool enable);
void ApplyHeatDetermineSpawnPatches();

enum SavePopupState { SAVE_IDLE, SAVE_SAVING, SAVE_SUCCESS, SAVE_FAILED };
static SavePopupState g_SavePopupState = SAVE_IDLE;
static double g_SavePopupStartTime = 0.0;
static double g_SavePopupEndTime = 0.0;

bool WriteConfig() {
    JC4TerrainSettings::ConfigWriteGuard terrainConfigWriteGuard;
    std::ofstream f("modmenu_jc4.ini");
    if (!f) return false;

    f << "# Just Cause 4 Mod Menu Configuration\n\n";

    f << "[UI]\n";
    f << "Scale=" << g_UIScale << "\n";
    f << "ToggleKey=" << g_ToggleKey << "\n";
    f << "MissionsSpoilerAccepted=" << (g_MissionsSpoilerAccepted ? 1 : 0) << "\n\n";

    f << "[Toggles]\n";
    f << "InfiniteBoost=" << (g_InfBoost ? 1 : 0) << "\n";
    f << "InfiniteMissiles=" << (g_InfMissiles ? 1 : 0) << "\n";
    f << "FullAutoMissiles=" << (g_FullAutoMissiles ? 1 : 0) << "\n";
    f << "AllVehiclesInvincible=" << (g_VehiclesInvincible ? 1 : 0) << "\n";
    f << "AllVehiclesInvinciblePlayerOnly=" << (g_VehiclesInvinciblePlayerOnly ? 1 : 0) << "\n";
    f << "RainbowVehicles=" << (g_RainbowVehicles ? 1 : 0) << "\n";
    f << "RainbowPlayerOnly=" << (g_RainbowPlayerOnly ? 1 : 0) << "\n";
    f << "RainbowSpeed=" << g_RainbowSpeed << "\n";
    f << "HideUI=" << (g_HideUI ? 1 : 0) << "\n";
    f << "Speedometer=" << (g_ShowSpeedometer ? 1 : 0) << "\n";
    f << "TrueKMHInStockDials=" << (g_SpeedoReplaceGameHUD ? 1 : 0) << "\n";
    f << "ShowHeatStatus=" << (g_ShowHeatStatus ? 1 : 0) << "\n";
    f << "AlwaysShowHeatStatus=" << (g_AlwaysShowHeatStatus ? 1 : 0) << "\n";
    f << "VehicleESP=" << (g_VehicleESP ? 1 : 0) << "\n";
    f << "CarSplineESP=" << (g_CarSplineESP ? 1 : 0) << "\n";
    f << "DisableDistanceFog=" << (g_DisableDistanceFog ? 1 : 0) << "\n";
    f << "DisableGroundHaze=" << (g_DisableGroundHaze ? 1 : 0) << "\n";
    f << "DisableAtmosphericScattering=" << (g_DisableAtmosphericScattering ? 1 : 0) << "\n";
    f << "DisableClouds=" << (g_DisableClouds ? 1 : 0) << "\n";
    f << "RainEverywhere=" << (g_RainEverywhere ? 1 : 0) << "\n";
    f << "DisableSSReflections=" << (g_DisableSSReflections ? 1 : 0) << "\n";
    f << "DisableMotionBlur=" << (g_DisableMotionBlur ? 1 : 0) << "\n";
    f << "DisableRadialBlur=" << (g_DisableRadialBlur ? 1 : 0) << "\n";
    f << "DisableVelocityReprojection=" << (g_DisableVelocityReprojection ? 1 : 0) << "\n";
    f << "DisableEdgeStencil=" << (g_DisableEdgeStencil ? 1 : 0) << "\n";
    f << "DisableWaterReflections=" << (g_DisableWaterReflections ? 1 : 0) << "\n";
    f << "DisableShadows=" << (g_DisableShadows ? 1 : 0) << "\n";
    f << "DisableMountainShadows=" << (g_DisableMountainShadows ? 1 : 0) << "\n";
    f << "DisableOcean=" << (g_DisableOcean ? 1 : 0) << "\n";
    f << "OceanSubVisuals=" << (g_OceanSubVisuals ? 1 : 0) << "\n";
    f << "OceanSubStates=" << (g_OceanSubStates ? 1 : 0) << "\n";
    f << "OceanSubCamera=" << (g_OceanSubCamera ? 1 : 0) << "\n";
    f << "OceanSubPhysics=" << (g_OceanSubPhysics ? 1 : 0) << "\n";
    f << "OceanSubEntry=" << (g_OceanSubEntry ? 1 : 0) << "\n";
    f << "DisableRivers=" << (g_DisableRivers ? 1 : 0) << "\n";
    f << "DisableFoliage=" << (g_DisableFoliage ? 1 : 0) << "\n";
    f << "DebugNoLogin=" << (g_DebugNoLogin ? 1 : 0) << "\n";
    f << "ForceMaxGroundLOD=" << (g_ForceMaxGroundLOD ? 1 : 0) << "\n";
    f << "TerrainLODMode=" << g_TerrainLODMode << "\n";
    f << "TerrainGridWidth=" << JC4TerrainSettings::GetSavedWidth() << "\n";
    f << "TerrainAltitudeDetail=" << (JC4TerrainSettings::GetSavedAltitudeDetail() ? 1 : 0) << "\n\n";

    f << "[Player]\n";
    f << "GodMode=" << (g_GodMode ? 1 : 0) << "\n";
    f << "DisableDamageScreen=" << (g_DisableDamageScreen ? 1 : 0) << "\n";
    f << "NoRagdoll=" << (g_DisableRagdoll ? 1 : 0) << "\n";
    f << "InfiniteAmmo=" << (g_InfWeaponAmmo ? 1 : 0) << "\n";
    f << "NeverWanted=" << (g_NeverWanted ? 1 : 0) << "\n";
    f << "AllVehiclesNitroJump=" << (g_AllVehiclesNitroJump ? 1 : 0) << "\n";
    f << "InfiniteNitro=" << (g_InfiniteNitro ? 1 : 0) << "\n";
    f << "InfiniteTurboJump=" << (g_InfiniteTurboJump ? 1 : 0) << "\n";
    f << "TurboJumpAirHop=" << (g_TurboJumpAirHop ? 1 : 0) << "\n";
    f << "LockOxygen=" << (g_LockOxygen ? 1 : 0) << "\n";
    f << "OxygenValue=" << g_OxygenValue << "\n";
    f << "LockHealth=" << (g_LockHealth ? 1 : 0) << "\n";
    f << "HealthValue=" << g_HealthValue << "\n";
    // GameSpeed is intentionally runtime-only and is not persisted to the INI.
    f << "BoostTorque=" << g_BoostTorque << "\n";
    f << "BoostGrip=" << g_BoostGrip << "\n";
    f << "BoostJumpHeight=" << g_BoostJumpHeight << "\n\n";

    f << "[Camera]\n";
    f << "OverrideFOV=" << (g_OverrideFOV ? 1 : 0) << "\n";
    f << "DesiredFOV=" << g_DesiredFOV << "\n\n";

    f << "[GlobalWorld]\n";
    f << "OverrideAltitudeLimit=" << (g_OverrideAltitudeLimit ? 1 : 0) << "\n";
    f << "MaxAltitude=" << g_LiveMaxAltitude << "\n";
    f << "MinAltitude=" << g_LiveMinAltitude << "\n";
    f << "BroadphaseSize=" << g_LiveBroadphaseSize << "\n";
    f << "OverrideSpawnLimits=" << (g_OverrideSpawnLimits ? 1 : 0) << "\n";
    f << "SimBudget=" << g_LiveSimBudget << "\n";
    f << "SpawnDelayMs=" << g_LiveSpawnDelayMs << "\n\n";

    int maxHeatEntities = (g_CustomMaxHeatEntities > 0) ? g_CustomMaxHeatEntities : 15;
    int maxVisibilityDist = (g_CustomMaxVisibilityDist > 0) ? g_CustomMaxVisibilityDist : 500;
    float detectRange = (g_CustomDetectionRange > 0.0f) ? g_CustomDetectionRange : 100.0f;
    float visionThresh = (g_CustomVisionThreshold > 0.0f) ? g_CustomVisionThreshold : 0.5f;

    if (g_ExeBase) {
        if (g_CustomMaxHeatEntities <= 0) {
            int live = 0;
            if (FastRead<int>(g_ExeBase + g_Addr_2AEAD0C, live) && live > 0) maxHeatEntities = live;
        }
        if (g_CustomMaxVisibilityDist <= 0) {
            int live = 0;
            if (FastRead<int>(g_ExeBase + g_Addr_2AEAD10, live) && live > 0) maxVisibilityDist = live;
        }
        if (g_CustomDetectionRange <= 0.0f || g_CustomVisionThreshold <= 0.0f) {
            uintptr_t heatMgr = 0;
            if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D38, heatMgr) && heatMgr) {
                if (g_CustomDetectionRange <= 0.0f) FastRead<float>(heatMgr + 0x3E8, detectRange);
                if (g_CustomVisionThreshold <= 0.0f) FastRead<float>(heatMgr + 0x3E4, visionThresh);
            }
        }
    }

    f << "[Heat]\n";
    f << "BypassCaps=" << (g_HeatBypassCaps ? 1 : 0) << "\n";
    f << "BypassCooldowns=" << (g_HeatBypassCooldowns ? 1 : 0) << "\n";
    f << "BypassQuotas=" << (g_HeatBypassQuotas ? 1 : 0) << "\n";
    f << "MaxHeatEntities=" << maxHeatEntities << "\n";
    f << "MaxVisibilityDist=" << maxVisibilityDist << "\n";
    f << "HeatSystemActive=" << (g_HeatSystemActive ? 1 : 0) << "\n";
    f << "HostileDetectionRange=" << detectRange << "\n";
    f << "AwarenessThreshold=" << visionThresh << "\n\n";

    f << "[HeatDistances]\n";
    for (int d = 0; d < 4; d++) {
        for (int i = 0; i < 8; i++) {
            if (g_HeatDistHasCustom[d][i]) {
                f << g_HeatDomainPrefixes[d] << "_" << g_HeatDistanceNames[i] << "=" << g_HeatDistances[d][i] << "\n";
            } else {
                f << g_HeatDomainPrefixes[d] << "_" << g_HeatDistanceNames[i] << "=\n";
            }
        }
    }
    f << "\n";

    f << "[Physics]\n";
    f << "Thrust=" << g_Thrust << "\n";
    f << "FloorHeight=" << g_Floor << "\n";
    f << "MaxSpeed=" << g_MaxSpeed << "\n";
    f << "MissileSpeedMultiplier=" << g_MissileSpeedMult << "\n";
    f << "MissileStage0Time=" << g_LiveMissileStage0Time << "\n";
    f << "MissileStage1Time=" << g_LiveMissileStage1Time << "\n";
    f << "MissileStage0Speed=" << g_LiveMissileStage0Speed << "\n";
    f << "MissileStage1Speed=" << g_LiveMissileStage1Speed << "\n";
    f << "MissileTurnSpeed=" << g_LiveMissileTurnSpeed << "\n";
    f << "MissileTurnDelay=" << g_LiveMissileTurnDelay << "\n\n";

    f << "[WingsuitHavokPhysics]\n";
    f << "HavokMaxSpeed=" << (g_HavokMaxSpeed > 0.0f ? g_HavokMaxSpeed : default_havok_max_speed) << "\n";
    f << "HavokMaxAccel=" << (g_HavokMaxAccel > 0.0f ? g_HavokMaxAccel : default_havok_max_accel) << "\n\n";

    f << "[Wingsuit]\n";
    for (auto& [name, field] : g_WingsuitSettings) {
        if (field.is_u32) {
            f << name << "=" << field.current_u32 << "\n";
        } else {
            f << name << "=";
            for (int i = 0; i < field.num_values; i++) {
                f << field.current[i] << (i < field.num_values - 1 ? "," : "");
            }
            f << "\n";
        }
    }

    f << "\n[Shortcuts]\n";
    f << "KeyNoclip=" << g_NoclipKey << "\n";
    f << "KeyFreeCam=" << g_FreeCamKey << "\n";
    f << "KeyFirstPerson=" << g_FirstPersonKey << "\n";
    f << "KeySpawnChaos=" << g_SpawnChaosKey << "\n";

    f << "\n[FirstPerson]\n";
    f << "HideHead=" << (g_FpHideHead ? 1 : 0) << "\n";
    f << "HideBody=" << (g_FpHideBody ? 1 : 0) << "\n";
    f << "ForwardOffset=" << g_FpForwardOffset << "\n";
    f << "UpOffset=" << g_FpUpOffset << "\n";
    f << "RightOffset=" << g_FpRightOffset << "\n";

    f << "\n[Spawn]\n";
    f << "FavoriteVkKey=" << g_SpawnFavoriteKey << "\n";
    f << "FavoriteVehicle=" << g_FavoriteVehicle << "\n";

    f << "\n[HUDLayout]\n";
    f << "ReferenceResX=" << g_HUDRefW << "\n";
    f << "ReferenceResY=" << g_HUDRefH << "\n";
    f << "SpeedoPosX=" << g_SpeedoPosX << "\n";
    f << "SpeedoPosY=" << g_SpeedoPosY << "\n";
    f << "SpeedoWidth=" << g_SpeedoWidth << "\n";
    f << "SpeedoHeight=" << g_SpeedoHeight << "\n";
    f << "HeatOffsetX=" << g_HeatOffsetX << "\n";
    f << "HeatOffsetY=" << g_HeatOffsetY << "\n";
    f << "HeatScale=" << g_HeatScale << "\n";
    f << "VehicleESPPanelX=" << g_VehicleESPPanelX << "\n";
    f << "VehicleESPPanelY=" << g_VehicleESPPanelY << "\n";
    f << "VehicleESPPanelW=" << g_VehicleESPPanelW << "\n";
    f << "VehicleESPPanelH=" << g_VehicleESPPanelH << "\n";

    f << "\n[Tornado]\n";
    f << "KeySpawnDefaultLocation="      << g_TorBinds[TB_SPAWN_DEFAULT].vk   << "\n";
    f << "KeySpawnAtCrosshair="          << g_TorBinds[TB_SPAWN_CROSSHAIR].vk << "\n";
    f << "KeyFollowCrosshairSmooth="     << g_TorBinds[TB_FOLLOW].vk          << "\n";
    f << "KeyTeleportToCrosshair="       << g_TorBinds[TB_TELEPORT].vk        << "\n";
    f << "KeyFreezeInPlace="             << g_TorBinds[TB_FREEZE].vk          << "\n";
    f << "KeySpawnSmoothly="             << g_TorBinds[TB_SPAWN_SMOOTH].vk    << "\n";
    f << "KeySpawnInstantly="            << g_TorBinds[TB_SPAWN_INSTANT].vk   << "\n";
    f << "KeyDespawnInstant="            << g_TorBinds[TB_DESPAWN_NOW].vk     << "\n";
    f << "KeyDespawnFade="               << g_TorBinds[TB_DESPAWN_FADE].vk    << "\n";
    f << "ManualController=" << g_TorManualController << "\n";
    f << "ManualObject="     << g_TorManualObject     << "\n";

    f << "\n[GrapplingHook]\n";
    f << "OverrideReach="          << (g_GrappleReach.overrideActive ? 1 : 0) << "\n";
    f << "Reach="                  << g_GrappleReach.customVal << "\n";
    f << "OverrideFlightSpeed="    << (g_GrappleFlight.overrideActive ? 1 : 0) << "\n";
    f << "FlightSpeed="            << g_GrappleFlight.customVal << "\n";
    f << "OverrideReelSpeed="      << (g_GrappleReelSpd.overrideActive ? 1 : 0) << "\n";
    f << "ReelSpeed="              << g_GrappleReelSpd.customVal << "\n";
    f << "OverrideReelAccel="      << (g_GrappleReelAcc.overrideActive ? 1 : 0) << "\n";
    f << "ReelAccel="              << g_GrappleReelAcc.customVal << "\n";
    f << "TetherUnbreakable="         << (g_TetherUnbreakable ? 1 : 0) << "\n";
    f << "OverrideTetherPullForce="    << (g_TetherPullForce.overrideActive ? 1 : 0) << "\n";
    f << "TetherPullForce="            << g_TetherPullForce.customVal << "\n";
    f << "OverrideTetherRetractSpeed=" << (g_TetherRetractSpeed.overrideActive ? 1 : 0) << "\n";
    f << "TetherRetractSpeed="         << g_TetherRetractSpeed.customVal << "\n";

    f << "OverrideBoosterSpeed="        << (g_BoosterSpeed.overrideActive ? 1 : 0) << "\n";
    f << "BoosterSpeed="                << g_BoosterSpeed.customVal << "\n";
    f << "OverrideBoosterForce="        << (g_BoosterForce.overrideActive ? 1 : 0) << "\n";
    f << "BoosterForce="                << g_BoosterForce.customVal << "\n";
    f << "OverrideBoosterSpool="        << (g_BoosterSpool.overrideActive ? 1 : 0) << "\n";
    f << "BoosterSpool="                << g_BoosterSpool.customVal << "\n";
    f << "BoosterLockOnly30s="          << (g_BoosterLockOnly30s ? 1 : 0) << "\n";

    f << "OverrideBalloonAltitudeDelta=" << (g_BalloonAltitudeDelta.overrideActive ? 1 : 0) << "\n";
    f << "BalloonAltitudeDelta="         << g_BalloonAltitudeDelta.customVal << "\n";
    f << "OverrideBalloonSize="          << (g_BalloonSize.overrideActive ? 1 : 0) << "\n";
    f << "BalloonSize="                 << g_BalloonSize.customVal << "\n";
    f << "OverrideBalloonLiftForce="    << (g_BalloonLiftForce.overrideActive ? 1 : 0) << "\n";
    f << "BalloonLiftForce="            << g_BalloonLiftForce.customVal << "\n";
    f << "BalloonExplosiveGas="         << (g_BalloonExplosiveGas ? 1 : 0) << "\n";
    f << "OverrideTethers="             << (g_OverrideTethers ? 1 : 0) << "\n";
    f << "UnlimitedTethers="            << (g_UnlimitedTethers ? 1 : 0) << "\n";
    f << "MaxTethersCount="             << g_MaxTethersCount << "\n";

    f << "\n[TeleportLocations]\n";
    for (const auto& loc : g_SavedLocations) {
        f << loc.name << "=" << loc.x << "," << loc.y << "," << loc.z << "\n";
    }
    f.close();
    return !f.fail();
}

static void DrawSaveConfigPopup() {
    if (g_SavePopupState == SAVE_IDLE) return;

    double now = ImGui::GetTime();
    ImGuiIO& io = ImGui::GetIO();

    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(230.0f * g_UIScale, 68.0f * g_UIScale));

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                             ImGuiWindowFlags_NoScrollbar;

    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.06f, 0.07f, 0.10f, 0.96f));
    ImGui::PushStyleColor(ImGuiCol_Border, (g_SavePopupState == SAVE_FAILED) ? ImVec4(1.0f, 0.3f, 0.3f, 0.9f) : ImVec4(0.55f, 0.38f, 0.96f, 0.9f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.5f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.0f * g_UIScale);

    if (ImGui::Begin("##SavePopupToast", nullptr, flags)) {
        if (g_SavePopupState == SAVE_SAVING) {
            // Minimalistic spinner loading animation
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 cur = ImGui::GetCursorScreenPos();
            float radius = 9.0f * g_UIScale;
            ImVec2 center(cur.x + radius + 12.0f * g_UIScale, cur.y + radius + 12.0f * g_UIScale);
            float time = (float)now * 7.0f;
            int segments = 24;
            float startAngle = time;
            float endAngle = time + 1.5f * 3.14159f;

            dl->PathClear();
            for (int i = 0; i <= segments; i++) {
                float a = startAngle + (endAngle - startAngle) * ((float)i / (float)segments);
                dl->PathLineTo(ImVec2(center.x + cosf(a) * radius, center.y + sinf(a) * radius));
            }
            dl->PathStroke(IM_COL32(149, 102, 255, 255), false, 2.5f * g_UIScale);

            ImGui::SetCursorPosX(42.0f * g_UIScale);
            ImGui::SetCursorPosY(18.0f * g_UIScale);
            ImGui::TextColored(ImVec4(0.9f, 0.85f, 1.0f, 1.0f), "Saving...");

            // Allow spinner to display briefly before file write completes
            if (now - g_SavePopupStartTime > 0.45) {
                bool ok = WriteConfig();
                g_SavePopupState = ok ? SAVE_SUCCESS : SAVE_FAILED;
                g_SavePopupEndTime = now;
            }
        } else if (g_SavePopupState == SAVE_SUCCESS) {
            ImGui::SetCursorPosX(20.0f * g_UIScale);
            ImGui::SetCursorPosY(18.0f * g_UIScale);
            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.5f, 1.0f), "[OK]");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.92f, 0.95f, 1.0f, 1.0f), "Saved successfully!");

            if (now - g_SavePopupEndTime > 1.2) {
                g_SavePopupState = SAVE_IDLE;
            }
        } else if (g_SavePopupState == SAVE_FAILED) {
            ImGui::SetCursorPosX(20.0f * g_UIScale);
            ImGui::SetCursorPosY(18.0f * g_UIScale);
            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "[FAIL]");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.8f, 1.0f), "Failed to save file!");

            if (now - g_SavePopupEndTime > 1.6) {
                g_SavePopupState = SAVE_IDLE;
            }
        }
    }
    ImGui::End();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

void ReadConfig() {
    std::ifstream f("modmenu_jc4.ini");
    if (!f) {
        WriteConfig();
        return;
    }

    bool needs_update = false;
    bool found_god_mode = false;
    bool found_rainbow = false;
    bool found_global_world = false;
    bool found_heat_distances = false;
    bool found_max_heat_entities = false;
    bool found_max_visibility_dist = false;
    bool found_heat_bypasses = false;
    bool found_heat_active = false;
    bool found_heat_detect = false;
    bool found_heat_vision = false;
    bool found_missions_spoiler = false;
    bool found_grapple_booster = false;
    bool found_grapple_balloon = false;
    bool found_all_vehicles_nitro_jump = false;
    bool found_infinite_nitro = false;
    bool found_infinite_turbo_jump = false;
    bool found_turbo_jump_air_hop = false;
    bool found_health = false;
    bool found_booster_30s = false;
    bool found_true_kmh = false;
    bool found_desired_fov = false;
    bool found_fov_override = false;

    g_SavedLocations.clear();

    std::string line;
    std::string current_section = "";
    while (std::getline(f, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line[0] == '[' && line.back() == ']') {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        if (current_section == "UI") {
            if (key == "Scale") g_UIScale = std::stof(val);
            if (key == "ToggleKey") g_ToggleKey = std::stoi(val);
            if (key == "MissionsSpoilerAccepted") {
                g_MissionsSpoilerAccepted = (val == "1" || val == "true" || val == "True");
                found_missions_spoiler = true;
            }
            if (key == "FreezeGame" || key == "OpenMenuOnStart") {
                needs_update = true;
            }
        } else if (current_section == "Toggles") {
            if (key == "InfiniteBoost") g_InfBoost = (val == "1" || val == "true" || val == "True");
            if (key == "InfiniteMissiles") g_InfMissiles = (val == "1" || val == "true" || val == "True");
            if (key == "FullAutoMissiles") g_FullAutoMissiles = (val == "1" || val == "true" || val == "True");
            if (key == "AllVehiclesInvincible") g_VehiclesInvincible = (val == "1" || val == "true" || val == "True");
            if (key == "AllVehiclesInvinciblePlayerOnly") g_VehiclesInvinciblePlayerOnly = (val == "1" || val == "true" || val == "True");
            if (key == "HideUI") g_HideUI = (val == "1" || val == "true" || val == "True");
            if (key == "RainbowVehicles") { g_RainbowVehicles = (val == "1"); found_rainbow = true; }
            if (key == "RainbowPlayerOnly") g_RainbowPlayerOnly = (val == "1");
            if (key == "RainbowSpeed") g_RainbowSpeed = std::stoi(val);
            if (key == "Speedometer") g_ShowSpeedometer = (val == "1");
            if (key == "TrueKMHInStockDials") { g_SpeedoReplaceGameHUD = (val == "1"); found_true_kmh = true; }
            if (key == "ShowHeatStatus") g_ShowHeatStatus = (val == "1");
            if (key == "AlwaysShowHeatStatus") g_AlwaysShowHeatStatus = (val == "1");
            if (key == "VehicleESP") g_VehicleESP = (val == "1");
            if (key == "CarSplineESP") g_CarSplineESP = (val == "1");
            if (key == "DisableDistanceFog") g_DisableDistanceFog = (val == "1");
            if (key == "DisableGroundHaze") g_DisableGroundHaze = (val == "1");
            if (key == "DisableAtmosphericScattering") g_DisableAtmosphericScattering = (val == "1");
            if (key == "DisableClouds") g_DisableClouds = (val == "1");
            if (key == "RainEverywhere") g_RainEverywhere = (val == "1");
            if (key == "DisableSSReflections") g_DisableSSReflections = (val == "1");
            if (key == "DisableMotionBlur") g_DisableMotionBlur = (val == "1");
            if (key == "DisableRadialBlur") g_DisableRadialBlur = (val == "1");
            if (key == "DisableVelocityReprojection") g_DisableVelocityReprojection = (val == "1");
            if (key == "DisableEdgeStencil") g_DisableEdgeStencil = (val == "1");
            if (key == "DisableWaterReflections") g_DisableWaterReflections = (val == "1");
            if (key == "DisableShadows") g_DisableShadows = (val == "1");
            if (key == "DisableMountainShadows") g_DisableMountainShadows = (val == "1");
            // NOTE: ShadowResolution is intentionally NOT persisted: the shadow
            // resolution choice is per-session and the menu always boots at
            // 'Game setting' (g_ShadowResolution == 0).
            if (key == "DisableOcean") g_DisableOcean = (val == "1");
            if (key == "OceanSubVisuals") g_OceanSubVisuals = (val == "1");
            if (key == "OceanSubStates") g_OceanSubStates = (val == "1");
            if (key == "OceanSubCamera") g_OceanSubCamera = (val == "1");
            if (key == "OceanSubPhysics") g_OceanSubPhysics = (val == "1");
            if (key == "OceanSubEntry") g_OceanSubEntry = (val == "1");
            if (key == "DisableRivers") g_DisableRivers = (val == "1");
            if (key == "DisableFoliage") g_DisableFoliage = (val == "1");
            if (key == "DebugNoLogin") { g_DebugNoLogin = (val == "1"); ToggleNoLogin(g_DebugNoLogin); }
            if (key == "ForceMaxGroundLOD") g_ForceMaxGroundLOD = (val == "1");
            if (key == "TerrainLODMode") g_TerrainLODMode = std::stoi(val);
        } else if (current_section == "Player") {
            if (key == "GodMode") { g_GodMode = (val == "1"); found_god_mode = true; }
            if (key == "DisableDamageScreen") g_DisableDamageScreen = (val == "1");
            if (key == "NoRagdoll") g_DisableRagdoll = (val == "1");
            if (key == "InfiniteAmmo") g_InfWeaponAmmo = (val == "1");
            if (key == "NeverWanted") g_NeverWanted = (val == "1");
            if (key == "AllVehiclesNitroJump") {
                        // Deferred: the warmup gate applies this, never ReadConfig.
                        g_AllVehiclesNitroJump = (val == "1");
                        found_all_vehicles_nitro_jump = true;
                    }
                    if (key == "InfiniteNitro") {
                        // Deferred: the warmup gate applies this, never ReadConfig.
                        g_InfiniteNitro = (val == "1");
                        found_infinite_nitro = true;
                    }
                    if (key == "InfiniteTurboJump") {
                        g_InfiniteTurboJump = (val == "1");
                        found_infinite_turbo_jump = true;
                    }
                    if (key == "TurboJumpAirHop") {
                        g_TurboJumpAirHop = (val == "1");
                        found_turbo_jump_air_hop = true;
                    }
            if (key == "LockOxygen") g_LockOxygen = (val == "1");
            if (key == "OxygenValue") g_OxygenValue = std::stof(val);
            if (key == "LockHealth") { g_LockHealth = (val == "1"); found_health = true; }
            if (key == "HealthValue") { g_HealthValue = std::stoi(val); found_health = true; }
            if (key == "GameSpeed") { /* ignored: game speed is runtime-only */ }
            if (key == "BoostTorque") { g_BoostTorque = std::stof(val); if (g_CodeCave) FastWrite<float>(g_CodeCave + 0x0, g_BoostTorque); }
            if (key == "BoostGrip") { g_BoostGrip = std::stof(val); if (g_CodeCave) FastWrite<float>(g_CodeCave + 0x4, g_BoostGrip); }
            if (key == "BoostJumpHeight") { g_BoostJumpHeight = std::stof(val); if (g_CodeCave) FastWrite<float>(g_CodeCave + 0xC, g_BoostJumpHeight); }
        } else if (current_section == "Camera") {
            if (key == "OverrideFOV") { g_OverrideFOV = (val == "1"); found_fov_override = true; }
            if (key == "DesiredFOV") {
                try {
                    int v = std::stoi(val);
                    if (v >= 30 && v <= 130) g_DesiredFOV = v;
                } catch (...) {}
                found_desired_fov = true;
            }
        } else if (current_section == "GlobalWorld") {
            if (key == "OverrideAltitudeLimit") { g_OverrideAltitudeLimit = (val == "1"); found_global_world = true; }
            if (key == "MaxAltitude") g_LiveMaxAltitude = std::stof(val);
            if (key == "MinAltitude") g_LiveMinAltitude = std::stof(val);
            if (key == "BroadphaseSize") g_LiveBroadphaseSize = std::stof(val);
            if (key == "OverrideSpawnLimits") { g_OverrideSpawnLimits = (val == "1"); }
            if (key == "SimBudget") g_LiveSimBudget = std::stoi(val);
            if (key == "SpawnDelayMs") g_LiveSpawnDelayMs = std::stoi(val);
        } else if (current_section == "Heat") {
            if (key == "BypassCaps") { g_HeatBypassCaps = (val == "1"); found_heat_bypasses = true; }
            if (key == "BypassCooldowns") g_HeatBypassCooldowns = (val == "1");
            if (key == "BypassQuotas") g_HeatBypassQuotas = (val == "1");
            if (key == "MaxHeatEntities") {
                int v = std::stoi(val);
                if (v > 0) g_CustomMaxHeatEntities = v;
                found_max_heat_entities = true;
            }
            if (key == "MaxVisibilityDist") {
                int v = std::stoi(val);
                if (v > 0) g_CustomMaxVisibilityDist = v;
                found_max_visibility_dist = true;
            }
            if (key == "HeatSystemActive") {
                g_HeatSystemActive = (val == "1");
                found_heat_active = true;
            }
            if (key == "HostileDetectionRange") {
                float v = std::stof(val);
                if (v > 0.0f) g_CustomDetectionRange = v;
                found_heat_detect = true;
            }
            if (key == "AwarenessThreshold") {
                float v = std::stof(val);
                if (v > 0.0f) g_CustomVisionThreshold = v;
                found_heat_vision = true;
            }
        } else if (current_section == "HeatDistances") {
            for (int d = 0; d < 4; d++) {
                for (int i = 0; i < 8; i++) {
                    std::string expectedKey = std::string(g_HeatDomainPrefixes[d]) + "_" + g_HeatDistanceNames[i];
                    if (key == expectedKey) {
                        // If empty (e.g. Air_PursuitSpawnMin=) -> DO NOT TOUCH MEMORY
                        if (val.empty() || val.find_first_not_of(" \t\r\n") == std::string::npos) {
                            g_HeatDistHasCustom[d][i] = false;
                        } else {
                            try {
                                g_HeatDistances[d][i] = std::stof(val);
                                g_HeatDistHasCustom[d][i] = true;
                            } catch (...) {
                                g_HeatDistHasCustom[d][i] = false;
                            }
                        }
                    }
                }
            }
        } else if (current_section == "TeleportLocations") {
            float tx = 0, ty = 0, tz = 0;
            if (sscanf(val.c_str(), "%f,%f,%f", &tx, &ty, &tz) == 3) {
                g_SavedLocations.push_back({ key, tx, ty, tz });
            }
        } else if (current_section == "Physics") {
            if (key == "Thrust") g_Thrust = std::stof(val);
            if (key == "FloorHeight") g_Floor = std::stof(val);
            if (key == "MaxSpeed") g_MaxSpeed = std::stof(val);
            if (key == "MissileSpeedMultiplier") g_MissileSpeedMult = std::stof(val);
            if (key == "MissileStage0Time")  g_LiveMissileStage0Time  = std::stof(val);
            if (key == "MissileStage1Time")  g_LiveMissileStage1Time  = std::stof(val);
            if (key == "MissileStage0Speed") g_LiveMissileStage0Speed = std::stof(val);
            if (key == "MissileStage1Speed") g_LiveMissileStage1Speed = std::stof(val);
            if (key == "MissileTurnSpeed")   g_LiveMissileTurnSpeed   = std::stof(val);
            if (key == "MissileTurnDelay")   g_LiveMissileTurnDelay   = std::stof(val);
        } else if (current_section == "WingsuitHavokPhysics") {
            if (key == "HavokMaxSpeed") g_HavokMaxSpeed = std::stof(val);
            if (key == "HavokMaxAccel") g_HavokMaxAccel = std::stof(val);
        } else if (current_section == "Shortcuts") {
            if (key == "KeyNoclip") g_NoclipKey = std::stoi(val);
            if (key == "KeyFreeCam") g_FreeCamKey = std::stoi(val);
            if (key == "KeyFirstPerson") g_FirstPersonKey = std::stoi(val);
            if (key == "KeySpawnChaos") g_SpawnChaosKey = std::stoi(val);
        } else if (current_section == "FirstPerson") {
            if (key == "HideHead") g_FpHideHead = (val == "1");
            if (key == "HideBody") g_FpHideBody = (val == "1");
            if (key == "ForwardOffset") g_FpForwardOffset = std::stof(val);
            if (key == "UpOffset") g_FpUpOffset = std::stof(val);
            if (key == "RightOffset") g_FpRightOffset = std::stof(val);
        } else if (current_section == "Spawn") {
            if (key == "FavoriteVkKey") g_SpawnFavoriteKey = std::stoi(val);
            if (key == "FavoriteVehicle") g_FavoriteVehicle = val;
        } else if (current_section == "HUDLayout") {
            if (key == "ReferenceResX") g_HUDRefW = std::stof(val);
            if (key == "ReferenceResY") g_HUDRefH = std::stof(val);
            if (key == "SpeedoPosX") g_SpeedoPosX = std::stof(val);
            if (key == "SpeedoPosY") g_SpeedoPosY = std::stof(val);
            if (key == "SpeedoWidth") g_SpeedoWidth = std::stof(val);
            if (key == "SpeedoHeight") g_SpeedoHeight = std::stof(val);
            if (key == "HeatOffsetX") g_HeatOffsetX = std::stof(val);
            if (key == "HeatOffsetY") g_HeatOffsetY = std::stof(val);
            if (key == "HeatScale") g_HeatScale = std::stof(val);
            if (key == "VehicleESPPanelX") g_VehicleESPPanelX = std::stof(val);
            if (key == "VehicleESPPanelY") g_VehicleESPPanelY = std::stof(val);
            if (key == "VehicleESPPanelW") g_VehicleESPPanelW = std::stof(val);
            if (key == "VehicleESPPanelH") g_VehicleESPPanelH = std::stof(val);
        } else if (current_section == "Tornado") {
            auto torKey = [&](int id) { if (!val.empty()) g_TorBinds[id].vk = std::stoi(val); };
            if (key == "KeySpawnDefaultLocation")    torKey(TB_SPAWN_DEFAULT);
            if (key == "KeySpawnAtCrosshair")        torKey(TB_SPAWN_CROSSHAIR);
            if (key == "KeyFollowCrosshairSmooth")   torKey(TB_FOLLOW);
            if (key == "KeyTeleportToCrosshair")     torKey(TB_TELEPORT);
            if (key == "KeyFreezeInPlace")           torKey(TB_FREEZE);
            if (key == "KeySpawnSmoothly")           torKey(TB_SPAWN_SMOOTH);
            if (key == "KeySpawnInstantly")          torKey(TB_SPAWN_INSTANT);
            if (key == "KeyDespawnInstant")          torKey(TB_DESPAWN_NOW);
            if (key == "KeyDespawnFade")             torKey(TB_DESPAWN_FADE);
            if (key == "ManualController" && !val.empty()) g_TorManualController = (uintptr_t)std::stoull(val, nullptr, 0);
            if (key == "ManualObject"     && !val.empty()) g_TorManualObject     = (uintptr_t)std::stoull(val, nullptr, 0);
        } else if (current_section == "GrapplingHook") {
            if (key == "OverrideReach")          g_GrappleReach.overrideActive = (std::stoi(val) != 0);
            if (key == "Reach")                  g_GrappleReach.customVal = std::stof(val);
            if (key == "OverrideFlightSpeed")    g_GrappleFlight.overrideActive = (std::stoi(val) != 0);
            if (key == "FlightSpeed")            g_GrappleFlight.customVal = std::stof(val);
            if (key == "OverrideReelSpeed")      g_GrappleReelSpd.overrideActive = (std::stoi(val) != 0);
            if (key == "ReelSpeed")              g_GrappleReelSpd.customVal = std::stof(val);
            if (key == "OverrideReelAccel")      g_GrappleReelAcc.overrideActive = (std::stoi(val) != 0);
            if (key == "ReelAccel")              g_GrappleReelAcc.customVal = std::stof(val);
            if (key == "TetherUnbreakable")         g_TetherUnbreakable = (std::stoi(val) != 0);
            if (key == "OverrideTetherPullForce")    g_TetherPullForce.overrideActive = (std::stoi(val) != 0);
            if (key == "TetherPullForce")            g_TetherPullForce.customVal = std::stof(val);
            if (key == "OverrideTetherRetractSpeed") g_TetherRetractSpeed.overrideActive = (std::stoi(val) != 0);
            if (key == "TetherRetractSpeed")         g_TetherRetractSpeed.customVal = std::stof(val);

            if (key == "OverrideBoosterSpeed")   { g_BoosterSpeed.overrideActive = (std::stoi(val) != 0); found_grapple_booster = true; }
            if (key == "BoosterSpeed")           g_BoosterSpeed.customVal = std::stof(val);
            if (key == "OverrideBoosterForce")   g_BoosterForce.overrideActive = (std::stoi(val) != 0);
            if (key == "BoosterForce")           g_BoosterForce.customVal = std::stof(val);
            if (key == "OverrideBoosterSpool")   g_BoosterSpool.overrideActive = (std::stoi(val) != 0);
            if (key == "BoosterSpool")           g_BoosterSpool.customVal = std::stof(val);
            if (key == "BoosterLockOnly30s")     { g_BoosterLockOnly30s = (std::stoi(val) != 0); found_booster_30s = true; }

            if (key == "OverrideBalloonAltitudeDelta" || key == "OverrideBalloonAltitude") { g_BalloonAltitudeDelta.overrideActive = (std::stoi(val) != 0); found_grapple_balloon = true; }
            if (key == "BalloonAltitudeDelta" || key == "BalloonAltitude")                 g_BalloonAltitudeDelta.customVal = std::stof(val);
            if (key == "OverrideBalloonSize")      g_BalloonSize.overrideActive = (std::stoi(val) != 0);
            if (key == "BalloonSize")              g_BalloonSize.customVal = std::stof(val);
            if (key == "OverrideBalloonLiftForce") g_BalloonLiftForce.overrideActive = (std::stoi(val) != 0);
            if (key == "BalloonLiftForce")         g_BalloonLiftForce.customVal = std::stof(val);
            if (key == "BalloonExplosiveGas")      g_BalloonExplosiveGas = (std::stoi(val) != 0);
            if (key == "OverrideTethers")          g_OverrideTethers = (std::stoi(val) != 0);
            if (key == "UnlimitedTethers")         g_UnlimitedTethers = (std::stoi(val) != 0);
            if (key == "MaxTethersCount")          g_MaxTethersCount = std::stoi(val);
        } else if (current_section == "Wingsuit") {
            auto it = g_WingsuitSettings.find(key);
            if (it != g_WingsuitSettings.end()) {
                auto& field = it->second;
                if (field.is_u32) {
                    field.current_u32 = (uint32_t)std::stoul(val);
                } else {
                    size_t pos = 0;
                    int idx = 0;
                    std::string token;
                    while ((pos = val.find(',')) != std::string::npos && idx < field.num_values) {
                        token = val.substr(0, pos);
                        field.current[idx++] = std::stof(token);
                        val.erase(0, pos + 1);
                    }
                    if (!val.empty() && idx < field.num_values) {
                        field.current[idx++] = std::stof(val);
                    }
                }
            }
        }
    }
    f.close();

    if (g_InfiniteTurboJump) {
        ToggleInfiniteTurboJump(g_InfiniteTurboJump, g_TurboJumpAirHop);
    }

    if (!found_god_mode || !found_rainbow || !found_global_world ||
        !found_max_heat_entities || !found_max_visibility_dist || !found_heat_bypasses ||
        !found_heat_active || !found_heat_detect || !found_heat_vision || !found_missions_spoiler ||
        !found_grapple_booster || !found_grapple_balloon ||
        !found_all_vehicles_nitro_jump || !found_infinite_nitro ||
        !found_infinite_turbo_jump || !found_turbo_jump_air_hop ||
        !found_health || !found_booster_30s || !found_true_kmh ||
        !found_desired_fov || !found_fov_override) {
        needs_update = true;
    }

    if (needs_update) {
        WriteConfig();
    }
}

// ============================================================================
// GLOBAL STATE
// ============================================================================
bool g_ImGuiInited = false;
bool g_ShowMenu = true;
bool g_FreezeGame = false;
// ============================================================================
// KEYBOARD POLL HOOKS (Prevents movement when menu is open)
// ============================================================================
typedef SHORT(WINAPI* GetAsyncKeyState_t)(int);
GetAsyncKeyState_t o_GetAsyncKeyState = nullptr;

typedef SHORT(WINAPI* GetKeyState_t)(int);
GetKeyState_t o_GetKeyState = nullptr;

static bool IsMovementKey(int vKey) {
    return vKey == 'W' || vKey == 'A' || vKey == 'S' || vKey == 'D' ||
           vKey == VK_SHIFT || vKey == VK_LSHIFT || vKey == VK_RSHIFT ||
           vKey == VK_SPACE ||
           vKey == VK_CONTROL || vKey == VK_LCONTROL || vKey == VK_RCONTROL ||
           vKey == VK_UP || vKey == VK_DOWN || vKey == VK_LEFT || vKey == VK_RIGHT;
}

static inline bool ShouldBlockMovementInput(int vKey) {
    if (!IsMovementKey(vKey)) return false;
    if (g_ShowMenu || g_ResizeMode != RESIZE_NONE || g_Noclip) return true;
    if (g_FreeCam && (g_FreeCamLockPlayer || g_FreeCamLockMovement)) {
        return vKey != g_ToggleKey && vKey != g_FreeCamKey && vKey != g_NoclipKey;
    }
    return false;
}

SHORT WINAPI hkGetAsyncKeyState(int vKey) {
    if (ShouldBlockMovementInput(vKey)) return 0;
    return o_GetAsyncKeyState(vKey);
}

SHORT WINAPI hkGetKeyState(int vKey) {
    if (ShouldBlockMovementInput(vKey)) return 0;
    return o_GetKeyState(vKey);
}
bool g_OpenMenuOnStart = false;
float g_MenuAlpha = 0.0f;
int g_CurrentTab = 0;
float g_UIScale = 1.7f;
int g_ToggleKey = VK_F2;

HWND g_HWnd = NULL;
WNDPROC g_OriginalWndProc = NULL;

typedef HRESULT(__stdcall* PresentFn) (IDXGISwapChain*, UINT, UINT);
PresentFn oPresent = NULL;

bool g_DisableSSReflections = false;
bool g_DisableShadows = false;
bool g_DisableMountainShadows = false;

typedef void(*SSR_Draw_t)(uintptr_t thisptr, uintptr_t ctx);
SSR_Draw_t o_SSR_Draw = nullptr;




void hk_SSR_Draw(uintptr_t thisptr, uintptr_t ctx) {
    if (thisptr) {
        static bool lastState = false;
        if (g_DisableSSReflections != lastState) {
            if (g_DisableSSReflections) {
                FastWrite<uint8_t>(thisptr + 0x301, 0);
                FastWrite<uint8_t>(thisptr + 0x302, 1);
            } else {
                FastWrite<uint8_t>(thisptr + 0x301, 1);
            }
            lastState = g_DisableSSReflections;
        }
    }
    o_SSR_Draw(thisptr, ctx);
}

ID3D11Device* g_pd3dDevice = NULL;
ID3D11DeviceContext* g_pd3dContext = NULL;
ID3D11RenderTargetView* g_mainRenderTargetView = NULL;
ID3D11Texture2D* g_FrozenTexture = nullptr;

typedef HRESULT(__stdcall* ResizeBuffersFn) (IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);
ResizeBuffersFn oResizeBuffers = NULL;

HRESULT __stdcall hkResizeBuffers(IDXGISwapChain* pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags) {
    if (g_mainRenderTargetView) {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
    HRESULT hr = oResizeBuffers(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
    if (SUCCEEDED(hr) && g_pd3dDevice) {
        ID3D11Texture2D* pBackBuffer = nullptr;
        if (SUCCEEDED(pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer))) {
            g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
            pBackBuffer->Release();
        }
    }
    return hr;
}

uintptr_t g_ExeBase = 0;
uintptr_t g_PlayerManagerAddr = 0;
bool g_HookedPresent = false;

bool g_InfBoost = false;
bool g_InfMissiles = false;
bool g_VehicleESP = false;
bool g_CarSplineESP = false;
bool g_DisableDistanceFog = false;

// ============================================================================
// REAL-TIME CAR SPLINE CAPTURE (Universal Vehicle Path & Road Capture)
// ============================================================================
struct CapturedSpline {
    uintptr_t splinePtr;
    std::vector<ImVec4> points;
    DWORD lastSeenTime;
};
static std::vector<CapturedSpline> g_ActiveCarSplines;
static CRITICAL_SECTION g_SplineLock;
static bool g_SplineLockInited = false;

static void StoreCapturedSpline(uintptr_t spline) {
    if (!g_CarSplineESP || !spline || spline < 0x10000 || spline > 0x7FFFFFFFFFFF) return;

    uintptr_t ptsBegin = 0, ptsEnd = 0;
    if (!FastRead<uintptr_t>(spline + 0x00, ptsBegin) ||
        !FastRead<uintptr_t>(spline + 0x08, ptsEnd) ||
        !ptsBegin || ptsEnd <= ptsBegin) return;

    size_t numPoints = (ptsEnd - ptsBegin) / 16;
    if (numPoints < 2 || numPoints > 2000) return;

    if (!g_SplineLockInited) {
        InitializeCriticalSection(&g_SplineLock);
        g_SplineLockInited = true;
    }

    EnterCriticalSection(&g_SplineLock);
    DWORD now = GetTickCount();
    bool found = false;

    for (auto& s : g_ActiveCarSplines) {
        if (s.splinePtr == spline) {
            s.lastSeenTime = now;
            found = true;
            break;
        }
    }

    if (!found && g_ActiveCarSplines.size() < 1000) {
        CapturedSpline newSpline;
        newSpline.splinePtr = spline;
        newSpline.lastSeenTime = now;
        newSpline.points.reserve(numPoints);

        for (size_t p = 0; p < numPoints; p++) {
            float px = 0, py = 0, pz = 0;
            uintptr_t ptAddr = ptsBegin + (p * 16);
            if (FastRead<float>(ptAddr + 0x0, px) &&
                FastRead<float>(ptAddr + 0x4, py) &&
                FastRead<float>(ptAddr + 0x8, pz)) {
                newSpline.points.push_back(ImVec4(px, py, pz, 1.0f));
            }
        }

        if (newSpline.points.size() >= 2) {
            g_ActiveCarSplines.push_back(newSpline);
        }
    }
    LeaveCriticalSection(&g_SplineLock);
}

typedef float(*AdvanceTByDistance_t)(uintptr_t spline, float curT, bool fwd, float dist, int stepLim, int iters, float tol);
AdvanceTByDistance_t o_AdvanceTByDistance = nullptr;
float hk_AdvanceTByDistance(uintptr_t spline, float curT, bool fwd, float dist, int stepLim, int iters, float tol) {
    StoreCapturedSpline(spline);
    return o_AdvanceTByDistance(spline, curT, fwd, dist, stepLim, iters, tol);
}

typedef float(*AdvanceTByDistance2_t)(uintptr_t spline, float curT, bool fwd, float dist, int stepLim, int iters, float tol, float maxT);
AdvanceTByDistance2_t o_AdvanceTByDistance2 = nullptr;
float hk_AdvanceTByDistance2(uintptr_t spline, float curT, bool fwd, float dist, int stepLim, int iters, float tol, float maxT) {
    StoreCapturedSpline(spline);
    return o_AdvanceTByDistance2(spline, curT, fwd, dist, stepLim, iters, tol, maxT);
}

typedef float(*GetNextT_t)(uintptr_t spline, float curT, float dist);
GetNextT_t o_GetNextT = nullptr;
float hk_GetNextT(uintptr_t spline, float curT, float dist) {
    StoreCapturedSpline(spline);
    return o_GetNextT(spline, curT, dist);
}

typedef float(*GetNearestT_t)(uintptr_t spline, float* pos, float radius);
GetNearestT_t o_GetNearestT = nullptr;
float hk_GetNearestT(uintptr_t spline, float* pos, float radius) {
    StoreCapturedSpline(spline);
    return o_GetNearestT(spline, pos, radius);
}

typedef void(*GetSplineData_t)(uintptr_t spline, bool p2, float* p3, float p4, float* p5, float* p6, float* p7, float* p8, float* p9, bool p10);
GetSplineData_t o_GetSplineData = nullptr;
void hk_GetSplineData(uintptr_t spline, bool p2, float* p3, float p4, float* p5, float* p6, float* p7, float* p8, float* p9, bool p10) {
    StoreCapturedSpline(spline);
    o_GetSplineData(spline, p2, p3, p4, p5, p6, p7, p8, p9, p10);
}

typedef void(*SampleSplineData_t)(uintptr_t spline, bool p2, float p3, float* p4, float* p5, float* p6, bool p7);
SampleSplineData_t o_SampleSplineData = nullptr;
void hk_SampleSplineData(uintptr_t spline, bool p2, float p3, float* p4, float* p5, float* p6, bool p7) {
    StoreCapturedSpline(spline);
    o_SampleSplineData(spline, p2, p3, p4, p5, p6, p7);
}

typedef bool(*Navmesh_CreatePathFromSpline_t)(uintptr_t thisptr, float* p1, uintptr_t spline, bool p3, bool p4, bool p5);
Navmesh_CreatePathFromSpline_t o_Navmesh_CreatePathFromSpline = nullptr;
bool hk_Navmesh_CreatePathFromSpline(uintptr_t thisptr, float* p1, uintptr_t spline, bool p3, bool p4, bool p5) {
    StoreCapturedSpline(spline);
    return o_Navmesh_CreatePathFromSpline(thisptr, p1, spline, p3, p4, p5);
}
bool g_DisableGroundHaze = false;
bool g_DisableAtmosphericScattering = false;
bool g_DisableClouds = false;
bool g_RainEverywhere = false;
bool g_DisableMotionBlur = false;
bool g_DisableRadialBlur = false;
bool g_DisableVelocityReprojection = false;
bool g_DisableEdgeStencil = false;
bool g_DisableWaterReflections = false;

// ============================================================================
// VEHICLE ESP OVERLAY - DIRECT RENDER MATRIX (+0x500)
// ============================================================================
#include <cmath>

static bool IsValidESPPointer(uintptr_t ptr) {
    if (!ptr || ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) return false;
    if ((ptr & 7) != 0) return false;
    if (g_ExeBase && ptr >= g_ExeBase && ptr <= g_ExeBase + g_Addr_6000000) return false;
    return true;
}

static std::string GetESPClassName(uintptr_t objPtr) {
    if (!objPtr || objPtr < 0x10000) return "Vehicle";
    uintptr_t vtable = 0;
    if (!FastRead<uintptr_t>(objPtr, vtable) || !vtable) return "Vehicle";
    uintptr_t col = 0;
    if (!FastRead<uintptr_t>(vtable - 8, col) || !col) return "Vehicle";
    uint32_t typeDescRVA = 0;
    if (!FastRead<uint32_t>(col + 0x0C, typeDescRVA) || !typeDescRVA) return "Vehicle";
    uintptr_t typeDesc = g_ExeBase + typeDescRVA;
    char mangledName[64] = { 0 };
    if (ReadProcessMemory(GetCurrentProcess(), (void*)(typeDesc + 0x10), mangledName, sizeof(mangledName) - 1, NULL)) {
        std::string s(mangledName);
        size_t start = s.find("?AV");
        if (start != std::string::npos) {
            s = s.substr(start + 3);
            size_t end = s.find("@@");
            if (end != std::string::npos) s = s.substr(0, end);
            return s;
        }
    }
    return "Vehicle";
}
uintptr_t g_CachedWorldSimMgr = 0;
uintptr_t GetWorldSimManager() {
    if (g_CachedWorldSimMgr) {
        uintptr_t vt = 0;
        if (FastRead<uintptr_t>(g_CachedWorldSimMgr, vt) && vt != 0) {
            return g_CachedWorldSimMgr;
        }
        g_CachedWorldSimMgr = 0;
    }

    // Never scan memory during loading screens or main menu
    if (!g_ExeBase || !GetPlayerPtr()) return 0;

    static DWORD s_lastWorldSimScan = 0;
    if (GetTickCount() - s_lastWorldSimScan < 5000) return 0;
    s_lastWorldSimScan = GetTickCount();

    // VTable RVA from Ghidra: 141d139e8 - 140000000 = 0x1D139E8
    uintptr_t targetVTable = g_ExeBase + g_Addr_1D139E8;

    // Scan memory for the global pointer that holds an instance of CAiWorldSimManager
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = nullptr;
    HANDLE hProc = GetCurrentProcess();

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && !(mbi.Protect & PAGE_GUARD)) {
            uintptr_t* ptr = (uintptr_t*)mbi.BaseAddress;
            for (size_t i = 0; i < mbi.RegionSize / sizeof(uintptr_t); ++i) {
                if (ptr[i] == targetVTable) {
                    uintptr_t candidate = (uintptr_t)&ptr[i];
                    // Validate it's a real object by checking its VTable function
                    // Just to be safe, we check if it has the Impostors array by reading +0x5C0
                    uintptr_t testBegin = 0, testEnd = 0;
                    if (FastRead<uintptr_t>(candidate + 0x5C0 + 0x18, testBegin) &&
                        FastRead<uintptr_t>(candidate + 0x5C0 + 0x20, testEnd)) {
                        if (testEnd >= testBegin) {
                            g_CachedWorldSimMgr = candidate;
                            return g_CachedWorldSimMgr;
                        }
                    }
                }
            }
        }
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uint8_t*)mbi.BaseAddress) break; // Overflow check
    }
    return 0;
}

void DrawImpostorESP(uintptr_t simVehiclesAddr, const char* typeName, 
                     float cx, float cy, float cz, 
                     float fx, float fy, float fz, 
                     float rx, float ry, float rz, 
                     float ux, float uy, float uz, 
                     float screenW, float screenH, float aspect, float fovTan, 
                     ImDrawList* drawList) {
    if (!simVehiclesAddr) return;

    // Read m_Impostors vector (Begin at +0x18, End at +0x20)
    uintptr_t impBegin = 0, impEnd = 0;
    if (!FastRead<uintptr_t>(simVehiclesAddr + 0x18, impBegin) || 
        !FastRead<uintptr_t>(simVehiclesAddr + 0x20, impEnd)) return;

    if (!impBegin || impEnd < impBegin) return;
    size_t count = (impEnd - impBegin) / 8;
    if (count > 500) count = 500; // Safety cap to prevent lag

    for (size_t i = 0; i < count; i++) {
        uintptr_t impostorPtr = 0;
        if (!FastRead<uintptr_t>(impBegin + (i * 8), impostorPtr) || !impostorPtr || !IsValidESPPointer(impostorPtr)) continue;

        // Read position from m_WorldMatrix (X=0x78, Y=0x7C, Z=0x80)
        float vx = 0, vy = 0, vz = 0;
        if (!FastRead<float>(impostorPtr + 0x78, vx) ||
            !FastRead<float>(impostorPtr + 0x7C, vy) ||
            !FastRead<float>(impostorPtr + 0x80, vz)) continue;

        if (std::abs(vx) < 1.0f && std::abs(vy) < 1.0f && std::abs(vz) < 1.0f) continue;

        float dx = vx - cx;
        float dy = vy - cy;
        float dz = vz - cz;

        float dist3D = std::sqrt(dx*dx + dy*dy + dz*dz);
        float distF = dx * fx + dy * fy + dz * fz;
        if (distF <= 0.0f) continue; // Cull objects behind camera

        float distR = dx * rx + dy * ry + dz * rz;
        float distU = dx * ux + dy * uy + dz * uz;

        float projX = (distR / (distF * aspect * fovTan));
        float projY = (distU / (distF * fovTan));

        ImVec2 screenPos;
        screenPos.x = (screenW * 0.5f) * (1.0f + projX);
        screenPos.y = (screenH * 0.5f) * (1.0f - projY);

        // Dynamic perspective projection scaling (6m wide, 3m high generic proportions)
        float boxW = (6.0f / (distF * aspect * fovTan)) * (screenW * 0.5f);
        float boxH = (3.0f / (distF * fovTan)) * (screenH * 0.5f);
        if (boxW < 8.0f) boxW = 8.0f;
        if (boxH < 5.0f) boxH = 5.0f;

        float x1 = screenPos.x - (boxW * 0.5f);
        float y1 = screenPos.y - (boxH * 0.5f);
        float x2 = screenPos.x + (boxW * 0.5f);
        float y2 = screenPos.y + (boxH * 0.5f);

        // Render Orange ESP Box for LODs
        drawList->AddRect(ImVec2(x1, y1), ImVec2(x2, y2), IM_COL32(255, 165, 0, 255), 4.0f, 0, 2.0f);
        drawList->AddRectFilled(ImVec2(x1, y1), ImVec2(x2, y2), IM_COL32(40, 25, 0, 90), 4.0f);

        float fontSize = 16.0f * g_UIScale;
        ImFont* font = ImGui::GetFont();

        // Name (Centered above box)
        char nameBuf[64];
        snprintf(nameBuf, sizeof(nameBuf), "%s LOD (%.0fm)", typeName, dist3D);
        ImVec2 nameSize = font->CalcTextSizeA(fontSize, FLT_MAX, 0.0f, nameBuf);
        drawList->AddText(font, fontSize, ImVec2(screenPos.x - (nameSize.x * 0.5f), y1 - fontSize - 4.0f), IM_COL32(255, 165, 0, 255), nameBuf);
    }
}
uintptr_t g_CachedGraphicsCamMgr = 0;
uintptr_t GetGraphicsCameraManager() {
    if (g_CachedGraphicsCamMgr) {
        uintptr_t vt = 0;
        if (FastRead<uintptr_t>(g_CachedGraphicsCamMgr, vt) && vt != 0) {
            return g_CachedGraphicsCamMgr;
        }
        g_CachedGraphicsCamMgr = 0;
    }

    // Never scan memory during loading screens or main menu
    if (!g_ExeBase || !GetPlayerPtr()) return 0;

    static DWORD s_lastGraphicsCamScan = 0;
    if (GetTickCount() - s_lastGraphicsCamScan < 5000) return 0;
    s_lastGraphicsCamScan = GetTickCount();

    // VTable RVA for NGraphicsEngine::CCameraManager: 141e7eec0 - 140000000 = 0x1E7EEC0
    uintptr_t targetVTable = g_ExeBase + g_Addr_1E7EEC0;

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = nullptr;
    HANDLE hProc = GetCurrentProcess();

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && !(mbi.Protect & PAGE_GUARD)) {
            uintptr_t* ptr = (uintptr_t*)mbi.BaseAddress;
            for (size_t i = 0; i < mbi.RegionSize / sizeof(uintptr_t); ++i) {
                if (ptr[i] == targetVTable) {
                    uintptr_t candidate = (uintptr_t)&ptr[i];
                    // Validate it's a real object by checking m_ActiveCamera pointer
                    uintptr_t activeCam = 0;
                    if (FastRead<uintptr_t>(candidate + 0x5C0, activeCam) && IsValidESPPointer(activeCam)) {
                        g_CachedGraphicsCamMgr = candidate;
                        return g_CachedGraphicsCamMgr;
                    }
                }
            }
        }
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uint8_t*)mbi.BaseAddress) break; // Overflow check
    }
    return 0;
}
void DrawCarSplineESP() {
    if (!g_CarSplineESP || !g_ExeBase) return;

    // 1. Read Camera Matrix (+0x500) and FOV
    uintptr_t cameraManager = 0;
    FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cameraManager);
    if (!cameraManager) return;

    float m[16] = { 0 };
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)(cameraManager + 0x500), m, sizeof(m), NULL)) return;

    float rx = m[0],  ry = m[1],  rz = m[2];
    float ux = m[4],  uy = m[5],  uz = m[6];
    float fx = -m[8], fy = -m[9], fz = -m[10];
    float cx = m[12], cy = m[13], cz = m[14];

    float liveFov = 0.0f;
    uintptr_t graphicsCamMgr = GetGraphicsCameraManager();
    if (graphicsCamMgr) {
        uintptr_t activeCam = 0;
        if (FastRead<uintptr_t>(graphicsCamMgr + 0x5C0, activeCam) && activeCam) {
            FastRead<float>(activeCam + 0x588, liveFov);
        }
    }
    if (liveFov <= 0.1f || liveFov > 3.0f) {
        FastRead<float>(cameraManager + 0x320, liveFov);
    }
    float fovTan = (liveFov > 0.1f && liveFov < 3.0f) ? tanf(liveFov / 2.0f) : 0.55f;

    ImGuiIO& io = ImGui::GetIO();
    float screenW = io.DisplaySize.x;
    float screenH = io.DisplaySize.y;
    if (screenW <= 100.0f || screenH <= 100.0f) return;
    float aspect = screenW / screenH;

    ImDrawList* drawList = ImGui::GetBackgroundDrawList();

    // 3D-to-2D World-to-Screen Projection Helper
    auto WorldToScreen = [&](float wx, float wy, float wz, ImVec2& outScreen) -> bool {
        float dx = wx - cx, dy = wy - cy, dz = wz - cz;
        float distF = dx * fx + dy * fy + dz * fz;
        if (distF <= 0.1f) return false;

        float distR = dx * rx + dy * ry + dz * rz;
        float distU = dx * ux + dy * uy + dz * uz;

        float projX = distR / (distF * aspect * fovTan);
        float projY = distU / (distF * fovTan);

        outScreen.x = (screenW * 0.5f) * (1.0f + projX);
        outScreen.y = (screenH * 0.5f) * (1.0f - projY);
        return true;
    };

    // 3D Near-Plane Segment Clipper (Prevents lines from vanishing when turning camera)
    auto ClipAndDrawLine = [&](ImVec4 pA, ImVec4 pB, ImU32 col, float thickness) {
        float dxA = pA.x - cx, dyA = pA.y - cy, dzA = pA.z - cz;
        float distFA = dxA * fx + dyA * fy + dzA * fz;

        float dxB = pB.x - cx, dyB = pB.y - cy, dzB = pB.z - cz;
        float distFB = dxB * fx + dyB * fy + dzB * fz;

        const float nearZ = 0.2f;
        if (distFA < nearZ && distFB < nearZ) return;

        ImVec4 finalA = pA;
        ImVec4 finalB = pB;

        if (distFA < nearZ) {
            float t = (nearZ - distFA) / (distFB - distFA);
            finalA.x = pA.x + t * (pB.x - pA.x);
            finalA.y = pA.y + t * (pB.y - pA.y);
            finalA.z = pA.z + t * (pB.z - pA.z);
        } else if (distFB < nearZ) {
            float t = (nearZ - distFA) / (distFB - distFA);
            finalB.x = pA.x + t * (pB.x - pA.x);
            finalB.y = pA.y + t * (pB.y - pA.y);
            finalB.z = pA.z + t * (pB.z - pA.z);
        }

        ImVec2 scrA, scrB;
        if (WorldToScreen(finalA.x, finalA.y, finalA.z, scrA) &&
            WorldToScreen(finalB.x, finalB.y, finalB.z, scrB)) {
            drawList->AddLine(scrA, scrB, col, thickness);
        }
    };

    if (!g_SplineLockInited) return;

    EnterCriticalSection(&g_SplineLock);
    DWORD now = GetTickCount();

    // Retain active traffic paths for 10 seconds and distance-cull beyond 800m
    size_t renderedCount = 0;
    for (int i = (int)g_ActiveCarSplines.size() - 1; i >= 0; i--) {
        if (now - g_ActiveCarSplines[i].lastSeenTime > 10000) {
            g_ActiveCarSplines.erase(g_ActiveCarSplines.begin() + i);
        }
    }

    // 2. Render all active car splines
    for (const auto& s : g_ActiveCarSplines) {
        if (s.points.size() < 2) continue;

        // Distance cull check (render if ANY point of the road is within 1200m)
        float minCamDistSq = 1e9f;
        for (const auto& pt : s.points) {
            float distSq = (pt.x - cx)*(pt.x - cx) + (pt.y - cy)*(pt.y - cy) + (pt.z - cz)*(pt.z - cz);
            if (distSq < minCamDistSq) minCamDistSq = distSq;
        }
        if (minCamDistSq > (1200.0f * 1200.0f)) continue;

        renderedCount++;

        // Exclude Catmull-Rom tangent ghost points (Index 0 and Index N-1)
        size_t startIdx = (s.points.size() >= 4) ? 1 : 0;
        size_t endIdx   = (s.points.size() >= 4) ? (s.points.size() - 2) : (s.points.size() - 1);

        for (size_t p = startIdx; p < endIdx; p++) {
            ClipAndDrawLine(s.points[p], s.points[p + 1], IM_COL32(0, 255, 140, 240), 2.5f);

            ImVec2 scrNode;
            if (WorldToScreen(s.points[p].x, s.points[p].y, s.points[p].z, scrNode)) {
                drawList->AddCircleFilled(scrNode, 2.0f * g_UIScale, IM_COL32(255, 230, 0, 255));
            }
        }
        
        ImVec2 scrLast;
        if (WorldToScreen(s.points[endIdx].x, s.points[endIdx].y, s.points[endIdx].z, scrLast)) {
            drawList->AddCircleFilled(scrLast, 2.0f * g_UIScale, IM_COL32(255, 230, 0, 255));
        }
    }
    LeaveCriticalSection(&g_SplineLock);

    // 3. Diagnostic HUD Tag
    char diagBuf[64];
    snprintf(diagBuf, sizeof(diagBuf), "[Car Splines ESP] Active Paths: %zu", renderedCount);
    drawList->AddText(ImVec2(screenW - 280.0f * g_UIScale, 20.0f * g_UIScale), IM_COL32(0, 255, 140, 255), diagBuf);
}
void DrawVehicleESP() {
    if (!g_VehicleESP || !g_ExeBase) return;

    ImDrawList* drawList = ImGui::GetBackgroundDrawList();

    // 1. Read CGameCameraManager Singleton (game.exe + 0x2CB1D90)
    uintptr_t cameraManager = 0;
    FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cameraManager);

    // 2. Read Live Render Matrix at +0x500
    float m[16] = { 0 };
    bool matrixValid = false;
    if (cameraManager) {
        matrixValid = ReadProcessMemory(GetCurrentProcess(), (void*)(cameraManager + 0x500), m, sizeof(m), NULL);
    }

    // 3. Read m_GameObjects vehicle vector
    uintptr_t m_GameObjects_Addr = g_ExeBase + g_Addr_2CB1938;
    uintptr_t myFirst = 0, myLast = 0;
    bool vecValid = FastRead<uintptr_t>(m_GameObjects_Addr + 0x0, myFirst) &&
                    FastRead<uintptr_t>(m_GameObjects_Addr + 0x8, myLast) &&
                    myFirst && myLast >= myFirst;

    size_t totalVehicles = vecValid ? ((myLast - myFirst) / 8) : 0;
    if (totalVehicles > 2000) totalVehicles = 2000;

    // Extract Camera Vectors from offset +0x500
    float rx = m[0],  ry = m[1],  rz = m[2];   // Right Vector (+0x500)
    float ux = m[4],  uy = m[5],  uz = m[6];   // Up Vector    (+0x510)
    float fx = -m[8], fy = -m[9], fz = -m[10]; // Forward Vec  (+0x520) [Inverted]
    float cx = m[12], cy = m[13], cz = m[14]; // Camera Pos   (+0x530)
    
        // Read live FOV from NGraphicsEngine::CCameraManager (Render Camera)
    float liveFov = 0.0f;
    uintptr_t graphicsCamMgr = GetGraphicsCameraManager();
    if (graphicsCamMgr) {
        uintptr_t activeCam = 0;
        if (FastRead<uintptr_t>(graphicsCamMgr + 0x5C0, activeCam) && activeCam) {
            FastRead<float>(activeCam + 0x588, liveFov); // Read m_FOV (0x588)
        }
    }
    
    // Fallback to GameCameraManager if render camera FOV is invalid
    if (liveFov <= 0.1f || liveFov > 3.0f) {
        FastRead<float>(cameraManager + 0x320, liveFov);
    }
    
    float fovTan = 0.55f; // Fallback
    if (liveFov > 0.1f && liveFov < 3.0f) {
        fovTan = tanf(liveFov / 2.0f);
    }

    // Read Vehicle 0 Position for Diagnostics
    float v0x = 0, v0y = 0, v0z = 0;
    uintptr_t v0Ptr = 0;
    if (totalVehicles > 0 && FastRead<uintptr_t>(myFirst, v0Ptr) && v0Ptr) {
        FastRead<float>(v0Ptr + 0x644, v0x);
        FastRead<float>(v0Ptr + 0x648, v0y);
        FastRead<float>(v0Ptr + 0x64C, v0z);
    }

    float dx0 = v0x - cx, dy0 = v0y - cy, dz0 = v0z - cz;
    float distF0 = dx0 * fx + dy0 * fy + dz0 * fz;

    // DRAW DIAGNOSTIC OVERLAY PANEL
    drawList->AddRectFilled(ImVec2(g_VehicleESPPanelX, g_VehicleESPPanelY), 
                            ImVec2(g_VehicleESPPanelX + g_VehicleESPPanelW, g_VehicleESPPanelY + g_VehicleESPPanelH), 
                            IM_COL32(0, 0, 0, 230), 6.0f);
    drawList->AddRect(ImVec2(g_VehicleESPPanelX, g_VehicleESPPanelY), 
                      ImVec2(g_VehicleESPPanelX + g_VehicleESPPanelW, g_VehicleESPPanelY + g_VehicleESPPanelH), 
                      IM_COL32(255, 200, 0, 255), 6.0f, 0, 1.5f);

    // Distribute the 11 lines evenly across the full height of the panel
    float lineStep = (g_VehicleESPPanelH - 18.0f) / 11.0f;
    
    // Scale font directly with line height so text fills the box cleanly
    float fontSize = lineStep * 0.72f;

    // Width constraint check (ensures long lines don't overflow horizontally if made narrow)
    float maxFontSizeWidth = (g_VehicleESPPanelW - 24.0f) / 34.0f;
    if (fontSize > maxFontSizeWidth) fontSize = maxFontSizeWidth;

    // Safety clamps
    if (fontSize < 10.0f) fontSize = 10.0f;
    if (fontSize > 36.0f) fontSize = 36.0f;
    if (lineStep < fontSize + 2.0f) lineStep = fontSize + 2.0f;

    ImFont* font = ImGui::GetFont();
    float y = g_VehicleESPPanelY + 9.0f;

    // Clip output so text never bleeds outside the user's resized box
    drawList->PushClipRect(ImVec2(g_VehicleESPPanelX, g_VehicleESPPanelY),
                           ImVec2(g_VehicleESPPanelX + g_VehicleESPPanelW, g_VehicleESPPanelY + g_VehicleESPPanelH), true);

    auto printLine = [&](const char* text) {
        drawList->AddText(font, fontSize, ImVec2(g_VehicleESPPanelX + 12.0f, y), IM_COL32(0, 255, 255, 255), text);
        y += lineStep;
    };

    char buf[256];
    snprintf(buf, sizeof(buf), "=== [LIVE RENDER MATRIX ESP (+0x500)] ==="); printLine(buf);
    snprintf(buf, sizeof(buf), "CameraManager Addr: 0x%X | Matrix Status: %s", (unsigned int)cameraManager, matrixValid ? "VALID" : "NOT FOUND"); printLine(buf);
    snprintf(buf, sizeof(buf), "Camera Position  : (%.1f, %.1f, %.1f)", cx, cy, cz); printLine(buf);
    snprintf(buf, sizeof(buf), "Camera Right     : (%.3f, %.3f, %.3f)", rx, ry, rz); printLine(buf);
    snprintf(buf, sizeof(buf), "Camera Up        : (%.3f, %.3f, %.3f)", ux, uy, uz); printLine(buf);
    snprintf(buf, sizeof(buf), "Camera Forward   : (%.3f, %.3f, %.3f)", fx, fy, fz); printLine(buf);
    snprintf(buf, sizeof(buf), "Live FOV (rad)   : %.3f | Tan: %.3f", liveFov, fovTan); printLine(buf);
    snprintf(buf, sizeof(buf), "--------------------------------------------------"); printLine(buf);
    snprintf(buf, sizeof(buf), "Vehicle Count    : %zu | Vehicle [0] Addr: 0x%X", totalVehicles, (unsigned int)v0Ptr); printLine(buf);
    snprintf(buf, sizeof(buf), "Vehicle [0] Pos  : (%.1f, %.1f, %.1f)", v0x, v0y, v0z); printLine(buf);
    snprintf(buf, sizeof(buf), "Delta (dx,dy,dz) : (%.1f, %.1f, %.1f)", dx0, dy0, dz0); printLine(buf);

    drawList->PopClipRect();

    if (!matrixValid) return;

    ImGuiIO& io = ImGui::GetIO();
    float screenW = io.DisplaySize.x;
    float screenH = io.DisplaySize.y;
    if (screenW <= 100.0f || screenH <= 100.0f) return;
    float aspect = screenW / screenH;

    int drawnBoxes = 0;

    for (size_t i = 0; i < totalVehicles; i++) {
        uintptr_t vehiclePtr = 0;
        if (!FastRead<uintptr_t>(myFirst + (i * 8), vehiclePtr) || !vehiclePtr) continue;

        float vx = 0.0f, vy = 0.0f, vz = 0.0f;
        if (!FastRead<float>(vehiclePtr + 0x644, vx) ||
            !FastRead<float>(vehiclePtr + 0x648, vy) ||
            !FastRead<float>(vehiclePtr + 0x64C, vz)) continue;

        float dx = vx - cx;
        float dy = vy - cy;
        float dz = vz - cz;

        float dist3D = std::sqrt(dx*dx + dy*dy + dz*dz);

        float distF = dx * fx + dy * fy + dz * fz;
        if (distF <= 0.0f) continue; // Cull objects strictly behind the camera

        float distR = dx * rx + dy * ry + dz * rz;
        float distU = dx * ux + dy * uy + dz * uz;

        float projX = (distR / (distF * aspect * fovTan));
        float projY = (distU / (distF * fovTan));

        ImVec2 screenPos;
        screenPos.x = (screenW * 0.5f) * (1.0f + projX);
        screenPos.y = (screenH * 0.5f) * (1.0f - projY);

        // Dynamic perspective projection scaling (6m wide, 3m high generic vehicle proportions)
        float boxW = (6.0f / (distF * aspect * fovTan)) * (screenW * 0.5f);
        float boxH = (3.0f / (distF * fovTan)) * (screenH * 0.5f);
        
        // Enforce a minimum screen size so it remains visible at extreme distances
        if (boxW < 8.0f) boxW = 8.0f;
        if (boxH < 5.0f) boxH = 5.0f;

        float x1 = screenPos.x - (boxW * 0.5f);
        float y1 = screenPos.y - (boxH * 0.5f);
        float x2 = screenPos.x + (boxW * 0.5f);
        float y2 = screenPos.y + (boxH * 0.5f);

        // Health via VTable +0x120 & IsDestroyed via VTable +0x128
        uintptr_t vtable = 0;
        int health = 0;
        int isDestroyed = 0;
        if (IsLikelyGameObject(vehiclePtr) && FastRead<uintptr_t>(vehiclePtr, vtable) && vtable) {
            typedef int(*HealthFn)(uintptr_t);
            typedef int(*DestroyedFn)(uintptr_t);
            uintptr_t hFunc = 0, dFunc = 0;
            if (FastRead<uintptr_t>(vtable + 0x120, hFunc) && hFunc && hFunc >= g_ExeBase && hFunc < g_ExeBase + g_Addr_10000000) {
                health = ((HealthFn)hFunc)(vehiclePtr);
            }
            if (FastRead<uintptr_t>(vtable + 0x128, dFunc) && dFunc && dFunc >= g_ExeBase && dFunc < g_ExeBase + g_Addr_10000000) {
                isDestroyed = ((DestroyedFn)dFunc)(vehiclePtr);
            }
        }

        std::string className = GetESPClassName(vehiclePtr);
        drawnBoxes++;

        // Render Red ESP Box
        drawList->AddRect(ImVec2(x1, y1), ImVec2(x2, y2), IM_COL32(255, 30, 30, 255), 4.0f, 0, 2.0f);
        drawList->AddRectFilled(ImVec2(x1, y1), ImVec2(x2, y2), IM_COL32(20, 0, 0, 90), 4.0f);

        float fontSize = 16.0f * g_UIScale;
        ImFont* font = ImGui::GetFont();

        // Name (Centered strictly above the box)
        char nameBuf[64];
        snprintf(nameBuf, sizeof(nameBuf), "%s (%.0fm)", className.c_str(), dist3D);
        ImVec2 nameSize = font->CalcTextSizeA(fontSize, FLT_MAX, 0.0f, nameBuf);
        drawList->AddText(font, fontSize, ImVec2(screenPos.x - (nameSize.x * 0.5f), y1 - fontSize - 4.0f), IM_COL32(255, 100, 100, 255), nameBuf);

        // Enforce a minimum width for the bottom row so "ALIVE" and "HP:" never overlap
        float minBoxW = 90.0f * g_UIScale;
        float textRowW = (boxW > minBoxW) ? boxW : minBoxW;
        float textX1 = screenPos.x - (textRowW * 0.5f);
        float textX2 = screenPos.x + (textRowW * 0.5f);

        // Status (Bottom left of the box)
        const char* statusStr = (isDestroyed == 1 || health <= 0) ? "DESTROYED" : "ALIVE";
        drawList->AddText(font, fontSize, ImVec2(textX1, y2 + 4.0f), 
            (isDestroyed == 1 || health <= 0) ? IM_COL32(255, 30, 30, 255) : IM_COL32(50, 255, 50, 255), statusStr);

        // HP (Bottom right of the box)
        char hpBuf[32];
        snprintf(hpBuf, sizeof(hpBuf), "HP:%d", health);
        ImVec2 hpSize = font->CalcTextSizeA(fontSize, FLT_MAX, 0.0f, hpBuf);
        drawList->AddText(font, fontSize, ImVec2(textX2 - hpSize.x, y2 + 4.0f), IM_COL32(255, 100, 100, 255), hpBuf);
    }

    // === DRAW LOD (IMPOSTOR) VEHICLES ===
    uintptr_t worldSimMgr = GetWorldSimManager();
    if (worldSimMgr) {
        DrawImpostorESP(worldSimMgr + 0x5C0, "Land", cx, cy, cz, fx, fy, fz, rx, ry, rz, ux, uy, uz, screenW, screenH, aspect, fovTan, drawList);
        DrawImpostorESP(worldSimMgr + 0x6D8, "Sea", cx, cy, cz, fx, fy, fz, rx, ry, rz, ux, uy, uz, screenW, screenH, aspect, fovTan, drawList);
        DrawImpostorESP(worldSimMgr + 0x7F0, "Air", cx, cy, cz, fx, fy, fz, rx, ry, rz, ux, uy, uz, screenW, screenH, aspect, fovTan, drawList);
    }
}
float g_Thrust = 0.0f, default_thrust = 0.0f;
float g_Floor = 0.0f, default_floor = 0.0f;
float g_MaxSpeed = 0.0f, default_maxspeed = 0.0f;
float g_HavokMaxSpeed = 250.0f, default_havok_max_speed = 250.0f;
float g_HavokMaxAccel = 625.0f, default_havok_max_accel = 625.0f;
bool g_DefaultsCaptured = false;

void ApplyHavokPhysicsSettings() {
    if (!g_ExeBase) return;

    // 1. Update static float constants for future character creations / respawns
    FastWrite<float>(g_ExeBase + g_Addr_1CAE1C4, g_HavokMaxSpeed);
    FastWrite<float>(g_ExeBase + g_Addr_1CAE1CC, g_HavokMaxAccel);

    // 2. Layer 1: Mutate all entries in Havok Motion Properties Library
    uintptr_t pWorld = 0;
    if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CE3F30, pWorld) && pWorld) {
        uintptr_t pMotionLib = 0;
        if (FastRead<uintptr_t>(pWorld + 0x990, pMotionLib) && pMotionLib) {
            uintptr_t pElementsData = 0;
            int numElements = 0;
            if (FastRead<uintptr_t>(pMotionLib + 0x30, pElementsData) &&
                FastRead<int>(pMotionLib + 0x38, numElements) &&
                pElementsData && numElements > 0) {
                for (int i = 0; i < numElements; i++) {
                    uintptr_t entryBase = pElementsData + (uintptr_t)(i * 0x40);
                    FastWrite<float>(entryBase + 0x10, g_HavokMaxSpeed);
                }
            }
        }
    }

    // 3. Layer 2: Mutate live player CCharacter -> CPfxCharacterInstance -> hknpCharacterContext
    uintptr_t player = GetPlayerPtr();
    if (player) {
        uintptr_t character = 0;
        if (FastRead<uintptr_t>(player + 0x68, character) && character) {
            uintptr_t pfxInstance = 0;
            if (FastRead<uintptr_t>(character + 0x2208, pfxInstance) && pfxInstance) {
                uintptr_t charContext = 0;
                if (FastRead<uintptr_t>(pfxInstance + 0x1C8, charContext) && charContext) {
                    FastWrite<float>(charContext + 0x34, g_HavokMaxAccel);
                    FastWrite<float>(charContext + 0x38, g_HavokMaxSpeed);
                }
            }
        }
    }
}

static char g_SearchBuf[256] = "";

// Spawn tab state
int g_SpawnFavoriteKey = VK_F3;
std::string g_FavoriteVehicle;
static char g_ManualSpawnBuf[256] = "";
static char g_SpawnSearchBuf[256] = "";
static bool g_AssigningFavoriteKey = false;
static double g_FavoriteKeyListenStart = 0.0;

// Chaos Object Spawner state
struct ChaosObjectEntry {
    const char* displayName;
    const char* tag;
};

static const ChaosObjectEntry g_ChaosObjects[] = {
    { "Black Hand Dictator Statue", "statue_blackhand" },
    { "Explosive Fuel Barrel", "barrel_fuel" },
    { "Naval Chaos Water Mine", "water_mine" },
    { "Demon Egg Nest Pod", "dlc2_single_egg_supply_drop" },
    { "Demon Core Mine", "dlc2_core_mine" },
    { "Sky Crane with Fuel Sphere Tank", "v200_helicopter_heavylift_military_chaos_sphere_tank" },
    { "Black Hand Huntsman SAM Site", "v904_trailer_smallmobileweapon_military" },
    { "Rebel Huntsman SAM Site", "v904_trailer_smallmobileweapon_rebel" },
    { "Military Radar Jammer", "v907_trailer_radarjammer_military" },
    { "Active Radar Dish (Upright)", "v902_trailer_lowloader_mobile_radar_upright" },
    { "Mobile Radar Dish (Folded)", "v902_trailer_lowloader_mobile_radar_folded" },
    { "Mounted Anti-Air Gun (Flak)", "wpn_203_aa_gun" },
    { "Heavy Artillery Cannon", "wpn_202_cannon" },
    { "Mounted Heavy Mortar", "wpn_204_mortar_mounted" },
    { "Agency Cruise Missile", "agency_cargo_missile" },
    { "Demonic Substrate AA Tank", "dlc2_substrate_weapon_aa_tank_01" },
    { "Demonic Substrate AA Gun", "dlc2_substrate_weapon_aa_gun_01" },
    { "Demonic Substrate Cannon Truck", "dlc2_substrate_weapon_cannon_truck_01" },
    { "Demonic Substrate Armored APC", "dlc2_substrate_weapon_apc_01" }
};

static int g_SelectedChaosIndex = 0;
int g_SpawnChaosKey = 0; // 0 = None (Disabled by default)
static bool g_AssigningChaosKey = false;
static double g_ChaosKeyListenStart = 0.0;
static char g_ManualChaosBuf[256] = "";

// ============================================================================
// CPlayerManager DISCOVERY
// ============================================================================
uintptr_t FindPlayerManagerAOB(uintptr_t base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD imgSize = nt->OptionalHeader.SizeOfImage;
    uint8_t* bytes = (uint8_t*)base;

    for (DWORD i = 0; i < imgSize - 7; i++) {
        if (bytes[i] == 0x48 && bytes[i + 1] == 0x8B &&
            bytes[i + 3] == 0x40 && bytes[i + 4] == 0x09 && bytes[i + 5] == 0x00 && bytes[i + 6] == 0x00) {
            for (int back = 1; back < 64; back++) {
                uint8_t* p = &bytes[i - back];
                if (p[0] == 0x48 && p[1] == 0x8B && (p[2] == 0x05 || p[2] == 0x0D || p[2] == 0x15 || p[2] == 0x1D)) {
                    int32_t rel = *reinterpret_cast<int32_t*>(p + 3);
                    return reinterpret_cast<uintptr_t>(p) + 7 + rel;
                }
            }
        }
    }
    return 0;
}

// ============================================================================
// WINGSUIT POINTER RESOLVER & APPLIER
// ============================================================================
uintptr_t g_CachedWingsuitPtr = 0;

void ApplyWingsuitSettings(uintptr_t settingsPtr) {
    if (!settingsPtr) return;
    for (auto& [n, f] : g_WingsuitSettings) {
        if (f.is_u32) {
            FastWrite<uint32_t>(settingsPtr + f.offset, f.current_u32);
        } else {
            for (int i = 0; i < f.num_values && i < 5; i++) {
                FastWrite<float>(settingsPtr + f.offset + (uintptr_t)(i * 4), f.current[i]);
            }
        }
    }
}
static DWORD g_LastWingsuitScan = 0;

static bool IsValidHeapPointer(uintptr_t ptr) {
    if (!ptr || ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) return false;
    if ((ptr & 7) != 0) return false;
    if (ptr >= g_ExeBase && ptr <= g_ExeBase + g_Addr_6000000) return false;
    return true;
}

uintptr_t GetWingsuitSettingsPtr() {
    uintptr_t playerPtr = GetPlayerPtr();
    if (!playerPtr) {
        g_CachedWingsuitPtr = 0;
        return 0;
    }

    uintptr_t characterPtr = 0;
    if (!FastRead<uintptr_t>(playerPtr + 0x68, characterPtr) || !characterPtr || !IsValidHeapPointer(characterPtr)) {
        g_CachedWingsuitPtr = 0;
        return 0;
    }

    uintptr_t settings = 0;
    if (!FastRead<uintptr_t>(characterPtr + 0x940, settings) || !settings || !IsValidHeapPointer(settings)) {
        g_CachedWingsuitPtr = 0;
        return 0;
    }

    float grav = 0.0f;
    if (!FastRead<float>(settings + 0x7B8, grav) || std::isnan(grav) || std::isinf(grav)) {
        g_CachedWingsuitPtr = 0;
        return 0;
    }

    g_CachedWingsuitPtr = settings;
    return g_CachedWingsuitPtr;
}

// ============================================================================
// PATCH IMPLEMENTATIONS
// ============================================================================
static bool BytesMatch(uintptr_t a, const uint8_t* b, size_t n) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (n > 32 || !VirtualQuery((void*)a, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) return false;
    uint8_t buf[32]; SIZE_T r = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)a, buf, n, &r) || r != n) return false;
    return memcmp(buf, b, n) == 0;
}
void ToggleInfBoost(bool enable) {
    if (!g_ExeBase) return;
    static bool isPatched = false;
    if (!enable && !isPatched) return; // Don't write memory on startup when disabled

    static const uint8_t nop_6[6]      = {0x90,0x90,0x90,0x90,0x90,0x90};
    static const uint8_t orig_cmp[6]   = {0x80,0x7B,0x15,0x00,0x74,0x0B};
    static const uint8_t patch_latch[6]= {0xC6,0x43,0x15,0x00,0xEB,0x0B};
    static const uint8_t orig_drain[6] = {0xF3,0x0F,0x11,0x4C,0x83,0x08};
    static const uint8_t patch_drain[6]= {0xF3,0x0F,0x11,0x5C,0x83,0x08};
    static const uint8_t orig_jae[6]   = {0x0F,0x83,0x1C,0x01,0x00,0x00};

    uintptr_t a1 = g_ExeBase + g_Addr_98ABC9B;
    uintptr_t a2 = g_ExeBase + g_Addr_98ABCE5;
    uintptr_t a3 = g_ExeBase + g_Addr_98ABD17;

    if (enable) {
        SafePatchBytes(a1, patch_latch, 6);
        SafePatchBytes(a2, patch_drain, 6);
        SafePatchBytes(a3, nop_6, 6);
        isPatched = true;
    } else {
        SafePatchBytes(a1, orig_cmp, 6);
        SafePatchBytes(a2, orig_drain, 6);
        SafePatchBytes(a3, orig_jae, 6);
        isPatched = false;
    }
}

void ToggleMountainShadows(bool enable) {
    if (!g_ExeBase) return;
    static bool isPatched = false;
    if (!enable && !isPatched) return; // Don't write memory on startup when disabled

    uintptr_t addr = g_ExeBase + g_Addr_A59C196;
    static const uint8_t orig_jz[6] = {0x0F, 0x84, 0xCE, 0x00, 0x00, 0x00};
    static const uint8_t patch_jmp[6] = {0xE9, 0xCF, 0x00, 0x00, 0x00, 0x90};
    if (!BytesMatch(addr, enable ? orig_jz : patch_jmp, 6)) return;
    SafePatchBytes(addr, enable ? patch_jmp : orig_jz, 6);
    isPatched = enable;
}

// ============================================================================
// SHADOW RESOLUTION — NATIVE SETTINGS-MANAGER PIPELINE (engine-driven, 1:1)
// ============================================================================
// How the game natively changes the shadow atlas resolution (traced in Ghidra
// with the Steam PDB symbols):
//
//  1. The options menu calls CSettingsManager::SetValue (0x140BAB800) with
//     EGraphicsShadowsQuality (m_Settings._Elems[4], +0x88) or
//     EGraphicsShadowsResolution (_Elems[8], +0x98). For the whole
//     graphics-quality group SetValue does ONLY:
//         m_Settings._Elems[type] = value;
//         m_UpdateFlagsChanges |= 4;                // dirty bit, this+0x70
//  2. Every frame CGraphicsEngine::Update (0x14086D1E0) calls
//     CSettingsManager::Update (0x140BB3A00), which runs:
//         if (m_UpdateFlagsChanges != 0)
//             UpdateSettings(this, m_UpdateFlagsChanges, ESMUT_REGULAR);
//  3. CSettingsManager::UpdateSettings (0x140BBAC20 tail-jumps to
//     0x149AD56E0), bit-4 block, ON THE MAIN THREAD IN THE GAME-UPDATE PHASE
//     (before the render phase records a single draw command of the new
//     frame):
//         SetTextureCacheStreamPoolSize / SetTextureCacheGroupLodBias
//         WaitForCPUDrawToFinish(engine);            // frame-boundary wait
//         m_Aniso, model+vehicle LOD factors
//         size = (ShadowsResolution==1 ? hi_q : lo_q)[ShadowsQuality];
//             // lo_q @0x1E63090 = {256,384,512,1024,1280} (ushort[5])
//             // hi_q @0x1E630A0 = {256,512,1024,2048,2536} (ushort[5])
//         CShadowManager::SetTextureSize(GetShadowManager(), size);
//             // Graphics::ResizeTexture("shadow_buffer") + rebuild of the 16
//             // depth surfaces / render setups + ESM/MSM filterable teardown
//             // + clears under the master context lock — all engine-owned.
//         SSAO / AA / SSR / water / motion-blur / GI re-asserts
//         m_UpdateFlagsChanges &= 0x3380;            // bit 4 consumed
//
// This is why the game itself resizes the atlas live when you change the
// shadow quality in the options and never crashes. Calling CShadowManager::SetTextureSize
// directly from hkPresent (holding graphics mutexes), from a worker thread, or from a
// WaitForCPUDrawToFinish hook (which also fires from UpdateRender mid-render-phase,
// DeleteAOVolume, and the video player) races in-flight frames and causes GPU device
// removal — the engine's own UpdateSettings call site is unique.
//
// This implementation therefore does NOT call SetTextureSize or any GPU
// function. It does EXACTLY what SetValue does — writes input data and
// raises the same dirty bit — so the engine runs its own unmodified workflow
// from its own safe position:
//   - the wanted resolution is written into the 10 lo_q/hi_q table slots
//     (plain ushort data), so whatever the in-game quality/selector is, the
//     engine computes the wanted size;
//   - bit 4 is OR-ed into m_UpdateFlagsChanges (atomic InterlockedOr);
//   - the engine applies on its next CSettingsManager::Update tick.
// Turning the override off restores the captured vanilla tables and the
// engine resizes back through the same native path.
//
// RVA map (Steam, image base 0x140000000):
//   0x2CBD1B0  CSettingsManager::Instance                (CSettingsManager*)
//   0x2CA5880  Base::CSingle<CGraphicsEngine>::Instance  (CGraphicsEngine*)
//   0x1E63090  lo_q resolution table   ushort[5]
//   0x1E630A0  hi_q resolution table   ushort[5]
//   +0x70      CSettingsManager::m_UpdateFlagsChanges  (uint; bit 4 = graphics)
//   +0x78      CSettingsManager::m_Settings            (std::array<int,64>)
//   +0x88      _Elems[4] = GraphicsShadowsQuality      (0..4)
//   +0x98      _Elems[8] = GraphicsShadowsResolution   (0 = lo_q, 1 = hi_q)
//   +0x5770    CGraphicsEngine::m_ShadowManager        (CShadowManager*)
//   +0         CShadowManager::m_TexSize               (ushort, live atlas side)
// ============================================================================

int g_ShadowResolution = 0; // 0 = follow the game's own setting; else atlas side in px

static const uintptr_t kShResRva_SettingsMgrInstance = 0x2CBD1B0;
static const uintptr_t kShResRva_GraphicsEngineInst  = 0x2CA5880;
static const uintptr_t kShResRva_LowQResTable        = 0x1E63090;
static const uintptr_t kShResRva_HiQResTable         = 0x1E630A0;

static uint16_t s_ShResVanilla[10];      // captured lo_q[5] + hi_q[5]
static bool     s_ShResVanillaValid = false;
static bool     s_ShResOverrideLive = false; // tables currently carry the override
static bool     s_ShResAddrWarned   = false;

// Fail-safe: on non-Steam builds every address must be present in the Epic
// RVA map. If a future Epic patch invalidates any of them, the feature goes
// INERT instead of reading/writing the wrong memory (an InterlockedOr into a
// random DWORD would be memory corruption).
static bool ShRes_AddressesKnown() {
    if (g_IsSteam) return true;
    if (JRVA_KNOWN(kShResRva_SettingsMgrInstance) &&
        JRVA_KNOWN(kShResRva_GraphicsEngineInst) &&
        JRVA_KNOWN(kShResRva_LowQResTable) &&
        JRVA_KNOWN(kShResRva_HiQResTable)) return true;
    if (!s_ShResAddrWarned) {
        s_ShResAddrWarned = true;
        std::cout << "\033[1;33m[ShadowRes] Epic address mapping incomplete - feature disabled safely.\033[0m\n";
    }
    return false;
}

static uintptr_t ShRes_SettingsManager() {
    if (!g_ExeBase) return 0;
    uintptr_t sm = 0;
    FastRead<uintptr_t>(g_ExeBase + JRVA(kShResRva_SettingsMgrInstance), sm);
    return sm;
}

static uint16_t ShRes_LiveAtlasSize() {
    if (!g_ExeBase) return 0;
    uintptr_t eng = 0, mgr = 0;
    uint16_t tex = 0;
    if (!FastRead<uintptr_t>(g_ExeBase + JRVA(kShResRva_GraphicsEngineInst), eng) || !eng) return 0;
    if (!FastRead<uintptr_t>(eng + 0x5770, mgr) || !mgr) return 0;
    if (!FastRead<uint16_t>(mgr, tex)) return 0;
    return tex;
}

static void ShRes_CaptureVanillaTables() {
    if (s_ShResVanillaValid || !g_ExeBase) return;
    uintptr_t lo = g_ExeBase + JRVA(kShResRva_LowQResTable);
    uintptr_t hi = g_ExeBase + JRVA(kShResRva_HiQResTable);
    bool ok = true;
    for (int i = 0; i < 5; i++) {
        ok = FastRead<uint16_t>(lo + 2 * i, s_ShResVanilla[i]) && ok;
        ok = FastRead<uint16_t>(hi + 2 * i, s_ShResVanilla[5 + i]) && ok;
    }
    s_ShResVanillaValid = ok;
}

static bool ShRes_TablesAllEqualTo(uint16_t v) {
    uintptr_t lo = g_ExeBase + JRVA(kShResRva_LowQResTable);
    uintptr_t hi = g_ExeBase + JRVA(kShResRva_HiQResTable);
    uint16_t x = 0;
    for (int i = 0; i < 5; i++) {
        if (!FastRead<uint16_t>(lo + 2 * i, x) || x != v) return false;
        if (!FastRead<uint16_t>(hi + 2 * i, x) || x != v) return false;
    }
    return true;
}

static void ShRes_WriteOverrideTables(uint16_t res) {
    uintptr_t lo = g_ExeBase + JRVA(kShResRva_LowQResTable);
    uintptr_t hi = g_ExeBase + JRVA(kShResRva_HiQResTable);
    for (int i = 0; i < 5; i++) {
        FastWrite<uint16_t>(lo + 2 * i, res);
        FastWrite<uint16_t>(hi + 2 * i, res);
    }
    s_ShResOverrideLive = true;
}

static void ShRes_RestoreVanillaTables() {
    if (!g_ExeBase) return;
    if (s_ShResVanillaValid) {
        uintptr_t lo = g_ExeBase + JRVA(kShResRva_LowQResTable);
        uintptr_t hi = g_ExeBase + JRVA(kShResRva_HiQResTable);
        for (int i = 0; i < 5; i++) {
            FastWrite<uint16_t>(lo + 2 * i, s_ShResVanilla[i]);
            FastWrite<uint16_t>(hi + 2 * i, s_ShResVanilla[5 + i]);
        }
    }
    s_ShResOverrideLive = false;
}

static void ShRes_KickGraphicsSettingsApply(uintptr_t sm) {
    // The engine's own dirty bit, OR-ed atomically so the engine's other
    // pending bits can never tear. CSettingsManager::Update consumes it on
    // the main thread within a frame or two and runs the whole native
    // workflow (wait + SetTextureSize + everything else) from ITS position.
    InterlockedOr(reinterpret_cast<volatile LONG*>(sm + 0x70), 4);
}

void UpdateShadowResolutionDriver() {
    if (!g_ExeBase) return;
    if (!ShRes_AddressesKnown()) return;
    uintptr_t sm = ShRes_SettingsManager();
    if (!sm) return;

    if (g_ShadowResolution > 0) {
        ShRes_CaptureVanillaTables();
        uint16_t want = (uint16_t)g_ShadowResolution;

        // Keep the 10 table slots pinned — the only data the engine reads.
        if (!ShRes_TablesAllEqualTo(want)) {
            ShRes_WriteOverrideTables(want);
        }

        // Fire the engine's own applier until the live atlas matches.
        uint16_t live = ShRes_LiveAtlasSize();
        static DWORD s_FirstMismatchAt = 0;
        static DWORD s_LastKickAt = 0;
        static uint16_t s_LastLoggedFrom = 0, s_LastLoggedTo = 0;
        DWORD now = GetTickCount();
        if (live != 0 && live != want) {
            if (!s_FirstMismatchAt) s_FirstMismatchAt = now;
            // 250 ms settle coalesces rapid combo changes; >= 1 s between
            // kicks keeps even a pathological mismatch from spamming the
            // engine's applier (each apply is the engine's own safe path).
            if (now - s_FirstMismatchAt >= 250 && now - s_LastKickAt >= 1000) {
                ShRes_KickGraphicsSettingsApply(sm);
                s_LastKickAt = now;
                s_FirstMismatchAt = 0;
                if (s_LastLoggedFrom != live || s_LastLoggedTo != want) {
                    std::cout << "\033[1;36m[ShadowRes] native settings-apply kicked: atlas "
                              << live << " -> " << want
                              << " (engine UpdateSettings/SetTextureSize path)\033[0m\n";
                    s_LastLoggedFrom = live;
                    s_LastLoggedTo = want;
                }
            }
        } else {
            s_FirstMismatchAt = 0;
        }
    } else if (s_ShResOverrideLive) {
        // Override turned off: restore the captured vanilla tables and let
        // the engine resize back to whatever the in-game quality implies.
        ShRes_RestoreVanillaTables();
        ShRes_KickGraphicsSettingsApply(sm);
        std::cout << "\033[1;36m[ShadowRes] override off - vanilla tables restored, "
                  << "engine resize-back kicked\033[0m\n";
    }
}

void ToggleInfMissiles(bool enable) {
    if (!g_ExeBase) return;
    static bool isPatched = false;
    if (!enable && !isPatched) return; // Don't write memory on startup when disabled

    uintptr_t addr = g_ExeBase + g_Addr_98AAED1;
    static const uint8_t orig[6] = {0xC7,0x07,0x00,0x00,0x00,0x00};
    static const uint8_t patch[6]= {0xC7,0x07,0x00,0x00,0x80,0x3F};
    if (!BytesMatch(addr, enable ? orig : patch, 6)) return;
    SafePatchBytes(addr, enable ? patch : orig, 6);
    isPatched = enable;
}

// --- WINGSUIT MISSILE PHYSICS & MULTI-MISSILE TUNING HOOK ---
static uintptr_t s_MissileSpeedCave = 0;
static uintptr_t s_MissilePropsCave = 0;

void ApplyMissileSpeedHook() {
    if (!g_ExeBase) return;
    // Steam: Hook1 0x702857 (20B) + Hook2 0x70288F (14B).
    // Epic:  Hook1 0x7063C8 (20B, byte-identical, live-verified) +
    //        Hook2 0x70640A (8B merge: mulss xmm2,xmm6; addss xmm1,xmm2, live-verified).

    // ------------------------------------------------------------------------
    // Hook 1: Capture Defaults & Enforce Overrides on Wingsuit Missiles
    // ------------------------------------------------------------------------
    if (!s_MissilePropsCave) {
        uintptr_t hookAddr = g_ExeBase + g_Addr_702857;
        static const uint8_t kExpHook1[20] = {
            0xF3,0x0F,0x10,0x86,0xA8,0x05,0x00,0x00, // movss xmm0,[rsi+0x5A8]
            0xF3,0x0F,0x10,0x64,0x24,0x40,             // movss xmm4,[rsp+0x40]
            0xF3,0x0F,0x10,0x5C,0x24,0x44              // movss xmm3,[rsp+0x44]
        };
        if (!BytesMatch(hookAddr, kExpHook1, sizeof(kExpHook1))) {
            std::cout << "[Missile] SKIP props hook: signature mismatch at +0x"
                      << std::hex << (hookAddr - g_ExeBase) << std::dec << " (wrong build?)\n";
        } else {
        s_MissilePropsCave = AllocateNear(hookAddr, 512);
        if (s_MissilePropsCave) {
            uintptr_t retAddr = hookAddr + 20; // 14070286B
            uintptr_t fnBridge = (uintptr_t)&HookMissileInit;

            std::vector<uint8_t> c;
            auto addB = [&](std::initializer_list<uint8_t> bytes) {
                c.insert(c.end(), bytes.begin(), bytes.end());
            };
            auto addU64 = [&](uint64_t val) {
                uint8_t* p = (uint8_t*)&val;
                c.insert(c.end(), p, p + 8);
            };

            // Save registers & preserve 16-byte stack alignment
            addB({0x9C});                                             // pushfq
            addB({0x50, 0x51, 0x52});                                 // push rax, rcx, rdx
            addB({0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53}); // push r8, r9, r10, r11
            addB({0x48, 0x83, 0xEC, 0x68});                           // sub rsp, 0x68 (xmm save area)
            addB({0x0F, 0x11, 0x04, 0x24});                           // movups [rsp+0x00], xmm0
            addB({0x0F, 0x11, 0x4C, 0x24, 0x10});                     // movups [rsp+0x10], xmm1
            addB({0x0F, 0x11, 0x54, 0x24, 0x20});                     // movups [rsp+0x20], xmm2
            addB({0x0F, 0x11, 0x5C, 0x24, 0x30});                     // movups [rsp+0x30], xmm3
            addB({0x0F, 0x11, 0x64, 0x24, 0x40});                     // movups [rsp+0x40], xmm4
            addB({0x0F, 0x11, 0x6C, 0x24, 0x50});                     // movups [rsp+0x50], xmm5

            // Call C++ HookMissileInit(rsi)
            addB({0x48, 0x89, 0xF1});                                 // mov rcx, rsi (CMissile*)
            addB({0x48, 0x83, 0xEC, 0x20});                           // sub rsp, 0x20 (shadow space)
            addB({0x48, 0xB8}); addU64(fnBridge);                     // mov rax, HookMissileInit
            addB({0xFF, 0xD0});                                       // call rax
            addB({0x48, 0x83, 0xC4, 0x20});                           // add rsp, 0x20

            // Restore registers
            addB({0x0F, 0x10, 0x04, 0x24});                           // movups xmm0, [rsp+0x00]
            addB({0x0F, 0x10, 0x4C, 0x24, 0x10});                     // movups xmm1, [rsp+0x10]
            addB({0x0F, 0x10, 0x54, 0x24, 0x20});                     // movups xmm2, [rsp+0x20]
            addB({0x0F, 0x10, 0x5C, 0x24, 0x30});                     // movups xmm3, [rsp+0x30]
            addB({0x0F, 0x10, 0x64, 0x24, 0x40});                     // movups xmm4, [rsp+0x40]
            addB({0x0F, 0x10, 0x6C, 0x24, 0x50});                     // movups xmm5, [rsp+0x50]
            addB({0x48, 0x83, 0xC4, 0x68});                           // add rsp, 0x68
            addB({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58}); // pop r11, r10, r9, r8
            addB({0x5A, 0x59, 0x58});                                 // pop rdx, rcx, rax
            addB({0x9D});                                             // popfq

            // Original instructions (20 bytes)
            addB({0xF3, 0x0F, 0x10, 0x86, 0xA8, 0x05, 0x00, 0x00}); // movss xmm0, [rsi+0x5A8]
            addB({0xF3, 0x0F, 0x10, 0x64, 0x24, 0x40});             // movss xmm4, [rsp+0x40]
            addB({0xF3, 0x0F, 0x10, 0x5C, 0x24, 0x44});             // movss xmm3, [rsp+0x44]

            // Jump back to game code
            int32_t relBack = (int32_t)((int64_t)retAddr - (int64_t)(s_MissilePropsCave + c.size() + 5));
            addB({0xE9});
            uint8_t* pRel = (uint8_t*)&relBack;
            c.insert(c.end(), pRel, pRel + 4);

            SafePatchBytes(s_MissilePropsCave, c.data(), c.size());

            int64_t delta = (int64_t)s_MissilePropsCave - (int64_t)(hookAddr + 5);
            uint8_t patch[20];
            patch[0] = 0xE9;
            int32_t rel = (int32_t)delta;
            memcpy(&patch[1], &rel, 4);
            memset(&patch[5], 0x90, 15);
            SafePatchBytes(hookAddr, patch, 20);
        }
        } // end signature-check else
    }

    // ------------------------------------------------------------------------
    // Hook 2: Dynamic Velocity Multiplier Hook - WINGSUIT ONLY
    //   Steam (0x70288F, 14B): mulss xmm2,xmm8; mulss xmm1,[rsi+0x28]; addss xmm1,xmm2
    //   Epic  (0x70640A, 8B):  mulss xmm2,xmm6; addss xmm1,xmm2 (stage speed already
    //                          selected by the two branches above; merge point)
    // ------------------------------------------------------------------------
    if (!s_MissileSpeedCave) {
        uintptr_t hookAddr = g_ExeBase + g_Addr_70288F;
        static const uint8_t kExpHook2Steam[14] = {
            0xF3,0x41,0x0F,0x59,0xD0, // mulss xmm2,xmm8
            0xF3,0x0F,0x59,0x4E,0x28, // mulss xmm1,[rsi+0x28]
            0xF3,0x0F,0x58,0xCA        // addss xmm1,xmm2
        };
        static const uint8_t kExpHook2Epic[8] = {
            0xF3,0x0F,0x59,0xD6, // mulss xmm2,xmm6
            0xF3,0x0F,0x58,0xCA  // addss xmm1,xmm2
        };
        const uint8_t* expBytes = g_IsSteam ? kExpHook2Steam : kExpHook2Epic;
        size_t expLen = g_IsSteam ? sizeof(kExpHook2Steam) : sizeof(kExpHook2Epic);
        if (!BytesMatch(hookAddr, expBytes, expLen)) {
            std::cout << "[Missile] SKIP speed hook: signature mismatch at +0x"
                      << std::hex << (hookAddr - g_ExeBase) << std::dec
                      << (g_IsSteam ? " (Steam 14B)" : " (Epic 8B)") << "\n";
        } else {
        s_MissileSpeedCave = AllocateNear(hookAddr, 512);
        if (s_MissileSpeedCave) {
            uintptr_t pMultAddr       = (uintptr_t)&g_MissileSpeedMult;
            uintptr_t pWingsuitWeapon = (uintptr_t)&g_ActiveWingsuitWeapon;
            uintptr_t retAddr         = hookAddr + (g_IsSteam ? 14 : 8);

            std::vector<uint8_t> c;
            auto addB = [&](std::initializer_list<uint8_t> bytes) {
                c.insert(c.end(), bytes.begin(), bytes.end());
            };
            auto addU64 = [&](uint64_t val) {
                uint8_t* p = (uint8_t*)&val;
                c.insert(c.end(), p, p + 8);
            };

            // Original instructions (platform-specific, verified against live bytes):
            if (g_IsSteam) {
                addB({ 0xF3, 0x41, 0x0F, 0x59, 0xD0 });                   // mulss xmm2, xmm8
                addB({ 0xF3, 0x0F, 0x59, 0x4E, 0x28 });                   // mulss xmm1, [rsi+0x28]
                addB({ 0xF3, 0x0F, 0x58, 0xCA });                         // addss xmm1, xmm2
            } else {
                addB({ 0xF3, 0x0F, 0x59, 0xD6 });                         // Epic: mulss xmm2, xmm6
                addB({ 0xF3, 0x0F, 0x58, 0xCA });                         // Epic: addss xmm1, xmm2
            }

            // Filter: verify [rsi + 0x48] (missile's CWeapon*) == g_ActiveWingsuitWeapon
            addB({ 0x50, 0x52 });                                     // push rax, rdx
            addB({ 0x48, 0xB8 }); addU64(pWingsuitWeapon);             // mov rax, &g_ActiveWingsuitWeapon
            addB({ 0x48, 0x8B, 0x00 });                               // mov rax, [rax]
                addB({ 0x48, 0x85, 0xC0 });                               // test rax, rax
                addB({ 0x74, 0x17 });                                     // jz skip_mult (offset +23 bytes)
                addB({ 0x48, 0x8B, 0x56, 0x48 });                         // mov rdx, [rsi+0x48] (missile weapon)
            addB({ 0x48, 0x39, 0xC2 });                               // cmp rdx, rax
            addB({ 0x75, 0x0E });                                     // jne skip_mult (offset +14 bytes)

            // Multiply speed ONLY for confirmed wingsuit missiles
            addB({ 0x48, 0xB8 }); addU64(pMultAddr);                  // mov rax, &g_MissileSpeedMult
            addB({ 0xF3, 0x0F, 0x59, 0x08 });                         // mulss xmm1, [rax]

            // skip_mult:
            addB({ 0x5A, 0x58 });                                     // pop rdx, rax

            // Jump back to retAddr (Steam 0x70289D / Epic 0x706412)
            int32_t relBack = (int32_t)((int64_t)retAddr - (int64_t)(s_MissileSpeedCave + c.size() + 5));
            addB({ 0xE9 });
            uint8_t* pRel = (uint8_t*)&relBack;
            c.insert(c.end(), pRel, pRel + 4);

            SafePatchBytes(s_MissileSpeedCave, c.data(), c.size());

            int64_t delta = (int64_t)s_MissileSpeedCave - (int64_t)(hookAddr + 5);
            size_t patchLen = g_IsSteam ? 14 : 8;
            uint8_t patch[14];
            patch[0] = 0xE9;
            int32_t rel = (int32_t)delta;
            memcpy(&patch[1], &rel, 4);
            memset(&patch[5], 0x90, patchLen - 5);
            SafePatchBytes(hookAddr, patch, patchLen);
        }
        } // end signature-check else
    }
}

// --- FULLY AUTOMATIC WINGSUIT MISSILES TOGGLE ---
static uintptr_t s_AutoFireCave = 0;

extern "C" SHORT GetWingsuitAutoFireState(int vKey) {
    if (g_ShowMenu || g_ResizeMode != RESIZE_NONE) return 0;
    HWND fg = GetForegroundWindow();
    DWORD fgPid = 0;
    if (fg) GetWindowThreadProcessId(fg, &fgPid);
    if (fgPid != GetCurrentProcessId()) return 0;
    return GetAsyncKeyState(vKey);
}

void ToggleFullAutoMissiles(bool enable) {
    if (!g_ExeBase) return;
    static bool isPatched = false;
    if (!enable && !isPatched) return;

    uintptr_t addrInput = g_ExeBase + g_Addr_98AAE20; // Wingsuit input hook only

    static const uint8_t origInput[24] = {
        0x8B, 0x15, 0xEE, 0x6F, 0x55, 0xF8,
        0x49, 0x8B, 0x8D, 0xE0, 0x03, 0x00, 0x00,
        0xE8, 0x6E, 0x65, 0x72, 0xF7,
        0x44, 0x0F, 0xB6, 0xF8,
        0xEB, 0x03
    };
    // NOTE: origInput above is the STEAM byte pattern. Epic's bytes at this
    // site differ (notably the rip-relative call displacement), so disable
    // must restore the bytes actually saved at enable time - never this table.
    // Restoring Steam bytes on Epic corrupts the call target and crashes with
    // 0xC000001D the next time wingsuit input code runs.
    static uint8_t savedInput[24];
    static bool savedInputValid = false;

    if (enable) {
        if (!savedInputValid) {
            memcpy(savedInput, (void*)addrInput, sizeof(savedInput));
            savedInputValid = true;
        }
        if (!s_AutoFireCave) {
            s_AutoFireCave = AllocateNear(addrInput, 512);
        }
        if (s_AutoFireCave) {
                uintptr_t fnGetAsync = (uintptr_t)&GetWingsuitAutoFireState;
                uintptr_t fnTriggered = g_ExeBase + g_Addr_FD13A0;
            uintptr_t hashWingsuitFireAddr = g_ExeBase + g_Addr_1E01E14;
            uintptr_t resumeAddr = g_ExeBase + g_Addr_98AAE3B;

            std::vector<uint8_t> c;
            auto addB = [&](const void* d, size_t sz) {
                const uint8_t* p = (const uint8_t*)d;
                c.insert(c.end(), p, p + sz);
            };

            // 1. Query Mouse Left Button (VK_LBUTTON = 1)
            uint8_t bProlog[] = { 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20 };
            addB(bProlog, sizeof(bProlog));
            uint8_t bCallGA1[] = { 0xB9, 0x01, 0x00, 0x00, 0x00, 0x48, 0xB8 };
            addB(bCallGA1, sizeof(bCallGA1)); addB(&fnGetAsync, 8);
            uint8_t bCallRax[] = { 0xFF, 0xD0 }; addB(bCallRax, sizeof(bCallRax));
            uint8_t bEpilog[] = { 0x48, 0x89, 0xEC, 0x5D }; addB(bEpilog, sizeof(bEpilog));
            uint8_t bShrAx[] = { 0x66, 0xC1, 0xE8, 0x0F, 0x44, 0x0F, 0xB6, 0xF8 }; 
            addB(bShrAx, sizeof(bShrAx));

            // 2. Query Gamepad Fallback (IsActionTriggered)
            uint8_t bPushRC[] = { 0x52, 0x51, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20 }; 
            addB(bPushRC, sizeof(bPushRC));
            uint8_t bMovRcx[] = { 0x49, 0x8B, 0x8D, 0xE0, 0x03, 0x00, 0x00 }; addB(bMovRcx, sizeof(bMovRcx));
            uint8_t bMovEdx[] = { 0x48, 0xB8 }; addB(bMovEdx, sizeof(bMovEdx)); addB(&hashWingsuitFireAddr, 8);
            uint8_t bMovEdxDeref[] = { 0x8B, 0x10 }; addB(bMovEdxDeref, sizeof(bMovEdxDeref));
            addB(bMovEdx, sizeof(bMovEdx)); addB(&fnTriggered, 8); addB(bCallRax, sizeof(bCallRax));
            uint8_t bPopRC[] = { 0x48, 0x89, 0xEC, 0x5D, 0x59, 0x5A }; addB(bPopRC, sizeof(bPopRC));

            // 3. Combine: r15b = r15b | al (Mouse OR Controller)
            uint8_t bCombine[] = { 0x44, 0x08, 0xC7, 0x45, 0x0F, 0xB6, 0xFF }; 
            addB(bCombine, sizeof(bCombine));

            // 4. Resume Game Execution
            addB(bMovEdx, sizeof(bMovEdx)); addB(&resumeAddr, 8);
            uint8_t bJmpRax[] = { 0xFF, 0xE0 }; addB(bJmpRax, sizeof(bJmpRax));

            SafePatchBytes(s_AutoFireCave, c.data(), c.size());

            int64_t delta = (int64_t)s_AutoFireCave - (int64_t)(addrInput + 5);
            uint8_t jmpBytes[24];
            jmpBytes[0] = 0xE9;
            int32_t rel = (int32_t)delta;
            memcpy(&jmpBytes[1], &rel, 4);
            memset(&jmpBytes[5], 0x90, 19);
            SafePatchBytes(addrInput, jmpBytes, 24);
        }
        isPatched = true;
    } else {
        SafePatchBytes(addrInput, savedInputValid ? savedInput : origInput, 24);
        isPatched = false;
    }
}

void ToggleDisableRivers(bool enable) {
    if (!g_ExeBase) return;
    static bool isPatched = false;
    if (!enable && !isPatched) return;

    uintptr_t addr = g_ExeBase + g_Addr_A369860;
    static const uint8_t orig[3] = { 0x49, 0x89, 0xE3 }; // mov r11, rsp
    static const uint8_t patch[3] = { 0xC3, 0x90, 0x90 }; // ret, nop, nop

    if (!BytesMatch(addr, enable ? orig : patch, 3)) return;
    SafePatchBytes(addr, enable ? patch : orig, 3);
    isPatched = enable;
}

// ============================================================================
// HIDE UI (HUD) ENGINE
// ============================================================================
static uintptr_t s_HideUICave = 0;
static uintptr_t s_AddrPreRenderScan = 0;
static uintptr_t s_AddrDisplayCall = 0;
static uint8_t s_OrigPreRender[14] = { 0 };
static uint8_t s_OrigDisplayCall[13] = { 0 };
static bool s_HideUIInited = false;
static bool s_HideUIPatched = false;

static bool InitHideUI() {
    if (s_HideUIInited) return true;
    if (!g_ExeBase) return false;

    // 1. Scan for scene list traversal in PreRender
    s_AddrPreRenderScan = PatternScan(g_ExeBase, "49 8B B5 80 03 00 00 4D 8B B5 88 03 00 00");
    if (!s_AddrPreRenderScan) {
        std::cout << "[HideUI] Failed to find AOB_PreRenderScan.\n";
        return false;
    }

    // 2. Scan for Movie::Display() call in Loop 2
    uintptr_t displayAOB = PatternScan(g_ExeBase, "FF 90 C0 00 00 00 49 8B 86 60 02 00 00 48 8B 48 60 48 8B 01 B2 01 FF 90 C8 00 00 00 48 89 85");
    if (!displayAOB) {
        std::cout << "[HideUI] Failed to find AOB_DisplayCall.\n";
        return false;
    }
    s_AddrDisplayCall = displayAOB + 0x16; // Points directly to: call qword ptr [rax+C8h]

    // 3. Backup original instruction bytes
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)s_AddrPreRenderScan, s_OrigPreRender, 14, NULL)) return false;
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)s_AddrDisplayCall, s_OrigDisplayCall, 13, NULL)) return false;

    // 4. Allocate code cave near the hooks
    s_HideUICave = AllocateNear(s_AddrPreRenderScan, 1024);
    if (!s_HideUICave) {
        std::cout << "[HideUI] Failed to allocate near code cave.\n";
        return false;
    }

    uintptr_t addrMenuActive = s_HideUICave;
    FastWrite<uint8_t>(addrMenuActive, 0);

    uintptr_t addrNewmemScan = s_HideUICave + 0x10;
    uintptr_t addrNewmemDisplay = s_HideUICave + 0x100;

    // --- Assemble Hook 1: newmem_scan (Detect active menu scenes) ---
    {
        std::vector<uint8_t> c;
        auto addB = [&](std::initializer_list<uint8_t> bytes) {
            c.insert(c.end(), bytes.begin(), bytes.end());
        };

        // mov rsi, [r13+0x380] (m_scenes.begin())
        addB({ 0x49, 0x8B, 0xB5, 0x80, 0x03, 0x00, 0x00 });
        // mov r14, [r13+0x388] (m_scenes.end())
        addB({ 0x4D, 0x8B, 0xB5, 0x88, 0x03, 0x00, 0x00 });

        // mov byte ptr [menu_active], 00
        size_t inst_m0 = c.size();
        addB({ 0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 });
        int32_t disp_m0 = (int32_t)((int64_t)addrMenuActive - (int64_t)(addrNewmemScan + inst_m0 + 7));
        memcpy(&c[inst_m0 + 2], &disp_m0, 4);

        // cmp rsi, r14
        addB({ 0x4C, 0x39, 0xF6 });

        // je end_scan
        addB({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_je_end = c.size() - 4;

        // push rax; push rdx; push rcx
        addB({ 0x50, 0x52, 0x51 });

        // mov rdx, rsi
        addB({ 0x48, 0x89, 0xF2 });

        // scan_loop:
        size_t off_scan_loop = c.size();

        // mov rcx, [rdx]
        addB({ 0x48, 0x8B, 0x0A });

        // test rcx, rcx
        addB({ 0x48, 0x85, 0xC9 });

        // jz next_scene
        addB({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_jz_next = c.size() - 4;

        // cmp byte ptr [rcx+0x140], 02 (state == 2 visible)
        addB({ 0x80, 0xB9, 0x40, 0x01, 0x00, 0x00, 0x02 });

        // jne next_scene
        addB({ 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_jne_next = c.size() - 4;

        // mov eax, [rcx+0x10] (scene ID hash)
        addB({ 0x8B, 0x41, 0x10 });

        // cmp eax, 508AC7E2h (Pause Menu)
        addB({ 0x3D, 0xE2, 0xC7, 0x8A, 0x50 });
        addB({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_je_menu1 = c.size() - 4;

        // cmp eax, A68C1FBCh (Comm-Map)
        addB({ 0x3D, 0xBC, 0x1F, 0x8C, 0xA6 });
        addB({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_je_menu2 = c.size() - 4;

        // cmp eax, C70A9933h (PDA / Settings / Comms)
        addB({ 0x3D, 0x33, 0x99, 0x0A, 0xC7 });
        addB({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_je_menu3 = c.size() - 4;

        // cmp dword ptr [rcx+0x110], 0Ah (Priority >= 10)
        addB({ 0x83, 0xB9, 0x10, 0x01, 0x00, 0x00, 0x0A });
        addB({ 0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_jge_menu = c.size() - 4;

        // next_scene:
        size_t off_next_scene = c.size();
        int32_t r_jz = (int32_t)(off_next_scene - (patch_jz_next + 4));
        memcpy(&c[patch_jz_next], &r_jz, 4);
        int32_t r_jne = (int32_t)(off_next_scene - (patch_jne_next + 4));
        memcpy(&c[patch_jne_next], &r_jne, 4);

        // add rdx, 08
        addB({ 0x48, 0x83, 0xC2, 0x08 });

        // cmp rdx, r14
        addB({ 0x4C, 0x39, 0xF2 });

        // jb scan_loop
        addB({ 0x0F, 0x82 });
        int32_t r_loop = (int32_t)(off_scan_loop - (c.size() + 4));
        uint8_t* pLoop = (uint8_t*)&r_loop;
        c.insert(c.end(), pLoop, pLoop + 4);

        // jmp cleanup_scan
        addB({ 0xE9, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_jmp_cleanup = c.size() - 4;

        // found_menu:
        size_t off_found_menu = c.size();
        int32_t r_m1 = (int32_t)(off_found_menu - (patch_je_menu1 + 4));
        memcpy(&c[patch_je_menu1], &r_m1, 4);
        int32_t r_m2 = (int32_t)(off_found_menu - (patch_je_menu2 + 4));
        memcpy(&c[patch_je_menu2], &r_m2, 4);
        int32_t r_m3 = (int32_t)(off_found_menu - (patch_je_menu3 + 4));
        memcpy(&c[patch_je_menu3], &r_m3, 4);
        int32_t r_mge = (int32_t)(off_found_menu - (patch_jge_menu + 4));
        memcpy(&c[patch_jge_menu], &r_mge, 4);

        // mov byte ptr [menu_active], 01
        size_t inst_m1 = c.size();
        addB({ 0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01 });
        int32_t disp_m1 = (int32_t)((int64_t)addrMenuActive - (int64_t)(addrNewmemScan + inst_m1 + 7));
        memcpy(&c[inst_m1 + 2], &disp_m1, 4);

        // cleanup_scan:
        size_t off_cleanup = c.size();
        int32_t r_cleanup = (int32_t)(off_cleanup - (patch_jmp_cleanup + 4));
        memcpy(&c[patch_jmp_cleanup], &r_cleanup, 4);

        // pop rcx; pop rdx; pop rax
        addB({ 0x59, 0x5A, 0x58 });

        // end_scan:
        size_t off_end = c.size();
        int32_t r_end = (int32_t)(off_end - (patch_je_end + 4));
        memcpy(&c[patch_je_end], &r_end, 4);

        // jmp AOB_PreRenderScan + 0x0E
        addB({ 0xE9 });
        int32_t r_ret1 = (int32_t)((int64_t)(s_AddrPreRenderScan + 14) - (int64_t)(addrNewmemScan + c.size() + 4));
        uint8_t* pRet1 = (uint8_t*)&r_ret1;
        c.insert(c.end(), pRet1, pRet1 + 4);

        SafePatchBytes(addrNewmemScan, c.data(), c.size());
    }

    // --- Assemble Hook 2: newmem_display (Selective Movie::Display call) ---
    {
        std::vector<uint8_t> c;
        auto addB = [&](std::initializer_list<uint8_t> bytes) {
            c.insert(c.end(), bytes.begin(), bytes.end());
        };

        // cmp byte ptr [menu_active], 01
        size_t inst_chk = c.size();
        addB({ 0x80, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x01 });
        int32_t disp_chk = (int32_t)((int64_t)addrMenuActive - (int64_t)(addrNewmemDisplay + inst_chk + 7));
        memcpy(&c[inst_chk + 2], &disp_chk, 4);

        // je do_display
        addB({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_je_disp1 = c.size() - 4;

        // mov edx, [r14+0x10] (sceneId)
        addB({ 0x41, 0x8B, 0x56, 0x10 });

        // cmp edx, 684F18A3h (shared_lib)
        addB({ 0x81, 0xFA, 0xA3, 0x18, 0x4F, 0x68 });
        addB({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_je_disp2 = c.size() - 4;

        // cmp edx, F7EAA450h (overlay)
        addB({ 0x81, 0xFA, 0x50, 0xA4, 0xEA, 0xF7 });
        addB({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_je_disp3 = c.size() - 4;

        // jmp skip_display
        addB({ 0xE9, 0x00, 0x00, 0x00, 0x00 });
        size_t patch_jmp_skip = c.size() - 4;

        // do_display:
        size_t off_do_disp = c.size();
        int32_t r_d1 = (int32_t)(off_do_disp - (patch_je_disp1 + 4));
        memcpy(&c[patch_je_disp1], &r_d1, 4);
        int32_t r_d2 = (int32_t)(off_do_disp - (patch_je_disp2 + 4));
        memcpy(&c[patch_je_disp2], &r_d2, 4);
        int32_t r_d3 = (int32_t)(off_do_disp - (patch_je_disp3 + 4));
        memcpy(&c[patch_je_disp3], &r_d3, 4);

        // mov dl, 01
        addB({ 0xB2, 0x01 });

        // call qword ptr [rax+0x000000C8]
        addB({ 0xFF, 0x90, 0xC8, 0x00, 0x00, 0x00 });

        // mov qword ptr [rbp+0x00000128], rax
        addB({ 0x48, 0x89, 0x85, 0x28, 0x01, 0x00, 0x00 });

        // skip_display:
        size_t off_skip = c.size();
        int32_t r_skip = (int32_t)(off_skip - (patch_jmp_skip + 4));
        memcpy(&c[patch_jmp_skip], &r_skip, 4);

        // jmp return_display (s_AddrDisplayCall + 13)
        addB({ 0xE9 });
        int32_t r_ret2 = (int32_t)((int64_t)(s_AddrDisplayCall + 13) - (int64_t)(addrNewmemDisplay + c.size() + 4));
        uint8_t* pRet2 = (uint8_t*)&r_ret2;
        c.insert(c.end(), pRet2, pRet2 + 4);

        SafePatchBytes(addrNewmemDisplay, c.data(), c.size());
    }

    s_HideUIInited = true;
    std::cout << "[+] Hide UI hooks successfully built in code cave.\n";
    return true;
}

void ApplyHideUI(bool enable) {
    if (!InitHideUI()) return;
    if (enable == s_HideUIPatched) return;

    if (enable) {
        // Detour 1: at s_AddrPreRenderScan (14 bytes total: 5-byte JMP rel32 + 9 NOPs)
        uint8_t patch1[14];
        patch1[0] = 0xE9;
        int32_t rel1 = (int32_t)((int64_t)(s_HideUICave + 0x10) - (int64_t)(s_AddrPreRenderScan + 5));
        memcpy(&patch1[1], &rel1, 4);
        memset(&patch1[5], 0x90, 9);
        SafePatchBytes(s_AddrPreRenderScan, patch1, 14);

        // Detour 2: at s_AddrDisplayCall (13 bytes total: 5-byte JMP rel32 + 8 NOPs)
        uint8_t patch2[13];
        patch2[0] = 0xE9;
        int32_t rel2 = (int32_t)((int64_t)(s_HideUICave + 0x100) - (int64_t)(s_AddrDisplayCall + 5));
        memcpy(&patch2[1], &rel2, 4);
        memset(&patch2[5], 0x90, 8);
        SafePatchBytes(s_AddrDisplayCall, patch2, 13);

        s_HideUIPatched = true;
    } else {
        SafePatchBytes(s_AddrPreRenderScan, s_OrigPreRender, 14);
        SafePatchBytes(s_AddrDisplayCall, s_OrigDisplayCall, 13);
        s_HideUIPatched = false;
    }
}
// ============================================================================
// FOLIAGE / VEGETATION SYSTEM HOOK (Port of INJECT_VEG_TOGGLE)
// ============================================================================
static uintptr_t s_FoliageCave = 0;
static uint8_t s_FoliageOrig[7] = { 0 };
static bool s_FoliageHooked = false;
static bool s_WasFoliageDisabled = false;

// ---------------------------------------------------------------------------
// FOLIAGE TOGGLE COOLDOWN
//
// Flipping "Disable Foliage" is what drives the engine's delayed vegetation
// reload: the hook below forces the "deactivate vegetation" branch of
// CLandscapeManager::Update and, on the enable->disable transition, re-arms
// SVegetationSystem::m_DelayedReloadTriggered / m_DelayedReloadFrameCount, whose
// consumer calls CLandscapeManager::ReloadVegetation. That is a full, NON
// re-entrant teardown + rebuild -- it flags all four patch-map layers (forest,
// billboard, model, PHYSICS) for DEFERRED delete, destroys and recreates every
// vegetation object's GPU resources, and reallocs the model type buffers -- and
// the flagged patch maps are deleted later by the patch system, not inline.
//
// Flipping the toggle faster than that drain completes leaves the vegetation and
// its collision patch maps out of sync (foliage invisible but still collidable,
// or the reverse), and re-arming the reload mid-drain is what used to kill the
// process outright (no CPU exception -> no crash_dump.log, no Event Viewer
// entry, no popup).
//
// So the TOGGLE is rate-limited: for 5 s after each accepted change, further
// changes are rejected. Nothing inside the hook cave is touched.
// ---------------------------------------------------------------------------
static const DWORD kFoliageToggleCooldownMs = 5000;
static DWORD s_FoliageLastToggleMs = 0;
static bool  s_FoliageToggleArmed = false;   // false until the first accepted change

// Pure query -- never arms the cooldown. True while a change must be rejected.
static bool FoliageToggleLocked() {
    if (!s_FoliageToggleArmed) return false;
    return (DWORD)(GetTickCount() - s_FoliageLastToggleMs) < kFoliageToggleCooldownMs;
}

// Arms the cooldown. Called exactly once, at the single point where an accepted
// change is actually applied (the per-frame driver in hkPresent), never from a
// UI check -- otherwise one click would consume the cooldown twice.
static void ArmFoliageToggleCooldown() {
    s_FoliageLastToggleMs = GetTickCount();
    s_FoliageToggleArmed = true;
}

void InstallFoliageHook() {
    if (!g_ExeBase || s_FoliageHooked) return;

    uintptr_t hookAddr = g_ExeBase + g_Addr_79AFC53; // RVA 0x79AFC53 (0x1479AFC53)
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)hookAddr, s_FoliageOrig, 7, NULL)) return;

    // Signature check: 83 BF B0 0D 00 00 02 (cmp dword ptr [rdi+0xDB0], 2)
    static const uint8_t expectedOrig[7] = { 0x83, 0xBF, 0xB0, 0x0D, 0x00, 0x00, 0x02 };
    if (memcmp(s_FoliageOrig, expectedOrig, 7) != 0) {
        std::cout << "[Foliage] Signature mismatch at RVA 0x79AFC53 - skipping hook.\n";
        return;
    }

    s_FoliageCave = AllocateNear(hookAddr, 512);
    if (!s_FoliageCave) return;

    uintptr_t retAddr = hookAddr + 7;
    uintptr_t pDisable = (uintptr_t)&g_DisableFoliage;
    uintptr_t pWasDisabled = (uintptr_t)&s_WasFoliageDisabled;

    std::vector<uint8_t> c;
    auto addB = [&](std::initializer_list<uint8_t> bytes) {
        c.insert(c.end(), bytes.begin(), bytes.end());
    };
    auto addU64 = [&](uint64_t val) {
        uint8_t* p = (uint8_t*)&val;
        c.insert(c.end(), p, p + 8);
    };
    auto addJmpRel32 = [&](uintptr_t from, uintptr_t to) {
        int32_t rel = (int32_t)((int64_t)to - (int64_t)(from + 5));
        c.push_back(0xE9);
        uint8_t* p = (uint8_t*)&rel;
        c.insert(c.end(), p, p + 4);
    };

    // newmem:
    addB({ 0x50 });                                         // push rax
    addB({ 0x48, 0xB8 }); addU64(pDisable);                 // mov rax, &g_DisableFoliage
    addB({ 0x80, 0x38, 0x01 });                             // cmp byte ptr [rax], 1
    addB({ 0x74, 0x00 });                                   // je force_deactivate (rel8 placeholder)
    size_t patch_je_force = c.size() - 1;

    // FOLIAGE ENABLED (Normal):
    addB({ 0x48, 0xB8 }); addU64(pWasDisabled);             // mov rax, &s_WasFoliageDisabled
    addB({ 0xC6, 0x00, 0x00 });                             // mov byte ptr [rax], 0
    addB({ 0x58 });                                         // pop rax
    addB({ 0x83, 0xBF, 0xB0, 0x0D, 0x00, 0x00, 0x02 });     // cmp dword ptr [rdi+0xDB0], 2 (original)
    addJmpRel32(s_FoliageCave + c.size(), retAddr);         // jmp returnhere

    // FOLIAGE DISABLED (force_deactivate):
    c[patch_je_force] = (uint8_t)(c.size() - (patch_je_force + 1));

    addB({ 0x48, 0xB8 }); addU64(pWasDisabled);             // mov rax, &s_WasFoliageDisabled
    addB({ 0x80, 0x38, 0x00 });                             // cmp byte ptr [rax], 0
    addB({ 0x75, 0x00 });                                   // jne already_disabled (rel8 placeholder)
    size_t patch_jne_already = c.size() - 1;

    // Transition Frame: trigger delayed reload to flush collision
    addB({ 0xC6, 0x00, 0x01 });                             // mov byte ptr [rax], 1
    addB({ 0x48, 0x8B, 0x87, 0x18, 0x0E, 0x00, 0x00 });     // mov rax, [rdi+0xE18] (SVegetationSystem*)
    addB({ 0x48, 0x85, 0xC0 });                             // test rax, rax
    addB({ 0x74, 0x00 });                                   // jz already_disabled (rel8 placeholder)
    size_t patch_jz_already = c.size() - 1;

    addB({ 0xC6, 0x80, 0xC8, 0x6E, 0x31, 0x00, 0x01 });     // mov byte ptr [rax+0x316EC8], 1 (m_DelayedReloadTriggered)
    addB({ 0xC7, 0x80, 0xCC, 0x6E, 0x31, 0x00, 0x01, 0x00, 0x00, 0x00 }); // mov dword ptr [rax+0x316ECC], 1 (m_DelayedReloadFrameCount)

    // already_disabled:
    c[patch_jne_already] = (uint8_t)(c.size() - (patch_jne_already + 1));
    c[patch_jz_already]  = (uint8_t)(c.size() - (patch_jz_already + 1));

    addB({ 0x31, 0xC0 });                                   // xor eax, eax
    addB({ 0x83, 0xF8, 0x02 });                             // cmp eax, 2 (forces downstream JL branch)
    addB({ 0x58 });                                         // pop rax
    addJmpRel32(s_FoliageCave + c.size(), retAddr);         // jmp returnhere

    SafePatchBytes(s_FoliageCave, c.data(), c.size());

    // Patch hookAddr with 5-byte JMP rel32 + 2 NOPs = 7 bytes
    int64_t delta = (int64_t)s_FoliageCave - (int64_t)(hookAddr + 5);
    uint8_t patch[7];
    patch[0] = 0xE9;
    int32_t rel = (int32_t)delta;
    memcpy(&patch[1], &rel, 4);
    patch[5] = 0x90;
    patch[6] = 0x90;

    SafePatchBytes(hookAddr, patch, 7);
    s_FoliageHooked = true;
    std::cout << "[Foliage] Vegetation toggle hook installed successfully.\n";
}

void UninstallFoliageHook() {
    if (!s_FoliageHooked || !g_ExeBase) return;
    SafePatchBytes(g_ExeBase + g_Addr_79AFC53, s_FoliageOrig, 7);
    s_FoliageHooked = false;
    Sleep(50);
    if (s_FoliageCave) {
        VirtualFree((void*)s_FoliageCave, 0, MEM_RELEASE);
        s_FoliageCave = 0;
    }
}

bool g_VehiclesInvincible = false;
bool g_VehiclesInvinciblePlayerOnly = false; // Sub-option: only the vehicle Rico is sitting in
bool g_RainbowVehicles = false;
bool g_RainbowPlayerOnly = true; // Only apply to Rico's current vehicle
int  g_RainbowSpeed = 1;         // 1 = every frame, higher = slower color change

// Native Avalanche function: CVehicle::SetSelectedPaletteTintIndex (RVA 0x9F8E980)
typedef void(__fastcall* SetSelectedPaletteTintIndex_t)(uintptr_t thisptr, int16_t index);
static SetSelectedPaletteTintIndex_t o_SetSelectedPaletteTintIndex = nullptr;

// Native Avalanche function: CGrapplingHookWire::Break (detaches the wire)
typedef void(__fastcall* WireBreak_t)(uintptr_t wire);
static WireBreak_t o_WireBreak = nullptr;

void UpdateRainbowVehicles() {
    if (!g_RainbowVehicles || !g_ExeBase || !o_SetSelectedPaletteTintIndex) return;

    // Rate-limit by frame speed (1 = every frame)
    static int s_Tick = 0;
    if (g_RainbowSpeed > 1 && (++s_Tick % g_RainbowSpeed != 0)) return;

    uintptr_t m_GameObjects_Addr = g_ExeBase + g_Addr_2CB1938;
    uintptr_t myFirst = 0, myLast = 0;
    if (!FastRead<uintptr_t>(m_GameObjects_Addr + 0x0, myFirst) || 
        !FastRead<uintptr_t>(m_GameObjects_Addr + 0x8, myLast) || 
        !myFirst || myLast < myFirst) return;

    size_t count = (myLast - myFirst) / 8;
    if (count > 500) count = 500;

    for (size_t i = 0; i < count; i++) {
        uintptr_t vehiclePtr = 0;
        if (!FastRead<uintptr_t>(myFirst + (i * 8), vehiclePtr) || !vehiclePtr) continue;
        if (!IsLikelyGameObject(vehiclePtr)) continue;

        // Ensure this is an active vehicle with physics (m_PfxVehicle at 0x13DE8)
        uintptr_t pfx = 0;
        if (!FastRead<uintptr_t>(vehiclePtr + 0x13DE8, pfx) || !pfx) continue;

        // Check if Rico is in this vehicle:
        // 0x1063C: m_LocalPlayerSeat (-1 = on foot / not in this car, >= 0 = in car)
        if (g_RainbowPlayerOnly) {
            int32_t playerSeat = -1;
            if (!FastRead<int32_t>(vehiclePtr + 0x1063C, playerSeat) || playerSeat < 0) {
                continue; // Skip vehicles Rico is not in
            }
        }

        uintptr_t palette = 0;
        // 0x6D0: SPalette * m_Palette
        if (FastRead<uintptr_t>(vehiclePtr + 0x6D0, palette) && palette) {
            uint32_t tintCount = 0;
            // 0x8: uint m_Count
            if (FastRead<uint32_t>(palette + 0x8, tintCount) && tintCount > 1) {
                int16_t curTint = 0;
                // 0x6F4: short m_PaletteTintIndex
                if (FastRead<int16_t>(vehiclePtr + 0x6F4, curTint)) {
                    int16_t nextTint = (curTint + 1) % (int16_t)tintCount;
                    o_SetSelectedPaletteTintIndex(vehiclePtr, nextTint);
                }
            }
        }
    }
}

// ============================================================================
// NATIVE DETOUR: VEHICLE DAMAGE
// ----------------------------------------------------------------------------
// Vehicle invincibility sits on a hot engine function, so a MinHook detour is
// both cheaper and much safer than overwriting the prologue bytes: the decision
// can be made per object (only Rico's vehicle) and the toggle is a plain flag
// flip. The install is gated on a prologue byte-signature check, so an unmapped
// platform RVA leaves the feature cleanly off.
// ============================================================================

static bool PrologueMatches(uintptr_t addr, const uint8_t* sig, size_t len) {
    uint8_t buf[64] = { 0 };
    if (!addr || !sig || len == 0 || len > sizeof(buf)) return false;
    if (!ReadProcessMemory(GetCurrentProcess(), (void*)addr, buf, len, NULL)) return false;
    return memcmp(buf, sig, len) == 0;
}

// Dumps what is actually at the address when a signature check fails. Ghidra's
// listing text silently drops redundant REX prefixes (a 2-byte "40 53" push
// shows up as a plain "PUSH RBX"), so comparing against a disassembly by eye is
// not enough - the raw bytes are the only truth.
static void LogPrologueBytes(const char* name, uintptr_t addr) {
    uint8_t buf[12] = { 0 };
    std::cout << "[!] " << name << " signature mismatch at RVA 0x" << std::hex
              << (addr - g_ExeBase) << std::dec << " - bytes:";
    if (ReadProcessMemory(GetCurrentProcess(), (void*)addr, buf, sizeof(buf), NULL)) {
        char b[8];
        for (int i = 0; i < (int)sizeof(buf); ++i) {
            snprintf(b, sizeof(b), " %02X", buf[i]);
            std::cout << b;
        }
    } else {
        std::cout << " <unreadable>";
    }
    std::cout << "\n";
}

// --- CVehicle::OnDamage (RVA 0xC3F540) -------------------------------------
// Choke point for every point of damage a vehicle can take. Returning 0 is
// exactly what the old entry patch did, but now we can answer per vehicle:
// m_LocalPlayerSeat (+0x1063C) is ENoSeatIdentifier (-1) unless Rico is
// actually sitting in it, so a >= 0 seat means "this is Rico's vehicle".
typedef short(__fastcall* VehicleOnDamage_t)(void* thisptr, void* damageMsg);
static VehicleOnDamage_t o_VehicleOnDamage = nullptr;
static bool s_VehicleDamageHooked = false;

static short __fastcall hk_VehicleOnDamage(void* thisptr, void* damageMsg) {
    if (g_VehiclesInvincible && thisptr) {
        if (!g_VehiclesInvinciblePlayerOnly) return 0; // every vehicle, as before
        int32_t seat = -1;
        if (FastRead<int32_t>((uintptr_t)thisptr + 0x1063C, seat) && seat >= 0) return 0;
    }
    return o_VehicleOnDamage ? o_VehicleOnDamage(thisptr, damageMsg) : 0;
}

// Present-thread owner of the native ragdoll/stumble player flag (+0x307).
// Noclip disables it while flying and restores the captured native value on
// exit. Never restore an old player's pointer after respawn, and never
// replace a native lock with true.
static void UpdateNoclipRagdollGate(uintptr_t player, bool disable) {
    static uintptr_t capturedPlayer = 0;
    static uint8_t savedEnabled = 0;
    static bool captured = false;
    if (player != capturedPlayer) {
        capturedPlayer = player;
        captured = false; // old object may already have been destroyed
    }
    if (!player) return;
    if (disable) {
        if (!captured) {
            if (!FastRead<uint8_t>(player + 0x307, savedEnabled)) return;
            captured = true;
        }
        const uint8_t off = 0;
        WriteProcessMemory(GetCurrentProcess(), (void*)(player + 0x307), &off, sizeof(off), nullptr);
    } else if (captured) {
        if (WriteProcessMemory(GetCurrentProcess(), (void*)(player + 0x307),
                               &savedEnabled, sizeof(savedEnabled), nullptr)) {
            captured = false;
        }
    }
}

static void InstallRedDamageHooks();
static void InstallNoRagdollHooks();
static std::atomic<bool> s_RedDamageReady{false};
static std::atomic<bool> s_NoRagdollReady{false};

// Used only by the two verified profile-specific hook groups below.
static uintptr_t PlayerFxAddress(uintptr_t steam, uintptr_t epic) {
    return g_ExeBase + (g_IsSteam ? steam : epic);
}

static bool SuppressDamageEffects() {
    return s_RedDamageReady.load(std::memory_order_acquire) && g_DisableDamageScreen;
}

static bool SuppressRagdoll() {
    return s_NoRagdollReady.load(std::memory_order_acquire) && g_DisableRagdoll;
}

static void InstallFeatureHooks() {
    if (!g_ExeBase) return;
    static bool s_Installed = false;
    if (s_Installed) return;
    s_Installed = true;

    // CVehicle::OnDamage -- mov rax,rsp; push rbp; push rsi; push rdi; push r12; push r13
    {
        static const uint8_t sig[] = { 0x48,0x8B,0xC4,0x55,0x56,0x57,0x41,0x54,0x41,0x55 };
        void* p = (void*)(g_ExeBase + g_Addr_C3F540);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig))) {
            if (MH_CreateHook(p, (void*)&hk_VehicleOnDamage, (void**)&o_VehicleOnDamage) == MH_OK) {
                MH_EnableHook(p);
                s_VehicleDamageHooked = true;
                std::cout << "[+] Hooked CVehicle::OnDamage (per-vehicle invincibility).\n";
            }
        } else {
            LogPrologueBytes("CVehicle::OnDamage", (uintptr_t)p);
            std::cout << "[!] vehicle invincibility unavailable.\n";
        }
    }

    InstallRedDamageHooks();
    InstallNoRagdollHooks();
}

// ============================================================================
// DISABLE RED DAMAGE SCREEN (SWF HUD + Post-Effects)
// ============================================================================
typedef void(__fastcall* UIHealthControllerUpdate_t)(void* thisptr, float dt, float alpha);
typedef bool(__fastcall* UIBaseInvoke_t)(void* thisptr, const char* method, void* args, uint32_t argCount, void* retVal, float delay);
typedef void(__fastcall* UIHealthOnOmniDamage_t)(void* thisptr);
typedef void(__fastcall* PlayerHealthEffectsUpdate_t)(void* thisptr, float dt, void* character);
typedef void(__fastcall* ApplyEffectParameterData_t)(void* thisptr, float level);
typedef void(__fastcall* CharacterNearDeathEffect_t)(void* character);

static UIHealthControllerUpdate_t   o_UIHealthControllerUpdate = nullptr;
static UIBaseInvoke_t               o_UIBaseInvoke = nullptr;
static UIHealthOnOmniDamage_t       o_UIHealthControllerOnOmniDamage = nullptr;
static PlayerHealthEffectsUpdate_t  o_PlayerHealthEffectsUpdate = nullptr;
static ApplyEffectParameterData_t   fn_ApplyEffectParameterData = nullptr;
static CharacterNearDeathEffect_t   o_PlayNearDeathEnterEffect = nullptr;
static CharacterNearDeathEffect_t   o_PlayNearDeathLoopEffect = nullptr;
static CharacterNearDeathEffect_t   fn_StopNearDeathLoopEffect = nullptr;

static SRWLOCK s_HealthUiLock = SRWLOCK_INIT;
static void* s_HealthControllerLast = nullptr;
static void* s_HealthRootUI = nullptr;
static uintptr_t s_HealthRootImpl = 0;
static uintptr_t s_HealthRootClip = 0;
static bool  s_HealthUiWasSuppressed = false;
static bool  s_HealthUiHasNearDeath = false;
static bool  s_HealthUiSentFull = false;

static void ReadUiRootIdentity(uintptr_t root, uintptr_t& impl, uintptr_t& clip) {
    impl = 0;
    clip = 0;
    if (root && FastRead<uintptr_t>(root + 0x260, impl) && impl) {
        FastRead<uintptr_t>(impl + 0x20, clip);
    }
}

static bool IsHealthRootMatchLocked(void* thisptr, uintptr_t impl, uintptr_t clip) {
    return thisptr != nullptr && thisptr == s_HealthRootUI &&
           impl == s_HealthRootImpl && clip == s_HealthRootClip;
}

static uintptr_t GetRenderPlayerDamagePtr() {
    if (!g_ExeBase) return 0;
    uintptr_t renderEng = 0, postMgr = 0, playerDmg = 0;
    if (!FastRead<uintptr_t>(g_ExeBase + g_Addr_2C84BE8, renderEng) || !renderEng) return 0;
    if (!FastRead<uintptr_t>(renderEng + 0x14B0, postMgr) || !postMgr) return 0;
    if (!FastRead<uintptr_t>(postMgr + 0x1C0, playerDmg) || !playerDmg) return 0;
    return playerDmg;
}

static bool __fastcall hk_UIBaseInvoke(void* thisptr, const char* method, void* args, uint32_t argCount, void* retVal, float delay) {
    if (!o_UIBaseInvoke) return false;
    if (method && thisptr) {
        uintptr_t impl = 0, clip = 0;
        ReadUiRootIdentity((uintptr_t)thisptr, impl, clip);
        const bool suppress = SuppressDamageEffects();

        if (suppress && strcmp(method, "OnOmniDamage") == 0) {
            return true;
        }

        AcquireSRWLockExclusive(&s_HealthUiLock);
        bool isHealthRoot = IsHealthRootMatchLocked(thisptr, impl, clip);
        if (!suppress) {
            if (isHealthRoot) {
                if (strcmp(method, "EnterNearDeath") == 0) s_HealthUiHasNearDeath = true;
                else if (strcmp(method, "ExitNearDeath") == 0) s_HealthUiHasNearDeath = false;
            }
            ReleaseSRWLockExclusive(&s_HealthUiLock);
            return o_UIBaseInvoke(thisptr, method, args, argCount, retVal, delay);
        }

        if (isHealthRoot) {
            if (strcmp(method, "EnterNearDeath") == 0) {
                ReleaseSRWLockExclusive(&s_HealthUiLock);
                return true;
            }
            if (strcmp(method, "ExitNearDeath") == 0) {
                if (!s_HealthUiHasNearDeath) {
                    ReleaseSRWLockExclusive(&s_HealthUiLock);
                    return true;
                }
                s_HealthUiHasNearDeath = false;
                ReleaseSRWLockExclusive(&s_HealthUiLock);
                return o_UIBaseInvoke(thisptr, method, args, argCount, retVal, delay);
            }
            if (strcmp(method, "EnterDeath") == 0 || strcmp(method, "ExitDeath") == 0 ||
                strcmp(method, "Show") == 0 || strcmp(method, "Reset") == 0) {
                s_HealthUiSentFull = false;
            }
            if (strcmp(method, "UpdateHealth") == 0 && args && argCount >= 2 && argCount <= 8) {
                if (s_HealthUiSentFull) {
                    ReleaseSRWLockExclusive(&s_HealthUiLock);
                    return true;
                }
                // Scaleform::GFx::Value is 0x30 bytes: +0x18 Type (3=VT_Int, 5=VT_Number, bit 6=managed), +0x20 payload.
                // Spoof to full health (800, 0.0) in a private copy so hud_health_damage_manager jumps to "full_health"
                // and skips AddNewHealthPaint without corrupting caller-owned GFx::Value slots.
                alignas(16) uint8_t safeArgs[8 * 0x30];
                memcpy(safeArgs, args, (size_t)argCount * 0x30);
                uint32_t t0 = *(uint32_t*)(safeArgs + 0x18);
                uint32_t t1 = *(uint32_t*)(safeArgs + 0x30 + 0x18);
                if ((t0 & 0x40u) == 0 && (t1 & 0x40u) == 0) {
                    s_HealthUiSentFull = true;
                    ReleaseSRWLockExclusive(&s_HealthUiLock);
                    if ((t0 & 0x8Fu) == 3u) {
                        *(int32_t*)(safeArgs + 0x20) = 800;
                    } else {
                        *(uint32_t*)(safeArgs + 0x18) = 5u;
                        *(double*)(safeArgs + 0x20) = 800.0;
                    }
                    *(uint32_t*)(safeArgs + 0x30 + 0x18) = 5u;
                    *(double*)(safeArgs + 0x30 + 0x20) = 0.0;
                    return o_UIBaseInvoke(thisptr, method, safeArgs, argCount, retVal, delay);
                }
            }
        }
        ReleaseSRWLockExclusive(&s_HealthUiLock);
    }

    return o_UIBaseInvoke(thisptr, method, args, argCount, retVal, delay);
}

static void __fastcall hk_UIHealthControllerUpdate(void* thisptr, float dt, float alpha) {
    if (!o_UIHealthControllerUpdate) return;
    if (thisptr) {
        uintptr_t rootPtr = 0, impl = 0, clip = 0;
        FastRead<uintptr_t>((uintptr_t)thisptr + 0x10, rootPtr);
        ReadUiRootIdentity(rootPtr, impl, clip);
        int16_t curLastHp = -1;
        FastRead<int16_t>((uintptr_t)thisptr + 0x18, curLastHp);

        const bool suppress = SuppressDamageEffects();
        void* exitNearDeathRoot = nullptr;
        bool writeLastHp = false;
        bool writeNearDeath = false;
        uint8_t nearDeathVal = 0;

        AcquireSRWLockExclusive(&s_HealthUiLock);
        if (thisptr != s_HealthControllerLast) {
            s_HealthControllerLast = thisptr;
            s_HealthUiWasSuppressed = false;
            s_HealthUiHasNearDeath = false;
            s_HealthUiSentFull = false;
        }
        if ((void*)rootPtr != s_HealthRootUI || impl != s_HealthRootImpl || clip != s_HealthRootClip) {
            s_HealthRootUI = (void*)rootPtr;
            s_HealthRootImpl = impl;
            s_HealthRootClip = clip;
            s_HealthUiHasNearDeath = false;
            s_HealthUiSentFull = false;
        }
        if (curLastHp == -1) {
            s_HealthUiHasNearDeath = false;
            s_HealthUiSentFull = false;
        }

        if (suppress != s_HealthUiWasSuppressed) {
            s_HealthUiSentFull = false;
            if (suppress) {
                if (s_HealthUiHasNearDeath && rootPtr && o_UIBaseInvoke) {
                    uint8_t markedDestruct = 0;
                    if (FastRead<uint8_t>(rootPtr + 0x15B, markedDestruct) && markedDestruct == 0) {
                        exitNearDeathRoot = (void*)rootPtr;
                    }
                    s_HealthUiHasNearDeath = false;
                }
                writeLastHp = true;
            } else {
                writeLastHp = true;
                writeNearDeath = true;
                nearDeathVal = s_HealthUiHasNearDeath ? 1 : 0;
            }
            s_HealthUiWasSuppressed = suppress;
        }
        ReleaseSRWLockExclusive(&s_HealthUiLock);

        if (exitNearDeathRoot) {
            o_UIBaseInvoke(exitNearDeathRoot, "ExitNearDeath", nullptr, 0, nullptr, 0.0f);
        }
        if (writeLastHp) {
            FastWrite<int16_t>((uintptr_t)thisptr + 0x18, -1); // m_LastHealth
        }
        if (writeNearDeath) {
            FastWrite<uint8_t>((uintptr_t)thisptr + 0x1A, nearDeathVal); // m_IsNearDeath
        }
    }
    o_UIHealthControllerUpdate(thisptr, dt, alpha);
}

static void __fastcall hk_UIHealthControllerOnOmniDamage(void* thisptr) {
    if (SuppressDamageEffects()) return;
    if (o_UIHealthControllerOnOmniDamage) o_UIHealthControllerOnOmniDamage(thisptr);
}

static void __fastcall hk_PlayNearDeathEnterEffect(void* character) {
    if (SuppressDamageEffects()) return;
    if (o_PlayNearDeathEnterEffect) o_PlayNearDeathEnterEffect(character);
}

static void __fastcall hk_PlayNearDeathLoopEffect(void* character) {
    if (SuppressDamageEffects()) return;
    if (o_PlayNearDeathLoopEffect) o_PlayNearDeathLoopEffect(character);
}

static void __fastcall hk_PlayerHealthEffectsUpdate(void* thisptr, float dt, void* character) {
    const bool suppress = SuppressDamageEffects();
    float preRenderDmgLevel = 0.0f;
    bool hasPreRenderDmg = false;
    uintptr_t prePlayerDmgPtr = 0;
    if (suppress) {
        prePlayerDmgPtr = GetRenderPlayerDamagePtr();
        if (prePlayerDmgPtr && FastRead<float>(prePlayerDmgPtr + 0x1A0, preRenderDmgLevel)) {
            hasPreRenderDmg = true;
        }
    }

    if (o_PlayerHealthEffectsUpdate) o_PlayerHealthEffectsUpdate(thisptr, dt, character);
    static std::atomic<bool> s_FxWasSuppressed{false};
    if (!thisptr) {
        s_FxWasSuppressed.store(suppress, std::memory_order_relaxed);
        return;
    }

    uint8_t deathTimerActive = 0;
    float curDeathTime = 0.0f;
    int16_t charHp = 0;
    FastRead<uint8_t>((uintptr_t)thisptr + 0x54, deathTimerActive);  // m_DeathTimerActive
    FastRead<float>((uintptr_t)thisptr + 0x60, curDeathTime);        // m_CurrentDeathTime
    const bool charAlive = character && FastRead<int16_t>((uintptr_t)character + 0x3AC, charHp) && charHp > 0;

    // o_PlayerHealthEffectsUpdate triggers respawn/fail when m_DeathTimerActive && m_CurrentDeathTime <= 0;
    // avoid invoking character effects or touching post-FX targets during teardown.
    if (deathTimerActive && curDeathTime <= 0.0f) {
        return;
    }

    uint8_t isNearDeath = 0;
    uint8_t isInRegen = 0;
    FastRead<uint8_t>((uintptr_t)thisptr + 0x78, isNearDeath);
    FastRead<uint8_t>((uintptr_t)thisptr + 0x88, isInRegen);
    const bool prevFx = s_FxWasSuppressed.exchange(suppress, std::memory_order_acq_rel);
    if (suppress != prevFx && charAlive) {
        if (suppress && isNearDeath && fn_StopNearDeathLoopEffect) {
            fn_StopNearDeathLoopEffect(character);
        } else if (!suppress && isNearDeath && o_PlayNearDeathLoopEffect) {
            o_PlayNearDeathLoopEffect(character);
        }
    }

    if (!suppress) return;

    // Zero damage overlay intensity and re-apply effect parameters so EThermalScope stays intact.
    FastWrite<float>((uintptr_t)thisptr + 0x74, 0.0f); // m_EffectLevel
    if (fn_ApplyEffectParameterData) {
        fn_ApplyEffectParameterData(thisptr, 0.0f);
    }

    // o_PlayerHealthEffectsUpdate bypasses ApplyEffectParameterData when (m_IsInRegen && m_IsInNearDeathState)
    // and directly writes m_PlayerDamage->m_EffectConstants.m_EffectLevel = m_EffectLevel * 0.25 + 0.75.
    // Re-sync that render constant back to COverlayUI::m_DamageEffect.m_EffectLevel (or preserve pause-menu fade).
    uintptr_t postPlayerDmgPtr = prePlayerDmgPtr ? prePlayerDmgPtr : GetRenderPlayerDamagePtr();
    if (postPlayerDmgPtr) {
        uintptr_t overlayUI = 0;
        float menuStrength = 0.0f;
        float overlayDmgLevel = 0.0f;
        if (FastRead<uintptr_t>(PlayerFxAddress(0x2CB7DC0, 0x2CBE188), overlayUI) && overlayUI) {
            FastRead<float>(overlayUI + 0x37C, menuStrength);     // COverlayUI::m_PostEffectStrength
            FastRead<float>(overlayUI + 0x414, overlayDmgLevel);  // COverlayUI::m_DamageEffect.m_EffectLevel
        }
        if (menuStrength > 0.0f) {
            if (isNearDeath && isInRegen && hasPreRenderDmg) {
                FastWrite<float>(postPlayerDmgPtr + 0x1A0, preRenderDmgLevel);
            }
        } else {
            FastWrite<float>(postPlayerDmgPtr + 0x1A0, overlayDmgLevel);
        }
    }
}

static void InstallRedDamageHooks() {
    if (IdentifyJC4NativeBuild(g_ExeBase) == JC4NativeBuild::Unknown) return;

    // Verify ApplyEffectParameterData (0xAFD360) before calling it from hk_PlayerHealthEffectsUpdate.
    {
        static const uint8_t sig[] = { 0x4C,0x8B,0xDC,0x56,0x57,0x41,0x56,0x48,0x81,0xEC,0xB0,0x00,0x00,0x00 };
        uintptr_t addr = PlayerFxAddress(0xAFD360, 0xB047C0);
        if (PrologueMatches(addr, sig, sizeof(sig))) {
            fn_ApplyEffectParameterData = (ApplyEffectParameterData_t)addr;
        } else {
            LogPrologueBytes("CPlayerHealthEffects::ApplyEffectParameterData", addr);
        }
    }

    int hooked = 0;

    // CUIBase::Invoke (0xE90280)
    {
        static const uint8_t sig[] = { 0x48,0x8B,0xC4,0x53,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57 };
        void* p = (void*)PlayerFxAddress(0xE90280, 0xE97E20);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_UIBaseInvoke, (void**)&o_UIBaseInvoke) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("CUIBase::Invoke", (uintptr_t)p);
        }
    }

    // CUIHealthController::Update (0xE60340)
    {
        static const uint8_t sig[] = { 0x48,0x8B,0xC4,0x55,0x41,0x56,0x41,0x57,0x48,0x8D,0x68,0xA1,0x48,0x81,0xEC,0xF0,0x00,0x00,0x00 };
        void* p = (void*)PlayerFxAddress(0xE60340, 0xE68340);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_UIHealthControllerUpdate, (void**)&o_UIHealthControllerUpdate) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("CUIHealthController::Update", (uintptr_t)p);
        }
    }

    // CUIHealthController::OnOmniDamage (0xE53480)
    {
        static const uint8_t sig[] = { 0x48,0x83,0xEC,0x78,0x48,0xC7,0x44,0x24,0x30,0xFE,0xFF,0xFF,0xFF };
        void* p = (void*)PlayerFxAddress(0xE53480, 0xE5B400);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_UIHealthControllerOnOmniDamage, (void**)&o_UIHealthControllerOnOmniDamage) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("CUIHealthController::OnOmniDamage", (uintptr_t)p);
        }
    }

    // CPlayerHealthEffects::Update (g_Addr_98AA180)
    {
        static const uint8_t sig[] = { 0x48,0x89,0xE0,0x55,0x57,0x41,0x56,0x48,0x81,0xEC,0xC0,0x00,0x00,0x00 };
        void* p = (void*)PlayerFxAddress(0x98AA180, 0x15DFEAD0);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_PlayerHealthEffectsUpdate, (void**)&o_PlayerHealthEffectsUpdate) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("CPlayerHealthEffects::Update", (uintptr_t)p);
        }
    }

    // CCharacter::PlayNearDeathEnterEffect (body RVA 0x85B17A0, stops camera white-red blowout/blur)
    {
        static const uint8_t sig[] = { 0x48,0x83,0xEC,0x38,0x0F,0xB6,0x91,0x4B,0x7A,0x01,0x00,0x41,0xB9,0x1F,0x00,0x00 };
        void* p = (void*)PlayerFxAddress(0x85B17A0, 0x148AA940);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_PlayNearDeathEnterEffect, (void**)&o_PlayNearDeathEnterEffect) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("CCharacter::PlayNearDeathEnterEffect", (uintptr_t)p);
        }
    }

    // CCharacter::PlayNearDeathLoopEffect (body RVA 0x85B2140)
    {
        static const uint8_t sig[] = { 0x48,0x83,0xEC,0x38,0x0F,0xB6,0x91,0x4D,0x7A,0x01,0x00,0x41,0xB9,0x1F,0x00,0x00 };
        void* p = (void*)PlayerFxAddress(0x85B2140, 0x148AB680);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_PlayNearDeathLoopEffect, (void**)&o_PlayNearDeathLoopEffect) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("CCharacter::PlayNearDeathLoopEffect", (uintptr_t)p);
        }
    }

    // CCharacter::StopNearDeathLoopEffect (body RVA 0x85DD4A0)
    {
        static const uint8_t sig[] = { 0x0F,0xB6,0x91,0x4D,0x7A,0x01,0x00,0x41,0xB9,0x01,0x00,0x00,0x00,0x48,0x81,0xC1 };
        uintptr_t addr = PlayerFxAddress(0x85DD4A0, 0x148E1630);
        if (PrologueMatches(addr, sig, sizeof(sig))) {
            fn_StopNearDeathLoopEffect = (CharacterNearDeathEffect_t)addr;
        } else {
            LogPrologueBytes("CCharacter::StopNearDeathLoopEffect", addr);
        }
    }

    const bool ready = hooked == 6 && fn_ApplyEffectParameterData && fn_StopNearDeathLoopEffect;
    s_RedDamageReady.store(ready, std::memory_order_release);
    JC4Terrain16x16::TerrainLog("[PlayerFX] Damage hooks %d/6; %s", hooked, ready ? "ready" : "inactive");
}

// ============================================================================
// NO RAGDOLL (STATE MACHINE + PHYSICS COLLISION + RAGDOLL SYNC + RECOVERY)
// ============================================================================
static std::atomic<uintptr_t> g_NoRagdollCachedPlayerChar{0};
static std::atomic<uint64_t>  g_RagdollEvalBlocks{0};
static std::atomic<uint64_t>  g_RagdollEventBlocks{0};
static std::atomic<uint64_t>  g_RagdollSyncBlocks{0};
static std::atomic<uint64_t>  g_RagdollCollisionBlocks{0};
static std::atomic<uint64_t>  g_RagdollOnEnterHits{0};
static std::atomic<uint64_t>  g_RagdollRecoveries{0};
static std::atomic<uint32_t>  g_RagdollLastAct{0};

typedef bool(__fastcall* SMIHandleEvent_t)(void* smi, const uint32_t* pEventId);
typedef bool(__fastcall* CTransitionEvaluate_t)(void* transition, void* smi);
typedef bool(__fastcall* SMIHandleUpdateEvent_t)(void* smi, bool animFinished);
typedef void(__fastcall* CharacterDoSyncRagdollState_t)(void* character, float dt);
typedef void(__cdecl* CapsuleCollisionDoTrigger_t)(void* ch, void* props, void* inst, float* prevVel, float* pos, float* normal);
typedef void(__cdecl* NRagdollingOnEnter_t)(void* stateCtx, void* props, void* inst);
typedef void*(__fastcall* CRagdollDescGetParamsByID_t)(void* desc, const uint32_t* pId);
typedef void(__fastcall* GameObjectResolveTransform_t)(void* gameObj);
typedef void(__fastcall* GameObjectSetWorldTransform_t)(void* gameObj, const float* mat4x4);
typedef void(__fastcall* PfxCharSetOrientation_t)(void* pfxChar, const float* mat4x4);

static SMIHandleEvent_t               o_SMIHandleEvent = nullptr;
static CTransitionEvaluate_t          o_CTransitionEvaluate = nullptr;
static SMIHandleUpdateEvent_t         o_SMIHandleUpdateEvent = nullptr;
static CharacterDoSyncRagdollState_t  o_DoSyncRagdollState = nullptr;
static CapsuleCollisionDoTrigger_t    o_CapsuleHandlingDoTrigger = nullptr;
static CapsuleCollisionDoTrigger_t    o_CapsuleTriggerDoTrigger = nullptr;
static NRagdollingOnEnter_t           o_NRagdollingOnEnter = nullptr;

static CRagdollDescGetParamsByID_t    fn_RagdollGetParamsByID = nullptr;
static GameObjectResolveTransform_t   fn_CharResolveTransform = nullptr;
static GameObjectSetWorldTransform_t  fn_CharSetWorldTransform = nullptr;
static PfxCharSetOrientation_t        fn_PfxSetOrientation = nullptr;

static int      s_IdxNRagdolling = -1;
static int      s_IdxNSetRagdoll = -1;
static int      s_IdxFreefallMove = -1;
static uint32_t s_HashACT_FULL_RAGDOLL = 0;
static uint32_t s_HashACT_RAGDOLL_IMPACT = 0;
static uint32_t s_HashACT_HITREACT_RAGDOLL = 0;
static uint32_t s_HashACT_GRAPPLE_RAGDOLL = 0;
static uint32_t s_HashACT_FORCE_DEATH_RAGDOLL = 0;
static uint32_t s_HashACT_CLOSE_WINGSUIT = 0;
static uint32_t s_HashACT_FORCE_FREEFALL = 0;
static uint32_t s_HashACT_NONE = 0;
static uint32_t s_HashS_DEAD = 0;
static uint32_t s_HashS_FREEFALL = 0;
static std::atomic<DWORD> g_WingsuitCrashCloseMs{0};
static std::atomic<uintptr_t> g_FreefallRecoverSMI{0};
static std::atomic<DWORD> g_FreefallStationaryMs{0};

static inline uint32_t HashRotLeft(uint32_t x, uint32_t k) {
    return (x << k) | (x >> (32 - k));
}

// Matches JustCause4.exe HashBuffer / Jenkins lookup3 hashlittle(str, len, 0).
static uint32_t JC4HashLittle(const char* str) {
    if (!str) return 0xdeadbeefu;
    size_t length = strlen(str);
    uint32_t a = 0xdeadbeefu + (uint32_t)length;
    uint32_t b = a;
    uint32_t c = a;
    const uint8_t* k = (const uint8_t*)str;

    while (length > 12) {
        a += (uint32_t)k[0] | ((uint32_t)k[1] << 8) | ((uint32_t)k[2] << 16) | ((uint32_t)k[3] << 24);
        b += (uint32_t)k[4] | ((uint32_t)k[5] << 8) | ((uint32_t)k[6] << 16) | ((uint32_t)k[7] << 24);
        c += (uint32_t)k[8] | ((uint32_t)k[9] << 8) | ((uint32_t)k[10] << 16) | ((uint32_t)k[11] << 24);
        a -= c; a ^= HashRotLeft(c, 4);  c += b;
        b -= a; b ^= HashRotLeft(a, 6);  a += c;
        c -= b; c ^= HashRotLeft(b, 8);  b += a;
        a -= c; a ^= HashRotLeft(c, 16); c += b;
        b -= a; b ^= HashRotLeft(a, 19); a += c;
        c -= b; c ^= HashRotLeft(b, 4);  b += a;
        length -= 12;
        k += 12;
    }

    switch (length) {
        case 12: c += ((uint32_t)k[11]) << 24; [[fallthrough]];
        case 11: c += ((uint32_t)k[10]) << 16; [[fallthrough]];
        case 10: c += ((uint32_t)k[9]) << 8;   [[fallthrough]];
        case 9:  c += k[8];                    [[fallthrough]];
        case 8:  b += ((uint32_t)k[7]) << 24;  [[fallthrough]];
        case 7:  b += ((uint32_t)k[6]) << 16;  [[fallthrough]];
        case 6:  b += ((uint32_t)k[5]) << 8;   [[fallthrough]];
        case 5:  b += k[4];                    [[fallthrough]];
        case 4:  a += ((uint32_t)k[3]) << 24;  [[fallthrough]];
        case 3:  a += ((uint32_t)k[2]) << 16;  [[fallthrough]];
        case 2:  a += ((uint32_t)k[1]) << 8;   [[fallthrough]];
        case 1:  a += k[0]; break;
        case 0:  return c;
    }

    c ^= b; c -= HashRotLeft(b, 14);
    a ^= c; a -= HashRotLeft(c, 11);
    b ^= a; b -= HashRotLeft(a, 25);
    c ^= b; c -= HashRotLeft(b, 16);
    a ^= c; a -= HashRotLeft(c, 4);
    b ^= a; b -= HashRotLeft(a, 14);
    c ^= b; c -= HashRotLeft(b, 24);
    return c;
}

static void InitNoRagdollMetadata() {
    s_HashACT_FULL_RAGDOLL        = JC4HashLittle("ACT_FULL_RAGDOLL");
    s_HashACT_RAGDOLL_IMPACT      = JC4HashLittle("ACT_RAGDOLL_IMPACT");
    s_HashACT_HITREACT_RAGDOLL    = JC4HashLittle("ACT_HITREACT_RAGDOLL");
    s_HashACT_GRAPPLE_RAGDOLL     = JC4HashLittle("ACT_GRAPPLE_RAGDOLL");
    s_HashACT_FORCE_DEATH_RAGDOLL = JC4HashLittle("ACT_FORCE_DEATH_RAGDOLL");
    s_HashACT_CLOSE_WINGSUIT      = JC4HashLittle("ACT_CLOSE_WINGSUIT");
    s_HashACT_FORCE_FREEFALL      = JC4HashLittle("ACT_FORCE_FREEFALL");
    s_HashACT_NONE                = JC4HashLittle("ACT_NONE");
    s_HashS_DEAD                  = JC4HashLittle("S_DEAD");
    s_HashS_FREEFALL              = JC4HashLittle("S_FREEFALL");

    const uintptr_t fnNRagdollingEnter = PlayerFxAddress(0x5EB850, 0x5ED920);
    const uintptr_t fnNSetRagdollEnter = PlayerFxAddress(0x606830, 0x608C90);
    const uintptr_t fnFreefallUpdate   = PlayerFxAddress(0x5D7060, 0x5D9070);

    // TASKS_DATA / s_StateTasks: 214 entries x 88 bytes at RVA 0x2AD93D0.
    // SStateTask layout: +0x04 m_Id (uint32), +0x10 m_Functions[6] (+0x18 OnEnter, +0x20 Update).
    const uintptr_t tasksTable = PlayerFxAddress(0x2AD93D0, 0x2AE03E0);
    s_IdxNRagdolling = -1;
    s_IdxNSetRagdoll = -1;
    s_IdxFreefallMove = -1;
    uint32_t idNRagdolling = 0, idNSetRagdoll = 0, idFreefallMove = 0;
    for (int i = 0; i < 214; ++i) {
        const uintptr_t entry = tasksTable + (size_t)i * 88;
        uintptr_t onEnter = 0, onUpdate = 0;
        if (!FastRead<uintptr_t>(entry + 0x18, onEnter)) break;
        FastRead<uintptr_t>(entry + 0x20, onUpdate);
        if (onEnter == fnNRagdollingEnter) {
            if (!FastRead<uint32_t>(entry + 0x04, idNRagdolling) || idNRagdolling != 0xddeabf96) continue;
            s_IdxNRagdolling = i;
        } else if (onEnter == fnNSetRagdollEnter) {
            if (!FastRead<uint32_t>(entry + 0x04, idNSetRagdoll) || idNSetRagdoll != 0xf386d51e) continue;
            s_IdxNSetRagdoll = i;
        } else if (onUpdate == fnFreefallUpdate) {
            if (!FastRead<uint32_t>(entry + 0x04, idFreefallMove) || idFreefallMove != 0x71bd6026) continue;
            s_IdxFreefallMove = i;
        }
    }
    std::cout << "[+] No Ragdoll state tasks: NRagdolling=" << s_IdxNRagdolling
              << " (0x" << std::hex << idNRagdolling << "), NSetRagdoll=" << std::dec
              << s_IdxNSetRagdoll << " (0x" << std::hex << idNSetRagdoll << "), Freefall=" << std::dec
              << s_IdxFreefallMove << " (0x" << std::hex << idFreefallMove << ")" << std::dec << ".\n";
}

static inline bool IsNonDeathRagdollAct(uint32_t act) {
    return act == s_HashACT_FULL_RAGDOLL ||
           act == s_HashACT_RAGDOLL_IMPACT ||
           act == s_HashACT_HITREACT_RAGDOLL ||
           act == s_HashACT_GRAPPLE_RAGDOLL;
}

static uint32_t GetPlayerStateFlags() {
    if (!g_ExeBase) return 0;
    uintptr_t mgr = 0;
    uint32_t flags = 0;
    if (FastRead<uintptr_t>(PlayerFxAddress(0x2CB22B8, 0x2CB8688), mgr) && mgr) {
        FastRead<uint32_t>(mgr + 0x10, flags);
    }
    return flags;
}

static bool IsCharacterDeadOrDying(uintptr_t ch) {
    int16_t hp = 0;
    if (!FastRead<int16_t>(ch + 0x3AC, hp) || hp <= 0) return true;
    uintptr_t ctrlParams = 0;
    if (FastRead<uintptr_t>(ch + 0x2760, ctrlParams) && ctrlParams) {
        uint64_t bits = 0;
        if (FastRead<uint64_t>(ctrlParams + 0xD0, bits) && (bits & (1ULL << 0x24))) return true;
    }
    return false;
}

static bool IsPlayerWingsuitActive(uintptr_t /*ch*/) {
    // Matches CConditional_IsPlayerInWingsuit::Evaluate (0x650E50 -> bit 0 of state manager +0x10)
    return (GetPlayerStateFlags() & 1u) != 0;
}

static bool IsPlayerParachuteActive(uintptr_t ch) {
    if ((GetPlayerStateFlags() & 2u) != 0) return true;
    uintptr_t ctrlParams = 0;
    uint64_t bits = 0;
    return FastRead<uintptr_t>(ch + 0x2760, ctrlParams) && ctrlParams &&
           FastRead<uint64_t>(ctrlParams + 0xD0, bits) && ((bits & (1ULL << 0x23)) != 0);
}

static bool IsControlledRagdollInstancePtr(uintptr_t ragPtr) {
    if (!ragPtr) return false;
    uint8_t forceCtrl = 0;
    int32_t ctrlType = 0;
    uintptr_t kfBegin = 0, kfEnd = 0;
    if (!FastRead<uint8_t>(ragPtr + 0x68, forceCtrl)) return false;
    FastRead<int32_t>(ragPtr + 0x2C8, ctrlType);
    FastRead<uintptr_t>(ragPtr + 0x2D0, kfBegin);
    FastRead<uintptr_t>(ragPtr + 0x2D8, kfEnd);
    return (forceCtrl != 0) || (ctrlType == 1) || (kfBegin != kfEnd);
}

// Fast O(1) filter against the Present-cached player character, then exact verification on hit
// so NPCs/vehicles pay zero syscalls and despawn/respawn transitions stay crash-safe.
static uintptr_t VerifyAlivePlayerCharacter(const void* candidateChar) {
    if (!candidateChar) return 0;
    uintptr_t cached = g_NoRagdollCachedPlayerChar.load(std::memory_order_relaxed);
    if (!cached || (uintptr_t)candidateChar != cached) return 0;
    uintptr_t live = GetPlayerCharacterPtr();
    if (!live || live != (uintptr_t)candidateChar) return 0;
    uint8_t isPlayer = 0;
    if (!FastRead<uint8_t>(live + 0x2A38, isPlayer) || !isPlayer) return 0;
    if (IsCharacterDeadOrDying(live)) return 0;
    return live;
}

static uintptr_t VerifyAlivePlayerFromSMI(const void* smi) {
    if (!smi) return 0;
    uintptr_t cached = g_NoRagdollCachedPlayerChar.load(std::memory_order_relaxed);
    if (!cached) return 0;
    uintptr_t userObj = *(const uintptr_t*)((const uint8_t*)smi + 0x20); // CStateMachineInstance::m_UserData = ch + 0x10
    if (userObj != cached + 0x10) return 0;
    return VerifyAlivePlayerCharacter((const void*)cached);
}

static bool IsControlledRagdollParamsPtr(uintptr_t paramsPtr) {
    if (!paramsPtr) return false;
    int32_t ctrlType = 0;
    uintptr_t kfBegin = 0, kfEnd = 0;
    if (!FastRead<int32_t>(paramsPtr + 0x44, ctrlType)) return false;
    FastRead<uintptr_t>(paramsPtr + 0x58, kfBegin);
    FastRead<uintptr_t>(paramsPtr + 0x60, kfEnd);
    return (ctrlType == 1) || (kfBegin != kfEnd); // 1 = RIGID_BODY (e.g. PARACHUTING)
}

static bool IsControlledRagdollParamId(uint32_t paramId) {
    if (paramId == 0xdeadbeefu || paramId == 0 || !fn_RagdollGetParamsByID || !g_ExeBase) {
        return false;
    }
    uintptr_t charMgr = 0;
    if (!FastRead<uintptr_t>(PlayerFxAddress(0x2CB1D40, 0x2CB8110), charMgr) || !charMgr) return false;
    uintptr_t resInfo = 0;
    if (!FastRead<uintptr_t>(charMgr + 0x260, resInfo) || !resInfo) return false;
    uintptr_t desc = 0;
    if (!FastRead<uintptr_t>(resInfo, desc) || !desc) return false;
    void* params = fn_RagdollGetParamsByID((void*)desc, &paramId);
    return params ? IsControlledRagdollParamsPtr((uintptr_t)params) : false;
}

static inline bool StateHasTaskBit(uintptr_t taskSet, int idx) {
    if (!taskSet || idx < 0 || idx >= 320) return false;
    uint64_t word = 0;
    if (!FastRead<uint64_t>(taskSet + 0x10 + (size_t)(idx >> 6) * 8, word)) return false;
    return (word & (1ULL << (idx & 63))) != 0;
}

static bool StateIsFreefallState(const void* statePtr) {
    if (!statePtr) return false;
    uint32_t stateHash = 0;
    if (!FastRead<uint32_t>((uintptr_t)statePtr + 0x0C, stateHash)) return false;
    if (s_HashS_FREEFALL && stateHash == s_HashS_FREEFALL) return true;
    uintptr_t taskSet = 0;
    if (s_IdxFreefallMove >= 0 && FastRead<uintptr_t>((uintptr_t)statePtr + 0x10, taskSet) && taskSet) {
        return StateHasTaskBit(taskSet, s_IdxFreefallMove);
    }
    return false;
}

static bool StateIsUncontrolledRagdollState(const void* statePtr) {
    if (!statePtr || s_IdxNRagdolling < 0 || s_IdxNSetRagdoll < 0) return false;

    uint32_t stateHash = 0;
    if (!FastRead<uint32_t>((uintptr_t)statePtr + 0x0C, stateHash)) return false;
    if (stateHash == s_HashS_DEAD) return false;

    uintptr_t taskSet = 0;
    if (!FastRead<uintptr_t>((uintptr_t)statePtr + 0x10, taskSet) || !taskSet) return false;

    const bool hasRagdolling = StateHasTaskBit(taskSet, s_IdxNRagdolling);
    const bool hasSetRagdoll = StateHasTaskBit(taskSet, s_IdxNSetRagdoll);
    if (!hasRagdolling && !hasSetRagdoll) return false;

    bool hasControlledSetRagdoll = false;
    if (hasSetRagdoll) {
        uint32_t taskCount = 0;
        uintptr_t updateInfos = 0;
        uintptr_t propsBase = 0;
        if (FastRead<uint32_t>(taskSet + 0x00, taskCount) &&
            FastRead<uintptr_t>(taskSet + 0x08, updateInfos) && updateInfos &&
            FastRead<uintptr_t>(taskSet + 0x38, propsBase) && propsBase) {
            if (taskCount > 64) taskCount = 64;
            for (uint32_t i = 0; i < taskCount; ++i) {
                uint16_t memOff = 0, taskIdx = 0xFFFF;
                if (!FastRead<uint16_t>(updateInfos + (size_t)i * 4 + 0x00, memOff)) break;
                if (!FastRead<uint16_t>(updateInfos + (size_t)i * 4 + 0x02, taskIdx)) break;
                if ((int)taskIdx == s_IdxNSetRagdoll) {
                    uint32_t paramId = 0xdeadbeefu;
                    if (FastRead<uint32_t>(propsBase + memOff, paramId) &&
                        paramId != 0xdeadbeefu && paramId != 0) {
                        if (!IsControlledRagdollParamId(paramId)) {
                            return true; // explicit uncontrolled NSetRagdoll
                        }
                        hasControlledSetRagdoll = true;
                    }
                }
            }
        }
    }

    return hasRagdolling && !hasControlledSetRagdoll;
}

static void MakeMatrixUpright(float m[16]) {
    // Same orthonormal upright projection as CCharacter::CreateUprightOrientation (0x52AE30):
    // preserve yaw & world translation [12..14], zero pitch/roll, set Up = (0, 1, 0).
    float x0 = 1.0f, z0 = 0.0f, x2 = 0.0f, z2 = 1.0f;
    if (m[1] * m[1] <= m[9] * m[9]) {
        float ax = m[0], az = -m[2];
        float len = sqrtf(ax * ax + az * az);
        if (len > 1e-6f) { ax /= len; az /= len; } else { ax = 1.0f; az = 0.0f; }
        x0 = ax; z0 = az; x2 = -az; z2 = ax;
    } else {
        float fx = -m[8], fz = m[10];
        float len = sqrtf(fx * fx + fz * fz);
        if (len > 1e-6f) { fx /= len; fz /= len; } else { fx = 0.0f; fz = 1.0f; }
        x0 = fz; z0 = -fx; x2 = fx; z2 = fz;
    }
    m[0] = x0;  m[1] = 0.0f; m[2] = z0;  m[3] = 0.0f;
    m[4] = 0.0f; m[5] = 1.0f; m[6] = 0.0f; m[7] = 0.0f;
    m[8] = x2;  m[9] = 0.0f; m[10] = z2; m[11] = 0.0f;
    m[15] = 1.0f;
}

static void ForceTransitionToInitialState(void* smi, uintptr_t ch, bool isRagdollRecovery) {
    static thread_local bool t_InRecovery = false;
    if (t_InRecovery || !smi || !ch) return;

    uintptr_t pCur = 0, resInfo = 0, pSM = 0, pInitial = 0;
    if (!FastRead<uintptr_t>((uintptr_t)smi + 0x18, pCur) || !pCur) return;
    if (!FastRead<uintptr_t>((uintptr_t)smi + 0x10, resInfo) || !resInfo) return;
    if (!FastRead<uintptr_t>(resInfo, pSM) || !pSM) return;
    if (!FastRead<uintptr_t>(pSM + 0x08, pInitial) || !pInitial) return;
    if (pInitial == pCur || StateIsUncontrolledRagdollState((const void*)pInitial)) return;

    uintptr_t curVtbl = 0, initVtbl = 0, curOnExit = 0, initOnEnter = 0;
    if (!FastRead<uintptr_t>(pCur, curVtbl) || !FastRead<uintptr_t>(curVtbl + 0x50, curOnExit)) return;
    if (!FastRead<uintptr_t>(pInitial, initVtbl) || !FastRead<uintptr_t>(initVtbl + 0x40, initOnEnter)) return;

    t_InRecovery = true;

    typedef void(__fastcall* StateLifecycleFn_t)(void* state, void* smi);
    ((StateLifecycleFn_t)curOnExit)((void*)pCur, smi);

    uint32_t curParam = 0xdeadbeefu;
    uintptr_t curRag = 0;
    FastRead<uint32_t>(ch + 0x25E8, curParam);
    FastRead<uintptr_t>(ch + 0x25F0, curRag);
    if (isRagdollRecovery || curRag != 0 || (curParam != 0xdeadbeefu && curParam != 0)) {
        // Tear down any active Havok ragdoll cleanly on the game thread so m_PartsMessenger
        // sends MERGED and NRagdolling's input context/motion state are never left dangling.
        uint32_t deadId = 0xdeadbeefu;
        float zeroBlend = 0.0f;
        uint8_t resetFlag = 0;
        uint8_t syncFlag = 1;
        FastWrite<uint32_t>(ch + 0x25E8, deadId);
        FastWrite<float>(ch + 0x2600, zeroBlend);
        FastWrite<uint8_t>(ch + 0x2605, resetFlag);
        FastWrite<uint8_t>(ch + 0x2604, syncFlag);
        if (o_DoSyncRagdollState) {
            o_DoSyncRagdollState((void*)ch, 0.0f);
        }
    }

    uint32_t defMotion = 0;
    if (FastRead<uint32_t>(ch + 0x2634, defMotion)) {
        FastWrite<uint32_t>(ch + 0x2630, defMotion);
    }

    // Project character + Pfx rigid body upright while preserving world XYZ position.
    if (fn_CharResolveTransform && fn_CharSetWorldTransform) {
        uint8_t xformFlag = 0;
        if (FastRead<uint8_t>(ch + 0x154, xformFlag) && (xformFlag & 1)) {
            fn_CharResolveTransform((void*)(ch + 0x10));
        }
        float mat[16] = {};
        bool gotMat = true;
        for (int i = 0; i < 16; ++i) {
            if (!FastRead<float>(ch + 0x114 + (size_t)i * 4, mat[i])) { gotMat = false; break; }
        }
        if (gotMat) {
            MakeMatrixUpright(mat);
            fn_CharSetWorldTransform((void*)(ch + 0x10), mat);
            if (FastRead<uint8_t>(ch + 0x154, xformFlag) && (xformFlag & 1)) {
                fn_CharResolveTransform((void*)(ch + 0x10));
            }
            uintptr_t pfxChar = 0;
            if (fn_PfxSetOrientation && FastRead<uintptr_t>(ch + 0x2208, pfxChar) && pfxChar) {
                fn_PfxSetOrientation((void*)pfxChar, (const float*)(ch + 0x114));
            }
        }
    }

    *(void**)((uintptr_t)smi + 0x18) = (void*)pInitial;
    ((StateLifecycleFn_t)initOnEnter)((void*)pInitial, smi);

    typedef void(__cdecl* SMCallback_t)(void* ctx, void* prevState, void* nextState);
    uintptr_t cbFn = 0, cbCtx = 0;
    FastRead<uintptr_t>((uintptr_t)smi + 0x38, cbFn);
    FastRead<uintptr_t>((uintptr_t)smi + 0x30, cbCtx);
    if (cbFn) {
        ((SMCallback_t)cbFn)((void*)cbCtx, (void*)pCur, (void*)pInitial);
    }

    if (isRagdollRecovery) {
        g_RagdollRecoveries++;
    }
    t_InRecovery = false;
}

static inline void RecoverFromMidRagdoll(void* smi, uintptr_t ch) {
    ForceTransitionToInitialState(smi, ch, true);
}

static bool __fastcall hk_CTransitionEvaluate(void* transition, void* smi) {
    if (!o_CTransitionEvaluate) return false;
    if (SuppressRagdoll() && transition && smi) {
        uintptr_t ch = VerifyAlivePlayerFromSMI(smi);
        if (ch) {
            uint32_t transEvt = 0;
            void* dest = nullptr;
            if (FastRead<uintptr_t>((uintptr_t)transition + 0x00, *(uintptr_t*)&dest) && dest) {
                FastRead<uint32_t>((uintptr_t)transition + 0x18, transEvt);
                if (transEvt != s_HashACT_FORCE_DEATH_RAGDOLL && StateIsUncontrolledRagdollState(dest)) {
                    g_RagdollEvalBlocks++;
                    void* curState = nullptr;
                    if (FastRead<uintptr_t>((uintptr_t)smi + 0x18, *(uintptr_t*)&curState) &&
                        curState && StateIsFreefallState(curState) &&
                        o_CTransitionEvaluate(transition, smi)) {
                        g_FreefallRecoverSMI.store((uintptr_t)smi, std::memory_order_relaxed);
                    }
                    return false;
                }
            }
        }
    }
    return o_CTransitionEvaluate(transition, smi);
}

static bool __fastcall hk_SMIHandleEvent(void* smi, const uint32_t* pEventId) {
    if (!o_SMIHandleEvent) return false;
    if (SuppressRagdoll() && smi && pEventId) {
        uintptr_t ch = VerifyAlivePlayerFromSMI(smi);
        if (ch) {
            uint32_t evt = 0;
            if (FastRead<uint32_t>((uintptr_t)pEventId, evt) && IsNonDeathRagdollAct(evt)) {
                g_RagdollLastAct.store(evt, std::memory_order_relaxed);
                g_RagdollEventBlocks++;
                if (IsPlayerWingsuitActive(ch)) {
                    uint32_t closeEvt = s_HashACT_CLOSE_WINGSUIT;
                    if (o_SMIHandleEvent(smi, &closeEvt)) {
                        g_WingsuitCrashCloseMs.store(0, std::memory_order_relaxed);
                        return true;
                    }
                    uint32_t ffEvt = s_HashACT_FORCE_FREEFALL;
                    if (o_SMIHandleEvent(smi, &ffEvt)) {
                        g_WingsuitCrashCloseMs.store(0, std::memory_order_relaxed);
                        return true;
                    }
                    return false;
                }
                // Let o_SMIHandleEvent try any authored non-ragdoll fallback transition;
                // hk_CTransitionEvaluate still blocks every uncontrolled ragdoll destination.
                return o_SMIHandleEvent(smi, pEventId);
            }
        }
    }
    return o_SMIHandleEvent(smi, pEventId);
}

static bool __fastcall hk_SMIHandleUpdateEvent(void* smi, bool animFinished) {
    if (!o_SMIHandleUpdateEvent) return false;
    if (!SuppressRagdoll()) {
        if (g_WingsuitCrashCloseMs.load(std::memory_order_relaxed) != 0) {
            g_WingsuitCrashCloseMs.store(0u, std::memory_order_relaxed);
        }
        if (g_FreefallRecoverSMI.load(std::memory_order_relaxed) != 0) {
            g_FreefallRecoverSMI.store(0u, std::memory_order_relaxed);
        }
        if (g_FreefallStationaryMs.load(std::memory_order_relaxed) != 0) {
            g_FreefallStationaryMs.store(0u, std::memory_order_relaxed);
        }
        return o_SMIHandleUpdateEvent(smi, animFinished);
    }

    uintptr_t ch = smi ? VerifyAlivePlayerFromSMI(smi) : 0;
    if (!ch) {
        return o_SMIHandleUpdateEvent(smi, animFinished);
    }

    void* curState = nullptr;
    if (FastRead<uintptr_t>((uintptr_t)smi + 0x18, *(uintptr_t*)&curState) &&
        curState && StateIsUncontrolledRagdollState(curState)) {
        RecoverFromMidRagdoll(smi, ch);
    }

    DWORD crashMs = g_WingsuitCrashCloseMs.load(std::memory_order_relaxed);
    if (crashMs != 0) {
        DWORD elapsed = GetTickCount() - crashMs;
        if (!IsPlayerWingsuitActive(ch) || elapsed > 400u) {
            g_WingsuitCrashCloseMs.compare_exchange_strong(crashMs, 0u, std::memory_order_relaxed);
        } else if (elapsed >= 35u) {
            uint32_t ffEvt = s_HashACT_FORCE_FREEFALL;
            if (o_SMIHandleEvent && o_SMIHandleEvent(smi, &ffEvt)) {
                g_WingsuitCrashCloseMs.store(0u, std::memory_order_relaxed);
            }
        }
    }

    bool res = o_SMIHandleUpdateEvent(smi, animFinished);
    void* postState = nullptr;
    FastRead<uintptr_t>((uintptr_t)smi + 0x18, *(uintptr_t*)&postState);
    if (res) {
        uintptr_t selfSmi = (uintptr_t)smi;
        g_FreefallRecoverSMI.compare_exchange_strong(selfSmi, (uintptr_t)0, std::memory_order_relaxed);
        if (!postState || !StateIsFreefallState(postState)) {
            if (g_FreefallStationaryMs.load(std::memory_order_relaxed) != 0) {
                g_FreefallStationaryMs.store(0u, std::memory_order_relaxed);
            }
        }
        return true;
    }

    if (postState && StateIsFreefallState(postState)) {
        uintptr_t wantSMI = g_FreefallRecoverSMI.load(std::memory_order_relaxed);
        float vy = 0.0f;
        bool stationaryGrounded = false;
        if (FastRead<float>(ch + 0x29C4, vy) && fabsf(vy) < 1.5f) {
            DWORD stMs = g_FreefallStationaryMs.load(std::memory_order_relaxed);
            DWORD now = GetTickCount() | 1u;
            if (stMs == 0) {
                g_FreefallStationaryMs.store(now, std::memory_order_relaxed);
            } else if ((DWORD)(now - stMs) >= 180u) {
                stationaryGrounded = true;
            }
        } else if (g_FreefallStationaryMs.load(std::memory_order_relaxed) != 0) {
            g_FreefallStationaryMs.store(0u, std::memory_order_relaxed);
        }

        if (wantSMI == (uintptr_t)smi || stationaryGrounded) {
            g_FreefallRecoverSMI.compare_exchange_strong(wantSMI, (uintptr_t)0, std::memory_order_relaxed);
            g_FreefallStationaryMs.store(0u, std::memory_order_relaxed);
            ForceTransitionToInitialState(smi, ch, false);
            return true;
        }
    }
    return false;
}

static void __fastcall hk_DoSyncRagdollState(void* character, float dt) {
    if (!o_DoSyncRagdollState) return;
    if (SuppressRagdoll() && character) {
        uintptr_t ch = VerifyAlivePlayerCharacter(character);
        if (ch) {
            uint32_t paramId = 0xdeadbeefu;
            if (FastRead<uint32_t>(ch + 0x25E8, paramId) &&
                paramId != 0xdeadbeefu && paramId != 0 &&
                !IsControlledRagdollParamId(paramId)) {
                // Rewrite to 0xdeadbeef before calling original so an already-active ragdoll
                // cleanly resets m_Ragdoll & sends MERGED, while a new ragdoll never starts.
                FastWrite<uint32_t>(ch + 0x25E8, 0xdeadbeefu);
                FastWrite<float>(ch + 0x2600, 0.0f);
                FastWrite<uint8_t>(ch + 0x2605, (uint8_t)0);
                g_RagdollSyncBlocks++;
            }
        }
    }
    o_DoSyncRagdollState(character, dt);
}

static bool SanitizeCapsuleCollisionProps(void* ch, const void* props, uint8_t* localProps, size_t copySize, bool clearRestorePrevVel) {
    if (!SuppressRagdoll() || !ch || !props) return false;
    uintptr_t playerCh = VerifyAlivePlayerCharacter(ch);
    if (!playerCh) return false;

    memcpy(localProps, props, copySize);
    uint32_t act = *(uint32_t*)(localProps + 0x00);
    bool wingsuit = IsPlayerWingsuitActive(playerCh);
    if (!IsNonDeathRagdollAct(act) && !(wingsuit && act != 0xdeadbeefu && act != s_HashACT_NONE)) {
        return false;
    }

    g_RagdollLastAct.store(act, std::memory_order_relaxed);
    g_RagdollCollisionBlocks++;
    if (clearRestorePrevVel) {
        localProps[0x30] = 0; // clear m_RestorePreviousVelocity to prevent surface/ground bounce
    }
    if (wingsuit) {
        *(uint32_t*)(localProps + 0x00) = s_HashACT_CLOSE_WINGSUIT;
        g_WingsuitCrashCloseMs.store(GetTickCount(), std::memory_order_relaxed);
    } else {
        *(uint32_t*)(localProps + 0x00) = 0xdeadbeefu;
    }
    return true;
}

static void __cdecl hk_CapsuleHandlingDoTrigger(void* ch, void* props, void* inst, float* prevVel, float* pos, float* normal) {
    if (!o_CapsuleHandlingDoTrigger) return;
    alignas(8) uint8_t localProps[52];
    void* effectiveProps = SanitizeCapsuleCollisionProps(ch, props, localProps, sizeof(localProps), true) ? localProps : props;
    o_CapsuleHandlingDoTrigger(ch, effectiveProps, inst, prevVel, pos, normal);
}

static void __cdecl hk_CapsuleTriggerDoTrigger(void* ch, void* props, void* inst, float* prevVel, float* pos, float* normal) {
    if (!o_CapsuleTriggerDoTrigger) return;
    alignas(8) uint8_t localProps[48];
    void* effectiveProps = SanitizeCapsuleCollisionProps(ch, props, localProps, sizeof(localProps), false) ? localProps : props;
    o_CapsuleTriggerDoTrigger(ch, effectiveProps, inst, prevVel, pos, normal);
}

static void __cdecl hk_NRagdollingOnEnter(void* stateCtx, void* props, void* inst) {
    if (SuppressRagdoll() && stateCtx) {
        uintptr_t userObj = 0;
        if (FastRead<uintptr_t>((uintptr_t)stateCtx + 0x00, userObj) && userObj > 0x10) {
            uintptr_t cached = g_NoRagdollCachedPlayerChar.load(std::memory_order_relaxed);
            if (cached && userObj == cached + 0x10 && VerifyAlivePlayerCharacter((void*)cached)) {
                // Allow displacement-controlled NRagdolling states (e.g. PARACHUTING / AIMING_PARACHUTING).
                uint32_t paramId = 0xdeadbeefu;
                uintptr_t ragPtr = 0;
                FastRead<uint32_t>(cached + 0x25E8, paramId);
                FastRead<uintptr_t>(cached + 0x25F0, ragPtr);
                if (!IsPlayerParachuteActive(cached) &&
                    !IsControlledRagdollParamId(paramId) &&
                    !(ragPtr && IsControlledRagdollInstancePtr(ragPtr))) {
                    g_RagdollOnEnterHits++;
                    if (inst) {
                        FastWrite<uint32_t>((uintptr_t)inst + 0x00, 0);
                        FastWrite<uint8_t>((uintptr_t)inst + 0x08, (uint8_t)0);
                    }
                    return;
                }
            }
        }
    }
    if (o_NRagdollingOnEnter) o_NRagdollingOnEnter(stateCtx, props, inst);
}

static void InstallNoRagdollHooks() {
    if (IdentifyJC4NativeBuild(g_ExeBase) == JC4NativeBuild::Unknown) return;

    InitNoRagdollMetadata();

    {
        static const uint8_t sig[] = {0x4c,0x8b,0x41,0x10,0x4c,0x89,0xc0,0x49,0x8b,0x48,0x08,0x80,0x79,0x19,0x00};
        const auto addr = PlayerFxAddress(0x789D480, 0x42E0B10);
        if (PrologueMatches(addr, sig, sizeof(sig))) fn_RagdollGetParamsByID = (CRagdollDescGetParamsByID_t)addr;
        else LogPrologueBytes("CRagdollDescription::GetParamsByID", addr);
    }

    // ResolveTransform (0x24DEB0)
    {
        static const uint8_t sig[] = { 0x48,0x8B,0xC4,0x55,0x41,0x56,0x41,0x57,0x48,0x8D,0xA8,0x38,0xFF,0xFF,0xFF,0x48 };
        uintptr_t addr = PlayerFxAddress(0x24DEB0, 0x24EA10);
        if (PrologueMatches(addr, sig, sizeof(sig))) fn_CharResolveTransform = (GameObjectResolveTransform_t)addr;
        else LogPrologueBytes("CGameObject::ResolveTransform", addr);
    }

    // SetWorldTransform (0x2506B0)
    {
        static const uint8_t sig[] = { 0x48,0x8B,0xC4,0x57,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0xD0,0x00,0x00,0x00,0x48 };
        uintptr_t addr = PlayerFxAddress(0x2506B0, 0x2513C0);
        if (PrologueMatches(addr, sig, sizeof(sig))) fn_CharSetWorldTransform = (GameObjectSetWorldTransform_t)addr;
        else LogPrologueBytes("CGameObject::SetWorldTransform", addr);
    }

    // CPfxCharacterInstance::SetOrientation, body reached by the native thunk.
    {
        static const uint8_t sig[] = {0x48,0x89,0x5c,0x24,0x10,0x55,0x48,0x8d,0x6c,0x24,0xa9,0x48,0x81,0xec,0xb0,0x00,0x00,0x00};
        uintptr_t addr = PlayerFxAddress(0x769A3E0, 0x401A030);
        if (PrologueMatches(addr, sig, sizeof(sig))) fn_PfxSetOrientation = (PfxCharSetOrientation_t)addr;
        else LogPrologueBytes("CPfxCharacterInstance::SetOrientation", addr);
    }

    int hooked = 0;

    // 1. NAnimationSystem::CTransition::Evaluate (body RVA 0x788EF10)
    {
        static const uint8_t sig[] = { 0x55,0x56,0x41,0x57,0x48,0x83,0xEC,0x20,0x45,0x31,0xFF,0x48,0x89,0x5C,0x24,0x40 };
        static const uint8_t epicSig[] = { 0x40,0x55,0x56,0x41,0x57,0x48,0x83,0xEC,0x20,0x45,0x31,0xFF,0x48,0x89,0x5C,0x24,0x40 };
        void* p = (void*)PlayerFxAddress(0x788EF10, 0x42D0800);
        if ((g_IsSteam ? PrologueMatches((uintptr_t)p, sig, sizeof(sig)) : PrologueMatches((uintptr_t)p, epicSig, sizeof(epicSig))) &&
            MH_CreateHook(p, (void*)&hk_CTransitionEvaluate, (void**)&o_CTransitionEvaluate) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("CTransition::Evaluate", (uintptr_t)p);
        }
    }

    // 2. CStateMachineInstance::HandleEvent (body RVA 0x78A7060)
    {
        static const uint8_t sig[] = { 0x48,0x89,0x5C,0x24,0x10,0x57,0x48,0x83,0xEC,0x40,0x48,0x8B,0x41,0x18,0x48,0x89 };
        void* p = (void*)PlayerFxAddress(0x78A7060, 0x42EC520);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_SMIHandleEvent, (void**)&o_SMIHandleEvent) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("CStateMachineInstance::HandleEvent", (uintptr_t)p);
        }
    }

    // 3. CStateMachineInstance::HandleUpdateEvent (body RVA 0x78A7C90)
    {
        static const uint8_t sig[] = { 0x48,0x89,0x5C,0x24,0x10,0x57,0x48,0x83,0xEC,0x30,0x0F,0xB6,0xFA,0x48,0x89,0xCB };
        void* p = (void*)PlayerFxAddress(0x78A7C90, 0x42ED0B0);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_SMIHandleUpdateEvent, (void**)&o_SMIHandleUpdateEvent) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("CStateMachineInstance::HandleUpdateEvent", (uintptr_t)p);
        }
    }

    // 4. CCharacter::DoSyncRagdollState (body RVA 0x8354F40)
    {
        static const uint8_t sig[] = { 0x49,0x89,0xE3,0x57,0x48,0x81,0xEC,0xF0,0x00,0x00,0x00,0x80,0xB9,0x04,0x26,0x00 };
        void* p = (void*)PlayerFxAddress(0x8354F40, 0x146F1510);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_DoSyncRagdollState, (void**)&o_DoSyncRagdollState) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("CCharacter::DoSyncRagdollState", (uintptr_t)p);
        }
    }

    // 5. NCapsuleCollisionHandlingTask::DoTrigger (body RVA 0x860F2F0)
    {
        static const uint8_t sig[] = { 0x48,0x89,0xE0,0x48,0x89,0x58,0x18,0x48,0x89,0x78,0x20,0x55,0x41,0x55,0x41,0x56 };
        void* p = (void*)PlayerFxAddress(0x860F2F0, 0x149221D0);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_CapsuleHandlingDoTrigger, (void**)&o_CapsuleHandlingDoTrigger) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("NCapsuleCollisionHandlingTask::DoTrigger", (uintptr_t)p);
        }
    }

    // 6. NCapsuleCollisionTrigger::DoTrigger (body RVA 0x860F820)
    {
        static const uint8_t sig[] = { 0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x57,0x48,0x83,0xEC,0x70,0x41 };
        void* p = (void*)PlayerFxAddress(0x860F820, 0x14922980);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_CapsuleTriggerDoTrigger, (void**)&o_CapsuleTriggerDoTrigger) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("NCapsuleCollisionTrigger::DoTrigger", (uintptr_t)p);
        }
    }

    // 7. NRagdolling::OnEnter (body RVA 0x868BE80)
    {
        static const uint8_t sig[] = { 0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57 };
        void* p = (void*)PlayerFxAddress(0x868BE80, 0x149E6D20);
        if (PrologueMatches((uintptr_t)p, sig, sizeof(sig)) &&
            MH_CreateHook(p, (void*)&hk_NRagdollingOnEnter, (void**)&o_NRagdollingOnEnter) == MH_OK) {
            if (MH_EnableHook(p) == MH_OK) ++hooked;
        } else {
            LogPrologueBytes("NRagdolling::OnEnter", (uintptr_t)p);
        }
    }

    const bool ready = hooked == 7 && fn_RagdollGetParamsByID && fn_CharResolveTransform && fn_CharSetWorldTransform &&
        fn_PfxSetOrientation && s_IdxNRagdolling >= 0 && s_IdxNSetRagdoll >= 0 && s_IdxFreefallMove >= 0;
    s_NoRagdollReady.store(ready, std::memory_order_release);
    JC4Terrain16x16::TerrainLog("[PlayerFX] Ragdoll hooks %d/7; tasks %d/%d/%d; %s", hooked,
        s_IdxNRagdolling, s_IdxNSetRagdoll, s_IdxFreefallMove, ready ? "ready" : "inactive");
}

void ToggleVehiclesInvincible(bool enable) {
    // The detour is installed once and stays resident; enabling/disabling is now
    // just a flag the detour reads, so there is no .text to patch or restore.
    if (enable && !s_VehicleDamageHooked) InstallFeatureHooks();
}

void ToggleAllVehiclesNitroJump(bool enable) {
    // Handled safely at runtime in hkPresent via native m_ForceModsOn (+0x13D34).
    // No .text code patches required, preventing any crash upon toggling off.
}

void ToggleInfiniteNitro(bool enable) {
    if (!g_ExeBase) return;
    static bool s_Patched = false;
    if (enable == s_Patched) return;

    // 0x9FEC432: NOP "subss xmm1, xmm0" so m_NitrousBar (+0x13D00) never drains
    uintptr_t addrDrain = g_ExeBase + g_Addr_9FEC432;
    static const uint8_t origDrain[4]  = { 0xF3, 0x0F, 0x5C, 0xC8 }; // subss xmm1, xmm0
    static const uint8_t patchDrain[4] = { 0x90, 0x90, 0x90, 0x90 }; // 4x NOP

    if (enable) {
        SafePatchBytes(addrDrain, patchDrain, 4);
        s_Patched = true;
    } else {
        SafePatchBytes(addrDrain, origDrain, 4);
        s_Patched = false;
    }
}

void ToggleInfiniteTurboJump(bool enable, bool allowAirHop) {
    if (!g_ExeBase) return;
    static bool s_CooldownPatched = false;
    static bool s_AirHopPatched    = false;

    // A. Zero Cooldown Timer write at 0x9FED943 (xor ecx, ecx; 5x NOP)
    uintptr_t addrCooldown = g_ExeBase + g_Addr_9FED943;
    static const uint8_t origCooldown[7]  = { 0x8B, 0x8C, 0x83, 0x14, 0x3D, 0x01, 0x00 };
    static const uint8_t patchCooldown[7] = { 0x31, 0xC9, 0x90, 0x90, 0x90, 0x90, 0x90 };

    if (enable != s_CooldownPatched) {
        if (enable) {
            SafePatchBytes(addrCooldown, patchCooldown, 7);
        } else {
            SafePatchBytes(addrCooldown, origCooldown, 7);
        }
        s_CooldownPatched = enable;
    }

    // B. CVehicle Input Lockout Bypass at 0x9FED7B9 (skips xor dil, dil)
    uintptr_t addrAirLockout = g_ExeBase + g_Addr_9FED7B9;
    static const uint8_t origAirLock[2]  = { 0x75, 0x09 }; // jnz 149fed7c4
    static const uint8_t patchAirLock[2] = { 0xEB, 0x0C }; // jmp short +0x0C to 149fed7c7

    // C. CPfxCar::SetTurboJumpActive Airborne Check at 0x77B4BFB (NOPs JBE to allow flag resets in mid-air)
    uintptr_t addrPfxAirLock = g_ExeBase + g_Addr_77B4BFB;
    static const uint8_t origPfxAir[2]  = { 0x76, 0x10 }; // jbe LAB_1477b4c0d
    static const uint8_t patchPfxAir[2] = { 0x90, 0x90 }; // 2x NOP

    bool shouldAirHop = enable && allowAirHop;
    if (shouldAirHop != s_AirHopPatched) {
        if (shouldAirHop) {
            SafePatchBytes(addrAirLockout, patchAirLock, 2);
            SafePatchBytes(addrPfxAirLock, patchPfxAir, 2);
        } else {
            SafePatchBytes(addrAirLockout, origAirLock, 2);
            SafePatchBytes(addrPfxAirLock, origPfxAir, 2);
        }
        s_AirHopPatched = shouldAirHop;
    }
}

bool g_DebugNoLogin = false;
void ToggleNoLogin(bool enable) {
    if (!g_ExeBase) return;
    static bool isPatched = false;
    if (!enable && !isPatched) return;

    uintptr_t addrFailed = g_ExeBase + g_Addr_E15C10; // CSnakebitePauseUI::OnLoginStateFailed
    uintptr_t addrBoot   = g_ExeBase + g_Addr_86D5B9; // CGameStateFrontend::Update Case 4 (JZ -> JMP)

    static uint8_t origFailed = 0;
    static uint8_t origBoot   = 0;
    static bool hasBackup = false;

    if (!hasBackup) {
        FastRead<uint8_t>(addrFailed, origFailed);
        FastRead<uint8_t>(addrBoot, origBoot);
        hasBackup = true;
    }

    if (enable) {
            // Safety: Only patch if original instruction at addrBoot is a conditional jump (0x74 = JZ)
            if (origBoot != 0x74) {
                std::cout << "[!] DebugNoLogin SKIPPED: addrBoot opcode mismatch (expected 0x74, got 0x" 
                          << std::hex << (int)origBoot << std::dec << ")\n";
                return;
            }
            uint8_t retByte = 0xC3; // ret -> suppresses failure dialog
            uint8_t jmpByte = 0xEB; // jmp -> forces built-in offline boot branch (EBX = 1)
            SafePatchBytes(addrFailed, &retByte, 1);
            SafePatchBytes(addrBoot, &jmpByte, 1);
            isPatched = true;
            std::cout << "[+] Fast No-Login mode applied (Offline boot forced).\n";
        } else {
        if (hasBackup) {
            SafePatchBytes(addrFailed, &origFailed, 1);
            SafePatchBytes(addrBoot, &origBoot, 1);
        }
        isPatched = false;
        std::cout << "[-] Fast No-Login mode restored to default.\n";
    }
}

void ToggleInfWeaponAmmo(bool enable) {
    // Handled dynamically via the hk_SetMagazineAmmo hook using the g_InfWeaponAmmo flag.
}

void UpdateOceanPatches() {
    if (!g_ExeBase) return;

    struct PatchInfo {
        uintptr_t rva;
        std::vector<uint8_t> orig;
        std::vector<uint8_t> patch;
        int category; // 0=Visuals, 1=States, 2=Camera, 3=Physics, 4=Entry
    };

    static const std::vector<PatchInfo> patches = {
        // --- Group A: Water Visual Rendering (Category 0) ---
        { 0x1B3EDE, { 0x49, 0x8B, 0x96, 0xF0, 0x10, 0x00, 0x00 }, { 0xEB, 0xEA, 0x90, 0x90, 0x90, 0x90, 0x90 }, 0 },
        { 0x1B76F0, { 0xE9, 0x6B, 0x24, 0x7C, 0x07 },             { 0xC3, 0x90, 0x90, 0x90, 0x90 }, 0 },
        { 0x20B420, { 0xE9, 0xDB, 0x23, 0x83, 0x07 },             { 0xC3, 0x90, 0x90, 0x90, 0x90 }, 0 },
        { 0x1B7540, { 0xE9, 0x7B, 0x1A, 0x7C, 0x07 },             { 0xC3, 0x90, 0x90, 0x90, 0x90 }, 0 },
        { 0x1B7610, { 0xE9, 0xEB, 0x1E, 0x7C, 0x07 },             { 0xC3, 0x90, 0x90, 0x90, 0x90 }, 0 },
        { 0x1B7710, { 0xE9, 0x9B, 0x25, 0x7C, 0x07 },             { 0xC3, 0x90, 0x90, 0x90, 0x90 }, 0 },
        { 0xD74D60, { 0x48, 0x8B, 0xC4 },                         { 0xC3, 0x90, 0x90 }, 0 },
        { 0xD74960, { 0xE9, 0xAB, 0x0A, 0x7E, 0x09 },             { 0xC3, 0x90, 0x90, 0x90, 0x90 }, 0 },

        // --- Group B: Animations, Oxygen, & Camera (Category 1 & 2) ---
        { 0x531090, { 0xE9, 0xAB, 0xE9, 0xE2, 0x07 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 1 },
        { 0x531160, { 0xE9, 0x3B, 0xED, 0xE2, 0x07 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 1 },
        { 0x536AC0, { 0xE9, 0x3B, 0xD7, 0xE3, 0x07 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 1 },
        { 0x556D10, { 0xE9, 0x4B, 0x73, 0x01, 0x08 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 1 },
        { 0xB1CAF0, { 0xE9, 0x8B, 0xA5, 0xD2, 0x08 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 1 },
        { 0x556FE0, { 0xE9, 0xAB, 0xAA, 0x01, 0x08 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 1 },
        { 0xCE9520, { 0xE9, 0xAB, 0x74, 0x41, 0x09 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 1 },
        { 0x1C01B0, { 0xE9, 0x6B, 0xCF, 0x7C, 0x07 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 1 },
        { 0xC37860, { 0xE9, 0x9B, 0xCB, 0x2F, 0x09 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 1 },
        { 0x4EB7A0, { 0xE9, 0x8B, 0xFD, 0xD8, 0x07 },             { 0xC3, 0x90, 0x90, 0x90, 0x90 }, 2 },
        { 0x4EBD30, { 0xE9, 0x3B, 0xFF, 0xD8, 0x07 },             { 0xC3, 0x90, 0x90, 0x90, 0x90 }, 2 },

        // --- Group C: Vehicle Physics & Seabed Entry (Category 3 & 4) ---
        { 0x11E2C0, { 0xE9, 0xEB, 0x89, 0x6D, 0x07 },             { 0xC3, 0x90, 0x90, 0x90, 0x90 }, 3 },
        { 0x12FDD0, { 0xE9, 0xAB, 0x6B, 0x6F, 0x07 },             { 0xC3, 0x90, 0x90, 0x90, 0x90 }, 3 },
        { 0x1264C0, { 0xE9, 0x1B, 0xA9, 0x6D, 0x07 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 3 },
        { 0x129570, { 0xE9, 0xBB, 0xD6, 0x6D, 0x07 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 3 },
        { 0xC4C2E0, { 0x48, 0x8B, 0xC4 },                         { 0xC3, 0x90, 0x90 }, 3 },
        { 0xC37EE0, { 0xE9, 0x4B, 0x10, 0x30, 0x09 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 3 },
        { 0x1311A0, { 0xE9, 0x0B, 0x81, 0x6F, 0x07 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 3 },
        { 0x141580, { 0xE9, 0xBB, 0xC3, 0x70, 0x07 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 3 },
        { 0xC22480, { 0xE9, 0x8B, 0x12, 0x20, 0x09 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 4 },
        { 0xC347B0, { 0xE9, 0xEB, 0x98, 0x2F, 0x09 },             { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 4 },
        { 0x96BBC0, { 0xE9, 0x3B, 0xC2, 0x9F, 0x08 },             { 0xB0, 0x01, 0xC3, 0x90, 0x90 }, 4 }
    };

    static std::map<uintptr_t, std::vector<uint8_t>> g_OceanRealOrig;
    static std::vector<bool> patchesApplied(patches.size(), false);

    int nChg = 0, nSkip = 0;
    for (size_t i = 0; i < patches.size(); i++) {
        const auto& p = patches[i];
        if (!JRVA_KNOWN(p.rva)) { nSkip++; continue; } // EPIC: unmapped entry -> skip
        bool catEnabled = false;
        switch (p.category) {
            case 0: catEnabled = g_OceanSubVisuals; break;
            case 1: catEnabled = g_OceanSubStates; break;
            case 2: catEnabled = g_OceanSubCamera; break;
            case 3: catEnabled = g_OceanSubPhysics; break;
            case 4: catEnabled = g_OceanSubEntry; break;
        }

        bool shouldApply = g_DisableOcean && catEnabled;
        if (shouldApply != patchesApplied[i]) {
            uintptr_t target = g_ExeBase + JRVA(p.rva);
            if (shouldApply) {
                // capture the real on-disk original bytes (per platform) before patching
                std::vector<uint8_t> realOrig(p.patch.size(), 0);
                ReadProcessMemory(GetCurrentProcess(), (void*)target, realOrig.data(), realOrig.size(), NULL);
                SafePatchBytes(target, p.patch.data(), p.patch.size());
                g_OceanRealOrig[p.rva] = realOrig;
            } else {
                auto it = g_OceanRealOrig.find(p.rva);
                if (it != g_OceanRealOrig.end())
                    SafePatchBytes(target, it->second.data(), it->second.size());
                else
                    SafePatchBytes(target, p.orig.data(), p.orig.size());
            }
            patchesApplied[i] = shouldApply;
            nChg++;
        }
    }
    if (nChg) std::cout << "[Ocean] changed=" << nChg << "  skipped_unmapped=" << nSkip << "/" << patches.size() << "\n" << std::flush;
}

void OnMainOceanToggleChanged() {
    if (g_DisableOcean) {
        g_OceanSubVisuals = true;
        g_OceanSubStates  = true;
        g_OceanSubCamera  = true;
        g_OceanSubPhysics = true;
        g_OceanSubEntry   = true;
        g_DisableRivers   = true;
        ToggleDisableRivers(true);
    } else {
        g_OceanSubVisuals = false;
        g_OceanSubStates  = false;
        g_OceanSubCamera  = false;
        g_OceanSubPhysics = false;
        g_OceanSubEntry   = false;
        g_DisableRivers   = false;
        ToggleDisableRivers(false);
    }
    UpdateOceanPatches();
}

void OnSubOceanToggleChanged() {
    if (g_OceanSubVisuals || g_OceanSubStates || g_OceanSubCamera || g_OceanSubPhysics || g_OceanSubEntry) {
        g_DisableOcean = true;
    } else {
        g_DisableOcean = false;
        // If all sub-toggles are unchecked, automatically turn off the River bypass
        if (g_DisableRivers) {
            g_DisableRivers = false;
            ToggleDisableRivers(false);
        }
    }
    UpdateOceanPatches();
}

// ============================================================================
// THEME
// ============================================================================
void ApplyEnhancedStyle() {
    ImGuiStyle& style = ImGui::GetStyle();
    style = ImGuiStyle(); // Reset to default first to prevent compounding scale multiplier
    ImVec4* colors = style.Colors;

    style.ScaleAllSizes(g_UIScale);
    style.MouseCursorScale = 1.0f;

    style.WindowRounding    = 10.0f * g_UIScale;
    style.FrameRounding     = 5.0f * g_UIScale;
    style.PopupRounding     = 6.0f * g_UIScale;
    style.ScrollbarRounding = 8.0f * g_UIScale;
    style.GrabRounding      = 4.0f * g_UIScale;
    style.TabRounding       = 5.0f * g_UIScale;
    style.WindowBorderSize  = 1.0f;
    style.FrameBorderSize   = 0.0f;

    style.WindowPadding      = ImVec2(18.0f, 18.0f);
    style.FramePadding       = ImVec2(10.0f, 6.0f);
    style.ItemSpacing        = ImVec2(10.0f, 8.0f);
    style.ItemInnerSpacing   = ImVec2(6.0f, 5.0f);
    style.IndentSpacing      = 18.0f;
    style.ScrollbarSize      = 16.0f * g_UIScale;

    colors[ImGuiCol_Text]                 = ImVec4(0.92f, 0.93f, 0.96f, 1.00f);
    colors[ImGuiCol_TextDisabled]         = ImVec4(0.40f, 0.43f, 0.50f, 1.00f);
    colors[ImGuiCol_WindowBg]             = ImVec4(0.06f, 0.07f, 0.09f, 0.97f);
    colors[ImGuiCol_ChildBg]              = ImVec4(0.08f, 0.09f, 0.12f, 1.00f);
    colors[ImGuiCol_PopupBg]              = ImVec4(0.08f, 0.09f, 0.12f, 0.98f);
    colors[ImGuiCol_Border]               = ImVec4(0.20f, 0.22f, 0.28f, 0.60f);
    colors[ImGuiCol_BorderShadow]         = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]              = ImVec4(0.12f, 0.13f, 0.17f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]       = ImVec4(0.18f, 0.20f, 0.27f, 1.00f);
    colors[ImGuiCol_FrameBgActive]        = ImVec4(0.22f, 0.25f, 0.33f, 1.00f);
    colors[ImGuiCol_TitleBg]              = ImVec4(0.05f, 0.06f, 0.08f, 1.00f);
    colors[ImGuiCol_TitleBgActive]        = ImVec4(0.05f, 0.06f, 0.08f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]     = ImVec4(0.05f, 0.06f, 0.08f, 0.75f);
    colors[ImGuiCol_MenuBarBg]            = ImVec4(0.08f, 0.09f, 0.12f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]          = ImVec4(0.04f, 0.05f, 0.07f, 0.60f);
    colors[ImGuiCol_ScrollbarGrab]        = ImVec4(0.20f, 0.22f, 0.30f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.28f, 0.31f, 0.42f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]  = ImVec4(0.36f, 0.40f, 0.55f, 1.00f);
    colors[ImGuiCol_CheckMark]            = ImVec4(0.55f, 0.38f, 0.96f, 1.00f);
    colors[ImGuiCol_SliderGrab]           = ImVec4(0.55f, 0.38f, 0.96f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]     = ImVec4(0.68f, 0.52f, 1.00f, 1.00f);
    colors[ImGuiCol_Button]               = ImVec4(0.14f, 0.15f, 0.20f, 1.00f);
    colors[ImGuiCol_ButtonHovered]        = ImVec4(0.22f, 0.18f, 0.35f, 1.00f);
    colors[ImGuiCol_ButtonActive]         = ImVec4(0.55f, 0.38f, 0.96f, 0.80f);
    colors[ImGuiCol_Header]               = ImVec4(0.14f, 0.15f, 0.20f, 1.00f);
    colors[ImGuiCol_HeaderHovered]        = ImVec4(0.22f, 0.18f, 0.35f, 1.00f);
    colors[ImGuiCol_HeaderActive]         = ImVec4(0.55f, 0.38f, 0.96f, 0.60f);
    colors[ImGuiCol_Separator]            = ImVec4(0.20f, 0.22f, 0.28f, 0.50f);
    colors[ImGuiCol_SeparatorHovered]     = ImVec4(0.55f, 0.38f, 0.96f, 0.60f);
    colors[ImGuiCol_SeparatorActive]      = ImVec4(0.55f, 0.38f, 0.96f, 1.00f);
    colors[ImGuiCol_ResizeGrip]           = ImVec4(0.55f, 0.38f, 0.96f, 0.25f);
    colors[ImGuiCol_ResizeGripHovered]    = ImVec4(0.55f, 0.38f, 0.96f, 0.67f);
    colors[ImGuiCol_ResizeGripActive]     = ImVec4(0.55f, 0.38f, 0.96f, 0.95f);
    colors[ImGuiCol_Tab]                  = ImVec4(0.10f, 0.11f, 0.14f, 1.00f);
    colors[ImGuiCol_TabHovered]           = ImVec4(0.22f, 0.18f, 0.35f, 1.00f);
    colors[ImGuiCol_TabActive]            = ImVec4(0.16f, 0.17f, 0.24f, 1.00f);
}

// ============================================================================
// WINDOW PROC - STRICT INPUT BLOCK
// ============================================================================
LRESULT WINAPI WndProc(const HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
// Instantly terminate the process on any close/end/quit message
    if (uMsg == WM_CLOSE || uMsg == WM_DESTROY || uMsg == WM_QUIT || uMsg == WM_ENDSESSION || uMsg == WM_QUERYENDSESSION) {
        TerminateProcess(GetCurrentProcess(), 0);
        return 0;
    }

    if ((g_ShowMenu || g_ResizeMode != RESIZE_NONE) && g_ImGuiInited) {
        ImGui_ImplWin32_WndProcHandler(hWnd, uMsg, wParam, lParam);

        // --- MOUSE LOCK ---
        // Block all standard mouse events (move, clicks, double-clicks, wheel)
        if (uMsg >= WM_MOUSEFIRST && uMsg <= WM_MOUSELAST) return 0;
        // Block horizontal mouse wheel
        if (uMsg == WM_MOUSEHWHEEL) return 0;
        // Block side mouse buttons (X1/X2)
        if (uMsg >= WM_XBUTTONDOWN && uMsg <= WM_XBUTTONDBLCLK) return 0;
        // Smart filter: block mouse raw input, block keyboard keydowns, but ALLOW keyboard keyups
        if (uMsg == WM_INPUT) {
            UINT dwSize = 0;
            GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize, sizeof(RAWINPUTHEADER));
            if (dwSize > 0 && dwSize <= 256) {
                BYTE lpb[256];
                if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, lpb, &dwSize, sizeof(RAWINPUTHEADER)) == dwSize) {
                    RAWINPUT* raw = reinterpret_cast<RAWINPUT*>(lpb);
                    if (raw->header.dwType == RIM_TYPEMOUSE) {
                        return 0; // Always block mouse to prevent camera movement
                    }
                    if (raw->header.dwType == RIM_TYPEKEYBOARD) {
                        bool isKeyDown = (raw->data.keyboard.Flags & RI_KEY_BREAK) == 0;
                        if (isKeyDown) {
                            return 0; // Block keyboard presses while menu is open
                        }
                        // If it's a key release, fall through to CallWindowProc so the game knows it was released!
                    }
                }
            }
        }

        // --- KEYBOARD LOCK ---
        // Block all key presses (keydown, syskeydown, char).
        // We DO NOT block WM_KEYUP so the game properly receives key releases!
        if (uMsg == WM_KEYDOWN || uMsg == WM_SYSKEYDOWN || uMsg == WM_CHAR) return 0;
    } else if (g_FreeCam && g_FreeCamLockMovement) {
        // Block movement keys from reaching Rico / his vehicle while leaving mouse look & freecam hotkeys intact.
        if (uMsg == WM_INPUT) {
            UINT dwSize = 0;
            GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize, sizeof(RAWINPUTHEADER));
            if (dwSize > 0 && dwSize <= 256) {
                BYTE lpb[256];
                if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, lpb, &dwSize, sizeof(RAWINPUTHEADER)) == dwSize) {
                    RAWINPUT* raw = reinterpret_cast<RAWINPUT*>(lpb);
                    if (raw->header.dwType == RIM_TYPEKEYBOARD) {
                        bool isKeyDown = (raw->data.keyboard.Flags & RI_KEY_BREAK) == 0;
                        int vk = (int)raw->data.keyboard.VKey;
                        if (isKeyDown && IsMovementKey(vk) &&
                            vk != g_ToggleKey && vk != g_FreeCamKey && vk != g_NoclipKey) {
                            return 0;
                        }
                    }
                }
            }
        }
        if (uMsg == WM_KEYDOWN || uMsg == WM_SYSKEYDOWN || uMsg == WM_CHAR) {
            int vk = (int)wParam;
            if (uMsg == WM_CHAR && vk >= 'a' && vk <= 'z') vk -= ('a' - 'A');
            if (IsMovementKey(vk) &&
                vk != g_ToggleKey && vk != g_FreeCamKey && vk != g_NoclipKey) {
                return 0;
            }
        }
    }

    // Safety check: Never call CallWindowProc on NULL or on WndProc itself (prevents user32.dll crash)
    if (g_OriginalWndProc != NULL && g_OriginalWndProc != WndProc) {
        return CallWindowProc(g_OriginalWndProc, hWnd, uMsg, wParam, lParam);
    }
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

// Helper to safely hook WndProc without recursive loops or multi-window corruption
static HWND g_HookedHWnd = NULL;
void HookWndProc(HWND hwnd) {
    if (!hwnd || !IsWindow(hwnd) || hwnd == g_HookedHWnd) return;
    WNDPROC current = (WNDPROC)GetWindowLongPtr(hwnd, GWLP_WNDPROC);
    if (current != WndProc) {
        WNDPROC old = (WNDPROC)SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)WndProc);
        if (old != WndProc && old != NULL) {
            g_OriginalWndProc = old;
            g_HookedHWnd = hwnd;
        }
    }
}

// ============================================================================
// UI HELPERS
// ============================================================================
static void DrawSectionHeader(const char* title) {
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.38f, 0.96f, 1.0f));
    ImGui::TextUnformatted(title);
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
}

static void RenderWingsuitField(const std::string& name, WingsuitField& field, uintptr_t base) {
    ImGui::PushID(name.c_str());
    ImGui::TableNextRow();

    ImGui::TableSetColumnIndex(0);
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(name.c_str());

    ImGui::TableSetColumnIndex(1);
    ImGui::SetNextItemWidth(-1);

    bool changed = false;
    if (field.is_u32) {
        if (field.offset == 0x810) { // DrawDebugLines boolean
            bool bVal = (field.current_u32 != 0);
            changed = ImGui::Checkbox("##v", &bVal);
            if (changed) {
                field.current_u32 = bVal ? 1 : 0;
                FastWrite<uint32_t>(base + field.offset, field.current_u32);
            }
        } else {
            int val = (int)field.current_u32;
            changed = ImGui::InputInt("##v", &val, 0, 0);
            if (changed) { field.current_u32 = (uint32_t)val; FastWrite<uint32_t>(base + field.offset, field.current_u32); }
        }
    } else {
        switch (field.num_values) {
            case 1: changed = ImGui::InputFloat("##v", &field.current[0], 0.0f, 0.0f, "%.3f"); break;
            case 2: changed = ImGui::InputFloat2("##v", field.current, "%.3f"); break;
            case 3: changed = ImGui::InputFloat3("##v", field.current, "%.3f"); break;
            case 5:
                changed = ImGui::InputFloat3("##v", field.current, "%.3f");
                ImGui::Spacing();
                ImGui::SetNextItemWidth(-1);
                changed = ImGui::InputFloat2("##v2", field.current + 3, "%.3f") || changed;
                break;
        }
        if (changed) {
            for (int i = 0; i < field.num_values && i < 5; i++) {
                FastWrite<float>(base + field.offset + (uintptr_t)(i * 4), field.current[i]);
            }
        }
    }

    ImGui::TableSetColumnIndex(2);
    if (ImGui::SmallButton("R")) {
        if (field.is_u32) {
            field.current_u32 = field.default_u32;
            if (field.offset == 0x810) FastWrite<uint8_t>(base + field.offset, (uint8_t)field.default_u32);
            else FastWrite<uint32_t>(base + field.offset, field.current_u32);
        } else {
            for (int i = 0; i < field.num_values && i < 5; i++) {
                field.current[i] = field.defaults[i];
                FastWrite<float>(base + field.offset + (uintptr_t)(i * 4), field.current[i]);
            }
        }
    }
    ImGui::PopID();
}

// ============================================================================
// SPAWN HINTS (copied from SpawnCommand::GetHints)
// ============================================================================
static const char* g_SpawnHints[] = {
    #include <spawn_hints.inc>
};

static std::string g_PendingSpawnVehicle = "";
static DWORD g_PendingSpawnStartTime = 0;
static DWORD g_LastSpawnAttemptTime = 0;
static bool g_SpawnInProgress = false;

void __cdecl SpawnCallback(void* objects, void* userdata) {
    std::cout << "[Spawn] SUCCESS: Vehicle spawned.\n";
    g_SpawnInProgress = false;
}

void __cdecl SpawnFailCallback(int failReason, void* userdata) {
    g_SpawnInProgress = false;
}

// Exact 9 parameters as shown in spawn.h
typedef void(__thiscall* Spawn_t)(uintptr_t thisptr, const char* name, float* transform, 
                                  unsigned int flags, void* callback, void* userdata, 
                                  void* failCallback, int param8, int param9);

void DoSpawnVehicle(const std::string& vehicleName) {
    if (!g_ExeBase || vehicleName.empty()) return;
    if (vehicleName == "rico_debug" || vehicleName == "rico_preview_debug" ||
        vehicleName == "rico_cow_skin" || vehicleName == "rico_cow_skin_debug") return;

    bool is_steam = (GetModuleHandleA("steam_api64.dll") != nullptr);
    
    // 1. Get Spawn System instance
    uintptr_t spawnSystemAddr = g_ExeBase + (g_Addr_2CB1D20);
    uintptr_t spawnSystem = 0;
    if (!FastRead<uintptr_t>(spawnSystemAddr, spawnSystem) || !spawnSystem) return;

    // 2. Get LocalPlayer (CPlayer)
    uintptr_t localPlayer = GetPlayerPtr();
    if (!localPlayer) return;

    // 3. Read aimpos (+0x1E4) directly — exactly like SpawnCommand
    uintptr_t aimControl = 0;
    if (!FastRead<uintptr_t>(localPlayer + 0x1C0, aimControl) || !aimControl) return;

    float ax = 0.0f, ay = 0.0f, az = 0.0f;
    if (!FastRead<float>(aimControl + 0x1E4, ax) ||
        !FastRead<float>(aimControl + 0x1E8, ay) ||
        !FastRead<float>(aimControl + 0x1EC, az)) return;

    // 4. Build Transform Matrix from Player Character
    float transform[16] = {0};
    uintptr_t characterPtr = 0;
    if (!FastRead<uintptr_t>(localPlayer + 0x68, characterPtr) || !characterPtr) return;

    for (int i = 0; i < 16; ++i) {
        FastRead<float>(characterPtr + 0x114 + (uintptr_t)(i * 4), transform[i]);
    }

    transform[12] = ax;
    transform[13] = ay + 1.0f;
    transform[14] = az;

    // 5. Execute Spawn
    char* nameBuf = new char[256];
    memset(nameBuf, 0, 256);
    strcpy(nameBuf, vehicleName.c_str());

    uintptr_t spawnFuncAddr = g_ExeBase + (g_Addr_BADC60);
    Spawn_t SpawnFunc = (Spawn_t)spawnFuncAddr;

    g_SpawnInProgress = true;
    g_PendingSpawnVehicle.clear();
    SpawnFunc(spawnSystem, nameBuf, transform, 0x597C, (void*)&SpawnCallback, nullptr, (void*)&SpawnFailCallback, 0, -1);
    
    delete[] nameBuf;
}

void TrySpawnVehicle(const std::string& vehicleName) {
    if (vehicleName.empty()) return;
    if (g_PendingSpawnVehicle == vehicleName && (GetTickCount() - g_PendingSpawnStartTime < 10000)) {
        return; // Don't reset 10s timer if already retrying this vehicle
    }
    g_PendingSpawnVehicle = vehicleName;
    g_PendingSpawnStartTime = GetTickCount();
    g_LastSpawnAttemptTime = 0;
    g_SpawnInProgress = false;
    std::cout << "[Spawn] Request queued for '" << vehicleName << "' (retrying up to 10s)...\n";
}

static std::string ReadMSVCString(uintptr_t strAddr) {
    if (!strAddr || strAddr < 0x10000 || strAddr > 0x7FFFFFFFFFFF) return "";
    size_t len = 0, cap = 0;
    if (!FastRead<size_t>(strAddr + 0x10, len) || !FastRead<size_t>(strAddr + 0x18, cap)) return "";
    if (len == 0 || len > 512 || cap < len) return "";

    char buf[512] = { 0 };
    if (cap > 15) {
        uintptr_t heapPtr = 0;
        if (!FastRead<uintptr_t>(strAddr, heapPtr) || heapPtr < 0x10000 || heapPtr > 0x7FFFFFFFFFFF) return "";
        size_t readLen = (len < 511) ? len : 511;
        if (ReadProcessMemory(GetCurrentProcess(), (void*)heapPtr, buf, readLen, NULL)) {
            buf[readLen] = '\0';
            return std::string(buf);
        }
    } else {
        size_t readLen = (len < 16) ? len : 15;
        if (ReadProcessMemory(GetCurrentProcess(), (void*)strAddr, buf, readLen, NULL)) {
            buf[readLen] = '\0';
            return std::string(buf);
        }
    }
    return "";
}

void DumpAllResourcePaths() {
    if (!g_ExeBase) return;
    bool is_steam = (GetModuleHandleA("steam_api64.dll") != nullptr);
    uintptr_t spawnSystemAddr = g_ExeBase + (g_Addr_2CB1D20);
    uintptr_t spawnSystem = 0;
    if (!FastRead<uintptr_t>(spawnSystemAddr, spawnSystem) || !spawnSystem) {
        std::cout << "[Dump] CSpawnSystem not ready yet.\n";
        return;
    }

    uint32_t lenBlocks = 0;
    FastRead<uint32_t>(spawnSystem + 0xB0, lenBlocks); // m_TagResourceArrayLen
    uintptr_t resDefs = 0;
    FastRead<uintptr_t>(spawnSystem + 0xC0, resDefs);  // m_ResourceDefs
    if (!resDefs || lenBlocks == 0) {
        std::cout << "[Dump] m_ResourceDefs is empty.\n";
        return;
    }

    size_t totalResources = (size_t)lenBlocks * 64;
    std::cout << "\n======================================================================\n";
    std::cout << "[CSpawnSystem] DUMPING ALL RESOURCE PATHS IN MEMORY (" << totalResources << " max slots)\n";
    std::cout << "======================================================================\n";

    std::vector<std::string> allPaths;
    std::vector<std::string> chaosCandidates;

    for (size_t i = 0; i < totalResources; i++) {
        uintptr_t resAddr = resDefs + (i * 0x188);

        // m_ResourcePath.m_Str.storage
        uintptr_t storagePtr = 0;
        if (!FastRead<uintptr_t>(resAddr, storagePtr) || !storagePtr) continue;

        // Try reading std::string directly or inside storage wrapper (+0x08, +0x00)
        std::string path = ReadMSVCString(storagePtr + 0x08);
        if (path.empty()) path = ReadMSVCString(storagePtr);

        if (!path.empty()) {
            allPaths.push_back(path);

            // Filter for chaos/prop/destruction candidates
            std::string lower = path;
            std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return (char)std::tolower(c); });

            if (lower.find("sphere") != std::string::npos ||
                lower.find("tank") != std::string::npos ||
                lower.find("generator") != std::string::npos ||
                lower.find("transformer") != std::string::npos ||
                lower.find("radar") != std::string::npos ||
                lower.find("antenna") != std::string::npos ||
                lower.find("destruct") != std::string::npos ||
                lower.find("chaos") != std::string::npos ||
                lower.find("prop") != std::string::npos) {
                chaosCandidates.push_back(path);
            }
        }
    }

    for (size_t i = 0; i < allPaths.size(); i++) {
        std::cout << "[" << i << "] " << allPaths[i] << "\n";
    }

    std::cout << "\n----------------------------------------------------------------------\n";
    std::cout << "[CSpawnSystem] HIGHLIGHTED CHAOS / PROP CANDIDATES (" << chaosCandidates.size() << " found):\n";
    std::cout << "----------------------------------------------------------------------\n";
    for (const auto& s : chaosCandidates) {
        std::cout << "  -> " << s << "\n";
    }
    std::cout << "======================================================================\n\n";
}


void DoSpawnChaosAtCrosshair(const std::string& chaosTag) {
    if (!g_ExeBase || chaosTag.empty()) return;

    bool is_steam = (GetModuleHandleA("steam_api64.dll") != nullptr);
    uintptr_t spawnSystemAddr = g_ExeBase + (g_Addr_2CB1D20);
    uintptr_t spawnSystem = 0;
    if (!FastRead<uintptr_t>(spawnSystemAddr, spawnSystem) || !spawnSystem) return;

    uintptr_t playerManagerAddr = g_ExeBase + (g_Addr_2CB2388);
    uintptr_t playerManager = 0;
    if (!FastRead<uintptr_t>(playerManagerAddr, playerManager) || !playerManager) return;

    uintptr_t localPlayer = 0;
    if (!FastRead<uintptr_t>(playerManager + 0x30, localPlayer) || !localPlayer) return;

    uintptr_t characterPtr = 0;
    if (!FastRead<uintptr_t>(localPlayer + 0x68, characterPtr) || !characterPtr) return;

    // 1. Build initial orientation matrix from player character
    float transform[16] = { 0 };
    for (int i = 0; i < 16; ++i) {
        FastRead<float>(characterPtr + 0x114 + (uintptr_t)(i * 4), transform[i]);
    }

    // 2. Set spawn transform directly to aimpos — matches SpawnCommand exactly
    float ax = 0.0f, ay = 0.0f, az = 0.0f;
    if (GetCrosshairAimPosition(ax, ay, az)) {
        transform[12] = ax;
        transform[13] = ay + 0.25f;
        transform[14] = az;
    } else {
        transform[12] += transform[8] * 8.0f;
        transform[13] += 1.0f;
        transform[14] += transform[10] * 8.0f;
    }

    // 3. Allocate buffer and execute spawn request
    char* nameBuf = new char[256];
    memset(nameBuf, 0, 256);
    strcpy(nameBuf, chaosTag.c_str());

    uintptr_t spawnFuncAddr = g_ExeBase + (g_Addr_BADC60);
    Spawn_t SpawnFunc = (Spawn_t)spawnFuncAddr;

    g_SpawnInProgress = true;
    SpawnFunc(spawnSystem, nameBuf, transform, 0x597C, (void*)&SpawnCallback, nullptr, (void*)&SpawnFailCallback, 0, -1);

    delete[] nameBuf;
}

// ============================================================================
// DEDICATED HEAT SYSTEM TAB (Complete AI Blackboard Control)
// ============================================================================
static uint32_t GetEngineClockTime() {
    if (!g_ExeBase) return 0;
    uintptr_t timeMgr = 0;
    if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2C846B0, timeMgr) && timeMgr) {
        uint32_t ms = 0;
        if (FastRead<uint32_t>(timeMgr + 0x60, ms)) return ms; // m_SumUnpausedTimeMillis
    }
    return 0;
}

// Bypass toggles for Heat_DetermineSpawnSet
bool g_HeatBypassCaps = false;
bool g_HeatBypassCooldowns = false;
bool g_HeatBypassQuotas = false;

static uintptr_t s_HeatSetHookCave = 0;

void ApplyHeatDetermineSpawnPatches() {
    if (!g_ExeBase) return;
    static const uint8_t origCap[6]    = { 0x0F, 0x83, 0x13, 0x01, 0x00, 0x00 }; // JNC
    static const uint8_t origCd[6]     = { 0x0F, 0x87, 0x0A, 0x01, 0x00, 0x00 }; // JA
    static const uint8_t origQuota[2]  = { 0x74, 0x78 };                         // JZ
    static const uint8_t nop6[6]       = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    static const uint8_t nop2[2]       = { 0x90, 0x90 };
    static const uint8_t nop12[12]     = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

    SafePatchBytes(g_ExeBase + g_Addr_4235BC, g_HeatBypassCaps ? nop6 : origCap, 6);
    SafePatchBytes(g_ExeBase + g_Addr_4235C5, g_HeatBypassCooldowns ? nop6 : origCd, 6);
    SafePatchBytes(g_ExeBase + g_Addr_423655, g_HeatBypassQuotas ? nop2 : origQuota, 2);
    SafePatchBytes(g_ExeBase + g_Addr_406CC9, nop12, 12);

    // Hook Heat_ActivateSet at RVA 0x422F0A to preserve custom squad caps and weights
    if (!s_HeatSetHookCave) {
        uintptr_t hookAddr = g_ExeBase + g_Addr_422F0A;
        uintptr_t retAddr  = g_ExeBase + g_Addr_422F12; // 8 bytes overwritten
        s_HeatSetHookCave  = AllocateNear(hookAddr, 64);
        if (s_HeatSetHookCave) {
            std::vector<uint8_t> c;
            // cmp dword ptr [rbx+0x1C], 0; jnz skip_cap; mov [rbx+0x1C], r12d
            c.insert(c.end(), { 0x83, 0x7B, 0x1C, 0x00, 0x75, 0x04, 0x44, 0x89, 0x63, 0x1C });
            // cmp dword ptr [rbx+0x24], 0; jnz skip_weight; mov [rbx+0x24], r15d
            c.insert(c.end(), { 0x83, 0x7B, 0x24, 0x00, 0x75, 0x04, 0x44, 0x89, 0x7B, 0x24 });
            // jmp rel32 to retAddr
            int32_t relBack = (int32_t)((int64_t)retAddr - (int64_t)(s_HeatSetHookCave + c.size() + 5));
            c.push_back(0xE9);
            uint8_t* pRel = (uint8_t*)&relBack;
            c.insert(c.end(), pRel, pRel + 4);

            SafePatchBytes(s_HeatSetHookCave, c.data(), c.size());

            // Write 5-byte JMP rel32 + 3 NOPs over the original 8 bytes
            int32_t relHook = (int32_t)((int64_t)s_HeatSetHookCave - (int64_t)(hookAddr + 5));
            uint8_t patch[8] = { 0xE9, 0, 0, 0, 0, 0x90, 0x90, 0x90 };
            memcpy(&patch[1], &relHook, 4);
            SafePatchBytes(hookAddr, patch, 8);
        }
    }
}

static void Heat_ForceCombatSync(uintptr_t heatMgr) {
    if (!heatMgr || !g_ExeBase) return;

    uintptr_t player = GetPlayerPtr();
    if (!player) return;
    uintptr_t character = 0;
    if (!FastRead<uintptr_t>(player + 0x68, character) || !character) return;

    float pos[3] = { 0 };
    FastRead<float>(character + 0x144, pos[0]);
    FastRead<float>(character + 0x148, pos[1]);
    FastRead<float>(character + 0x14C, pos[2]);

    // 1. Enable Chase Mode (m_bChaseMode)
    FastWrite<uint8_t>(heatMgr + 0xE5, 1);

    // 2. Set Heat Zone Origin (+0x0C) and Radius (+0x18)
    FastWrite<float>(heatMgr + 0x0C, pos[0]);
    FastWrite<float>(heatMgr + 0x10, pos[1]);
    FastWrite<float>(heatMgr + 0x14, pos[2]);
    FastWrite<float>(heatMgr + 0x18, 1200.0f); // 1200m active engagement radius

    // 3. Set Spawner Target Coordinates (+0xA0, +0xA4, +0xA8)
    FastWrite<float>(heatMgr + 0xA0, pos[0]);
    FastWrite<float>(heatMgr + 0xA4, pos[1]);
    FastWrite<float>(heatMgr + 0xA8, pos[2]);

    // 4. Set Spawner Target Direction Vector (+0xAC, +0xB0, +0xB4) from Camera
    uintptr_t cameraManager = 0;
    if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D90, cameraManager) && cameraManager) {
        float fx = 0.0f, fy = 0.0f, fz = 0.0f;
        FastRead<float>(cameraManager + 0x520, fx);
        FastRead<float>(cameraManager + 0x524, fy);
        FastRead<float>(cameraManager + 0x528, fz);
        FastWrite<float>(heatMgr + 0xAC, -fx);
        FastWrite<float>(heatMgr + 0xB0, -fy);
        FastWrite<float>(heatMgr + 0xB4, -fz);
    }

    // 5. Bypass Perception Gate & Clear Suppression Kill-Switch (+0x1F4)
    FastWrite<float>(heatMgr + 0x20, 25.0f); // Nearest enemy distance (< 100m detection range)
    FastWrite<uint8_t>(heatMgr + 0x1E, 1);  // m_bDamagedByPlayer
    FastWrite<uint8_t>(heatMgr + 0x478, 1); // m_bSystemActive
    FastWrite<uint8_t>(heatMgr + 0x1F4, 0); // Clear global suppression flag (1480e8f73)
    FastWrite<uint8_t>(heatMgr + 0xE4, 0);  // Clear wave spawner lock

    // 6. Populate m_ActiveSets (+0x68) directly from registered templates (+0x80)
    uintptr_t setsBegin = 0, setsEnd = 0;
    FastRead<uintptr_t>(heatMgr + 0x68, setsBegin);
    FastRead<uintptr_t>(heatMgr + 0x70, setsEnd);

    if (o_Heat_ActivateSet && (!setsBegin || setsEnd <= setsBegin)) {
        uintptr_t dataBegin = 0, dataEnd = 0;
        if (FastRead<uintptr_t>(heatMgr + 0x80, dataBegin) && FastRead<uintptr_t>(heatMgr + 0x88, dataEnd) && dataBegin && dataEnd > dataBegin) {
            size_t count = (dataEnd - dataBegin) / 8;
            bool activatedLand = false, activatedAir = false;

            for (size_t i = 0; i < count && i < 32; i++) {
                uintptr_t pData = 0;
                if (!FastRead<uintptr_t>(dataBegin + (i * 8), pData) || !pData) continue;

                int role = 0;
                FastRead<int>(pData + 0x1D4, role);

                if (role == 0 && !activatedLand) {
                    o_Heat_ActivateSet(heatMgr, pData, 6, 10, 0, false, 0); // Land Patrol squad
                    activatedLand = true;
                } else if (role == 1 && !activatedAir) {
                    o_Heat_ActivateSet(heatMgr, pData, 4, 10, 0, false, 0); // Helicopter squad
                    activatedAir = true;
                } else if (role == 3) {
                    o_Heat_ActivateSet(heatMgr, pData, 4, 10, 0, false, 0); // Base Defense / Armored squad
                }
            }
        }
    }
}

void DrawHeatTab() {
    if (!g_ExeBase) return;

    uintptr_t heatMgr = 0;
    if (!FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D38, heatMgr) || !heatMgr) {
        ImGui::TextColored(ImVec4(0.9f, 0.5f, 0.3f, 1.0f), "[!] Heat system is unavailable (In Menu / Loading).");
        return;
    }

    uint32_t clockTime = GetEngineClockTime();

    // ------------------------------------------------------------------------
    // SECTION 1: HEAT LEVEL & CONTROLS
    // ------------------------------------------------------------------------
    DrawSectionHeader("HEAT LEVEL & CONTROLS");

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.35f, 1.0f));
    ImGui::TextWrapped("Note: You must be in an active heat chase with enemies for changing heat levels, points, and alert states to take full effect. Artificial chases (giving you heat level 5 + points) will not always work as intended.");
    ImGui::PopStyleColor();
    ImGui::Spacing();

    uint32_t heatLevel = 0;
    int32_t heatStatus = 0;
    uint32_t threatScore = 0;
    uint32_t timeStamp = 0;
    FastRead<uint32_t>(heatMgr + 0x04, heatLevel);
    FastRead<int32_t>(heatMgr + 0x00, heatStatus);
    FastRead<uint32_t>(heatMgr + 0x28, threatScore);
    FastRead<uint32_t>(heatMgr + 0x08, timeStamp);

    float timeAtLvl = (clockTime >= timeStamp && timeStamp > 0) ? (float)(clockTime - timeStamp) / 1000.0f : 0.0f;

    // Keep spawner target coords and chase mode synced while at Level >= 1 and Hot
    if (heatLevel >= 1 && heatStatus == 8) {
        Heat_ForceCombatSync(heatMgr);
    }

    ImGui::Text("Current Heat Level: ");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Level %u", heatLevel);
    ImGui::SameLine();
    ImGui::TextDisabled("(Active for %.1fs)", timeAtLvl);

    // Set Level Quick Buttons
    ImGui::Text("Set Heat Level:");
    for (uint32_t lvl = 0; lvl <= 5; lvl++) {
        char bName[32];
        snprintf(bName, sizeof(bName), (lvl == 0) ? "Calm (0)##Lvl0" : (lvl == 5) ? "MAX (5)##Lvl5" : "Level %u##Lvl%u", lvl, lvl);
        if (lvl > 0) ImGui::SameLine();
        if (ImGui::Button(bName)) {
            if (o_Heat_SetLevel) o_Heat_SetLevel(heatMgr, lvl);
            else {
                FastWrite<uint32_t>(heatMgr + 0x04, lvl);
                FastWrite<uint32_t>(heatMgr + 0x08, clockTime);
            }
            if (lvl > 0) {
                if (o_Heat_SetStatus) o_Heat_SetStatus(heatMgr, 8);
                else FastWrite<int32_t>(heatMgr + 0x00, 8);
                FastWrite<uint32_t>(heatMgr + 0x28, 1000);
                Heat_ForceCombatSync(heatMgr);
            }
        }
    }

    ImGui::Spacing();

    // Threat Score (Points) Input & Buttons
    int ptsInput = (int)threatScore;
    ImGui::AlignTextToFramePadding();
    ImGui::Text("Threat Points:");
    ImGui::SameLine(200.0f * g_UIScale);
    ImGui::SetNextItemWidth(140.0f * g_UIScale);
    if (ImGui::InputInt("##ThreatPtsInput", &ptsInput, 50, 200)) {
        if (ptsInput < 0) ptsInput = 0;
        FastWrite<uint32_t>(heatMgr + 0x28, (uint32_t)ptsInput);
    }
    ImGui::SameLine();
    if (ImGui::Button("+100##Pts")) {
        if (o_Heat_AddHeatPoints) o_Heat_AddHeatPoints(heatMgr, 100, 0, 0);
        else FastWrite<uint32_t>(heatMgr + 0x28, threatScore + 100);
    }
    ImGui::SameLine();
    if (ImGui::Button("+500##Pts")) {
        if (o_Heat_AddHeatPoints) o_Heat_AddHeatPoints(heatMgr, 500, 0, 0);
        else FastWrite<uint32_t>(heatMgr + 0x28, threatScore + 500);
    }
    ImGui::SameLine();
    if (ImGui::Button("Zero##Pts")) {
        FastWrite<uint32_t>(heatMgr + 0x28, 0);
    }

    ImGui::Spacing();

    // Heat Status Selector
    const char* statusNames[] = { "Inactive / Escaped", "Evading", "Spotted", "Hot (In Combat)" };
    const int statusVals[] = { 1, 2, 4, 8 };
    int curStatusIdx = 0;
    for (int s = 0; s < 4; s++) {
        if (heatStatus == statusVals[s]) curStatusIdx = s;
    }

    ImGui::AlignTextToFramePadding();
    ImGui::Text("Alert State:");
    ImGui::SameLine(200.0f * g_UIScale);
    ImGui::SetNextItemWidth(200.0f * g_UIScale);
    if (ImGui::Combo("##StatusCombo", &curStatusIdx, statusNames, 4)) {
        if (o_Heat_SetStatus) o_Heat_SetStatus(heatMgr, statusVals[curStatusIdx]);
        else FastWrite<int32_t>(heatMgr + 0x00, statusVals[curStatusIdx]);
        if (statusVals[curStatusIdx] == 8) {
            Heat_ForceCombatSync(heatMgr);
        }
    }

    ImGui::Spacing();

    // Master Reset & Clear Buttons
    if (ImGui::Button("Reset Heat (Cool Down)", ImVec2(240.0f * g_UIScale, 0))) {
        if (o_Heat_Reset) o_Heat_Reset(heatMgr);
        FastWrite<uint32_t>(heatMgr + 0x04, 0);
        FastWrite<uint32_t>(heatMgr + 0x28, 0);
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear Active Reinforcements", ImVec2(240.0f * g_UIScale, 0))) {
        if (o_Heat_ClearAllSets) o_Heat_ClearAllSets(heatMgr, true, true, true, true);
    }

    // ------------------------------------------------------------------------
    // SECTION 2: REINFORCEMENT SQUADS
    // ------------------------------------------------------------------------
    DrawSectionHeader("REINFORCEMENT SQUADS");

    // Assembly Patch Toggles
    bool patchChanged = false;
    if (ImGui::Checkbox("Bypass Squad Unit Caps", &g_HeatBypassCaps)) patchChanged = true;
    ImGui::SameLine();
    ImGui::TextDisabled("[?]");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Allows reinforcement squads to exceed standard unit limits and spawn continuously.");

    ImGui::SameLine(260.0f * g_UIScale);
    if (ImGui::Checkbox("Instant Spawn Cooldowns", &g_HeatBypassCooldowns)) patchChanged = true;
    ImGui::SameLine();
    ImGui::TextDisabled("[?]");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Removes wave timers so enemy reinforcements arrive immediately.");

    if (ImGui::Checkbox("Bypass Vehicle Category Quotas", &g_HeatBypassQuotas)) patchChanged = true;
    ImGui::SameLine();
    ImGui::TextDisabled("[?]");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Prevents reinforcement spawns from being throttled by vehicle quota checks.");

    if (patchChanged) {
        ApplyHeatDetermineSpawnPatches();
        WriteConfig();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    uintptr_t setsBegin = 0, setsEnd = 0;
    FastRead<uintptr_t>(heatMgr + 0x68, setsBegin);
    FastRead<uintptr_t>(heatMgr + 0x70, setsEnd);

    size_t activeCount = (setsBegin && setsEnd >= setsBegin) ? ((setsEnd - setsBegin) / 8) : 0;

    if (activeCount > 0) {
        ImGui::Text("Active Reinforcement Squads: %zu", activeCount);
        ImGui::SameLine();
        if (ImGui::SmallButton("Ready All Cooldowns")) {
            for (size_t s = 0; s < activeCount && s < 32; s++) {
                uintptr_t pSet = 0;
                if (FastRead<uintptr_t>(setsBegin + (s * 8), pSet) && pSet) {
                    FastWrite<uint32_t>(pSet + 0x20, clockTime);
                }
            }
        }

        ImGui::Spacing();

        if (ImGui::BeginTable("##HeatSetsTuningTable", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit)) {
            ImGui::TableSetupColumn("Squad Role", ImGuiTableColumnFlags_WidthFixed, 140.0f * g_UIScale);
            ImGui::TableSetupColumn("Active", ImGuiTableColumnFlags_WidthFixed, 65.0f * g_UIScale);
            ImGui::TableSetupColumn("Cooldown Status", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (size_t i = 0; i < activeCount && i < 20; i++) {
                uintptr_t pSet = 0;
                if (!FastRead<uintptr_t>(setsBegin + (i * 8), pSet) || !pSet) continue;

                uintptr_t pData = 0;
                uint32_t minUnits = 0, weight = 0, cooldownTick = 0, activeUnits = 0;
                FastRead<uintptr_t>(pSet + 0x00, pData);
                FastRead<uint32_t>(pSet + 0x1C, minUnits);
                FastRead<uint32_t>(pSet + 0x20, cooldownTick);
                FastRead<uint32_t>(pSet + 0x24, weight);
                FastRead<uint32_t>(pSet + 0x44, activeUnits);

                int roleId = 0;
                if (pData) {
                    FastRead<int>(pData + 0x1D4, roleId);
                }

                ImGui::TableNextRow();
                ImGui::PushID((int)i);

                // Role Name
                ImGui::TableSetColumnIndex(0);
                ImGui::AlignTextToFramePadding();
                const char* roleName = "Combat Squad";
                switch (roleId) {
                    case 0: roleName = "Land Patrol"; break;
                    case 1: roleName = "Air Support"; break;
                    case 2: roleName = "Naval Patrol"; break;
                    case 3: roleName = "Base Defense"; break;
                }
                ImGui::TextUnformatted(roleName);

                // Active Count
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%u", activeUnits);

                // Cooldown Status
                ImGui::TableSetColumnIndex(2);
                if (g_HeatBypassCooldowns) {
                    ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "INSTANT");
                } else {
                    float cdRemaining = (cooldownTick > clockTime) ? (float)(cooldownTick - clockTime) / 1000.0f : 0.0f;
                    if (cdRemaining > 0.0f) {
                        ImGui::Text("%.1fs", cdRemaining);
                        ImGui::SameLine();
                        if (ImGui::SmallButton("Ready##CdBtn")) {
                            FastWrite<uint32_t>(pSet + 0x20, clockTime);
                        }
                    } else {
                        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "READY");
                    }
                }

                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    } else {
        ImGui::TextDisabled("  (No reinforcement squads currently active)");
    }

    // ------------------------------------------------------------------------
    // SECTION 3: COMBAT AI TARGETING & SHOOTING LIMITS
    // ------------------------------------------------------------------------
    DrawSectionHeader("COMBAT AI TARGETING & SHOOTING LIMITS");

    int liveMaxHeat = 15;
    int liveMaxVis = 500;
    if (g_ExeBase) {
        FastRead<int>(g_ExeBase + g_Addr_2AEAD0C, liveMaxHeat);
        FastRead<int>(g_ExeBase + g_Addr_2AEAD10, liveMaxVis);
    }

    int displayMaxHeat = (g_CustomMaxHeatEntities > 0) ? g_CustomMaxHeatEntities : liveMaxHeat;
    int displayMaxVis  = (g_CustomMaxVisibilityDist > 0) ? g_CustomMaxVisibilityDist : liveMaxVis;

    ImGui::AlignTextToFramePadding();
    ImGui::Text("Max Simultaneous Shooters:");
    ImGui::SameLine();
    ImGui::TextDisabled("[?]");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Limits how many enemies can actively aim and fire at Rico at the same time (Attack Tokens). Excess enemies will seek cover.");
    ImGui::SameLine(260.0f * g_UIScale);
    ImGui::SetNextItemWidth(120.0f * g_UIScale);
    if (ImGui::InputInt("##MaxHeatEntities", &displayMaxHeat, 2, 8)) {
        if (displayMaxHeat < 1) displayMaxHeat = 1;
        g_CustomMaxHeatEntities = displayMaxHeat;
        if (g_ExeBase) FastWrite<int>(g_ExeBase + g_Addr_2AEAD0C, g_CustomMaxHeatEntities);
        WriteConfig();
    }

    ImGui::AlignTextToFramePadding();
    ImGui::Text("Max AI Firing Range:");
    ImGui::SameLine();
    ImGui::TextDisabled("[?]");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("The maximum distance from Rico at which enemies will open fire with weapons.");
    ImGui::SameLine(260.0f * g_UIScale);
    ImGui::SetNextItemWidth(120.0f * g_UIScale);
    if (ImGui::InputInt("##MaxVisDist", &displayMaxVis, 50, 200)) {
        if (displayMaxVis < 1) displayMaxVis = 1;
        g_CustomMaxVisibilityDist = displayMaxVis;
        if (g_ExeBase) FastWrite<int>(g_ExeBase + g_Addr_2AEAD10, g_CustomMaxVisibilityDist);
        WriteConfig();
    }

    // ------------------------------------------------------------------------
    // SECTION 4: REINFORCEMENT DISTANCES
    // ------------------------------------------------------------------------
    DrawSectionHeader("REINFORCEMENT SPAWN DISTANCES");

    static int s_SelectedRangeDomain = 0;
    const char* domainNames[] = { "Land Vehicles", "Aircraft", "Sea Vessels", "Infantry Soldiers" };

    ImGui::SetNextItemWidth(260.0f * g_UIScale);
    ImGui::Combo("Category", &s_SelectedRangeDomain, domainNames, 4);

    ImGui::SameLine();
    if (ImGui::SmallButton("Reset Category and INI values")) {
        uintptr_t curBase = heatMgr ? (heatMgr + g_HeatDomainOffsets[s_SelectedRangeDomain]) : 0;
        for (int i = 0; i < 8; i++) {
            g_HeatDistHasCustom[s_SelectedRangeDomain][i] = false;
            // Restore pristine default read off the game before our mod overwrote it
            if (curBase && g_HeatDistCaptured) {
                FastWrite<float>(curBase + (i * 4), g_DefHeatDistances[s_SelectedRangeDomain][i]);
                g_HeatDistances[s_SelectedRangeDomain][i] = g_DefHeatDistances[s_SelectedRangeDomain][i];
            }
        }
        if (heatMgr) FastWrite<uint8_t>(heatMgr + 0xEA, 1);
        WriteConfig(); // Empties all 8 keys in the INI (e.g. Land_PursuitSpawnMin=)
    }

    ImGui::Spacing();

    const char* rowTooltips[8] = {
        "Closest distance enemies can spawn around the player.",
        "Farthest distance pursuit enemies will spawn.",
        "Distance where pursuit units despawn to recycle slots.",
        "Hard cutoff boundary where pursuit units are removed.",
        "Closest distance ambush / roadblock units spawn.",
        "Farthest distance roadblock units spawn.",
        "Radius checked to ensure area is not overcrowded.",
        "Despawn cutoff distance for stationary ambush units."
    };

    const char* rowLabels[8] = {
        "Pursuit Spawn Min",
        "Pursuit Spawn Max",
        "Pursuit Recycle Dist",
        "Pursuit Despawn Dist",
        "Roadblock Spawn Min",
        "Roadblock Spawn Max",
        "Block Density Range",
        "Block Despawn Dist"
    };

    uintptr_t curRangeAddr = heatMgr ? (heatMgr + g_HeatDomainOffsets[s_SelectedRangeDomain]) : 0;

    for (int i = 0; i < 8; i++) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(rowLabels[i]);
        ImGui::SameLine();
        ImGui::TextDisabled("[?]");
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", rowTooltips[i]);

        ImGui::SameLine(260.0f * g_UIScale);
        ImGui::SetNextItemWidth(140.0f * g_UIScale);

        char idBuf[64];
        snprintf(idBuf, sizeof(idBuf), "##RangeInput_%s_%d", g_HeatDomainPrefixes[s_SelectedRangeDomain], i);

        // If the user set a custom value in the INI, display that.
        // Otherwise, read live directly from game memory without touching it.
        float displayVal = 0.0f;
        if (g_HeatDistHasCustom[s_SelectedRangeDomain][i]) {
            displayVal = g_HeatDistances[s_SelectedRangeDomain][i];
        } else if (curRangeAddr) {
            FastRead<float>(curRangeAddr + (i * 4), displayVal);
            // Snapshot pristine unoverwritten game value if not captured yet
            if (!g_HeatDistCaptured) {
                g_DefHeatDistances[s_SelectedRangeDomain][i] = displayVal;
            }
        }

        float inputVal = displayVal;
        if (ImGui::InputFloat(idBuf, &inputVal, 10.0f, 50.0f, "%.0fm")) {
            g_HeatDistances[s_SelectedRangeDomain][i] = inputVal;
            g_HeatDistHasCustom[s_SelectedRangeDomain][i] = true;
            if (curRangeAddr) {
                FastWrite<float>(curRangeAddr + (i * 4), inputVal);
                FastWrite<uint8_t>(heatMgr + 0xEA, 1);
            }
            WriteConfig();
        }

        ImGui::SameLine();
        if (g_HeatDistHasCustom[s_SelectedRangeDomain][i]) {
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "[Custom]");
        } else {
            ImGui::TextDisabled("[Native]");
        }
    }

    // ------------------------------------------------------------------------
    // SECTION 5: DETECTION & PERCEPTION
    // ------------------------------------------------------------------------
    DrawSectionHeader("DETECTION & PERCEPTION");

    if (ImGui::Checkbox("Enable Heat & Reinforcements", &g_HeatSystemActive)) {
        if (heatMgr) FastWrite<uint8_t>(heatMgr + 0x478, g_HeatSystemActive ? 1 : 0);
        WriteConfig();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("[?]");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("When disabled, completely suspends heat accumulation and reinforcements.");

    ImGui::Spacing();

    float detectRange = 100.0f;
    FastRead<float>(heatMgr + 0x3E8, detectRange);
    if (g_CustomDetectionRange > 0.0f) detectRange = g_CustomDetectionRange;

    ImGui::AlignTextToFramePadding();
    ImGui::Text("Hostile Detection Range:");
    ImGui::SameLine(240.0f * g_UIScale);
    ImGui::SetNextItemWidth(160.0f * g_UIScale);
    if (ImGui::SliderFloat("##DetectRange", &detectRange, 10.0f, 500.0f, "%.0fm")) {
        g_CustomDetectionRange = detectRange;
        FastWrite<float>(heatMgr + 0x3E8, detectRange);
        WriteConfig();
    }

    float visionThresh = 0.5f;
    FastRead<float>(heatMgr + 0x3E4, visionThresh);
    if (g_CustomVisionThreshold > 0.0f) visionThresh = g_CustomVisionThreshold;

    ImGui::AlignTextToFramePadding();
    ImGui::Text("Awareness Threshold:");
    ImGui::SameLine(240.0f * g_UIScale);
    ImGui::SetNextItemWidth(160.0f * g_UIScale);
    if (ImGui::SliderFloat("##VisionThresh", &visionThresh, 0.01f, 2.0f, "%.2f")) {
        g_CustomVisionThreshold = visionThresh;
        FastWrite<float>(heatMgr + 0x3E4, visionThresh);
        WriteConfig();
    }
        }

// ============================================================================
// DYNAMIC MISSION & OPERATION CONTROLLER (ZERO HARDCODING)
// ============================================================================
typedef const char* (__fastcall* GetLocalizedStringRaw_t)(uintptr_t locMgr, uint32_t hash);
typedef void (__fastcall* ResetObjectiveRoots_t)(uintptr_t mission);
typedef void (__fastcall* SetMissionStatusInternal_t)(uintptr_t mission, int32_t status);
typedef void (__fastcall* DoActivate_t)(uintptr_t mission);
typedef uint8_t (__fastcall* ResetToCheckpoint_t)(uintptr_t obj1, uintptr_t obj2, uint64_t p3, uintptr_t p4);
typedef void (__fastcall* MissionManager_Update_t)(uintptr_t thisptr);

static MissionManager_Update_t o_MissionManager_Update = nullptr;

struct MissionCmd {
    volatile int mode; // 0 = Idle, 1 = Activate, 2 = Complete, 3 = Inactive
    uintptr_t targetMission;
    volatile bool done;
};
static MissionCmd g_QueuedMissionCmd = { 0, 0, false };

// Main-Thread Synchronization Hook (Guarantees zero TLS / concurrency crashes)
static void __fastcall hk_MissionManager_Update(uintptr_t thisptr) {
    if (g_QueuedMissionCmd.mode != 0 && g_QueuedMissionCmd.targetMission) {
        uintptr_t m = g_QueuedMissionCmd.targetMission;
        int mode = g_QueuedMissionCmd.mode;

        auto fnResetRoots = (ResetObjectiveRoots_t)(g_ExeBase + g_Addr_955940);
        auto fnSetStatus  = (SetMissionStatusInternal_t)(g_ExeBase + g_Addr_8F0E40);
        auto fnActivate   = (DoActivate_t)(g_ExeBase + g_Addr_91CA540);
        auto fnResetCheck = (ResetToCheckpoint_t)(g_ExeBase + g_Addr_91C920);

        if (mode == 2) {
            fnSetStatus(m, 2); // Set COMPLETED
        } else {
            // Recursively reset all child objectives in m_Objectives (0x220 to 0x228)
            uintptr_t bgn = 0, end = 0;
            FastRead<uintptr_t>(m + 0x220, bgn);
            FastRead<uintptr_t>(m + 0x228, end);
            if (bgn && end > bgn && (end - bgn) < 0x2000) {
                for (uintptr_t cur = bgn; cur < end; cur += 0x18) {
                    uintptr_t px = 0;
                    if (FastRead<uintptr_t>(cur + 0x8, px) && px) {
                        fnResetCheck(px, px, 0, 0);
                    }
                }
            }

            fnResetRoots(m); // Reset root objectives

            if (mode == 1) {
                fnSetStatus(m, 0);
                fnActivate(m); // Set ACTIVE & reboot mission scripts
            } else if (mode == 3) {
                fnSetStatus(m, 0); // Set INACTIVE
            }
        }

        g_QueuedMissionCmd.mode = 0;
        g_QueuedMissionCmd.targetMission = 0;
        g_QueuedMissionCmd.done = true;
    }

    if (o_MissionManager_Update) {
        o_MissionManager_Update(thisptr);
    }
}

// Dynamic Localization Engine Wrapper (Queries game memory on demand)
static std::string GetLocalizedGameString(uint32_t hash) {
    if (!g_ExeBase || !hash || hash == 0xDEADBEEF) return "";
    auto fnGetStr = (GetLocalizedStringRaw_t)(g_ExeBase + g_Addr_88850);
    uintptr_t locMgrPtr = 0;
    FastRead<uintptr_t>(g_ExeBase + g_Addr_2C73AE0, locMgrPtr);
    uintptr_t locMgr = (locMgrPtr > 0x10000) ? locMgrPtr : (g_ExeBase + g_Addr_2C73AE0);
    const char* res = fnGetStr(locMgr, hash);
    std::string first = (res && res[0]) ? std::string(res) : "";
    // EPIC: fn returns loc KEYS ("campaign_...") instead of text when the key
    // table precedes the text table. Keys contain '_' and no spaces; real text
    // does not. If we got a key, walk the lookup tables (same layout both
    // builds: lookups at +0x8/+0x10, info 16B, lookup pairs at +0x0/+0x8 size
    // 0xC with hash+0x0/off+0x4, text at +0x20) for a non-key match.
    auto looksLikeKey = [](const std::string& s) {
        return s.find('_') != std::string::npos && s.find(' ') == std::string::npos;
    };
    if (first.empty() || !looksLikeKey(first)) return first;
    uintptr_t vBegin = 0, vEnd = 0;
    if (!FastRead<uintptr_t>(locMgr + 0x8, vBegin) || !FastRead<uintptr_t>(locMgr + 0x10, vEnd) ||
        !vBegin || vEnd <= vBegin || (vEnd - vBegin) > 0x10000) return first;
    for (uintptr_t info = vBegin; info < vEnd; info += 0x10) {
        uintptr_t lk = 0;
        if (!FastRead<uintptr_t>(info, lk) || !lk) continue;
        uint32_t cnt = 0;
        uintptr_t data = 0;
        if (!FastRead<uint32_t>(lk + 0x8, cnt) || !cnt || cnt > 200000) continue;
        if (!FastRead<uintptr_t>(lk, data) || !data) continue;
        uintptr_t textBase = 0;
        if (!FastRead<uintptr_t>(lk + 0x20, textBase) || !textBase) continue;
        // binary search sorted pairs (12B: hash+0, off+4)
        uint32_t lo = 0, hi = cnt;
        bool found = false; uint32_t off = 0;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            uint32_t h = 0;
            if (!FastRead<uint32_t>(data + mid * 0xC, h)) break;
            if (h < hash) lo = mid + 1;
            else if (h > hash) hi = mid;
            else { FastRead<uint32_t>(data + mid * 0xC + 4, off); found = true; break; }
        }
        if (!found) continue;
        char buf[512] = {0};
        if (!ReadProcessMemory(GetCurrentProcess(), (void*)(textBase + off), buf, sizeof(buf) - 1, NULL)) continue;
        buf[sizeof(buf)-1] = 0;
        std::string cand(buf);
        if (!cand.empty() && !looksLikeKey(cand)) return cand;
    }
    return first;
}

// Queries the in-game CBookmarkMissionDescription table (0x2CB9CB0) for the official map card description
static std::string GetMissionBookmarkDescription(uint32_t missionHash) {
    if (!g_ExeBase || !missionHash) return "";
    uintptr_t vecBegin = 0, vecEnd = 0;
    FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB9CB0, vecBegin);
    FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB9CB8, vecEnd);
    if (!vecBegin || vecEnd <= vecBegin) return "";

    size_t count = (vecEnd - vecBegin) / 8;
    if (count > 200) count = 200;

    for (size_t i = 0; i < count; i++) {
        uintptr_t pDesc = 0;
        if (!FastRead<uintptr_t>(vecBegin + (i * 8), pDesc) || !pDesc) continue;

        uint32_t mHash = 0;
        FastRead<uint32_t>(pDesc + 0x1D8, mHash);
        if (mHash == missionHash) {
            uint32_t descHash = 0;
            FastRead<uint32_t>(pDesc + 0x1DC, descHash);
            if (descHash && descHash != 0xDEADBEEF) {
                std::string desc = GetLocalizedGameString(descHash);
                if (!desc.empty()) return desc;
            }
        }
    }
    return "";
}

static std::string GetDynamicMissionTitle(uintptr_t pMission, uint32_t missionHash) {
    uint32_t nameHash = 0;
    FastRead<uint32_t>(pMission + 0x298, nameHash);
    std::string title = GetLocalizedGameString(nameHash);
    if (!title.empty()) return title;

    uint32_t altHash = 0;
    FastRead<uint32_t>(pMission + 0x294, altHash);
    title = GetLocalizedGameString(altHash);
    if (!title.empty()) return title;

    title = GetLocalizedGameString(missionHash);
    if (!title.empty()) return title;

    std::string subStr = ReadMSVCString(pMission + 0x2E0);
    if (!subStr.empty() && subStr != "Main") return subStr;

    std::string tagStr = ReadMSVCString(pMission + 0x2A0);
    if (!tagStr.empty()) return tagStr;

    return "Operation";
}

static std::string GetDynamicMissionDescription(uintptr_t pMission, uint32_t missionHash) {
    std::string desc = GetMissionBookmarkDescription(missionHash);
    if (!desc.empty()) return desc;

    uint32_t descHash = 0;
    FastRead<uint32_t>(pMission + 0x29C, descHash);
    if (descHash && descHash != 0xDEADBEEF) {
        desc = GetLocalizedGameString(descHash);
        if (!desc.empty()) return desc;
    }
    return "Investigate the operation beacon in the province to initiate the combat sequence.";
}

struct NativeMissionEntry {
    uintptr_t ptr;
    uint32_t hash;
    int32_t status;
    std::string title;
    std::string description;
    std::string iconTag;
    std::string poiTag;
    float posX, posY, posZ;
    bool hasLocation;
};

static std::vector<NativeMissionEntry> g_NativeMissions;
static int g_SelectedNativeMission = -1;
static std::string g_MissionStatusMsg = "Click 'Scan Operations' to fetch live missions.";

static void ScanNativeMissions() {
    g_NativeMissions.clear();
    g_SelectedNativeMission = -1;
    if (!g_ExeBase) return;

    uintptr_t pMgr = 0;
    if (!FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB5C70, pMgr) || !pMgr) {
        g_MissionStatusMsg = "CMissionManager is not ready. Enter game world first.";
        return;
    }

    uintptr_t headNode = 0;
    if (!FastRead<uintptr_t>(pMgr + 0xF8, headNode) || !headNode) return;

    uintptr_t cur = 0;
    FastRead<uintptr_t>(headNode, cur);
    size_t count = 0;

    while (cur && cur != headNode && count < 1000) {
        uintptr_t pMission = 0;
        uint32_t hash = 0;
        FastRead<uintptr_t>(cur + 0x18, pMission);
        FastRead<uint32_t>(cur + 0x10, hash);

        if (pMission) {
            NativeMissionEntry e;
            e.ptr = pMission;
            e.hash = hash;
            FastRead<int32_t>(pMission + 0x288, e.status);

            e.title = GetDynamicMissionTitle(pMission, hash);
            e.description = GetDynamicMissionDescription(pMission, hash);

            // ITrackableContent interface is at +0x1D0; icon string is at 0x1D0 + 0xF0 = 0x2C0
            e.iconTag = ReadMSVCString(pMission + 0x2C0);
            if (e.iconTag.empty()) e.iconTag = ReadMSVCString(pMission + 0x2A0);
            if (e.iconTag.empty()) e.iconTag = "icon_campaign_default";

            e.poiTag = ReadMSVCString(pMission + 0x2A0);

            uint8_t hasLoc = 0;
            FastRead<uint8_t>(pMission + 0x272, hasLoc);
            e.hasLocation = (hasLoc == 1);

            if (e.hasLocation) {
                FastRead<float>(pMission + 0x274, e.posX);
                FastRead<float>(pMission + 0x278, e.posY);
                FastRead<float>(pMission + 0x27C, e.posZ);
            } else {
                e.posX = 0.0f; e.posY = 0.0f; e.posZ = 0.0f;
            }

            g_NativeMissions.push_back(e);
        }

        if (!FastRead<uintptr_t>(cur, cur)) break;
        count++;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "Successfully scanned %zu operations.", g_NativeMissions.size());
    g_MissionStatusMsg = buf;
}

static void QueueMissionCommand(uintptr_t pMission, int mode) {
    g_QueuedMissionCmd.targetMission = pMission;
    g_QueuedMissionCmd.mode = mode;
    g_QueuedMissionCmd.done = false;

    DWORD start = GetTickCount();
    while (!g_QueuedMissionCmd.done && (GetTickCount() - start < 1000)) {
        Sleep(5);
    }
}

void DrawOtherTab() {
    static int s_PendingScanFrames = 0;
    if (s_PendingScanFrames > 0) {
        if (--s_PendingScanFrames == 0) {
            ScanNativeMissions();
        }
    }

    if (!g_MissionsSpoilerAccepted) {
        ImGui::BeginDisabled(true);
    }

    DrawSectionHeader("MISSION MANAGER (BETA)");

    // --- Header Bar ---
    if (ImGui::Button("Scan Operations##Btn", ImVec2(200.0f * g_UIScale, 34.0f * g_UIScale))) {
        ScanNativeMissions();
    }
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "%s", g_MissionStatusMsg.c_str());

    ImGui::Spacing();

    // --- Two-Column Layout (List on Left, Dynamic Card on Right) ---
    float totalW = ImGui::GetContentRegionAvail().x;
    float colLeftW = totalW * 0.46f;
    float colRightW = totalW - colLeftW - (15.0f * g_UIScale);

    // LEFT: Operation List
    ImGui::BeginChild("##OpListChild", ImVec2(colLeftW, 430.0f * g_UIScale), true);
    for (size_t i = 0; i < g_NativeMissions.size(); i++) {
        const auto& m = g_NativeMissions[i];
        ImGui::PushID((int)i);

        bool selected = (g_SelectedNativeMission == (int)i);

        ImVec4 statusCol = ImVec4(0.5f, 0.55f, 0.65f, 1.0f);
        const char* statusPrefix = "[INACTIVE]";
        if (m.status == 1) {
            statusCol = ImVec4(0.2f, 1.0f, 0.4f, 1.0f);
            statusPrefix = "[ACTIVE]  ";
        } else if (m.status == 2) {
            statusCol = ImVec4(0.2f, 0.8f, 1.0f, 1.0f);
            statusPrefix = "[COMPLETE]";
        }

        char itemText[256];
        snprintf(itemText, sizeof(itemText), "%s %02zu. %s", statusPrefix, i + 1, m.title.c_str());

        ImGui::PushStyleColor(ImGuiCol_Text, statusCol);
        if (ImGui::Selectable(itemText, selected, 0, ImVec2(0, 24.0f * g_UIScale))) {
            g_SelectedNativeMission = (int)i;
        }
        ImGui::PopStyleColor();

        ImGui::PopID();
    }
    ImGui::EndChild();

    ImGui::SameLine();

    // RIGHT: Sleek Emblem, Mission Card, and Metadata
    ImGui::BeginChild("##OpDetailsChild", ImVec2(colRightW, 430.0f * g_UIScale), true);
    if (g_SelectedNativeMission >= 0 && g_SelectedNativeMission < (int)g_NativeMissions.size()) {
        const auto& sel = g_NativeMissions[g_SelectedNativeMission];

        // 1. Header Banner & Title
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.85f, 0.35f, 1.0f));
        ImGui::TextWrapped("%s", sel.title.c_str());
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // 2. Custom Sleek Emblem / Logo Box
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 p0 = ImGui::GetCursorScreenPos();
        float emblemBoxW = ImGui::GetContentRegionAvail().x;
        float emblemBoxH = 68.0f * g_UIScale;
        ImVec2 p1 = ImVec2(p0.x + emblemBoxW, p0.y + emblemBoxH);

        dl->AddRectFilled(p0, p1, IM_COL32(18, 22, 32, 240), 6.0f);
        dl->AddRect(p0, p1, IM_COL32(0, 210, 220, 200), 6.0f, 0, 1.5f);

        // Styled graphical badge
        ImVec2 badgePos = ImVec2(p0.x + 12.0f * g_UIScale, p0.y + 12.0f * g_UIScale);
        dl->AddRectFilled(badgePos, ImVec2(badgePos.x + 44.0f * g_UIScale, badgePos.y + 44.0f * g_UIScale), IM_COL32(0, 150, 170, 120), 4.0f);
        dl->AddRect(badgePos, ImVec2(badgePos.x + 44.0f * g_UIScale, badgePos.y + 44.0f * g_UIScale), IM_COL32(0, 240, 255, 255), 4.0f, 0, 1.5f);

        // Graphic emblem icon (Thunderbolt / Star vector)
        ImVec2 center = ImVec2(badgePos.x + 22.0f * g_UIScale, badgePos.y + 22.0f * g_UIScale);
        dl->AddTriangleFilled(ImVec2(center.x + 2, center.y - 14.0f * g_UIScale),
                              ImVec2(center.x - 10.0f * g_UIScale, center.y + 2.0f),
                              ImVec2(center.x + 2, center.y + 2.0f), IM_COL32(255, 230, 40, 255));
        dl->AddTriangleFilled(ImVec2(center.x - 2, center.y + 14.0f * g_UIScale),
                              ImVec2(center.x + 10.0f * g_UIScale, center.y - 2.0f),
                              ImVec2(center.x - 2, center.y - 2.0f), IM_COL32(255, 200, 30, 255));

        // Textual tags inside the emblem box
        ImGui::SetCursorScreenPos(ImVec2(p0.x + 68.0f * g_UIScale, p0.y + 12.0f * g_UIScale));
        ImGui::TextColored(ImVec4(0.0f, 0.9f, 1.0f, 1.0f), "MISSION TITLE:");
        ImGui::SetCursorScreenPos(ImVec2(p0.x + 68.0f * g_UIScale, p0.y + 32.0f * g_UIScale));
        ImGui::TextUnformatted(sel.title.c_str());

        ImGui::SetCursorScreenPos(ImVec2(p0.x, p1.y + 12.0f * g_UIScale));

        // 3. Official Mission Description
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.45f, 0.95f, 1.0f));
        ImGui::TextUnformatted("MISSION DESCRIPTION:");
        ImGui::PopStyleColor();

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.95f, 0.98f, 1.0f));
        ImGui::TextWrapped("\"%s\"", sel.description.c_str());
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // 4. Intelligence & Coordinates Telemetry
        ImGui::TextDisabled("Telemetry:");
        ImGui::BulletText("POI World Tag : %s", sel.poiTag.c_str());
        if (sel.hasLocation) {
            ImGui::BulletText("Map Coordinates: (%.1f, %.1f, %.1f)", sel.posX, sel.posY, sel.posZ);
        } else {
            ImGui::BulletText("Map Coordinates: Frontline Event / Story Trigger (No static beacon)");
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // 5. Operation Actions
        if (ImGui::Button("Replay Mission", ImVec2(-1, 32.0f * g_UIScale))) {
            // Cancel any other currently active mission first for mutual exclusivity
            for (const auto& other : g_NativeMissions) {
                if (other.ptr != sel.ptr && other.status == 1) {
                    QueueMissionCommand(other.ptr, 3);
                }
            }
            QueueMissionCommand(sel.ptr, 1);
            s_PendingScanFrames = 6;
        }

        ImGui::Spacing();

        if (ImGui::Button("Set COMPLETED", ImVec2((colRightW - 10.0f) * 0.5f, 30.0f * g_UIScale))) {
            QueueMissionCommand(sel.ptr, 2);
            s_PendingScanFrames = 6;
        }
        ImGui::SameLine();
        if (ImGui::Button("Set INACTIVE", ImVec2((colRightW - 10.0f) * 0.5f, 30.0f * g_UIScale))) {
            QueueMissionCommand(sel.ptr, 3);
            s_PendingScanFrames = 6;
        }
    } else {
        ImGui::TextDisabled("");
    }
    ImGui::EndChild();

    if (!g_MissionsSpoilerAccepted) {
        ImGui::EndDisabled();

        // Draw translucent frosted layer over background tab items
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 winPos = ImGui::GetWindowPos();
        ImVec2 winSize = ImGui::GetWindowSize();
        dl->AddRectFilled(winPos, ImVec2(winPos.x + winSize.x, winPos.y + winSize.y), IM_COL32(10, 13, 18, 190));

        // Center the disclaimer card using local child layout (guarantees strict text wrapping)
        float cardW = winSize.x * 0.85f;
        if (cardW > 540.0f * g_UIScale) cardW = 540.0f * g_UIScale;
        if (cardW < 320.0f * g_UIScale) cardW = 320.0f * g_UIScale;
        float cardH = 220.0f * g_UIScale;

        float cardLocalX = (winSize.x - cardW) * 0.5f;
        float cardLocalY = (winSize.y - cardH) * 0.5f;
        if (cardLocalY < 15.0f * g_UIScale) cardLocalY = 15.0f * g_UIScale;

        ImGui::SetCursorPos(ImVec2(cardLocalX, cardLocalY));

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.07f, 0.09f, 0.13f, 0.98f));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.95f, 0.60f, 0.15f, 0.90f));
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.8f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f * g_UIScale);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(22.0f * g_UIScale, 20.0f * g_UIScale));

        if (ImGui::BeginChild("##SpoilerCard", ImVec2(cardW, cardH), true, ImGuiWindowFlags_NoScrollbar)) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.2f, 1.0f));
            ImGui::TextUnformatted("SPOILER WARNING");
            ImGui::PopStyleColor();
            ImGui::Spacing();

            ImGui::TextWrapped("This tab lists and allows you to control all operations and story missions in Just Cause 4.\n\nViewing or interacting with this tab will reveal story progression, mission objectives, and plot points.");

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            float availW = ImGui::GetContentRegionAvail().x;
            float btnSpacing = 12.0f * g_UIScale;
            float btnW = (availW - btnSpacing) * 0.5f;
            float btnH = 34.0f * g_UIScale;

            if (ImGui::Button("Go back", ImVec2(btnW, btnH))) {
                extern int g_CurrentTab;
                g_CurrentTab = 0; // Return to Toggles tab
            }
            ImGui::SameLine(0, btnSpacing);
            if (ImGui::Button("Continue", ImVec2(btnW, btnH))) {
                g_MissionsSpoilerAccepted = true;
                WriteConfig();
            }
        }
        ImGui::EndChild();

        ImGui::PopStyleVar(3);
        ImGui::PopStyleColor(2);
    }
}
static uintptr_t GetWorldTimeInstance() {
    if (!g_ExeBase) return 0;
    static const bool is_steam = (GetModuleHandleA("steam_api64.dll") != nullptr);
    uintptr_t addr = g_ExeBase + (g_Addr_2CAFDB0);
    uintptr_t inst = 0;
    if (FastRead<uintptr_t>(addr, inst)) return inst;
    return 0;
}

static void ExecuteSetTime(float hour) {
    uintptr_t wt = GetWorldTimeInstance();
    if (!wt || !o_WorldTime_SetTime) return;
    hour = std::clamp(hour, -24.0f, 24.0f);
    o_WorldTime_SetTime(wt, hour, 2);
}

static void ExecuteSetTimeScale(float scale) {
    uintptr_t wt = GetWorldTimeInstance();
    if (!wt) return;
    scale = std::clamp(scale, -1000.0f, 1000.0f);
    FastWrite<float>(wt + 0xE4, scale);
    g_TimeScale = scale;
}

static bool ExecuteTeleport(float x, float y, float z) {
    if (!g_ExeBase) return false;
    static const bool is_steam = (GetModuleHandleA("steam_api64.dll") != nullptr);

    // Safeguard: Engine crashes when attempting to teleport to (0, y, 0)
    if (fabsf(x) < 0.01f && fabsf(z) < 0.01f) {
        x = 1.0f;
        z = 1.0f;
    }

    // Single dereference to get CGameWorld*
    uintptr_t gameWorld = 0;
    uintptr_t instAddr = g_ExeBase + (g_Addr_2CB0A48);
    if (!FastRead<uintptr_t>(instAddr, gameWorld) || !gameWorld) return false;

    uintptr_t vtable = 0;
    if (!FastRead<uintptr_t>(gameWorld, vtable) || !vtable) return false;

    // Sanity-check: VTable must reside within executable image memory
    if (vtable < g_ExeBase || vtable > (g_ExeBase + g_Addr_10000000)) return false;

    // Virtual Index 13 = TeleportPlayer (offset 13 * 8 = 0x68)
    uintptr_t fnTeleport = 0;
    if (!FastRead<uintptr_t>(vtable + 0x68, fnTeleport) || !fnTeleport) return false;

    // Sanity-check: Function pointer must point to executable code
    if (fnTeleport < g_ExeBase || fnTeleport > (g_ExeBase + g_Addr_10000000)) return false;

    // 16-byte aligned SIMD 4x4 matrix initialized to Identity
    alignas(16) float transform[16] = {
        1.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 1.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 1.0f, 0.0f,
        x,    y,    z,    1.0f
    };

    // Copy player's orientation axes (first 3 rows) so Rico retains his facing direction
    uintptr_t player = GetPlayerPtr();
    uintptr_t character = 0;
    if (player && FastRead<uintptr_t>(player + 0x68, character) && character) {
        for (int i = 0; i < 12; ++i) {
            FastRead<float>(character + 0x114 + (uintptr_t)(i * 4), transform[i]);
        }
    }

    transform[12] = x;
    transform[13] = y;
    transform[14] = z;
    transform[15] = 1.0f;

    auto TeleportFunc = (GameWorld_TeleportPlayer_t)fnTeleport;
    TeleportFunc(gameWorld, transform, nullptr, false, false, 0.0f, 0.0f, 0, nullptr, false, nullptr);
    return true;
}

void DrawTimeTab() {
    DrawSectionHeader("WORLD TIME OF DAY");

    uintptr_t wt = GetWorldTimeInstance();
    if (!wt) {
        ImGui::TextColored(ImVec4(0.9f, 0.5f, 0.3f, 1.0f), "[!] WorldTime instance unavailable (must be in-game).");
        return;
    }

    float liveTime = 0.0f;
    FastRead<float>(wt + 0xE0, liveTime);

    int hours = (int)liveTime;
    float fractionalHour = liveTime - (float)hours;
    if (fractionalHour < 0.0f) fractionalHour += 1.0f;
    int minutes = (int)(fractionalHour * 60.0f);
    int seconds = (int)(fmodf(fractionalHour * 3600.0f, 60.0f));

    ImGui::Text("Current World Time: ");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.2f, 0.85f, 1.0f, 1.0f), "%02d:%02d:%02d  (%.2f hrs)", hours, minutes, seconds, liveTime);

    ImGui::Spacing();
    ImGui::Text("Presets:");
    ImGui::Spacing();

    if (ImGui::Button("Sunrise (06:00)", ImVec2(140.0f * g_UIScale, 32.0f * g_UIScale))) ExecuteSetTime(6.0f);
    ImGui::SameLine();
    if (ImGui::Button("Noon (12:00)",    ImVec2(140.0f * g_UIScale, 32.0f * g_UIScale))) ExecuteSetTime(12.0f);
    ImGui::SameLine();
    if (ImGui::Button("Sunset (18:00)",  ImVec2(140.0f * g_UIScale, 32.0f * g_UIScale))) ExecuteSetTime(18.0f);
    ImGui::SameLine();
    if (ImGui::Button("Night (22:00)",   ImVec2(140.0f * g_UIScale, 32.0f * g_UIScale))) ExecuteSetTime(22.0f);
    ImGui::SameLine();
    if (ImGui::Button("Midnight (00:00)",ImVec2(140.0f * g_UIScale, 32.0f * g_UIScale))) ExecuteSetTime(0.0f);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    static bool s_TimeSliderActive = false;
    if (!s_TimeSliderActive) {
        g_TargetTime = liveTime;
    }

    ImGui::AlignTextToFramePadding();
    ImGui::Text("Time of Day Slider:");
    ImGui::SameLine(180.0f * g_UIScale);
    ImGui::SetNextItemWidth(260.0f * g_UIScale);

    if (ImGui::SliderFloat("##TimeOfDaySlider", &g_TargetTime, 0.0f, 24.0f, "%.2f hrs")) {
        ExecuteSetTime(g_TargetTime);
    }
    s_TimeSliderActive = ImGui::IsItemActive();

    DrawSectionHeader("TIME SCALE (SIMULATION SPEED)");

    float liveScale = 1.0f;
    FastRead<float>(wt + 0xE4, liveScale);

    static bool s_ScaleInputActive = false;
    if (!s_ScaleInputActive) {
        g_TimeScale = liveScale;
    }

    ImGui::AlignTextToFramePadding();
    ImGui::Text("Time Scale Multiplier:");
    ImGui::SameLine(180.0f * g_UIScale);

    // Linked Method 1: Continuous Floating-point Slider
    ImGui::SetNextItemWidth(200.0f * g_UIScale);
    if (ImGui::SliderFloat("##TimeScaleSlider", &g_TimeScale, 0.0f, 20.0f, "%.2fx")) {
        ExecuteSetTimeScale(g_TimeScale);
    }
    bool sliderActive = ImGui::IsItemActive();

    ImGui::SameLine();

    // Linked Method 2: Integer Input Box
    int timeScaleInt = (int)roundf(g_TimeScale);
    ImGui::SetNextItemWidth(80.0f * g_UIScale);
    if (ImGui::InputInt("##TimeScaleIntBox", &timeScaleInt, 1, 5)) {
        if (timeScaleInt < 0) timeScaleInt = 0;
        g_TimeScale = (float)timeScaleInt;
        ExecuteSetTimeScale(g_TimeScale);
    }
    bool intActive = ImGui::IsItemActive();

    s_ScaleInputActive = sliderActive || intActive;

    ImGui::SameLine();
    if (ImGui::SmallButton("Reset##TimeScale")) {
        ExecuteSetTimeScale(1.0f);
    }

    ImGui::Spacing();
    if (ImGui::Button("Freeze Time (0x)")) ExecuteSetTimeScale(0.0f);
    ImGui::SameLine();
    if (ImGui::Button("Normal Speed (1x)")) ExecuteSetTimeScale(1.0f);
    ImGui::SameLine();
    if (ImGui::Button("Fast (5x)")) ExecuteSetTimeScale(5.0f);
    ImGui::SameLine();
    if (ImGui::Button("Ultra (10x)")) ExecuteSetTimeScale(10.0f);

    ImGui::Spacing();
    ImGui::TextDisabled("Live Engine Timescale: %.2f", liveScale);
}

void DrawTeleportTab() {
    DrawSectionHeader("COORDINATE TELEPORTER");

    float curPos[3] = { 0.0f, 0.0f, 0.0f };
    uintptr_t player = GetPlayerPtr();
    uintptr_t character = 0;
    if (player && FastRead<uintptr_t>(player + 0x68, character) && character) {
        FastRead<float>(character + 0x144, curPos[0]);
        FastRead<float>(character + 0x148, curPos[1]);
        FastRead<float>(character + 0x14C, curPos[2]);
    }

    ImGui::Text("Current Position: X: %.1f  Y: %.1f  Z: %.1f", curPos[0], curPos[1], curPos[2]);
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy Current Coords")) {
        g_TeleportCoords[0] = curPos[0];
        g_TeleportCoords[1] = curPos[1];
        g_TeleportCoords[2] = curPos[2];
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::AlignTextToFramePadding();
    ImGui::Text("Destination (X, Y, Z):");
    ImGui::SameLine(180.0f * g_UIScale);
    ImGui::SetNextItemWidth(320.0f * g_UIScale);
    ImGui::InputFloat3("##TpDestInputs", g_TeleportCoords, "%.1f");
    ImGui::SameLine();
    if (ImGui::Button("Teleport Now", ImVec2(140.0f * g_UIScale, 0))) {
        ExecuteTeleport(g_TeleportCoords[0], g_TeleportCoords[1], g_TeleportCoords[2]);
    }

    DrawSectionHeader("SAVED LOCATIONS");

    ImGui::SetNextItemWidth(220.0f * g_UIScale);
    ImGui::InputTextWithHint("##NewLocationName", "Location Name...", g_TpNameBuf, sizeof(g_TpNameBuf));
    ImGui::SameLine();
    if (ImGui::Button("Save Current Spot")) {
        if (g_TpNameBuf[0] != '\0') {
            g_SavedLocations.push_back({ g_TpNameBuf, curPos[0], curPos[1], curPos[2] });
            g_TpNameBuf[0] = '\0';
            WriteConfig(); // Instantly write to ini upon saving
        }
    }

    ImGui::Spacing();

    if (g_SavedLocations.empty()) {
        ImGui::TextDisabled("No locations saved yet. Capture locations with 'Save Current Spot'.");
    } else {
        if (ImGui::BeginTable("##SavedLocationsTable", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit)) {
            ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Coordinates (X, Y, Z)", ImGuiTableColumnFlags_WidthFixed, 220.0f * g_UIScale);
            ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 140.0f * g_UIScale);
            ImGui::TableHeadersRow();

            for (int i = 0; i < (int)g_SavedLocations.size(); i++) {
                auto& loc = g_SavedLocations[i];
                ImGui::PushID(i);
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                ImGui::AlignTextToFramePadding();
                ImGui::TextUnformatted(loc.name.c_str());

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%.0f, %.0f, %.0f", loc.x, loc.y, loc.z);

                ImGui::TableSetColumnIndex(2);
                if (ImGui::SmallButton("Go")) {
                    ExecuteTeleport(loc.x, loc.y, loc.z);
                }
                ImGui::SameLine();
                if (ImGui::SmallButton("Delete")) {
                    g_SavedLocations.erase(g_SavedLocations.begin() + i);
                    WriteConfig(); // Instantly write to ini upon deleting
                    ImGui::PopID();
                    break;
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    }
}
// ============================================================================
// GRAPPLING HOOK TUNING ENGINE
// ============================================================================
static uintptr_t GetGrappleHookPtr() {
    if (!g_ExeBase) return 0;
    uintptr_t player = GetPlayerPtr();
    if (!player) return 0;
    uintptr_t character = 0;
    if (!FastRead<uintptr_t>(player + 0x68, character) || !character) return 0;

    typedef uintptr_t*(__fastcall* GetGrappleHook_t)(uintptr_t);
    static GetGrappleHook_t fnGetGrapple = (GetGrappleHook_t)(g_ExeBase + g_Addr_542110); // 0x542110 Steam, 0x543DC0 Epic
    if (!fnGetGrapple) return 0;
    uintptr_t* pShared = fnGetGrapple(character);
    if (!pShared || !*pShared) return 0;
    return *pShared;
}

static uintptr_t GetGrappleTuningPtr() {
    uintptr_t hook = GetGrappleHookPtr();
    if (!hook) return 0;
    uintptr_t tuning = 0;
    if (!FastRead<uintptr_t>(hook + 0x6B0, tuning) || !tuning) return 0;
    return tuning;
}

static bool s_GrappleDefaultsCaptured = false;

// Native CBoosterEngine::UpdateBoosterEngine Hook (0x1406F7F40)
typedef void(__fastcall* BoosterEngine_Update_t)(uintptr_t thisptr, uintptr_t proxy, float dt);
static BoosterEngine_Update_t o_BoosterEngine_Update = nullptr;
// CPlayer::SetOpacity Hook (Steam 0xB28D30, Epic 0xB31FB0): forces Rico opaque
// while freecam is active. Raw CPlayer float writes (+0x3504 etc.) land but do
// not propagate to the renderer; routing through the setter does.
typedef void(__fastcall* PlayerSetOpacity_t)(uintptr_t thisptr, float opacity);
static PlayerSetOpacity_t o_PlayerSetOpacity = nullptr;
void __fastcall hk_PlayerSetOpacity(uintptr_t thisptr, float opacity) {
    uintptr_t localCh = 0;
    if ((g_FreeCam || IsFirstPersonActive(localCh)) && opacity < 0.99f) opacity = 1.0f;
    o_PlayerSetOpacity(thisptr, opacity);
}

struct BoosterInstanceData {
    bool  overrideForce;
    float force;
    bool  overrideSpeed;
    float speed;
    bool  overrideSpool;
    float spool;
};

static std::map<uintptr_t, BoosterInstanceData> s_BoosterInstanceMap;
static CRITICAL_SECTION g_BoosterMapLock;
static bool g_BoosterMapLockInited = false;
// Per-booster defaults set in the Active Boosters list (wire -> seconds).
// Only editable while the wire is idle; seeded once when its burn starts.
// Tweaking a held wire adjusts its hold level instead. R removes the entry.
static std::map<uintptr_t, float> s_BoosterWireTimeOverride;
// Last firing state per wire, to seed manual times once at fire start.
static std::map<uintptr_t, bool> s_BurnWasFiring;

void __fastcall hk_BoosterEngine_Update(uintptr_t thisptr, uintptr_t proxy, float dt) {
    if (thisptr) {
        if (!g_BoosterMapLockInited) {
            InitializeCriticalSection(&g_BoosterMapLock);
            g_BoosterMapLockInited = true;
        }

        EnterCriticalSection(&g_BoosterMapLock);
        auto it = s_BoosterInstanceMap.find(thisptr);

        // First tick this active booster is seen: snapshot the current UI settings for THIS instance
        if (it == s_BoosterInstanceMap.end()) {
            BoosterInstanceData data;
            data.overrideForce = g_BoosterForce.overrideActive;
            data.force         = g_BoosterForce.overrideActive ? g_BoosterForce.customVal : *(float*)(thisptr + 0x230);
            data.overrideSpeed = g_BoosterSpeed.overrideActive;
            data.speed         = g_BoosterSpeed.overrideActive ? g_BoosterSpeed.customVal : *(float*)(thisptr + 0x22C);
            data.overrideSpool = g_BoosterSpool.overrideActive;
            data.spool         = g_BoosterSpool.overrideActive ? g_BoosterSpool.customVal : *(float*)(thisptr + 0x234);

            if (!data.overrideForce && data.force <= 0.0f) {
                data.force = (g_DefBoosterForce[1] > 0.0f) ? g_DefBoosterForce[1] : 2000.0f;
            }

            s_BoosterInstanceMap[thisptr] = data;
            it = s_BoosterInstanceMap.find(thisptr);
        }

        // Enforce THIS specific booster's snapshotted properties right before physics calculation
        if (it != s_BoosterInstanceMap.end()) {
            if (it->second.overrideForce) {
                FastWrite<float>(thisptr + 0x230, it->second.force);
            }
            if (it->second.overrideSpeed) {
                FastWrite<float>(thisptr + 0x22C, it->second.speed);
            }
            if (it->second.overrideSpool) {
                FastWrite<float>(thisptr + 0x234, it->second.spool);
            }
        }
        LeaveCriticalSection(&g_BoosterMapLock);
    }

    o_BoosterEngine_Update(thisptr, proxy, dt);
}

static uint8_t s_Orig30sIconBytes[32] = { 0 };
static uintptr_t s_Booster30sOptAddr = 0;
static uintptr_t s_InfiniteOptAddr = 0;
static bool s_RetoolerIconsCaptured = false;
static bool s_RetoolerDumped = false;

static void UpdateRetoolerBoosterIcon(bool enable) {
    if (!g_ExeBase) return;

    uintptr_t mgr = 0;
    if (!FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB5ED0, mgr) || !mgr) return;

    uintptr_t settings = 0;
    if (!FastRead<uintptr_t>(mgr + 0x88, settings) || !settings) return;

    uintptr_t optBegin = 0, optEnd = 0;
    if (!FastRead<uintptr_t>(settings + 0x1E8, optBegin) ||
        !FastRead<uintptr_t>(settings + 0x1F0, optEnd) ||
        !optBegin || optEnd <= optBegin) return;

    size_t count = (optEnd - optBegin) / 0x58;
    if (count > 200) count = 200;

    // Discover the 30s Booster option and the native Infinite option
    if (!s_RetoolerIconsCaptured) {
        if (!s_RetoolerDumped) {
            std::cout << "\n=== [Retooler Options List (" << count << " entries)] ===\n";
        }

        for (size_t i = 0; i < count; i++) {
            uintptr_t opt = optBegin + (i * 0x58);
            std::string icon = ReadMSVCString(opt + 0x30);
            if (icon.empty()) continue;

            if (!s_RetoolerDumped) {
                std::cout << "  [" << i << "] Icon: '" << icon << "'\n";
            }

            std::string lower = icon;
            std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return (char)std::tolower(c); });

            // Match 30s booster option
            if (lower.find("timeout_30") != std::string::npos || (lower.find("booster") != std::string::npos && lower.find("30") != std::string::npos)) {
                if (!s_Booster30sOptAddr) {
                    s_Booster30sOptAddr = opt;
                    ReadProcessMemory(GetCurrentProcess(), (void*)(opt + 0x30), s_Orig30sIconBytes, 32, NULL);
                    std::cout << "[Retooler] -> Matched 30s Icon: '" << icon << "' at 0x" << std::hex << opt << std::dec << "\n";
                }
            }

            // Case-insensitive match for the native Infinite option (Air Lifter Peak Altitude)
            if (lower.find("infinite") != std::string::npos || lower.find("infinity") != std::string::npos ||
                lower.find("nolimit") != std::string::npos || lower.find("no_limit") != std::string::npos) {
                if (!s_InfiniteOptAddr) {
                    s_InfiniteOptAddr = opt;
                    std::cout << "[Retooler] -> Matched Infinite Icon: '" << icon << "' at 0x" << std::hex << opt << std::dec << "\n";
                }
            }
        }

        if (!s_RetoolerDumped) {
            std::cout << "=================================================\n\n";
            s_RetoolerDumped = true;
        }

        if (s_Booster30sOptAddr && s_InfiniteOptAddr) {
            s_RetoolerIconsCaptured = true;
        }
    }

    if (!s_RetoolerIconsCaptured) return;

    static bool s_LastIconApplied = false;
    if (enable != s_LastIconApplied) {
        if (enable) {
            uint8_t infBytes[32] = { 0 };
            if (ReadProcessMemory(GetCurrentProcess(), (void*)(s_InfiniteOptAddr + 0x30), infBytes, 32, NULL)) {
                SafePatchBytes(s_Booster30sOptAddr + 0x30, infBytes, 32);
                std::cout << "[Retooler] Applied INFINITE icon to 30s booster option.\n";
            }
        } else {
            SafePatchBytes(s_Booster30sOptAddr + 0x30, s_Orig30sIconBytes, 32);
            std::cout << "[Retooler] Restored ORIGINAL 30s icon.\n";
        }
        s_LastIconApplied = enable;
    }
}

static uintptr_t s_BalloonLiftCave = 0;
static bool s_BalloonLiftHooked = false;

static void InstallBalloonLiftHook() {
    if (!g_ExeBase || s_BalloonLiftHooked) return;
    uintptr_t hookAddr = g_ExeBase + g_Addr_ABDFF7;
    uintptr_t resumeAddr = g_ExeBase + g_Addr_ABE007;

    s_BalloonLiftCave = AllocateNear(hookAddr, 256);
    if (!s_BalloonLiftCave) return;

    float baseTwelve = 12.0f;
    uint8_t* p12 = (uint8_t*)&baseTwelve;

    std::vector<uint8_t> c;
    auto addB = [&](std::initializer_list<uint8_t> bytes) {
        c.insert(c.end(), bytes.begin(), bytes.end());
    };
    auto addU64 = [&](uint64_t val) {
        uint8_t* p = (uint8_t*)&val;
        c.insert(c.end(), p, p + 8);
    };

    // 1. Pack base 12.0f at cave + 0x00
    c.insert(c.end(), p12, p12 + 4);
    while (c.size() < 0x10) c.push_back(0x90);

    // 2. Code execution starts at cave + 0x10
    addB({ 0x50 });                                         // push rax

    // mulss xmm1, [cave + 0x00] (native 12.0f)
    addB({ 0x48, 0xB8 }); addU64(s_BalloonLiftCave);       // mov rax, s_BalloonLiftCave
    addB({ 0xF3, 0x0F, 0x59, 0x08 });                       // mulss xmm1, dword ptr [rax]

    // Multiply by this specific balloon's instance multiplier at [rdi + 0x920]
    addB({ 0x0F, 0x57, 0xC0 });                             // xorps xmm0, xmm0
    addB({ 0x0F, 0x2F, 0x87, 0x20, 0x09, 0x00, 0x00 });     // comiss xmm0, dword ptr [rdi + 0x920]
    addB({ 0x73, 0x08 });                                   // jae skip_mult (if 0.0 >= [rdi+0x920], skip)
    addB({ 0xF3, 0x0F, 0x59, 0x8F, 0x20, 0x09, 0x00, 0x00 }); // mulss xmm1, dword ptr [rdi + 0x920]

    // skip_mult:
    addB({ 0x58 });                                         // pop rax

    // Original instruction: movss dword ptr [rdi + 0x8D0], xmm1
    addB({ 0xF3, 0x0F, 0x11, 0x8F, 0xD0, 0x08, 0x00, 0x00 });

    // Jump back to game code (0xABE007)
    int32_t relBack = (int32_t)((int64_t)resumeAddr - (int64_t)(s_BalloonLiftCave + c.size() + 5));
    addB({ 0xE9 });
    uint8_t* pRel = (uint8_t*)&relBack;
    c.insert(c.end(), pRel, pRel + 4);

    SafePatchBytes(s_BalloonLiftCave, c.data(), c.size());

    int64_t delta = (int64_t)(s_BalloonLiftCave + 0x10) - (int64_t)(hookAddr + 5);
    uint8_t patch[16];
    patch[0] = 0xE9;
    int32_t rel = (int32_t)delta;
    memcpy(&patch[1], &rel, 4);
    memset(&patch[5], 0x90, 11);

    SafePatchBytes(hookAddr, patch, 16);
    s_BalloonLiftHooked = true;
    std::cout << "[AirLifter] Per-balloon instance physics lift hook installed.\n";
}

// --- Wire classification (offsets Ghidra-verified on CGrapplingHookWire) ---
// wire+0x2F8 = SRetoolerData::m_RetoolerCapabilitiesFlags
//   (bits 0x08/0x10/0x20 = tap/auto/manual BOOSTER capability)
// wire+0x8F8 = m_WireEnds[1].m_BoosterEngine; engine+0x220 =
//   CBoosterEngine::m_InternalState (0 == EInactive: no booster on this wire).
// End boost flag set in SetRetoolerData only for booster-enabled loadouts, so a
// retractor/lifter-only tether keeps the engine in EInactive forever.
static bool IsBoosterTetherWire(uintptr_t wire) {
    uint32_t caps = 0;
    FastRead<uint32_t>(wire + 0x2F8, caps);
    if (caps & 0x38) return true;
    int engineState = 0;
    FastRead<int>(wire + 0x8F8 + 0x220, engineState);
    return engineState != 0;
}

// Unbreakable tethers: the tuning tension thresholds (0x14/0x17C/0x180/0x184)
// only neutralize the *tension* snap/tear path in UpdateWireTension. Lifter,
// booster (and balloon) tethers actually snap via the *stretch* break in
// CGrapplingHookWire::Update: "if (m_MaxLength * 1.2 < length &&
// state != ACTIVE_PHYSICAL) Break(this)". Raise the per-wire m_MaxLength
// (wire+0x370) and remember the original so toggling off restores it.
static std::map<uintptr_t, float> s_WireMaxLenBackup;
static void ApplyWireUnbreakable(uintptr_t wire) {
    if (s_WireMaxLenBackup.find(wire) == s_WireMaxLenBackup.end()) {
        float cur = 0.0f;
        if (FastRead<float>(wire + 0x370, cur) && cur > 0.0f && cur < 100000.0f)
            s_WireMaxLenBackup[wire] = cur;
    }
    FastWrite<float>(wire + 0x370, 10000000.0f);
}

void UpdateGrappleTuning() {
    InstallBalloonLiftHook();
    UpdateRetoolerBoosterIcon(g_BoosterLockOnly30s);

    uintptr_t hook = GetGrappleHookPtr();
    uintptr_t t = GetGrappleTuningPtr();
    if (!t) {
        return;
    }

    // 1. Capture pristine defaults once on boot BEFORE applying any overrides
    if (!s_GrappleDefaultsCaptured) {
        float probe = 0.0f;
        if (FastRead<float>(t + 0x00, probe) && probe > 0.0f) {
            FastRead<float>(t + 0x00, g_GrappleReach.defVal1);
            FastRead<float>(t + 0x6C, g_GrappleFlight.defVal1);
            FastRead<float>(t + 0x28, g_GrappleReelSpd.defVal1);
            FastRead<float>(t + 0x30, g_GrappleReelSpd.defVal2);
            FastRead<float>(t + 0x38, g_GrappleReelAcc.defVal1);
            FastRead<float>(t + 0x34, g_GrappleReelAcc.defVal2);

            // Capture unbreakable tension defaults
            FastRead<float>(t + 0x14,  g_DefTetherBreakScale);
            FastRead<float>(t + 0x17C, g_DefTensionSnap);
            FastRead<float>(t + 0x180, g_DefTensionTear);
            FastRead<float>(t + 0x184, g_DefTensionTimer);

            // Capture Retooler Hold, Tap, and Speed defaults
            for (int i = 0; i < 6; i++) {
                FastRead<float>(t + 0x18C + (i * 4), g_DefRetractHold[i]);
                FastRead<float>(t + 0x1A4 + (i * 4), g_DefRetractTap[i]);
            }
            for (int i = 0; i < 3; i++) {
                FastRead<float>(t + 0x1BC + (i * 4), g_DefRetractSpeed[i]);
            }

            // Capture Booster & Balloon (Air Lifter) Force defaults
            FastRead<float>(t + 0x1E0, g_DefBoosterForce[0]);
            FastRead<float>(t + 0x1E8, g_DefBoosterForce[1]);
            FastRead<float>(t + 0x1F0, g_DefBoosterForce[2]);

            FastRead<float>(t + 0x210, g_DefBalloonForce[0]);
            FastRead<float>(t + 0x218, g_DefBalloonForce[1]);
            FastRead<float>(t + 0x220, g_DefBalloonForce[2]);

            g_TetherPullForce.defVal1 = g_DefRetractHold[0];
            g_TetherRetractSpeed.defVal1 = g_DefRetractSpeed[0];

            g_BoosterForce.defVal1 = g_DefBoosterForce[0];
            g_BoosterForce.defVal2 = g_DefBoosterForce[1];
            g_BoosterForce.defVal3 = g_DefBoosterForce[2];

            g_BalloonLiftForce.defVal1 = g_DefBalloonForce[0];
            g_BalloonLiftForce.defVal2 = g_DefBalloonForce[1];
            g_BalloonLiftForce.defVal3 = g_DefBalloonForce[2];

            s_GrappleDefaultsCaptured = true;
        }
    }

    // 2. Max Reach (0x00)
    if (g_GrappleReach.overrideActive) {
        FastWrite<float>(t + 0x00, g_GrappleReach.customVal);
    } else if (s_GrappleDefaultsCaptured && g_GrappleReach.defVal1 > 0.0f) {
        FastWrite<float>(t + 0x00, g_GrappleReach.defVal1);
    }

    // 3. Hook Flight Speed (0x6C)
    if (g_GrappleFlight.overrideActive) {
        FastWrite<float>(t + 0x6C, g_GrappleFlight.customVal);
    } else if (s_GrappleDefaultsCaptured && g_GrappleFlight.defVal1 > 0.0f) {
        FastWrite<float>(t + 0x6C, g_GrappleFlight.defVal1);
    }

    // 4. Grapple Reel Speed (Linked: writes both Max 0x28 and Min 0x30)
    if (g_GrappleReelSpd.overrideActive) {
        FastWrite<float>(t + 0x28, g_GrappleReelSpd.customVal);
        FastWrite<float>(t + 0x30, g_GrappleReelSpd.customVal);
    } else if (s_GrappleDefaultsCaptured && g_GrappleReelSpd.defVal1 > 0.0f) {
        FastWrite<float>(t + 0x28, g_GrappleReelSpd.defVal1);
        FastWrite<float>(t + 0x30, g_GrappleReelSpd.defVal2);
    }

    // 5. Grapple Reel Acceleration (Linked: writes both Accel 0x38 and Clamp 0x34)
    if (g_GrappleReelAcc.overrideActive) {
        FastWrite<float>(t + 0x38, g_GrappleReelAcc.customVal);
        FastWrite<float>(t + 0x34, g_GrappleReelAcc.customVal);
    } else if (s_GrappleDefaultsCaptured && g_GrappleReelAcc.defVal1 > 0.0f) {
        FastWrite<float>(t + 0x38, g_GrappleReelAcc.defVal1);
        FastWrite<float>(t + 0x34, g_GrappleReelAcc.defVal2);
    }

    // 6. Retooler Tether Pull Force (0x18C..0x194 and 0x1A4..0x1AC)
    if (g_TetherPullForce.overrideActive) {
        for (int i = 0; i < 3; i++) {
            FastWrite<float>(t + 0x18C + (i * 4), g_TetherPullForce.customVal);
            FastWrite<float>(t + 0x1A4 + (i * 4), g_TetherPullForce.customVal);
        }
    } else if (s_GrappleDefaultsCaptured && g_DefRetractHold[0] > 0.0f) {
        for (int i = 0; i < 3; i++) {
            FastWrite<float>(t + 0x18C + (i * 4), g_DefRetractHold[i]);
            FastWrite<float>(t + 0x1A4 + (i * 4), g_DefRetractTap[i]);
        }
    }

    // 7. Retooler Tether Retract Speed (0x198..0x1A0, 0x1B0..0x1B8, and 0x1BC..0x1C4)
    if (g_TetherRetractSpeed.overrideActive) {
        for (int i = 3; i < 6; i++) {
            FastWrite<float>(t + 0x18C + (i * 4), g_TetherRetractSpeed.customVal);
            FastWrite<float>(t + 0x1A4 + (i * 4), g_TetherRetractSpeed.customVal);
        }
        for (int i = 0; i < 3; i++) {
            FastWrite<float>(t + 0x1BC + (i * 4), g_TetherRetractSpeed.customVal);
        }
    } else if (s_GrappleDefaultsCaptured && g_DefRetractSpeed[0] > 0.0f) {
        for (int i = 3; i < 6; i++) {
            FastWrite<float>(t + 0x18C + (i * 4), g_DefRetractHold[i]);
            FastWrite<float>(t + 0x1A4 + (i * 4), g_DefRetractTap[i]);
        }
        for (int i = 0; i < 3; i++) {
            FastWrite<float>(t + 0x1BC + (i * 4), g_DefRetractSpeed[i]);
        }
    }

    // 8. Booster Force Tuning Defaults (Keep pristine template; overrides are baked per-instance)
    if (s_GrappleDefaultsCaptured && g_DefBoosterForce[0] > 0.0f) {
        FastWrite<float>(t + 0x1E0, g_DefBoosterForce[0]);
        FastWrite<float>(t + 0x1E8, g_DefBoosterForce[1]);
        FastWrite<float>(t + 0x1F0, g_DefBoosterForce[2]);
    }

    // Restore pristine inflation scale defaults (stops balloons from growing)
    if (s_GrappleDefaultsCaptured && g_DefBalloonForce[0] > 0.0f) {
        FastWrite<float>(t + 0x210, g_DefBalloonForce[0]);
        FastWrite<float>(t + 0x218, g_DefBalloonForce[1]);
        FastWrite<float>(t + 0x220, g_DefBalloonForce[2]);
    }

    // 10. Max Dual Tethers Capacity Patch & Enforcement
    if (g_ExeBase) {
        uintptr_t patchAddr = g_ExeBase + g_Addr_6CFBB9;
        uintptr_t limitAddr = g_ExeBase + g_Addr_6CFBB4;
        static const uint8_t origJle[6]  = { 0x0F, 0x8E, 0xD5, 0x01, 0x00, 0x00 };
        static const uint8_t patchJmp[6] = { 0xE9, 0xD6, 0x01, 0x00, 0x00, 0x90 };
        static bool s_TethersOverridden = false;
        static bool s_LastUnlimited = false;
        static int  s_LastMaxTethers = -1;

        if (g_OverrideTethers) {
            if (g_UnlimitedTethers) {
                if (!s_TethersOverridden || !s_LastUnlimited) {
                    SafePatchBytes(patchAddr, patchJmp, 6);
                    s_LastUnlimited = true;
                }
            } else {
                if (!s_TethersOverridden || s_LastUnlimited) {
                    SafePatchBytes(patchAddr, origJle, 6);
                    s_LastUnlimited = false;
                }
                if (g_MaxTethersCount != s_LastMaxTethers) {
                    uint8_t clampVal = (g_MaxTethersCount > 127) ? 127 : (uint8_t)g_MaxTethersCount;
                    FastWrite<uint8_t>(limitAddr, clampVal);
                    s_LastMaxTethers = g_MaxTethersCount;
                }
            }
            s_TethersOverridden = true;
        } else if (s_TethersOverridden) {
            // Revert completely to pristine vanilla game code and memory defaults
            SafePatchBytes(patchAddr, origJle, 6);
            FastWrite<uint8_t>(limitAddr, 0x0A);
            s_TethersOverridden = false;
            s_LastUnlimited = false;
            s_LastMaxTethers = -1;
        }
    }

    // 11. Live Active Tether Wires Update & Booster Pruning (CGrapplingHook + 0x610)
    if (hook) {
        uintptr_t wBegin = 0, wEnd = 0;
        if (FastRead<uintptr_t>(hook + 0x610, wBegin) &&
            FastRead<uintptr_t>(hook + 0x618, wEnd) &&
            wBegin && wEnd > wBegin && (wEnd - wBegin) <= 0x10000) {

            std::vector<uintptr_t> currentLiveEngines;
            currentLiveEngines.reserve(16);
            std::vector<uintptr_t> seenBurnWires;
            seenBurnWires.reserve(16);
            std::vector<uintptr_t> seenAllWires;
            seenAllWires.reserve(16);

            for (uintptr_t cur = wBegin; cur < wEnd; cur += 0x10) {
                uintptr_t wire = 0;
                if (!FastRead<uintptr_t>(cur, wire) || !wire || !IsLikelyGameObject(wire)) continue;

                int wireState = 0;
                FastRead<int>(wire + 0x368, wireState);
                if (wireState == 3) continue;

                seenAllWires.push_back(wire);

                // Unbreakable: defeat the stretch-snap for every live dual tether
                if (g_TetherUnbreakable) ApplyWireUnbreakable(wire);

                const bool isBoosterWire = IsBoosterTetherWire(wire);

                // Track live CBoosterEngine sub-object for engine pruning
                // (booster wires only - lifter/retractor wires keep the engine
                // sub-object dormant and must not own map entries)
                if (isBoosterWire) currentLiveEngines.push_back(wire + 0x8F8);

                // Continuous Retractor properties (Retractor mod)
                if (g_TetherPullForce.overrideActive) {
                    FastWrite<float>(wire + 0x30C, g_TetherPullForce.customVal);
                    FastWrite<float>(wire + 0x310, g_TetherPullForce.customVal);
                    FastWrite<float>(wire + 0x314, g_TetherPullForce.customVal);
                }

                if (g_TetherRetractSpeed.overrideActive) {
                    FastWrite<float>(wire + 0x318, g_TetherRetractSpeed.customVal);
                    FastWrite<float>(wire + 0x31C, g_TetherRetractSpeed.customVal);
                    FastWrite<float>(wire + 0x320, g_TetherRetractSpeed.customVal);
                }

                // Booster burn enforcement: idle-set defaults seed once at fire
                // start; the 30s toggle holds 30s-preset wires indefinitely
                // (at their default if one was set). Mid-burn tweaks only
                // nudge the live timer and never touch the default, unless
                // the wire is held - then the tweak becomes its new hold level.
                // The 30s check reads the stable retooler preset, never the
                // live timer.
                {
                    if (!isBoosterWire) continue; // burn tracking: boosters only
                    seenBurnWires.push_back(wire);
                    uint8_t firing = 0, flagged = 0;
                    FastRead<uint8_t>(wire + 0x332, firing);
                    FastRead<uint8_t>(wire + 0xD66, flagged);
                    const bool isFiring = (firing || flagged);
                    bool wasFiring = false;
                    auto wasIt = s_BurnWasFiring.find(wire);
                    if (wasIt != s_BurnWasFiring.end()) wasFiring = wasIt->second;

                    bool hold30 = false;
                    if (g_BoosterLockOnly30s && wire > 0x10000 && (wire & 0x7) == 0) {
                        int preset = 0;
                        FastRead<int>(wire + 0x344, preset);
                        hold30 = (preset == 4);
                    }

                    auto burnIt = s_BoosterWireTimeOverride.find(wire);
                    const bool hasDefault = (burnIt != s_BoosterWireTimeOverride.end());
                    if (hasDefault && !(hold30 && isFiring)) {
                        if (isFiring && !wasFiring && burnIt->second > 0.0f)
                            FastWrite<float>(wire + 0xD5C, burnIt->second);
                    } else if (hold30 && isFiring) {
                        float holdVal = hasDefault ? burnIt->second : 30.0f;
                        if (holdVal > 0.0f) FastWrite<float>(wire + 0xD5C, holdVal);
                    }
                    s_BurnWasFiring[wire] = isFiring;
                }
            }

            // Drop burn state for wires that no longer exist.
            for (auto it = s_BoosterWireTimeOverride.begin(); it != s_BoosterWireTimeOverride.end(); ) {
                bool stillLive = false;
                for (uintptr_t w : seenBurnWires) { if (it->first == w) { stillLive = true; break; } }
                if (!stillLive) it = s_BoosterWireTimeOverride.erase(it);
                else ++it;
            }
            for (auto it = s_BurnWasFiring.begin(); it != s_BurnWasFiring.end(); ) {
                bool stillLive = false;
                for (uintptr_t w : seenBurnWires) { if (it->first == w) { stillLive = true; break; } }
                if (!stillLive) it = s_BurnWasFiring.erase(it);
                else ++it;
            }

            // Unbreakable tether stretch-limit bookkeeping: prune dead wires,
            // or restore every original m_MaxLength when the toggle turns off.
            if (g_TetherUnbreakable) {
                for (auto it = s_WireMaxLenBackup.begin(); it != s_WireMaxLenBackup.end(); ) {
                    bool stillLive = false;
                    for (uintptr_t w : seenAllWires) { if (it->first == w) { stillLive = true; break; } }
                    if (!stillLive) it = s_WireMaxLenBackup.erase(it);
                    else ++it;
                }
            } else if (!s_WireMaxLenBackup.empty()) {
                for (const auto& kv : s_WireMaxLenBackup) {
                    if (kv.first && IsLikelyGameObject(kv.first))
                        FastWrite<float>(kv.first + 0x370, kv.second);
                }
                s_WireMaxLenBackup.clear();
            }

            // Prune detached/dead booster engines from the instance map
            if (g_BoosterMapLockInited) {
                EnterCriticalSection(&g_BoosterMapLock);
                for (auto it = s_BoosterInstanceMap.begin(); it != s_BoosterInstanceMap.end(); ) {
                    bool isStillLive = false;
                    for (uintptr_t live : currentLiveEngines) {
                        if (it->first == live) {
                            isStillLive = true;
                            break;
                        }
                    }
                    if (!isStillLive) {
                        it = s_BoosterInstanceMap.erase(it);
                    } else {
                        ++it;
                    }
                }
                LeaveCriticalSection(&g_BoosterMapLock);
            }
        }
    }

    // 12. Per-Balloon Spawn-Time Latching Update (g_ExeBase + g_Addr_2CB4B28)
    static std::vector<uintptr_t> s_ConfiguredBalloons;
    static std::map<uintptr_t, float> s_BalloonAltDeltaLatch; // balloon -> creation-time lift height delta

    if (g_ExeBase) {
        uintptr_t bBegin = 0, bEnd = 0;
        if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB4B28, bBegin) &&
            FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB4B30, bEnd) &&
            bBegin && bEnd > bBegin && (bEnd - bBegin) <= 0x2000) {

            std::vector<uintptr_t> currentLiveBalloons;
            currentLiveBalloons.reserve(16);

            for (uintptr_t bCur = bBegin; bCur < bEnd; bCur += 8) {
                uintptr_t balloon = 0;
                if (!FastRead<uintptr_t>(bCur, balloon) || !balloon) continue;
                if (!IsLikelyGameObject(balloon)) continue;

                // Safety guard: ignore balloons currently popping or destroyed
                uint8_t isDestroyed = 0;
                FastRead<uint8_t>(balloon + 0x8FE, isDestroyed);
                if (isDestroyed != 0) continue;

                uint8_t isPopping = 0;
                FastRead<uint8_t>(balloon + 0x927, isPopping);
                if (isPopping != 0) continue;

                currentLiveBalloons.push_back(balloon);

                // Unbreakable: the balloon<>object tether gets a hard m_MaxLength
                // of 3.5 in ConnectTether, so the 1.2x stretch-snap pops lifter
                // balloons under load. Raise it too (restore 3.5 when toggled off).
                {
                    uintptr_t tw = 0;
                    if (FastRead<uintptr_t>(balloon + 0x8B0, tw) && tw && IsLikelyGameObject(tw)) {
                        if (g_TetherUnbreakable) {
                            FastWrite<float>(tw + 0x370, 10000000.0f);
                        } else {
                            float ml = 0.0f;
                            if (FastRead<float>(tw + 0x370, ml) && ml > 100000.0f)
                                FastWrite<float>(tw + 0x370, 3.5f);
                        }
                    }
                }

                // Check if this balloon instance was already configured
                bool alreadyConfigured = false;
                for (uintptr_t configured : s_ConfiguredBalloons) {
                    if (configured == balloon) {
                        alreadyConfigured = true;
                        break;
                    }
                }

                if (alreadyConfigured) {
                    // Enforce the creation-time altitude delta EVERY frame.
                    // ConnectTether runs after the balloon shows up in the world
                    // list and rewrites m_PeakHeight (+0x934) / m_TargetHeight
                    // (+0x930) from the retooler preset (preset 0 = "No Limit"
                    // writes TargetHeight=-1 = infinite full-thrust lift) - so a
                    // one-shot spawn write raced and randomly lost, leaving
                    // balloons that hover briefly then shoot sky-high forever.
                    auto latched = s_BalloonAltDeltaLatch.find(balloon);
                    if (latched != s_BalloonAltDeltaLatch.end() && latched->second > 0.0f) {
                        const float d = latched->second;
                        uint8_t tethered = 0;
                        FastRead<uint8_t>(balloon + 0x8FC, tethered); // m_IsTethered
                        if (tethered) {
                            float startY = 0.0f;
                            FastRead<float>(balloon + 0x928, startY);  // m_StartingHeight
                            FastWrite<float>(balloon + 0x934, d);      // m_PeakHeight
                            FastWrite<float>(balloon + 0x930, startY + d); // m_TargetHeight
                        }
                    }
                    continue;
                }

                // --- BAKE CREATION-TIME SETTINGS INTO NEW BALLOON ---

                // 1. Instance Lift Multiplier (+0x920)
                float liftMult = (g_BalloonLiftForce.overrideActive && g_BalloonLiftForce.customVal > 0.0f)
                                 ? g_BalloonLiftForce.customVal : 1.0f;
                FastWrite<float>(balloon + 0x920, liftMult);

                // 2. Instance Max Inflation Scale (+0x918)
                float sizeScale = (g_BalloonSize.overrideActive && g_BalloonSize.customVal > 0.0f)
                                  ? g_BalloonSize.customVal : 5.0f;
                FastWrite<float>(balloon + 0x918, sizeScale);

                // 3. Instance Altitude Delta: latch the creation-time value; it is
                // then enforced every frame above (see alreadyConfigured branch).
                if (g_BalloonAltitudeDelta.overrideActive && g_BalloonAltitudeDelta.customVal > 0.0f) {
                    s_BalloonAltDeltaLatch[balloon] = g_BalloonAltitudeDelta.customVal;
                }

                // 4. Instance Explosive Gas Payload (+0x944)
                if (g_BalloonExplosiveGas) {
                    FastWrite<uint8_t>(balloon + 0x944, 1);
                }

                // Mark balloon as configured
                s_ConfiguredBalloons.push_back(balloon);
            }

            // Prune popped/detached balloons from the tracking list
            for (int i = (int)s_ConfiguredBalloons.size() - 1; i >= 0; i--) {
                bool isStillLive = false;
                for (uintptr_t live : currentLiveBalloons) {
                    if (s_ConfiguredBalloons[i] == live) {
                        isStillLive = true;
                        break;
                    }
                }
                if (!isStillLive) {
                    s_BalloonAltDeltaLatch.erase(s_ConfiguredBalloons[i]);
                    s_ConfiguredBalloons.erase(s_ConfiguredBalloons.begin() + i);
                }
            }
        }
    }

    // 12. Unbreakable Tether Tension Thresholds (0x14, 0x17C, 0x180, 0x184)
    if (g_TetherUnbreakable) {
        FastWrite<float>(t + 0x17C, 10000000.0f);
        FastWrite<float>(t + 0x180, 10000000.0f);
        FastWrite<float>(t + 0x184, 10000000.0f);
        FastWrite<float>(t + 0x14,  10000000.0f);
    } else if (s_GrappleDefaultsCaptured && g_DefTensionSnap > 0.0f) {
        FastWrite<float>(t + 0x17C, g_DefTensionSnap);
        FastWrite<float>(t + 0x180, g_DefTensionTear);
        FastWrite<float>(t + 0x184, g_DefTensionTimer);
        FastWrite<float>(t + 0x14,  g_DefTetherBreakScale);
    }
}

void DrawGrappleSection() {
    DrawSectionHeader("GRAPPLING HOOK & RETRACTOR");

    uintptr_t hook = GetGrappleHookPtr();
    uintptr_t tuning = GetGrappleTuningPtr();
    if (!tuning) {
        ImGui::TextDisabled("Grappling hook unavailable (must be in-game).");
        return;
    }

    // Query newest active wire for live reading (scans backwards from newest to oldest)
    uintptr_t activeWire = 0;
    if (hook) {
        uintptr_t wBegin = 0, wEnd = 0;
        if (FastRead<uintptr_t>(hook + 0x610, wBegin) && FastRead<uintptr_t>(hook + 0x618, wEnd) && wBegin && wEnd > wBegin && (wEnd - wBegin) <= 0x10000) {
            for (uintptr_t cur = wEnd - 0x10; cur >= wBegin; cur -= 0x10) {
                uintptr_t candWire = 0;
                if (!FastRead<uintptr_t>(cur, candWire) || !candWire) continue;
                if (!IsLikelyGameObject(candWire)) continue;

                int candState = 0;
                FastRead<int>(candWire + 0x368, candState);
                if (candState == 3) continue; // Skip dead wires, accept State 0, 1, and 2

                activeWire = candWire;
                break;
            }
        }
    }

    // Query newest active, connected balloon for live reading (scans backwards from newest to oldest)
    uintptr_t activeBalloon = 0;
    bool hasActiveBalloon = false;
    if (g_ExeBase) {
        uintptr_t bBegin = 0, bEnd = 0;
        if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB4B28, bBegin) &&
            FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB4B30, bEnd) &&
            bBegin && bEnd > bBegin && (bEnd - bBegin) <= 0x10000) {
            for (uintptr_t bCur = bEnd - 8; bCur >= bBegin; bCur -= 8) {
                uintptr_t cand = 0;
                if (FastRead<uintptr_t>(bCur, cand) && cand) {
                    uint8_t isConnected = 0;
                    FastRead<uint8_t>(cand + 0x8FC, isConnected);
                    if (isConnected != 0) {
                        activeBalloon = cand;
                        hasActiveBalloon = true;
                        break;
                    }
                }
                if (bCur == bBegin) break;
            }
        }
    }

    auto DrawGrappleInput = [&](const char* label, const char* id, GrappleSetting& s, float liveVal, const char* note) {
        ImGui::PushID(id);
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(label);
        ImGui::SameLine(220.0f * g_UIScale);

        bool enabled = s.overrideActive;
        if (ImGui::Checkbox("Override", &enabled)) {
            s.overrideActive = enabled;
            if (enabled && s.customVal <= 0.0f) {
                s.customVal = liveVal;
            }
        }

        ImGui::SameLine();
        ImGui::SetNextItemWidth(130.0f * g_UIScale);
        if (s.overrideActive) {
            ImGui::InputFloat("##input", &s.customVal, 10.0f, 50.0f, "%.1f");
        } else {
            ImGui::BeginDisabled();
            float temp = liveVal;
            ImGui::InputFloat("##input", &temp, 0.0f, 0.0f, "%.1f");
            ImGui::EndDisabled();
        }

        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
        ImGui::Text("(Live: %.1f)", liveVal);
        ImGui::PopStyleColor();

        if (note && note[0]) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
            ImGui::Text("    %s", note);
            ImGui::PopStyleColor();
        }
        ImGui::Spacing();

        ImGui::PopID();
    };

    float liveReach = 0.0f, liveFlight = 0.0f, liveReelSpd = 0.0f, liveReelAcc = 0.0f;
    float livePullForce = 0.0f, liveRetractSpd = 0.0f;

    FastRead<float>(tuning + 0x00, liveReach);
    FastRead<float>(tuning + 0x6C, liveFlight);
    FastRead<float>(tuning + 0x28, liveReelSpd);
    FastRead<float>(tuning + 0x38, liveReelAcc);

    if (activeWire) {
        FastRead<float>(activeWire + 0x30C, livePullForce);
        FastRead<float>(activeWire + 0x318, liveRetractSpd);
    } else {
        FastRead<float>(tuning + 0x18C, livePullForce);
        FastRead<float>(tuning + 0x1BC, liveRetractSpd);
    }

    DrawGrappleInput("Grapple Max Reach",         "##g_reach",          g_GrappleReach,       liveReach,       "Maximum distance you can grapple to.");
    DrawGrappleInput("Hook Flight Speed",         "##g_flight",         g_GrappleFlight,      liveFlight,      "Speed the hook claw shoots out. Recommended: >50000");
    DrawGrappleInput("Grapple Reel Speed",        "##g_reelspeed",      g_GrappleReelSpd,     liveReelSpd,     "How fast Rico pulls toward the grapple point.");
    DrawGrappleInput("Grapple Reel Acceleration", "##g_reelaccel",      g_GrappleReelAcc,     liveReelAcc,     "How fast Rico speeds up while pulling.");
    DrawGrappleInput("Tether Retract Pull Force",         "##g_tetherforce",    g_TetherPullForce,    livePullForce,   "Pull acceleration and force between tethered objects when retracting tethers.");
    DrawGrappleInput("Tether Retract Speed",      "##g_tetherspeed",    g_TetherRetractSpeed, liveRetractSpd,  "Maximum velocity ceiling when retracting tethers.");

    ImGui::Spacing();
    if (ImGui::Checkbox("Unbreakable Tether (No Snapping)", &g_TetherUnbreakable)) {
        if (!g_TetherUnbreakable && s_GrappleDefaultsCaptured && g_DefTensionSnap > 0.0f) {
            FastWrite<float>(tuning + 0x17C, g_DefTensionSnap);
            FastWrite<float>(tuning + 0x180, g_DefTensionTear);
            FastWrite<float>(tuning + 0x184, g_DefTensionTimer);
            FastWrite<float>(tuning + 0x14,  g_DefTetherBreakScale);
        }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("[ ? ]");
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
        ImGui::TextUnformatted("Prevents dual tethers from snapping or tearing under extreme physical tension.");
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }

    ImGui::Spacing();
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Tether Wires Capacity");
    ImGui::SameLine(220.0f * g_UIScale);

    ImGui::Checkbox("Override##TetherCap", &g_OverrideTethers);

    if (g_OverrideTethers) {
        ImGui::SameLine();
        ImGui::Checkbox("Unlimited", &g_UnlimitedTethers);
        ImGui::SameLine();
        ImGui::TextDisabled("[ ? ]");
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
            ImGui::TextUnformatted("Completely removes the tether limit. Newly placed tethers will never cause older tethers to detach and disappear.");
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }

        if (!g_UnlimitedTethers) {
            ImGui::AlignTextToFramePadding();
            ImGui::Text("    Custom Tether Limit:");
            ImGui::SameLine(220.0f * g_UIScale);
            ImGui::SetNextItemWidth(130.0f * g_UIScale);
            if (ImGui::SliderInt("##MaxTethersCount", &g_MaxTethersCount, 2, 100)) {
                if (g_MaxTethersCount < 2) g_MaxTethersCount = 2;
                if (g_MaxTethersCount > 100) g_MaxTethersCount = 100;
            }
            ImGui::SameLine();
            ImGui::TextDisabled("(Default: 10)");
        }
    } else {
        ImGui::SameLine();
        ImGui::TextDisabled("(Vanilla Engine Behavior)");
    }

    // ------------------------------------------------------------------------
    // SECTION: BOOSTER MOD
    // ------------------------------------------------------------------------
    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
    ImGui::TextWrapped("Reminder: Each placed booster and lifter keeps its own values. Changing a setting only affects wires placed afterwards, and wires already out keep what they were created with.");
    ImGui::PopStyleColor();
    ImGui::Spacing();
    DrawSectionHeader("BOOSTER TETHERS");

    float liveBoostForce = 0.0f, liveBoostSpeed = 0.0f, liveBoostSpool = 0.0f;
    bool hasActiveBooster = false;

    // Helper: Resolve equipped loadout defaults dynamically from tuning template
    auto GetEquippedDefaults = [&](float& outForce, float& outSpeed, float& outSpool) {
        outForce = (g_DefBoosterForce[1] > 0.0f) ? g_DefBoosterForce[1] : g_DefBoosterForce[0];
        if (outForce <= 0.0f) FastRead<float>(tuning + 0x1E8, outForce);
        if (outForce <= 0.0f) FastRead<float>(tuning + 0x1E0, outForce);
        outSpeed = 50.0f;
        outSpool = 0.2f;
    };

    if (activeWire && IsBoosterTetherWire(activeWire)) {
        uintptr_t engine = activeWire + 0x8F8;
        bool foundInMap = false;

        if (g_BoosterMapLockInited) {
            EnterCriticalSection(&g_BoosterMapLock);
            auto it = s_BoosterInstanceMap.find(engine);
            if (it != s_BoosterInstanceMap.end()) {
                liveBoostForce = it->second.force;
                liveBoostSpeed = it->second.speed;
                liveBoostSpool = it->second.spool;
                foundInMap = true;
            }
            LeaveCriticalSection(&g_BoosterMapLock);
        }

        if (!foundInMap) {
            FastRead<float>(activeWire + 0xB28, liveBoostForce);
            FastRead<float>(activeWire + 0xB24, liveBoostSpeed);
            FastRead<float>(activeWire + 0xB2C, liveBoostSpool);
        }

        // If booster is placed but idle, display the equipped loadout defaults
        if (liveBoostForce <= 0.0f || liveBoostSpeed <= 0.0f || liveBoostSpool <= 0.0f) {
            float defF = 0.0f, defS = 0.0f, defSp = 0.0f;
            GetEquippedDefaults(defF, defS, defSp);
            if (liveBoostForce <= 0.0f) liveBoostForce = defF;
            if (liveBoostSpeed <= 0.0f) liveBoostSpeed = defS;
            if (liveBoostSpool <= 0.0f) liveBoostSpool = defSp;
        }

        hasActiveBooster = true;
    } else {
        // No wires placed: display the equipped loadout defaults across all fields
        GetEquippedDefaults(liveBoostForce, liveBoostSpeed, liveBoostSpool);
    }

    DrawGrappleInput("Booster Thrust Force",      "##b_force",   g_BoosterForce,        liveBoostForce, "Acceleration and push impulse applied to attached object.");

    // Booster Speed Input (with explicit None Active state)
    ImGui::PushID("##b_speed");
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Booster Target Max Speed");
    ImGui::SameLine(220.0f * g_UIScale);

    bool bSpeedEnabled = g_BoosterSpeed.overrideActive;
    if (ImGui::Checkbox("Override", &bSpeedEnabled)) {
        g_BoosterSpeed.overrideActive = bSpeedEnabled;
        if (bSpeedEnabled && g_BoosterSpeed.customVal <= 0.0f) {
            g_BoosterSpeed.customVal = (liveBoostSpeed > 0.0f) ? liveBoostSpeed : 50.0f;
        }
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(130.0f * g_UIScale);
    if (g_BoosterSpeed.overrideActive) {
        ImGui::InputFloat("##input", &g_BoosterSpeed.customVal, 10.0f, 50.0f, "%.1f");
    } else {
        ImGui::BeginDisabled();
        float temp = hasActiveBooster ? liveBoostSpeed : 50.0f;
        ImGui::InputFloat("##input", &temp, 0.0f, 0.0f, "%.1f");
        ImGui::EndDisabled();
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
    if (hasActiveBooster) {
        ImGui::Text("(Live: %.1f)", liveBoostSpeed);
    } else {
        ImGui::Text("(Live: None Active)");
    }
    ImGui::PopStyleColor();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
    ImGui::Text("    Target velocity limit for the booster.");
    ImGui::PopStyleColor();
    ImGui::Spacing();
    ImGui::PopID();

    DrawGrappleInput("Booster Spool-Up Time",     "##b_spool",   g_BoosterSpool,        liveBoostSpool, "Ramp-up duration (in seconds) to reach 100% full burn thrust.");

    if (ImGui::Checkbox("Make 30s boosters infinite", &g_BoosterLockOnly30s)) {
        UpdateRetoolerBoosterIcon(g_BoosterLockOnly30s);
    }
    ImGui::SameLine();
    ImGui::TextDisabled("[ ? ]");
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Boosters set to the 30s preset in the loadout menu burn indefinitely.\nBoosters set to 2s, 5s, etc. expire and detach as normal.");
    }
    ImGui::Spacing();

    // Dropdown: every live booster wire with its own burn time + detach.
    {
        std::vector<uintptr_t> boosterWires;
        if (hook) {
            uintptr_t wBegin = 0, wEnd = 0;
            if (FastRead<uintptr_t>(hook + 0x610, wBegin) && FastRead<uintptr_t>(hook + 0x618, wEnd) &&
                wBegin && wEnd > wBegin && (wEnd - wBegin) <= 0x10000) {
                for (uintptr_t cur = wBegin; cur < wEnd; cur += 0x10) {
                    uintptr_t w = 0;
                    if (!FastRead<uintptr_t>(cur, w) || !w || !IsLikelyGameObject(w)) continue;
                    int st = 0;
                    FastRead<int>(w + 0x368, st);
                    if (st == 3) continue;
                    if (!IsBoosterTetherWire(w)) continue; // skip retractor/lifter-only tethers
                    boosterWires.push_back(w);
                }
            }
        }
        char boosterHeader[96];
        snprintf(boosterHeader, sizeof(boosterHeader), "Active Boosters (%d)###ActiveBoosters", (int)boosterWires.size());
        if (ImGui::CollapsingHeader(boosterHeader)) {
            if (boosterWires.empty()) {
                ImGui::TextDisabled("No active boosters.");
            }
            int idx = 0;
            for (uintptr_t w : boosterWires) {
                ImGui::PushID((void*)w);
                uint8_t firing = 0, flagged = 0;
                FastRead<uint8_t>(w + 0x332, firing);
                FastRead<uint8_t>(w + 0xD66, flagged);
                float timer = 0.0f;
                FastRead<float>(w + 0xD5C, timer);
                const bool isFiring = (firing || flagged);
                int preset = 0;
                FastRead<int>(w + 0x344, preset);
                float presetSecs = 2.0f;
                if (preset == 1) presetSecs = 5.0f;
                else if (preset == 2) presetSecs = 10.0f;
                else if (preset == 3) presetSecs = 15.0f;
                else if (preset == 4) presetSecs = 30.0f;

                char rowLabel[48];
                if (isFiring) snprintf(rowLabel, sizeof(rowLabel), "Booster %d - Firing", idx + 1);
                else snprintf(rowLabel, sizeof(rowLabel), "Booster %d - Idle", idx + 1);
                ImGui::AlignTextToFramePadding();
                ImGui::TextUnformatted(rowLabel);
                ImGui::SameLine(220.0f * g_UIScale);

                // The box always tracks live: countdown while firing, own
                // default or preset while idle. Only idle edits change the
                // default; firing edits just nudge this burn.
                float v = 0.0f;
                auto wit = s_BoosterWireTimeOverride.find(w);
                if (isFiring && timer > 0.0f) v = timer;
                else if (wit != s_BoosterWireTimeOverride.end()) v = wit->second;
                else v = presetSecs;
                ImGui::SetNextItemWidth(110.0f * g_UIScale);
                const bool heldWire = (g_BoosterLockOnly30s && preset == 4);
                if (ImGui::InputFloat("##btime", &v, 1.0f, 5.0f, "%.1fs")) {
                    if (v > 0.0f && v < 3600.0f) {
                        if (isFiring && heldWire) {
                            s_BoosterWireTimeOverride[w] = v;
                            FastWrite<float>(w + 0xD5C, v);
                        } else if (isFiring) {
                            FastWrite<float>(w + 0xD5C, v);
                        } else {
                            s_BoosterWireTimeOverride[w] = v;
                        }
                    }
                }
                ImGui::SameLine();
                if (ImGui::SmallButton("R")) {
                    s_BoosterWireTimeOverride.erase(w);
                    if (isFiring) FastWrite<float>(w + 0xD5C, presetSecs);
                }
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("Reset this booster's timer to its preset length.");
                ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
                if (isFiring) ImGui::Text("(Live: %.1fs)", timer);
                else ImGui::Text("(Preset: %.0fs)", presetSecs);
                ImGui::PopStyleColor();
                ImGui::SameLine();
                if (ImGui::SmallButton("Detach")) {
                    int st = 0;
                    FastRead<int>(w + 0x368, st);
                    if (w && IsLikelyGameObject(w) && st != 3 && o_WireBreak && VH_IsExeCode((uintptr_t)o_WireBreak, 16))
                        o_WireBreak(w);
                    s_BoosterWireTimeOverride.erase(w);
                }
                ImGui::PopID();
                idx++;
            }
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
            ImGui::TextWrapped("Edit at idle to set a booster's default burn; edit mid-burn to stretch just this burn. R refills it to its preset length. Detach removes the wire.");
            ImGui::PopStyleColor();
            ImGui::Spacing();
        }
    }

    // ------------------------------------------------------------------------
    // SECTION: AIR LIFTER (BALLOONS)
    // ------------------------------------------------------------------------
    DrawSectionHeader("AIR LIFTER (BALLOONS)");

    float liveLiftForce = 1.0f, liveBalloonSize = 5.0f, liveAltitudeDelta = 15.0f;
    if (activeBalloon) {
        FastRead<float>(activeBalloon + 0x920, liveLiftForce);
        FastRead<float>(activeBalloon + 0x918, liveBalloonSize);
        FastRead<float>(activeBalloon + 0x934, liveAltitudeDelta);
    } else if (activeWire) {
        FastRead<float>(activeWire + 0x300, liveLiftForce);
    } else {
        FastRead<float>(tuning + 0x210, liveLiftForce);
    }

    DrawGrappleInput("Upward Lift Multiplier",           "##l_force",    g_BalloonLiftForce,         liveLiftForce,         "Buoyancy pull force multiplier lifting objects upward.");
    DrawGrappleInput("Max Inflation Size Scale",         "##l_size",     g_BalloonSize,              liveBalloonSize,       "Visual and physical inflation size scale of the balloon.");

    // Lift Height Delta with explicit None Active state
    ImGui::PushID("##l_altdelta");
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Lift Height Delta");
    ImGui::SameLine(220.0f * g_UIScale);

    bool bAltEnabled = g_BalloonAltitudeDelta.overrideActive;
    if (ImGui::Checkbox("Override", &bAltEnabled)) {
        g_BalloonAltitudeDelta.overrideActive = bAltEnabled;
        if (bAltEnabled && g_BalloonAltitudeDelta.customVal <= 0.0f) {
            g_BalloonAltitudeDelta.customVal = hasActiveBalloon ? liveAltitudeDelta : 15.0f;
        }
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(130.0f * g_UIScale);
    if (g_BalloonAltitudeDelta.overrideActive) {
        ImGui::InputFloat("##input", &g_BalloonAltitudeDelta.customVal, 10.0f, 50.0f, "%.0fm");
    } else {
        ImGui::BeginDisabled();
        float temp = hasActiveBalloon ? liveAltitudeDelta : 15.0f;
        ImGui::InputFloat("##input", &temp, 0.0f, 0.0f, "%.0fm");
        ImGui::EndDisabled();
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
    if (hasActiveBalloon) {
        ImGui::Text("(Live: %.0fm)", liveAltitudeDelta);
    } else {
        ImGui::Text("(Live: None Active)");
    }
    ImGui::PopStyleColor();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
    ImGui::Text("    Height in meters the balloon lifts the object above its attachment point.");
    ImGui::PopStyleColor();
    ImGui::Spacing();
    ImGui::PopID();

    ImGui::Spacing();
    ImGui::Checkbox("Explosive Gas Balloons", &g_BalloonExplosiveGas);
    ImGui::SameLine();
    ImGui::TextDisabled("[ ? ]");
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
        ImGui::TextUnformatted("Arm balloons with explosive gas. Detonates with high explosive force upon popping or release.");
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }

    ImGui::Dummy(ImVec2(0.0f, 30.0f * g_UIScale));
}
// ============================================================================
// MENU RENDERING LOGIC
// ============================================================================
void DrawMenuUI() {
    DWORD now = GetTickCount();
    ImGuiIO& io = ImGui::GetIO();
    float screenW = io.DisplaySize.x;
    float screenH = io.DisplaySize.y;
    if (screenW <= 100.0f || screenH <= 100.0f) return;
    float winW = screenW * 0.42f;
    float winH = screenH * 0.72f;
    if (winW < 580.0f * g_UIScale) winW = 580.0f * g_UIScale;
    if (winH < 460.0f * g_UIScale) winH = 460.0f * g_UIScale;
    if (winW > screenW * 0.95f)    winW = screenW * 0.95f;
    if (winH > screenH * 0.95f)    winH = screenH * 0.95f;

    static float s_LastMenuW = 0.0f;
    static float s_LastMenuH = 0.0f;
    static float s_LastScale = 0.0f;
    bool resChanged = (s_LastMenuW > 100.0f && s_LastMenuH > 100.0f &&
                      (fabsf(screenW - s_LastMenuW) > 1.0f || fabsf(screenH - s_LastMenuH) > 1.0f));
    bool scaleChanged = (s_LastScale > 0.1f && fabsf(g_UIScale - s_LastScale) > 0.01f);
    ImGuiCond cond = (resChanged || scaleChanged) ? ImGuiCond_Always : ImGuiCond_FirstUseEver;

    s_LastMenuW = screenW;
    s_LastMenuH = screenH;
    s_LastScale = g_UIScale;

    ImGui::SetNextWindowPos(ImVec2(screenW * 0.03f, screenH * 0.12f), cond);
    ImGui::SetNextWindowSize(ImVec2(winW, winH), cond);
    ImGui::SetNextWindowSizeConstraints(ImVec2(500.0f * g_UIScale, 400.0f * g_UIScale),
                                        ImVec2(screenW * 0.95f, screenH * 0.95f));

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, g_MenuAlpha);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse;
    ImGui::Begin("##EnhancedModMenu", nullptr, flags);

    ImGui::PopStyleVar();
    {
        ImVec2 cursor = ImGui::GetCursorScreenPos();
        ImVec2 size(ImGui::GetContentRegionAvail().x, 44.0f * g_UIScale);
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(cursor, ImVec2(cursor.x + size.x, cursor.y + size.y), IM_COL32(30, 24, 50, 255));
        dl->AddRectFilledMultiColor(cursor, ImVec2(cursor.x + size.x, cursor.y + size.y),
                                    IM_COL32(40, 30, 70, 255), IM_COL32(80, 50, 140, 255),
                                    IM_COL32(80, 50, 140, 255), IM_COL32(40, 30, 70, 255));

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.85f, 0.75f, 1.0f, 1.0f));
        ImGui::SetCursorScreenPos(ImVec2(cursor.x + 18.0f * g_UIScale, cursor.y + 8.0f * g_UIScale));
        ImGui::TextUnformatted("JUST CAUSE 4");
        ImGui::SameLine(0.0f, 12.0f * g_UIScale);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.85f, 0.60f, 1.0f));
        ImGui::Text("Mod Menu Version: %s", kModMenuVersion);
        ImGui::PopStyleColor();
        ImGui::SetCursorScreenPos(ImVec2(cursor.x + 18.0f * g_UIScale, cursor.y + 24.0f * g_UIScale));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.45f, 0.55f, 1.0f));
        ImGui::TextUnformatted("MOD MENU");
        ImGui::SameLine(0.0f, 12.0f * g_UIScale);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.85f, 0.60f, 1.0f));
        ImGui::Text("Platform: %s", GetPlatformName());
        ImGui::PopStyleColor();
        ImGui::PopStyleColor(2);

        ImGui::SetCursorScreenPos(ImVec2(cursor.x + size.x - 120.0f * g_UIScale, cursor.y + 14.0f * g_UIScale));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.40f, 0.42f, 0.50f, 1.0f));
        ImGui::TextUnformatted("[Key Toggle]");
        ImGui::PopStyleColor();

        ImGui::SetCursorScreenPos(ImVec2(cursor.x, cursor.y + size.y + 4.0f));
    }

    float sidebarW = 140.0f * g_UIScale;
    float contentH = ImGui::GetContentRegionAvail().y;

    ImGui::BeginChild("##Sidebar", ImVec2(sidebarW, contentH), false, ImGuiWindowFlags_NoScrollbar);
    {
        const char* tabs[] = {"Toggles", "Wingsuit", "Weather", "Player", "Spawn", "Global", "Tornado", "Heat", "Missions", "Time", "Teleport"};
for (int i = 0; i < 11; i++) {
            bool selected = (g_CurrentTab == i);
            ImVec2 pos = ImGui::GetCursorScreenPos();

            if (selected) {
                ImDrawList* dl = ImGui::GetWindowDrawList();
                dl->AddRectFilled(pos, ImVec2(pos.x + 3.0f, pos.y + 34.0f * g_UIScale), IM_COL32(149, 102, 255, 255), 2.0f);
            }

            if (selected) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.18f, 0.15f, 0.28f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.22f, 0.18f, 0.35f, 1.0f));
            } else {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.12f, 0.13f, 0.17f, 0.5f));
            }

            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.55f, 0.38f, 0.96f, 0.4f));
            ImGui::PushStyleColor(ImGuiCol_Text, selected ? ImVec4(0.85f, 0.75f, 1.0f, 1.0f) : ImVec4(0.60f, 0.62f, 0.68f, 1.0f));

            if (ImGui::Button(tabs[i], ImVec2(-1, 34.0f * g_UIScale))) {
g_CurrentTab = i;
g_AssigningFavoriteKey = false;
s_TorCapture = -1; // cancel tornado keybind capture when leaving the Tornado tab
}
            ImGui::PopStyleColor(4);
            ImGui::Spacing();
        }

        ImGui::Dummy(ImVec2(0, 20.0f * g_UIScale));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.35f, 0.37f, 0.42f, 1.0f));
        char scale_text[32];
        snprintf(scale_text, sizeof(scale_text), "Scale: %.1fx", g_UIScale);
        float text_width = ImGui::CalcTextSize(scale_text).x;
        float avail_width = ImGui::GetContentRegionAvail().x;
        if (avail_width > text_width)
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (avail_width - text_width) * 0.5f);
        ImGui::TextUnformatted(scale_text);
        ImGui::PopStyleColor();
        
        ImGui::SetNextItemWidth(-1);
        static float temp_scale = -1.0f;
        if (temp_scale < 0.0f) temp_scale = g_UIScale; // Sync if config changed it
        ImGui::SliderFloat("##ScaleSlider", &temp_scale, 0.5f, 3.0f, "%.1f");
        if (ImGui::IsItemDeactivatedAfterEdit()) {
            g_UIScale = temp_scale;
            ApplyEnhancedStyle();
            ImGui::GetIO().FontGlobalScale = g_UIScale;
        }

        ImGui::Spacing();
        if (g_FreezeGame) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.55f, 0.38f, 0.96f, 0.80f));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.14f, 0.15f, 0.20f, 1.00f));
        }
        if (ImGui::Button("Freeze game in menu", ImVec2(-1, 0))) {
            g_FreezeGame = !g_FreezeGame;
        }
        ImGui::PopStyleColor();

        ImGui::Spacing();
        if (ImGui::Button("Save Config", ImVec2(-1, 0))) {
            g_SavePopupState = SAVE_SAVING;
            g_SavePopupStartTime = ImGui::GetTime();
        }
    }
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##Content", ImVec2(0, contentH), false);
    {
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.0f * g_UIScale, 12.0f * g_UIScale));
        ImGui::BeginChild("##ContentInner", ImVec2(0, 0), false);
        ImGui::PopStyleVar();

        if (g_CurrentTab == 6) {
            DrawTornadoTab();
        }
        else if (g_CurrentTab == 7) {
            DrawHeatTab();
        }
        else if (g_CurrentTab == 8) {
    DrawOtherTab();
}
else if (g_CurrentTab == 9) {
    DrawTimeTab();
}
else if (g_CurrentTab == 10) {
    DrawTeleportTab();
}
        else if (g_CurrentTab == 0) {
            DrawSectionHeader("GAMEPLAY TOGGLES");
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12.0f, 8.0f));
            if (ImGui::Checkbox("Infinite Wingsuit Boost", &g_InfBoost)) ToggleInfBoost(g_InfBoost);
            ImGui::Spacing();
            if (ImGui::Checkbox("Infinite Wingsuit Missiles", &g_InfMissiles)) ToggleInfMissiles(g_InfMissiles);
            ImGui::Spacing();
            if (ImGui::Checkbox("All Vehicles Invincible", &g_VehiclesInvincible)) ToggleVehiclesInvincible(g_VehiclesInvincible);
            if (g_VehiclesInvincible) {
                ImGui::Indent(20.0f * g_UIScale);
                if (ImGui::Checkbox("Only Rico's Vehicle##Invincibility", &g_VehiclesInvinciblePlayerOnly)) WriteConfig();
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("When enabled, only the vehicle Rico is currently driving/sitting in is immune to damage.\nEvery other vehicle in the world stays destructible.");
                }
                ImGui::Unindent(20.0f * g_UIScale);
            }
            ImGui::Spacing();
            if (ImGui::Checkbox("Hide UI (HUD)", &g_HideUI)) {
                ApplyHideUI(g_HideUI);
                WriteConfig();
            }
            ImGui::Spacing();
            ImGui::Checkbox("Rainbow Vehicles", &g_RainbowVehicles);
            if (g_RainbowVehicles) {
                ImGui::Indent(20.0f * g_UIScale);
                ImGui::Checkbox("Only Rico's Vehicle##Rainbow", &g_RainbowPlayerOnly);
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("When enabled, only the vehicle Rico is currently driving/sitting in will change colors.");
                }
                ImGui::SetNextItemWidth(160.0f * g_UIScale);
                ImGui::SliderInt("Change Every N Frames", &g_RainbowSpeed, 1, 30);
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("1 = Changes color every single frame (Fastest)\n6 = ~10-15 shifts per second");
                }
                ImGui::Unindent(20.0f * g_UIScale);
            }
            ImGui::Spacing();

            ImGui::Checkbox("Real Global Speedometer HUD", &g_ShowSpeedometer);
            if (g_ShowSpeedometer) {
                ImGui::SameLine();
                if (ImGui::SmallButton("Resize##SpeedoBtn")) {
                    g_ResizeMode = RESIZE_SPEEDOMETER;
                    g_ShowMenu = false;
                }
            }
            ImGui::Spacing();

            if (ImGui::Checkbox("Replace vehicle stock dials with accurate speed km/h", &g_SpeedoReplaceGameHUD)) {
                WriteConfig();
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Makes vehicles speedometers HUDs read the accurate speed in km/h rather than the inaccurate stock representation.");
            }
            ImGui::Spacing();

            ImGui::Checkbox("Show Heat Status", &g_ShowHeatStatus);
            if (g_ShowHeatStatus) {
                ImGui::SameLine();
                if (ImGui::SmallButton("Resize##HeatBtn")) {
                    g_ResizeMode = RESIZE_HEAT;
                    g_ShowMenu = false;
                }
                ImGui::Indent(20.0f * g_UIScale);
                ImGui::Checkbox("Always show heat status", &g_AlwaysShowHeatStatus);
                ImGui::Unindent(20.0f * g_UIScale);
            }
            ImGui::Spacing();

            ImGui::Checkbox("Vehicle ESP Overlay (For Debugging)", &g_VehicleESP);
            if (g_VehicleESP) {
                ImGui::SameLine();
                if (ImGui::SmallButton("Resize##ESPBtn")) {
                    g_ResizeMode = RESIZE_VEHICLE_ESP;
                    g_ShowMenu = false;
                }
            }
            ImGui::Spacing();
            ImGui::Checkbox("Visualize Car Splines ESP (For Debugging)", &g_CarSplineESP);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Distance Fog", &g_DisableDistanceFog);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Ground Fog", &g_DisableGroundHaze);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Atmospheric Scattering", &g_DisableAtmosphericScattering);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Volumetric Clouds", &g_DisableClouds);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Screen Space Reflections", &g_DisableSSReflections);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Motion Blur", &g_DisableMotionBlur);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Radial Blur (Speed Blur)", &g_DisableRadialBlur);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Velocity Reprojection", &g_DisableVelocityReprojection);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Edge Stencil", &g_DisableEdgeStencil);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Water Reflections", &g_DisableWaterReflections);
            ImGui::Spacing();
            ImGui::Checkbox("Disable Global Shadows", &g_DisableShadows);
            ImGui::Spacing();
            if (ImGui::Checkbox("Disable Mountain Shadows", &g_DisableMountainShadows)) ToggleMountainShadows(g_DisableMountainShadows);
            ImGui::Spacing();
            
            // --- Custom Ocean, Lakes & Rivers Controls Block ---
            if (ImGui::Checkbox("Disable Ocean & Lakes & Rivers", &g_DisableOcean)) {
                OnMainOceanToggleChanged();
            }
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0)); // Flat clear icon button style
            if (ImGui::Button("[ ⚙ ]")) {
                ImGui::OpenPopup("ocean_detailed_settings");
            }
            ImGui::PopStyleColor();

            if (ImGui::BeginPopup("ocean_detailed_settings")) {
                ImGui::TextUnformatted("Water Bypass Configurations");
                ImGui::Separator();
                ImGui::Spacing();
                
                if (ImGui::Checkbox("Water & Ocean Visuals", &g_OceanSubVisuals)) OnSubOceanToggleChanged();
                ImGui::Spacing();
                if (ImGui::Checkbox("Swimming & Oxygen States", &g_OceanSubStates)) OnSubOceanToggleChanged();
                ImGui::Spacing();
                if (ImGui::Checkbox("Camera Surface Snap Fix", &g_OceanSubCamera)) OnSubOceanToggleChanged();
                ImGui::Spacing();
                if (ImGui::Checkbox("Vehicle Buoyancy & Physics", &g_OceanSubPhysics)) OnSubOceanToggleChanged();
                ImGui::Spacing();
                if (ImGui::Checkbox("Vehicle Seabed Entry Prompts", &g_OceanSubEntry)) OnSubOceanToggleChanged();
                
                ImGui::EndPopup();
            }

            ImGui::Spacing();

            if (ImGui::Checkbox("Disable Foliage (Visuals & Collision)", &g_DisableFoliage)) {
                // Rate-limit the toggle: flipping it faster than the engine's
                // vegetation reload can drain desyncs the foliage from its
                // collision patch maps. A rejected click is undone in the SAME
                // frame so the checkbox never visibly flickers; the cooldown
                // itself is armed by the per-frame driver (FoliageToggleLocked
                // is a pure query and never arms it).
                if (FoliageToggleLocked()) g_DisableFoliage = !g_DisableFoliage;
            }
            if (FoliageToggleLocked()) {
                ImGui::SameLine();
                ImGui::TextDisabled("(cooldown %.1fs)",
                    (double)(DWORD)(kFoliageToggleCooldownMs -
                                    (DWORD)(GetTickCount() - s_FoliageLastToggleMs)) / 1000.0);
            }
            ImGui::SameLine();
            ImGui::TextDisabled("[ ? ]");
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
                ImGui::TextUnformatted("Toggles on and off the landscape vegetation system.");
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }

            ImGui::Spacing();
            if (ImGui::Checkbox("DEBUG: No start login", &g_DebugNoLogin)) {
                ToggleNoLogin(g_DebugNoLogin);
            }
            ImGui::SameLine();
            ImGui::TextDisabled("[ ? ]");
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
                ImGui::TextUnformatted("Makes the game go to offline mode after getting a failed login, only for debugging purposes.");
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }

            DrawSectionHeader("WORLD MESH & GROUND QUALITY (HIGHLY EXPERIMENTAL)");

            // Startup-only terrain mode: this control saves a preference only.
            {
                auto terrain = JC4TerrainSettings::GetSnapshot();
                const char* sizes[] = {"8 x 8 - Stock (256 slots)", "16 x 16 - Expanded (1,024 slots)"};
                int selected = terrain.savedWidth == 16 ? 1 : 0;
                ImGui::TextUnformatted("Terrain patch grid (restart required)");
                ImGui::SetNextItemWidth(300.0f * g_UIScale);
                if (ImGui::Combo("##TerrainPatchGridStartup", &selected, sizes, 2)) {
                    JC4TerrainSettings::SaveRequestedWidth(selected == 1 ? 16 : 8);
                    terrain = JC4TerrainSettings::GetSnapshot();
                }
                if (ImGui::IsItemHovered()) {
                    ImGui::BeginTooltip();
                    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
                    ImGui::TextUnformatted("Expands the ground slots that the game loads into the memory.\n"
                        "May make the ground and terrain around the player higher quality.\n"
                        "A full game restart is required whenever this is altered.\n"
                        "Memory usage is heavily affected by this option."
                        );
                    ImGui::PopTextWrapPos();
                    ImGui::EndTooltip();
                }
                ImGui::Text("Active this session: %d x %d (%d patch slots)",
                    terrain.activeWidth, terrain.activeWidth, 4 * terrain.activeWidth * terrain.activeWidth);
                ImGui::Text("Saved for next launch: %d x %d", terrain.savedWidth, terrain.savedWidth);
                if (terrain.savedWidth != terrain.activeWidth)
                    ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.25f, 1.0f), "Restart the game to apply the saved grid.");
                else
                    ImGui::TextDisabled("Saved grid is active. No restart pending.");
                if (terrain.overrideWidth)
                    ImGui::TextWrapped("Environment override forces %d x %d. Clear JC4_TERRAIN_16X16 to use the saved choice on the next launch.",
                        terrain.overrideWidth, terrain.overrideWidth);
                if (terrain.invalidFileValue || terrain.pathError)
                    ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.35f, 1.0f), "Invalid/unreadable saved preference: defaulted to 8 x 8.");
                if (terrain.invalidEnvironment)
                    ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.35f, 1.0f), "Invalid environment override: terrain expansion disabled for this launch.");
                if (terrain.saveFailed)
                    ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), "Could not save terrain grid (Windows error %lu).", static_cast<unsigned long>(terrain.saveError));
                ImGui::TextDisabled("Live terrain is never resized by this control.");
                bool altitudeDetail = terrain.savedAltitudeDetail;
                if (ImGui::Checkbox("High-altitude terrain detail (16 x 16, restart required)", &altitudeDetail)) {
                    JC4TerrainSettings::SaveRequestedAltitudeDetail(altitudeDetail);
                    terrain = JC4TerrainSettings::GetSnapshot();
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Lock all ground patches to LOD 9 (highest quality)\nMakes far away terrain look more detailed, at an expense of roughly 5-15% less FPS.");
                ImGui::TextDisabled("Altitude detail: %s now / %s saved", terrain.activeWidth == 16 && terrain.startupAltitudeDetail ? "On" : "Off", terrain.savedAltitudeDetail ? "On" : "Off");
                if (terrain.altitudeOverride >= 0)
                    ImGui::TextWrapped("JC4_TERRAIN_ALTITUDE_DETAIL overrides the saved selection at launch.");
                if (terrain.savedAltitudeDetail && terrain.savedWidth != 16)
                    ImGui::TextWrapped("Altitude detail only applies when the 16 x 16 grid is active.");
                if (terrain.altitudeSaveFailed)
                    ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), "Could not save altitude detail.");
                ImGui::Spacing();
            }


            ImGui::Spacing();

            if (ImGui::Checkbox("Force ground meshes to max detail", &g_ForceMaxGroundLOD)) {
                ApplyGlobalGroundLOD(g_ForceMaxGroundLOD);
            }
            ImGui::SameLine();
            ImGui::TextDisabled("[ ? ]");
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(ImGui::GetFontSize() * 36.0f);
                ImGui::TextUnformatted(
                    "Forces ground meshes and textures to their max detail. Does not affect LODs. No restart required."
                );
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::Spacing();

            // --- Shadow Resolution (engine-driven native pipeline) ---
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Shadow Resolution");
            ImGui::SameLine(160.0f * g_UIScale);
            ImGui::SetNextItemWidth(180.0f * g_UIScale);
            {
                static const int kResValues[] = { 0, 256, 512, 1024, 2048, 4096, 8192 };
                static const char* kResNames[] = {
                    "Native game setting",
                    "256 (native low preset, low vram & fps impact)",
                    "512 (native medium preset, low vram & fps impact)",
                    "1024 (native high preset, low vram & fps impact)",
                    "2048 (native very high preset, medium vram & fps impact)",
                    "4096 (custom ultra preset, high vram & fps impact)",
                    "8192 (custom extreme preset, extreme vram & fps impact)"
                };
                static const bool kResCustom[] = { false, false, false, false, false, true, true };
                int curIdx = 0;
                bool found = false;
                for (int i = 0; i < 7; i++) {
                    if (kResValues[i] == g_ShadowResolution) { curIdx = i; found = true; break; }
                }
                if (!found) g_ShadowResolution = 0; // stale value from an older build: snap to Game setting

                // Wider dropdown so the description text fits.
                ImGui::SetNextWindowSize(ImVec2(520.0f * g_UIScale, 0.0f));
                // Preview text turns red while a custom preset is selected.
                if (kResCustom[curIdx]) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.00f, 0.38f, 0.38f, 1.00f));
                bool shOpen = ImGui::BeginCombo("##ShadowResolution", kResNames[curIdx]);
                if (kResCustom[curIdx]) ImGui::PopStyleColor();
                if (shOpen) {
                    for (int i = 0; i < 7; i++) {
                        bool shSel = (i == curIdx);
                        if (kResCustom[i]) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.00f, 0.38f, 0.38f, 1.00f));
                        if (ImGui::Selectable(kResNames[i], shSel)) {
                            g_ShadowResolution = kResValues[i];
                            // No GPU work here: the per-frame driver pins the engine's
                            // resolution tables and raises the settings-dirty bit, and
                            // the ENGINE performs the live resize through its own
                            // UpdateSettings -> SetTextureSize workflow (the exact path
                            // the in-game options menu uses).
                        }
                        if (kResCustom[i]) ImGui::PopStyleColor();
                        if (shSel) ImGui::SetItemDefaultFocus();
                    }
                    ImGui::EndCombo();
                }
            }
            {
                uint16_t shLive = ShRes_LiveAtlasSize();
                ImGui::SameLine();
                if (shLive) ImGui::TextDisabled("(live: %u)", (unsigned)shLive);
                else        ImGui::TextDisabled("(live: n/a)");
            }
            ImGui::SameLine();
            ImGui::TextDisabled("[ ? ]");
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(ImGui::GetFontSize() * 36.0f);
                ImGui::TextUnformatted(
                    "Overrides the shadow resolution of the game.\n"
                    "Selecting 'Native game setting' will choose your selected in-game shadow quality from your options.\n"
                    "Note: Custom presets (4096 / 8192) allocate a lot of extra memory\n"
                    "A 6 GB VRAM GPU is recommended for both."
                );
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::PopStyleVar(); // closes the FramePadding push at the top of the Toggles tab

        }
        else if (g_CurrentTab == 1) {
            // Entire tab is wrapped in a single master scrollable child
            ImGui::BeginChild("##WingsuitMasterScroll", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);

            // 1. Physics Variables
            DrawSectionHeader("GLOBAL PHYSICS");
            auto DrawPhysicsInput = [](const char* label, float* val, float def, uintptr_t addr) {
                ImGui::PushID(label);
                ImGui::AlignTextToFramePadding();
                ImGui::TextUnformatted(label);
                ImGui::SameLine(160.0f * g_UIScale);
                ImGui::SetNextItemWidth(180.0f * g_UIScale);
                if (ImGui::InputFloat("##val", val, 0.0f, 0.0f, "%.2f")) FastWrite<float>(addr, *val);
                ImGui::SameLine();
                if (ImGui::SmallButton("Reset")) { *val = def; FastWrite<float>(addr, *val); }
                ImGui::PopID();
            };
            DrawPhysicsInput("Wingsuit Thrust",      &g_Thrust,   default_thrust,   g_ExeBase + g_Addr_1CB8220);
            ImGui::Spacing();
            DrawPhysicsInput("Wingsuit Floor Height", &g_Floor,   default_floor,    g_ExeBase + g_Addr_1D083E0);
            ImGui::Spacing();
            ImGui::PushID("Wingsuit Max Speed");
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Wingsuit Max Speed");
            ImGui::SameLine(160.0f * g_UIScale);
            ImGui::SetNextItemWidth(180.0f * g_UIScale);
            if (ImGui::InputFloat("##val", &g_MaxSpeed, 0.0f, 0.0f, "%.2f")) {
                FastWrite<float>(g_ExeBase + g_Addr_2AE2760, g_MaxSpeed);
                auto itMV = g_WingsuitSettings.find("MaxVelocity");
                if (itMV != g_WingsuitSettings.end()) itMV->second.current[0] = g_MaxSpeed;
                auto itMVXZ = g_WingsuitSettings.find("MaxVelocityXZ");
                if (itMVXZ != g_WingsuitSettings.end()) itMVXZ->second.current[0] = g_MaxSpeed;
                uintptr_t s = GetWingsuitSettingsPtr();
                if (s) {
                    FastWrite<float>(s + 0x7BC, g_MaxSpeed);
                    FastWrite<float>(s + 0x7C0, g_MaxSpeed);
                }
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Reset")) {
                g_MaxSpeed = default_maxspeed;
                FastWrite<float>(g_ExeBase + g_Addr_2AE2760, g_MaxSpeed);
                uintptr_t s = GetWingsuitSettingsPtr();
                auto itMV = g_WingsuitSettings.find("MaxVelocity");
                if (itMV != g_WingsuitSettings.end()) {
                    itMV->second.current[0] = itMV->second.defaults[0];
                    if (s) FastWrite<float>(s + itMV->second.offset, itMV->second.defaults[0]);
                }
                auto itMVXZ = g_WingsuitSettings.find("MaxVelocityXZ");
                if (itMVXZ != g_WingsuitSettings.end()) {
                    itMVXZ->second.current[0] = itMVXZ->second.defaults[0];
                    if (s) FastWrite<float>(s + itMVXZ->second.offset, itMVXZ->second.defaults[0]);
                }
            }
            ImGui::PopID();

            ImGui::Spacing();

            // 2. Havok Physics Engine Section
            DrawSectionHeader("HAVOK PHYSICS ENGINE");
            auto DrawHavokInput = [](const char* label, float* val, float def) {
                ImGui::PushID(label);
                ImGui::AlignTextToFramePadding();
                ImGui::TextUnformatted(label);
                ImGui::SameLine(180.0f * g_UIScale);
                ImGui::SetNextItemWidth(160.0f * g_UIScale);
                if (ImGui::InputFloat("##val", val, 10.0f, 100.0f, "%.1f")) {
                    ApplyHavokPhysicsSettings();
                }
                ImGui::SameLine();
                if (ImGui::SmallButton("Reset")) {
                    *val = def;
                    ApplyHavokPhysicsSettings();
                }
                ImGui::PopID();
            };
            DrawHavokInput("Havok Max Speed",        &g_HavokMaxSpeed, default_havok_max_speed);
            ImGui::Spacing();
            DrawHavokInput("Havok Max Acceleration", &g_HavokMaxAccel, default_havok_max_accel);

            ImGui::Spacing();

            // 3. Wingsuit Missiles Section
            DrawSectionHeader("WINGSUIT MISSILES");

            // --- Global Speed Multiplier (Always Available) ---
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Missile Speed Multiplier");
            ImGui::SameLine();
            ImGui::TextDisabled("[ ? ]");
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
                ImGui::TextUnformatted("Scales the speed of the wingsuit missiles");
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::SameLine(220.0f * g_UIScale);
            ImGui::SetNextItemWidth(140.0f * g_UIScale);
            ImGui::InputFloat("##MVal_SpeedMult", &g_MissileSpeedMult, 0.5f, 1.0f, "%.2f");
            ImGui::SameLine();
            if (ImGui::SmallButton("Reset##SpeedMult")) {
                g_MissileSpeedMult = 1.0f;
            }

            ImGui::Spacing();

            // --- Full Auto Toggle (Always Available) ---
            if (ImGui::Checkbox("Fully Automatic Wingsuit Missiles", &g_FullAutoMissiles)) {
                ToggleFullAutoMissiles(g_FullAutoMissiles);
            }
            ImGui::SameLine();
            ImGui::TextDisabled("[ ? ]");
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(ImGui::GetFontSize() * 34.0f);
                ImGui::TextUnformatted(
                    "Makes holding left click fire wingsuit missiles automatically, without having to spam it"
                );
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            // --- Detailed Property Tuning (Requires 1 Shot to Capture Defaults) ---
            if (!g_MissileDefaultsCaptured) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.65f, 0.25f, 1.0f));
                ImGui::TextWrapped("[!] Fire a wingsuit missile once in-game to capture engine defaults and unlock live property tuning.");
                ImGui::PopStyleColor();
            } else {
                // If live values are uninitialized (-1.0f) and defaults have been captured, sync them
                if (g_LiveMissileStage0Time  < 0.0f) g_LiveMissileStage0Time  = g_DefMissileStage0Time;
                if (g_LiveMissileStage1Time  < 0.0f) g_LiveMissileStage1Time  = g_DefMissileStage1Time;
                if (g_LiveMissileStage0Speed < 0.0f) g_LiveMissileStage0Speed = g_DefMissileStage0Speed;
                if (g_LiveMissileStage1Speed < 0.0f) g_LiveMissileStage1Speed = g_DefMissileStage1Speed;
                if (g_LiveMissileTurnSpeed   < 0.0f) g_LiveMissileTurnSpeed   = g_DefMissileTurnSpeed;
                if (g_LiveMissileTurnDelay   < 0.0f) g_LiveMissileTurnDelay   = g_DefMissileTurnDelay;

                if (ImGui::BeginTable("##MissileLiveTable", 3, ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV)) {
                    ImGui::TableSetupColumn("Property Name", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 140.0f * g_UIScale);
                    ImGui::TableSetupColumn("Reset", ImGuiTableColumnFlags_WidthFixed, 36.0f * g_UIScale);
                    ImGui::TableHeadersRow();

                    auto DrawMissileRow = [&](const char* label, float& liveVal, float& defVal, const char* tooltip, const char* format) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::AlignTextToFramePadding();
                        ImGui::TextUnformatted(label);
                        ImGui::SameLine();
                        ImGui::TextDisabled("[ ? ]");
                        if (ImGui::IsItemHovered()) {
                            ImGui::BeginTooltip();
                            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
                            ImGui::TextUnformatted(tooltip);
                            ImGui::Spacing();
                            ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.5f, 1.0f), "Captured Game Default: %.3f", defVal);
                            ImGui::PopTextWrapPos();
                            ImGui::EndTooltip();
                        }

                        ImGui::TableSetColumnIndex(1);
                        ImGui::SetNextItemWidth(-1);
                        char inputId[64];
                        snprintf(inputId, sizeof(inputId), "##MVal_%s", label);
                        
                        float displayVal = (liveVal >= 0.0f) ? liveVal : defVal;
                        if (ImGui::InputFloat(inputId, &displayVal, 0.1f, 1.0f, format)) {
                            liveVal = displayVal;
                        }

                        ImGui::TableSetColumnIndex(2);
                        ImGui::PushID(label);
                        if (ImGui::SmallButton("R")) {
                            liveVal = defVal; // Restores genuine captured game default
                        }
                        ImGui::PopID();
                    };

                    DrawMissileRow("Stage 0 Duration", g_LiveMissileStage0Time, g_DefMissileStage0Time,
                        "Duration of initial post-launch acceleration phase in seconds.", "%.2f");

                    DrawMissileRow("Stage 1 Duration", g_LiveMissileStage1Time, g_DefMissileStage1Time,
                        "Maximum tracking and thrust flight duration before motor cutoff.", "%.2f");

                    DrawMissileRow("Stage 0 Launch Speed", g_LiveMissileStage0Speed, g_DefMissileStage0Speed,
                        "Initial ejection speed right as the missile leaves the wingsuit pod.", "%.2f");

                    DrawMissileRow("Stage 1 Cruise Speed", g_LiveMissileStage1Speed, g_DefMissileStage1Speed,
                        "Maximum cruising velocity reached during powered flight.", "%.2f");

                    DrawMissileRow("Turning Speed", g_LiveMissileTurnSpeed, g_DefMissileTurnSpeed,
                        "Base angular turning rate for target tracking and homing in radians/sec.", "%.3f");

                    DrawMissileRow("Initial Turn Delay", g_LiveMissileTurnDelay, g_DefMissileTurnDelay,
                        "Delay timer in seconds before homing rotation begins.", "%.2f");

                    ImGui::EndTable();
                }
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            // 4. Wingsuit Variables (All 50+ fields render inside the main scrollbar)
            DrawSectionHeader("WINGSUIT SETTINGS");
            uintptr_t settings_ptr = GetWingsuitSettingsPtr();
            if (!settings_ptr) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.5f, 0.3f, 1.0f));
                ImGui::TextWrapped("[!] WINGSUIT NOT ACTIVE");
                ImGui::PopStyleColor();
            } else {
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 6.0f));
                ImGui::SetNextItemWidth(-120.0f * g_UIScale);
                ImGui::InputTextWithHint("##search", "Search fields...", g_SearchBuf, sizeof(g_SearchBuf));
                ImGui::PopStyleVar();
                ImGui::SameLine();
                if (ImGui::Button("Reset All", ImVec2(-1, 0))) {
                    for (auto& [n, f] : g_WingsuitSettings) {
                        if (f.is_u32) { f.current_u32 = f.default_u32; FastWrite<uint32_t>(settings_ptr + f.offset, f.current_u32); }
                        else { for (int i = 0; i < f.num_values && i < 5; i++) { f.current[i] = f.defaults[i]; FastWrite<float>(settings_ptr + f.offset + (uintptr_t)(i*4), f.current[i]); } }
                    }
                }
                ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
                
                if (ImGui::BeginTable("##WingsuitTable", 3, ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV)) {
                    ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 180.0f * g_UIScale);
                    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Reset", ImGuiTableColumnFlags_WidthFixed, 36.0f * g_UIScale);
                    ImGui::TableHeadersRow();
                    bool hasSearch = g_SearchBuf[0] != '\0';
                    std::string searchLower;
                    if (hasSearch) {
                        searchLower = g_SearchBuf;
                        std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), [](unsigned char c){ return std::tolower(c); });
                    }
                    for (auto& [name, field] : g_WingsuitSettings) {
                        if (hasSearch) {
                            std::string nameLower = name;
                            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), [](unsigned char c){ return std::tolower(c); });
                            if (nameLower.find(searchLower) == std::string::npos) continue;
                        }
                        RenderWingsuitField(name, field, settings_ptr);
                    }
                    ImGui::EndTable();
                }
            }

            ImGui::EndChild(); // Close ##WingsuitMasterScroll
        }
        
        else if (g_CurrentTab == 3) {
            DrawSectionHeader("PLAYER CHEATS");
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12.0f, 8.0f));
            
            if (ImGui::Checkbox("Invincibility (God Mode)", &g_GodMode)) {
                TriggerEvent(g_GodMode ? "ply.jesus.enable" : "ply.jesus.disable");
            }
            ImGui::Spacing();

            ImGui::BeginDisabled(!s_RedDamageReady.load(std::memory_order_acquire));
            ImGui::Checkbox("Disable Red Damage Screen", &g_DisableDamageScreen);
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Eliminates the red screen effect when you get damaged, aswell as the critical health state effect (HP below 200)");
            }
            ImGui::Spacing();

            ImGui::BeginDisabled(!s_NoRagdollReady.load(std::memory_order_acquire));
            ImGui::Checkbox("No Ragdoll", &g_DisableRagdoll);
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Prevents Rico from entering uncontrolled ragdoll states.");
            }
            ImGui::Spacing();

            if (ImGui::Checkbox("Noclip / Free Flight", &g_Noclip)) {
                if (g_Noclip && g_FreeCam) g_FreeCam = false;
            }
            ImGui::SameLine();
            ImGui::TextDisabled("[ ? ]");
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted("Controls:\n- W / S : Fly in camera look direction\n- A / D : Strafe left / right\n- Space / Ctrl : Ascend / Descend\n- Shift : Speed boost");
                ImGui::EndTooltip();
            }

            // Noclip Rebind Button
            ImGui::SameLine();
            char noclipBtnLbl[48];
            if (g_AssigningNoclipKey) snprintf(noclipBtnLbl, sizeof(noclipBtnLbl), "[ press key ]##NoclipKb");
            else snprintf(noclipBtnLbl, sizeof(noclipBtnLbl), "[ %s ]##NoclipKb", TorVkName(g_NoclipKey));
            if (ImGui::SmallButton(noclipBtnLbl)) {
                g_AssigningNoclipKey = !g_AssigningNoclipKey;
                g_AssigningFreeCamKey = false;
                g_NoclipKeyListenStart = ImGui::GetTime();
            }
            if (g_AssigningNoclipKey && (ImGui::GetTime() - g_NoclipKeyListenStart > 0.2)) {
                for (int vk = 0x08; vk <= 0xFE; vk++) {
                    if (vk == g_ToggleKey) continue;
                    if (GetAsyncKeyState(vk) & 0x8000) {
                        g_NoclipKey = (vk == VK_ESCAPE) ? 0 : vk;
                        g_AssigningNoclipKey = false;
                        WriteConfig();
                        break;
                    }
                }
            }

            if (g_Noclip) {
                ImGui::Indent(20.0f * g_UIScale);
                ImGui::SetNextItemWidth(160.0f * g_UIScale);
                ImGui::SliderFloat("Flight Speed", &g_NoclipSpeed, 0.0f, 250.0f, "%.1f m/s");
                ImGui::SetNextItemWidth(160.0f * g_UIScale);
                ImGui::SliderFloat("Shift Boost Multiplier", &g_NoclipFastMult, 1.5f, 10.0f, "%.1fx");
                ImGui::Spacing();
                if (ImGui::Checkbox("Hide UI (HUD)##NoclipHideUI", &g_HideUI)) {
                    ApplyHideUI(g_HideUI);
                    WriteConfig();
                }
                ImGui::Unindent(20.0f * g_UIScale);
            }
            ImGui::Spacing();

            if (ImGui::Checkbox("Free Camera (Freecam)", &g_FreeCam)) {
                if (g_FreeCam && g_Noclip) g_Noclip = false;
            }
            ImGui::SameLine();
            ImGui::TextDisabled("[ ? ]");
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted("Controls:\n- W / S : Fly in camera look direction\n- A / D : Strafe left / right\n- Space / Ctrl : Ascend / Descend\n- Shift : Speed boost");
                ImGui::EndTooltip();
            }

            // Freecam Rebind Button
            ImGui::SameLine();
            char freecamBtnLbl[48];
            if (g_AssigningFreeCamKey) snprintf(freecamBtnLbl, sizeof(freecamBtnLbl), "[ press key ]##FreecamKb");
            else snprintf(freecamBtnLbl, sizeof(freecamBtnLbl), "[ %s ]##FreecamKb", TorVkName(g_FreeCamKey));
            if (ImGui::SmallButton(freecamBtnLbl)) {
                g_AssigningFreeCamKey = !g_AssigningFreeCamKey;
                g_AssigningNoclipKey = false;
                g_FreeCamKeyListenStart = ImGui::GetTime();
            }
            if (g_AssigningFreeCamKey && (ImGui::GetTime() - g_FreeCamKeyListenStart > 0.2)) {
                for (int vk = 0x08; vk <= 0xFE; vk++) {
                    if (vk == g_ToggleKey) continue;
                    if (GetAsyncKeyState(vk) & 0x8000) {
                        g_FreeCamKey = (vk == VK_ESCAPE) ? 0 : vk;
                        g_AssigningFreeCamKey = false;
                        WriteConfig();
                        break;
                    }
                }
            }

            if (g_FreeCam) {
                ImGui::Indent(20.0f * g_UIScale);
                ImGui::SetNextItemWidth(160.0f * g_UIScale);
                ImGui::SliderFloat("Camera Speed", &g_FreeCamSpeed, 0.0f, 250.0f, "%.1f m/s");
                ImGui::SetNextItemWidth(160.0f * g_UIScale);
                ImGui::SliderFloat("Shift Boost Multiplier##FreeCam", &g_FreeCamFastMult, 1.5f, 10.0f, "%.1fx");

                ImGui::Spacing();
                ImGui::Checkbox("Lock Player to Current Position", &g_FreeCamLockPlayer);
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
                ImGui::TextWrapped("Note: If enabled, Rico will be frozen at his current position and will not move, drift, or fall while you roam with the camera.");
                ImGui::PopStyleColor();

                ImGui::Spacing();
                ImGui::Checkbox("Lock player movement", &g_FreeCamLockMovement);
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
                ImGui::TextWrapped("Note: If enabled, camera flight keys (WASD / Space / Ctrl / Shift / Arrows) will not move Rico or control his vehicle while flying the camera.");
                ImGui::PopStyleColor();

                ImGui::Spacing();
                if (ImGui::Checkbox("Hide UI (HUD)##FreeCamHideUI", &g_HideUI)) {
                    ApplyHideUI(g_HideUI);
                    WriteConfig();
                }

                ImGui::Unindent(20.0f * g_UIScale);
            }
            ImGui::Spacing();

            if (ImGui::Checkbox("First Person Mode", &g_FirstPerson)) {
                if (g_FirstPerson && g_FreeCam) g_FreeCam = false;
            }
            ImGui::SameLine();
            ImGui::TextDisabled("[ ? ]");
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted("Enables first person mode.");
                ImGui::EndTooltip();
            }
            ImGui::SameLine();
            char fpBtnLbl[48];
            if (g_AssigningFirstPersonKey) snprintf(fpBtnLbl, sizeof(fpBtnLbl), "[ press key ]##FirstPersonKb");
            else snprintf(fpBtnLbl, sizeof(fpBtnLbl), "[ %s ]##FirstPersonKb", TorVkName(g_FirstPersonKey));
            if (ImGui::SmallButton(fpBtnLbl)) {
                g_AssigningFirstPersonKey = !g_AssigningFirstPersonKey;
                g_AssigningNoclipKey = false;
                g_AssigningFreeCamKey = false;
                g_FirstPersonKeyListenStart = ImGui::GetTime();
            }
            if (g_AssigningFirstPersonKey && (ImGui::GetTime() - g_FirstPersonKeyListenStart > 0.2)) {
                for (int vk = 0x08; vk <= 0xFE; vk++) {
                    if (vk == g_ToggleKey) continue;
                    if (GetAsyncKeyState(vk) & 0x8000) {
                        g_FirstPersonKey = (vk == VK_ESCAPE) ? 0 : vk;
                        g_AssigningFirstPersonKey = false;
                        WriteConfig();
                        break;
                    }
                }
            }
            if (g_FirstPerson) {
                ImGui::Indent(20.0f * g_UIScale);
                if (ImGui::Checkbox("Hide Body (Keep Arms & Gun)##FP", &g_FpHideBody)) WriteConfig();
                if (!g_FpHideBody) {
                    if (ImGui::Checkbox("Hide Head Mesh##FP", &g_FpHideHead)) WriteConfig();
                }
                ImGui::SetNextItemWidth(160.0f * g_UIScale);
                if (ImGui::SliderFloat("Forward Offset##FP", &g_FpForwardOffset, -0.10f, 0.35f, "%.3f m")) WriteConfig();
                ImGui::SetNextItemWidth(160.0f * g_UIScale);
                if (ImGui::SliderFloat("Up Offset##FP", &g_FpUpOffset, -0.10f, 0.25f, "%.3f m")) WriteConfig();
                ImGui::SetNextItemWidth(160.0f * g_UIScale);
                if (ImGui::SliderFloat("Right Offset##FP", &g_FpRightOffset, -0.15f, 0.15f, "%.3f m")) WriteConfig();
                if (ImGui::SmallButton("Reset Offsets##FP")) {
                    g_FpForwardOffset = 0.12f;
                    g_FpUpOffset = 0.06f;
                    g_FpRightOffset = 0.0f;
                    WriteConfig();
                }
                ImGui::Unindent(20.0f * g_UIScale);
            }
            ImGui::Spacing();

            if (ImGui::Checkbox("Infinite Ammo", &g_InfWeaponAmmo)) {
                ToggleInfWeaponAmmo(g_InfWeaponAmmo);
            }
            ImGui::Spacing();

            if (ImGui::Checkbox("Never Wanted", &g_NeverWanted)) {}
ImGui::Spacing();

if (ImGui::Checkbox("Enable Pirate Skin", &g_PirateSkin)) {
    if (g_PirateSkin) {
        TriggerEvent("enable_pirate_skin");
    }
}

ImGui::Spacing();

// --- Desired FOV Section ---
if (ImGui::Checkbox("Override FOV", &g_OverrideFOV)) {
    if (g_OverrideFOV) {
        g_DesiredFOV = 60;      // start the edit at stock
        g_FovNeedAnchor = true; // detour captures the live base on next tick
    }
    WriteConfig();
}
ImGui::SameLine();
ImGui::TextDisabled("[ ? ]");
if (ImGui::IsItemHovered()) {
    ImGui::BeginTooltip();
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
    ImGui::TextUnformatted("Allows you overwrite the default camera FOV values.");
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
}

if (g_OverrideFOV) {
    ImGui::Indent(20.0f * g_UIScale);
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Desired FOV:");
    ImGui::SameLine(180.0f * g_UIScale);

    ImGui::SetNextItemWidth(140.0f * g_UIScale);
    if (ImGui::InputInt("##DesiredFOV", &g_DesiredFOV, 1, 5)) {
        if (g_DesiredFOV < 30) g_DesiredFOV = 30;
        if (g_DesiredFOV > 130) g_DesiredFOV = 130;
        WriteConfig();
    }
    ImGui::Unindent(20.0f * g_UIScale);
}

ImGui::Spacing();

// --- Oxygen Control Section ---
if (!g_LockOxygen && (now - g_LastOxygenReadTime > 350)) {
    g_LastOxygenReadTime = now;
    uintptr_t playerPtr = GetPlayerPtr();
    if (playerPtr) {
        FastRead<float>(playerPtr + 0x5F8, g_OxygenValue);
    }
}

ImGui::AlignTextToFramePadding();
ImGui::TextUnformatted("Oxygen level (real time):");
ImGui::SameLine(180.0f * g_UIScale);

ImGui::SetNextItemWidth(140.0f * g_UIScale);
if (ImGui::InputFloat("##OxygenVal", &g_OxygenValue, 1.0f, 10.0f, "%.1f")) {
    uintptr_t playerPtr = GetPlayerPtr();
    if (playerPtr) {
        FastWrite<float>(playerPtr + 0x5F8, g_OxygenValue);
    }
}

ImGui::SameLine();
if (ImGui::Checkbox("Lock##Oxygen", &g_LockOxygen)) {
    if (g_LockOxygen) {
        uintptr_t playerPtr = GetPlayerPtr();
        if (playerPtr) {
            FastWrite<float>(playerPtr + 0x5F8, g_OxygenValue);
        }
    }
}

ImGui::Spacing();

// --- Health Control Section ---
if (!g_LockHealth && (now - g_LastHealthReadTime > 350)) {
    g_LastHealthReadTime = now;
    uintptr_t playerPtr = GetPlayerPtr();
    if (playerPtr) {
        uintptr_t characterPtr = 0;
        if (FastRead<uintptr_t>(playerPtr + 0x68, characterPtr) && characterPtr) {
            int16_t curHp = 0, maxHp = 0;
            if (FastRead<int16_t>(characterPtr + 0x3AC, curHp)) {
                g_HealthValue = (int)curHp;
            }
            if (FastRead<int16_t>(characterPtr + 0x3AA, maxHp)) {
                g_MaxHealthValue = (int)maxHp;
            }
        }
    }
}

ImGui::AlignTextToFramePadding();
ImGui::TextUnformatted("Health level (real time):");
ImGui::SameLine(180.0f * g_UIScale);

ImGui::SetNextItemWidth(140.0f * g_UIScale);
if (ImGui::InputInt("##HealthVal", &g_HealthValue, 25, 100)) {
    if (g_HealthValue < 0) g_HealthValue = 0;
    if (g_HealthValue > 32767) g_HealthValue = 32767;
    uintptr_t playerPtr = GetPlayerPtr();
    if (playerPtr) {
        uintptr_t characterPtr = 0;
        if (FastRead<uintptr_t>(playerPtr + 0x68, characterPtr) && characterPtr) {
            FastWrite<int16_t>(characterPtr + 0x3AC, (int16_t)g_HealthValue);
        }
    }
}

ImGui::SameLine();
if (ImGui::Checkbox("Lock##Health", &g_LockHealth)) {
    if (g_LockHealth) {
        uintptr_t playerPtr = GetPlayerPtr();
        if (playerPtr) {
            uintptr_t characterPtr = 0;
            if (FastRead<uintptr_t>(playerPtr + 0x68, characterPtr) && characterPtr) {
                FastWrite<int16_t>(characterPtr + 0x3AC, (int16_t)g_HealthValue);
            }
        }
    }
}

// Drops to its own full-width line below the inputs
ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.35f, 1.0f));
ImGui::TextWrapped("Tip: For infinite health, do not modify the health directly or lock it, enable the 'Invincibility' toggle instead. Locking the health will cause glitches and softlocks if you encounter an insta-kill scenario (such as being on an exploding vehicle).");
ImGui::PopStyleColor();

ImGui::Spacing();
            DrawSectionHeader("GAME SPEED (SLOW-MO / FAST-FORWARD)");
            {
                bool gsEnabled = (g_CustomGameSpeed >= 0.0f);
                if (ImGui::Checkbox("Override Game Speed", &gsEnabled)) {
                    if (gsEnabled) {
                        float init = g_LiveGameSpeed;
                        if (!(init >= 0.1f && init <= 10.0f)) init = 1.0f;
                        g_CustomGameSpeed = init;
                    } else {
                        g_CustomGameSpeed = -1.0f;
                    }
                }
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("Changes the game speed.");
                if (gsEnabled) {
                    ImGui::SetNextItemWidth(160.0f * g_UIScale);
                    ImGui::SliderFloat("##GameSpeedSlider", &g_CustomGameSpeed, 0.1f, 10.0f, "%.2fx");
                    ImGui::SameLine();
                    if (ImGui::SmallButton("0.25x")) g_CustomGameSpeed = 0.25f;
                    ImGui::SameLine();
                    if (ImGui::SmallButton("0.5x")) g_CustomGameSpeed = 0.5f;
                    ImGui::SameLine();
                    if (ImGui::SmallButton("1x")) g_CustomGameSpeed = 1.0f;
                    ImGui::SameLine();
                    if (ImGui::SmallButton("5x")) g_CustomGameSpeed = 5.0f;
                    ImGui::SameLine();
                    if (ImGui::SmallButton("10x")) g_CustomGameSpeed = 10.0f;
                } else {
                    ImGui::SameLine();
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
                    ImGui::Text("(Live: %.2f)", g_LiveGameSpeed);
                    ImGui::PopStyleColor();
                }
            }
            ImGui::Spacing();
DrawSectionHeader("VEHICLE NITROUS & TURBO JUMP");

if (ImGui::Checkbox("Make All Vehicles Have Nitro + Jump", &g_AllVehiclesNitroJump)) {
    ToggleAllVehiclesNitroJump(g_AllVehiclesNitroJump);
    WriteConfig();
}
ImGui::SameLine();
ImGui::TextDisabled("[ ? ]");
if (ImGui::IsItemHovered()) {
    ImGui::BeginTooltip();
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
    ImGui::TextUnformatted(
        "Enables Level 1 Nitro and Turbo Jump on ALL vehicles in the world, "
        "including civilian and military traffic cars."
    );
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
}

ImGui::Spacing();

if (ImGui::Checkbox("Infinite Nitrous (No Fuel Depletion)", &g_InfiniteNitro)) {
    ToggleInfiniteNitro(g_InfiniteNitro);
    WriteConfig();
}
ImGui::SameLine();
ImGui::TextDisabled("[ ? ]");
if (ImGui::IsItemHovered()) {
    ImGui::BeginTooltip();
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
    ImGui::TextUnformatted("Stops nitrous fuel bar from draining. Boost thrusters can be held down indefinitely.");
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
}

ImGui::Spacing();

if (ImGui::Checkbox("Infinite Turbo Jump", &g_InfiniteTurboJump)) {
    ToggleInfiniteTurboJump(g_InfiniteTurboJump, g_TurboJumpAirHop);
    WriteConfig();
}
ImGui::SameLine();
ImGui::TextDisabled("[ ? ]");
if (ImGui::IsItemHovered()) {
    ImGui::BeginTooltip();
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
    ImGui::TextUnformatted("Removes the cooldown delay between turbo jumps entirely.");
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
}

if (g_InfiniteTurboJump) {
    ImGui::Indent(20.0f * g_UIScale);

    if (ImGui::RadioButton("Ground Only (Zero Cooldown)", !g_TurboJumpAirHop)) {
        g_TurboJumpAirHop = false;
        ToggleInfiniteTurboJump(g_InfiniteTurboJump, g_TurboJumpAirHop);
        WriteConfig();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("[ ? ]");
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Jump cooldown is 0s, but the vehicle can only jump if its on the ground.");
    }

    if (ImGui::RadioButton("Multi-Jump Mid-Air (Air-Hop)", g_TurboJumpAirHop)) {
        g_TurboJumpAirHop = true;
        ToggleInfiniteTurboJump(g_InfiniteTurboJump, g_TurboJumpAirHop);
        WriteConfig();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("[ ? ]");
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Lets you nitro jump with any ground vehicle mid-air.");
    }

    ImGui::Unindent(20.0f * g_UIScale);
}

ImGui::Spacing();

// --- Custom Event Section ---

ImGui::Spacing();
ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.38f, 0.96f, 1.0f));
ImGui::TextUnformatted("CUSTOM EVENT");
ImGui::PopStyleColor();

ImGui::SameLine();
ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 0.0f, 0.0f)); // Flat styled button
if (ImGui::Button("[ Show Known Events ]")) {
    ImGui::OpenPopup("available_events_popup");
}
ImGui::PopStyleColor();

if (ImGui::BeginPopup("available_events_popup")) {
    // Warning banner at the top of the event menu
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.6f, 0.2f, 1.0f));
    ImGui::TextWrapped("Reminder: Depending on game state or character mode, some events may have no effect OR crash the game.");
    ImGui::PopStyleColor();
    ImGui::Spacing();
    
    ImGui::TextDisabled("Click any event to copy to the text box:");
    ImGui::Separator();
    
    static const char* playerEvents[] = {
        "ply.input.disable",
        "ply.input.disable_except_look",
        "ply.input.enable",
        "ply.jesus.enable",
        "ply.jesus.disable",
        "ply.jesus.toggle",
        "ply.ragdoll_and_stumble.enable",
        "ply.ragdoll_and_stumble.disable",
        "ply.jumping.enable",
        "ply.jumping.disable",
        "ply.grapple.enable",
        "ply.grapple.disable",
        "ply.weapon_pickup.enable",
        "ply.weapon_pickup.disable",
        "ply.pda.enable",
        "ply.pda.disable",
        "ply.inventory.give",
        "equipweapon",
        "unequipweapon",
        "ply.unequipweapon",
        "ply.vehicle.burn",
        "ply.pause",
        "ply.unpause",
        "freeze_frames",
        "ply.unlimitedammo.enable",
        "ply.unlimitedammo.disable",
        "ply.health.takedamage",
        "ply.health.takedamage.track_event",
        "ply.ammo.givemax",
        "ply.check_achievement.sanctuary",
        "ply.check_achievement.i_can_show_you_the_world",
        "ply.award_achievement.i_can_see_my_house_from_here",
        "ply.explosives.remove_all",
        "teleporttoroad",
        "enablestayonroad",
        "disablestayonroad",
        "offroad_exclusion_enter",
        "offroad_exclusion_exit",
        "offroad_exclusion_reset",
        "offroad_inclusion_enter",
        "offroad_inclusion_exit",
        "offroad_inclusion_reset",
        "moon_gravity_on",
        "moon_gravity_off",
        "enable_pirate_skin"
    };

    for (const char* evt : playerEvents) {
        if (ImGui::Selectable(evt)) {
            strncpy_s(g_CustomEventBuf, evt, sizeof(g_CustomEventBuf));
        }
    }
    ImGui::EndPopup();
}

ImGui::Separator();
ImGui::Spacing();

ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.55f, 0.6f, 1.0f));
ImGui::TextWrapped("Use this ONLY if you know the exact internal event name. Unknown events are known for crashing the game sometimes.");
ImGui::PopStyleColor();

ImGui::Spacing();

ImGui::SetNextItemWidth(-120.0f * g_UIScale);
ImGui::InputTextWithHint("##CustomEvent", "e.g. enable_pirate_skin", g_CustomEventBuf, sizeof(g_CustomEventBuf));
ImGui::SameLine();

if (ImGui::Button("Trigger Event", ImVec2(-1, 0))) {
    if (g_CustomEventBuf[0] != '\0') {
        TriggerEvent(g_CustomEventBuf);
    }
}

            ImGui::Spacing();
            ImGui::Dummy(ImVec2(0.0f, 15.0f * g_UIScale)); // Add extra padding below Trigger Event

            // --- Vehicle Boost Properties Section ---
            DrawSectionHeader("VEHICLE BOOST PROPERTIES");
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
            ImGui::TextWrapped("Only applies while nitro boosting.");
            ImGui::PopStyleColor();
            ImGui::Spacing();

            // Refresh our assembly multipliers every 2 seconds to keep the UI in sync,
            // BUT ONLY if the user isn't actively interacting with the text inputs.
            if (now - g_LastBoostReadTime > 2000) {
                g_LastBoostReadTime = now;
                
                if (!ImGui::IsAnyItemActive()) {
                    // Fetch our assembly multipliers
                    if (g_CodeCave) {
                        FastRead<float>(g_CodeCave + 0x0, g_BoostTorque);
                        FastRead<float>(g_CodeCave + 0x4, g_BoostGrip);
                        FastRead<float>(g_CodeCave + 0xC, g_BoostJumpHeight);
                    }
                }
            }

            // Global "Reset All" Button
if (ImGui::Button("Reset All Values", ImVec2(-1, 0))) {
    // Reset Assembly Multipliers in Code Cave
    if (g_CodeCave) {
        g_BoostTorque = 1.0f;     FastWrite<float>(g_CodeCave + 0x0, 1.0f);
        g_BoostGrip = 1.0f;       FastWrite<float>(g_CodeCave + 0x4, 1.0f);
        g_BoostJumpHeight = 1.0f; FastWrite<float>(g_CodeCave + 0xC, 1.0f);
    }
}
            ImGui::Spacing();

            // Clean 3-column table
            if (ImGui::BeginTable("##BoostPropsTable", 3, ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_RowBg)) {
                ImGui::TableSetupColumn("Property Name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Input Value", ImGuiTableColumnFlags_WidthFixed, 140.0f * g_UIScale);
                ImGui::TableSetupColumn("Reset", ImGuiTableColumnFlags_WidthFixed, 36.0f * g_UIScale);
                ImGui::TableHeadersRow();

                auto DrawBoostRow = [&](const char* label, float* val, uintptr_t offset) {
                    ImGui::TableNextRow();

                    // Column 0: Label
                    ImGui::TableSetColumnIndex(0);
                    ImGui::AlignTextToFramePadding();
                    ImGui::TextUnformatted(label);

                    // Column 1: Input Float
                    ImGui::TableSetColumnIndex(1);
                    ImGui::SetNextItemWidth(-1);
                    char valueId[64];
                    snprintf(valueId, sizeof(valueId), "##Value_%s", label);

                    // If InputFloat returns true, the user typed something or hit +/-
                    if (ImGui::InputFloat(valueId, val, 0.1f, 1.0f, "%.2f")) {
                        // Reject NaN / negative / absurd values for global physical bounds
                        if (!(*val > 0.0f)) *val = 1.0f;
                        if (*val > 50.0f)   *val = 50.0f;
                        
                        // Write instantly upon edit
                        if (g_CodeCave) {
                            FastWrite<float>(g_CodeCave + offset, *val);
                        }
                    }

                    // Column 2: Reset Button (R)
                    ImGui::TableSetColumnIndex(2);
                    ImGui::PushID(label);
                    if (ImGui::SmallButton("R")) {
                        *val = 1.0f;
                        if (g_CodeCave) FastWrite<float>(g_CodeCave + offset, 1.0f);
                    }
                    ImGui::PopID();
                };

                // Assembly Multipliers
                DrawBoostRow("Torque Multiplier", &g_BoostTorque, 0x0);
                DrawBoostRow("Grip Multiplier", &g_BoostGrip, 0x4);
                DrawBoostRow("Custom Jump Height", &g_BoostJumpHeight, 0xC);

                ImGui::EndTable();
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            // --- CURRENT VEHICLE: live tuning, no boost needed ---
            DrawSectionHeader("VEHICLE BASE PROPERTIES");
            ImGui::Spacing();

            {
                uintptr_t bVeh = 0, bPfx = 0, bEng = 0, bTrans = 0;
                bool hasPhys = GetRicoVehiclePhysics(bVeh, bPfx, bEng, bTrans);
                // Real-time: live values every frame; defaults refresh when not typing (read-only).
                // Nothing is WRITTEN here. Writes happen only in ApplyVehBaseTuning for ticked rows.
                if (hasPhys && bPfx) {
                    if (!ImGui::IsAnyItemActive()) CaptureVehBaseDefaults(bEng, bTrans, bPfx);
                    FastRead<float>(bPfx + 0x29A4, g_VehLiveTorque);
                    FastRead<float>(bPfx + 0x29A8, g_VehLiveRPM);
                    FastRead<float>(bPfx + 0x2A0C, g_VehLiveTransRPM);
                } else {
                    ZeroUntickedVehFields();
                }
                if (!hasPhys) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.65f, 0.35f, 1.0f));
                    ImGui::TextWrapped("Enter a land vehicle to tune it and see its stats in real time.");
                    ImGui::PopStyleColor();
                    ImGui::Spacing();
                } else {
                    ImGui::Text("Live torque %.0f | RPM %.0f | Gearbox RPM %.0f",
                        g_VehLiveTorque, g_VehLiveRPM, g_VehLiveTransRPM);
                    ImGui::Spacing();
                }

                if (ImGui::SmallButton("Reset all")) { ResetVehBaseTuning(); }

                auto RestoreFieldNow = [&](VehBaseField& f) {
                    // User-initiated restore: write default back once, then stop touching.
                    f.customVal = f.defVal; f.overrideActive = false;
                    if (!hasPhys) return;
                    if (&f == &g_VehBaseMaxTorque && bEng) FastWrite<float>(bEng + 0x4C, f.defVal);
                    else if (&f == &g_VehBaseMaxRPM && bEng) FastWrite<float>(bEng + 0x48, f.defVal);
                    else if (&f == &g_VehBaseMinRPM && bEng) FastWrite<float>(bEng + 0x40, f.defVal);
                    else if (&f == &g_VehBaseOptRPM && bEng) FastWrite<float>(bEng + 0x44, f.defVal);
                    else if (&f == &g_VehBasePrimaryRatio && bTrans) FastWrite<float>(bTrans + 0x58, f.defVal);
                    else if (&f == &g_VehBaseTopSpeed && bPfx) FastWrite<float>(bPfx + 0x2AC4, f.defVal);
                    else if (&f == &g_VehGripFriction && bPfx) {
                        uintptr_t fProps = 0, rProps = 0;
                        FastRead<uintptr_t>(bPfx + 0x1C20, fProps);
                        FastRead<uintptr_t>(bPfx + 0x1C28, rProps);
                        if (fProps) FastWrite<float>(fProps + 0x14, f.defVal);
                        if (rProps) FastWrite<float>(rProps + 0x14, f.defVal);
                        uintptr_t wData = 0; int wCount = 0;
                        if (FastRead<uintptr_t>(bPfx + 0x1BE0, wData) && wData &&
                            FastRead<int>(bPfx + 0x1BE0 + 0x8, wCount) && wCount > 0 && wCount <= 16) {
                            for (int i = 0; i < wCount; i++)
                                FastWrite<float>(wData + (uintptr_t)i * 0x210 + 0x17C, f.defVal);
                        }
                    }
                    else if (&f == &g_VehGripDownforce && bPfx) {
                        uintptr_t fProps = 0, rProps = 0;
                        FastRead<uintptr_t>(bPfx + 0x1C20, fProps);
                        FastRead<uintptr_t>(bPfx + 0x1C28, rProps);
                        if (fProps) FastWrite<float>(fProps + 0x1C, f.defVal);
                        if (rProps) FastWrite<float>(rProps + 0x1C, f.defVal);
                        uintptr_t wData = 0; int wCount = 0;
                        if (FastRead<uintptr_t>(bPfx + 0x1BE0, wData) && wData &&
                            FastRead<int>(bPfx + 0x1BE0 + 0x8, wCount) && wCount > 0 && wCount <= 16) {
                            for (int i = 0; i < wCount; i++)
                                FastWrite<float>(wData + (uintptr_t)i * 0x210 + 0x18C, f.defVal);
                        }
                    }
                    else if (&f == &g_VehDriftMaxTorque && bPfx) {
                        uintptr_t cust = 0;
                        if (FastRead<uintptr_t>(bPfx + 0x2A78, cust) && cust)
                            FastWrite<float>(cust + 52 + 20, f.defVal);
                    }
                };

                auto DrawBaseRow = [&](const char* label, VehBaseField& f, float minV, float maxV, const char* fmt, const char* tip, float step, float stepFast) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::AlignTextToFramePadding();
                    ImGui::TextUnformatted(label);
                    if (tip && ImGui::IsItemHovered()) ImGui::SetTooltip("%s", tip);
                    ImGui::TableSetColumnIndex(1);
                    ImGui::PushID(label);
                    bool en = f.overrideActive;
                    if (ImGui::Checkbox("##en", &en)) {
                        if (!en) {
                            ImGui::PopID();
                            RestoreFieldNow(f);
                            return;
                        }
                        f.overrideActive = true;
                        if (f.captured && hasPhys) f.customVal = f.defVal;
                    }
                    ImGui::PopID();
                    ImGui::TableSetColumnIndex(2);
                    ImGui::SetNextItemWidth(-1);
                    char bid[96]; snprintf(bid, sizeof(bid), "##Base_%s", label);
                    bool dis = !f.overrideActive;
                    if (dis) ImGui::BeginDisabled();
                    if (ImGui::InputFloat(bid, &f.customVal, step, stepFast, fmt)) {
                        if (!(f.customVal >= minV && f.customVal <= maxV)) {
                            if (f.customVal < minV) f.customVal = minV;
                            if (f.customVal > maxV) f.customVal = maxV;
                        }
                    }
                    if (dis) ImGui::EndDisabled();
                    ImGui::TableSetColumnIndex(3);
                    char defBuf[64]; snprintf(defBuf, sizeof(defBuf), "(def %.1f)", f.defVal);
                    ImGui::TextDisabled("%s", defBuf);
                    ImGui::TableSetColumnIndex(4);
                    ImGui::PushID(label);
                    if (ImGui::SmallButton("R")) {
                        ImGui::PopID();
                        RestoreFieldNow(f);
                        return;
                    }
                    ImGui::PopID();
                };

                if (ImGui::BeginTable("##VehBaseTable", 5, ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_RowBg)) {
                    ImGui::TableSetupColumn("Setting", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 36.0f * g_UIScale);
                    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 150.0f * g_UIScale);
                    ImGui::TableSetupColumn("Default", ImGuiTableColumnFlags_WidthFixed, 110.0f * g_UIScale);
                    ImGui::TableSetupColumn("R", ImGuiTableColumnFlags_WidthFixed, 36.0f * g_UIScale);
                    ImGui::TableHeadersRow();
                    DrawBaseRow("Max torque", g_VehBaseMaxTorque, 1.0f, 5000000.0f, "%.0f", "Controls the vehicle base torque. internal value: m_maxTorque", 100.0f, 1000.0f);
                    DrawBaseRow("Max RPM", g_VehBaseMaxRPM, 500.0f, 100000.0f, "%.0f", "Controls the vehicle max RPM it can go. internal value: m_maxRPM", 100.0f, 500.0f);
                    DrawBaseRow("Min RPM", g_VehBaseMinRPM, 50.0f, 50000.0f, "%.0f", "Controls the vehicle minimum RPM it can go. internal value: m_minRPM", 50.0f, 250.0f);
                    DrawBaseRow("Optimal RPM", g_VehBaseOptRPM, 50.0f, 80000.0f, "%.0f", "Controls the vehicle optimal RPM. The gearbox tries to stay as close to it. internal value: m_optRPM", 50.0f, 250.0f);
                    DrawBaseRow("Top speed", g_VehBaseTopSpeed, 10.0f, 20000.0f, "%.1f", "Controls the vehicle base max speed. internal value: m_TopSpeedKmph", 5.0f, 20.0f);
                    DrawBaseRow("Primary ratio", g_VehBasePrimaryRatio, 0.001f, 200.0f, "%.3f", "Lower number, taller gears. internal value: m_primaryTransmissionRatio", 0.05f, 0.2f);
                    DrawBaseRow("Tire friction", g_VehGripFriction, 0.01f, 50.0f, "%.2f", "Controls the vehicle's wheels grip. internal value: m_WheelFrictionMultiplier", 0.05f, 0.2f);
                    DrawBaseRow("Wheel downforce", g_VehGripDownforce, 0.0f, 100.0f, "%.2f", "Controls the vehicle's wheel downforce. Helps wheels grip better. internal value: m_WheelDownforceCoefficient", 0.05f, 0.2f);
                    DrawBaseRow("Drift max torque", g_VehDriftMaxTorque, 1.0f, 100000000.0f, "%.0f", "Lower values make drifting slightly easier to drift. internal value: m_max_drift_torque", 500.0f, 5000.0f);
                    ImGui::EndTable();
                }
            }

            DrawGrappleSection();

            ImGui::PopStyleVar();
        }
        else if (g_CurrentTab == 2) {
            DrawSectionHeader("OCEAN WAVES (NVIDIA WAVEWORKS)");
            
            auto DrawWaveInput = [](const char* label, float* val, float liveVal) {
                ImGui::PushID(label);
                ImGui::AlignTextToFramePadding();
                ImGui::TextUnformatted(label);
                ImGui::SameLine(180.0f * g_UIScale);
                
                bool enabled = (*val >= 0.0f);
                if (ImGui::Checkbox("Override", &enabled)) {
                    if (enabled) *val = liveVal; // Initialize overrides using live weather metrics for smooth transitons
                    else *val = -1.0f;
                    g_ForceWaveWorksUpdate = true;
                }
                ImGui::SameLine();
                ImGui::SetNextItemWidth(130.0f * g_UIScale);
                if (enabled) {
                    if (ImGui::InputFloat("##input", val, 0.5f, 5.0f, "%.2f")) {
                        g_ForceWaveWorksUpdate = true;
                    }
                } else {
                    ImGui::BeginDisabled();
                    float temp = liveVal;
                    ImGui::InputFloat("##input", &temp, 0.0f, 0.0f, "%.2f");
                    ImGui::EndDisabled();
                }
                ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
                ImGui::Text("(Live: %.2f)", liveVal); // Shows current weather-driven setting in real-time
                ImGui::PopStyleColor();
                ImGui::PopID();
            };

            DrawWaveInput("Wave Amplitude", &g_CustomWaveAmplitude, g_LiveWaveAmplitude);
            ImGui::Spacing();
            DrawWaveInput("Wind Speed", &g_CustomWindSpeed, g_LiveWindSpeed);
            ImGui::Spacing();
            DrawWaveInput("Choppy Scale", &g_CustomChoppyScale, g_LiveChoppyScale);
            ImGui::Spacing();
            DrawWaveInput("Small Wave Fraction", &g_CustomSmallWaveFraction, g_LiveSmallWaveFraction);

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            DrawSectionHeader("WEATHER SETTINGS");
            if (ImGui::Checkbox("Rain Everywhere", &g_RainEverywhere)) WriteConfig();
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Forces rain everywhere.");
            ImGui::Spacing();
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 6.0f));
            static char weatherSearch[256] = "";
            ImGui::SetNextItemWidth(-120.0f * g_UIScale);
            ImGui::InputTextWithHint("##weatherSearch", "Search fields...", weatherSearch, sizeof(weatherSearch));
            ImGui::PopStyleVar();
            ImGui::SameLine();
            if (ImGui::Button("Reset All", ImVec2(-1, 0))) {
                for (auto& [n, v] : g_WeatherSettings) {
                    v.modified = false; // Allow recapture
                    if (v.type == WeatherVar::Float) { v.f_cur = v.f_def; FastWrite<float>(g_ExeBase + v.offset, v.f_cur); }
                    else if (v.type == WeatherVar::Bool) { v.b_cur = v.b_def; FastWrite<uint8_t>(g_ExeBase + v.offset, v.b_cur ? 1 : 0); }
                    else { 
                        v.i_cur = v.i_def; 
                        if (v.type == WeatherVar::UInt) FastWrite<uint32_t>(g_ExeBase + v.offset, (uint32_t)v.i_cur);
                        else FastWrite<int32_t>(g_ExeBase + v.offset, v.i_cur);
                    }
                }
            }
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
            ImGui::BeginChild("##WeatherScroll", ImVec2(0, 0), false);
            if (ImGui::BeginTable("##WeatherTable", 3, ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV)) {
                ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 220.0f * g_UIScale);
                ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Reset", ImGuiTableColumnFlags_WidthFixed, 36.0f * g_UIScale);
                ImGui::TableHeadersRow();
                
                bool hasSearch = weatherSearch[0] != '\0';
                std::string searchLower;
                if (hasSearch) {
                    searchLower = weatherSearch;
                    std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), [](unsigned char c){ return std::tolower(c); });
                }
                for (auto& [name, v] : g_WeatherSettings) {
                    if (hasSearch) {
                        std::string nameLower = name;
                        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), [](unsigned char c){ return std::tolower(c); });
                        if (nameLower.find(searchLower) == std::string::npos) continue;
                    }
                    RenderWeatherField(name, v);
                }
                ImGui::EndTable();
            }
            ImGui::EndChild();
            ImGui::PopStyleColor();
        }
        else if (g_CurrentTab == 4) {
            DrawSectionHeader("SPAWN CHAOS OBJECT AT CROSSHAIR");

            // 1. Curated Chaos Object Dropdown Selector
            size_t chaosCount = sizeof(g_ChaosObjects) / sizeof(g_ChaosObjects[0]);
            const char* currentChaosName = (g_SelectedChaosIndex >= 0 && g_SelectedChaosIndex < (int)chaosCount)
                ? g_ChaosObjects[g_SelectedChaosIndex].displayName : "Select Object";

            ImGui::SetNextItemWidth(320.0f * g_UIScale);
            if (ImGui::BeginCombo("##Combo", currentChaosName)) {
                for (int i = 0; i < (int)chaosCount; i++) {
                    bool isSelected = (g_SelectedChaosIndex == i);
                    if (ImGui::Selectable(g_ChaosObjects[i].displayName, isSelected)) {
                        g_SelectedChaosIndex = i;
                    }
                    if (isSelected) ImGui::SetItemDefaultFocus();
                }
                ImGui::EndCombo();
            }

            ImGui::SameLine();
            if (ImGui::Button("Spawn at Crosshair##Btn", ImVec2(180.0f * g_UIScale, 0))) {
                if (g_SelectedChaosIndex >= 0 && g_SelectedChaosIndex < (int)chaosCount) {
                    DoSpawnChaosAtCrosshair(g_ChaosObjects[g_SelectedChaosIndex].tag);
                }
            }

            ImGui::Spacing();

            // 2. Direct In-Game Keybind for Spawning while Aiming
            ImGui::AlignTextToFramePadding();
            ImGui::Text("Crosshair Spawn Hotkey:");
            ImGui::SameLine();

            char chaosBtnLbl[48];
            if (g_AssigningChaosKey) snprintf(chaosBtnLbl, sizeof(chaosBtnLbl), "[ press key ]##ChaosKb");
            else snprintf(chaosBtnLbl, sizeof(chaosBtnLbl), "[ %s ]##ChaosKb", TorVkName(g_SpawnChaosKey));
            if (ImGui::SmallButton(chaosBtnLbl)) {
                g_AssigningChaosKey = !g_AssigningChaosKey;
                g_ChaosKeyListenStart = ImGui::GetTime();
            }
            if (g_AssigningChaosKey && (ImGui::GetTime() - g_ChaosKeyListenStart > 0.2)) {
                for (int vk = 0x08; vk <= 0xFE; vk++) {
                    if (vk == g_ToggleKey) continue;
                    if (GetAsyncKeyState(vk) & 0x8000) {
                        g_SpawnChaosKey = (vk == VK_ESCAPE) ? 0 : vk;
                        g_AssigningChaosKey = false;
                        WriteConfig();
                        break;
                    }
                }
            }
            if (g_SpawnChaosKey != 0) {
                ImGui::SameLine();
                if (ImGui::SmallButton("Clear##ChaosKbClear")) {
                    g_SpawnChaosKey = 0; // Reset to None
                    WriteConfig();
                }
            }
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
            ImGui::Text("(Press key in-game to spawn at crosshair)");
            ImGui::PopStyleColor();

            ImGui::Spacing();

            // 3. Manual Chaos Tag Entry
            ImGui::SetNextItemWidth(-180.0f * g_UIScale);
            ImGui::InputTextWithHint("##ManualChaos", "Manual tag (e.g. v904_trailer_smallmobileweapon_military)", g_ManualChaosBuf, sizeof(g_ManualChaosBuf));
            ImGui::SameLine();
            if (ImGui::Button("Spawn Custom at Crosshair##ManualBtn", ImVec2(-1, 0))) {
                if (g_ManualChaosBuf[0] != '\0') {
                    DoSpawnChaosAtCrosshair(g_ManualChaosBuf);
                }
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            DrawSectionHeader("SPAWN VEHICLE");

            ImGui::Text("Favorite Spawn Key:");
ImGui::SameLine();

if (g_AssigningFavoriteKey) {
    float pulse = (sinf((float)ImGui::GetTime() * 5.0f) + 1.0f) * 0.5f;

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.25f + 0.75f * pulse);
    if (ImGui::Button("Press any button to assign the new key", ImVec2(0, 0))) {
        g_AssigningFavoriteKey = false;
    }
    ImGui::PopStyleVar();

    if (g_AssigningFavoriteKey && ImGui::GetTime() - g_FavoriteKeyListenStart > 0.25) {
        for (int vk = 0x01; vk <= 0xFE; vk++) {
            if (vk == VK_LBUTTON || vk == VK_RBUTTON || vk == VK_MBUTTON || vk == VK_CANCEL || vk == g_ToggleKey) {
                continue;
            }

            SHORT state = o_GetAsyncKeyState ? o_GetAsyncKeyState(vk) : GetAsyncKeyState(vk);
            if (state & 0x8000) {
                g_SpawnFavoriteKey = vk;
                g_AssigningFavoriteKey = false;
                break;
            }
        }
    }
} else {
    if (ImGui::Button("Assign a new key", ImVec2(0, 0))) {
        g_AssigningFavoriteKey = true;
        g_FavoriteKeyListenStart = ImGui::GetTime();
    }
}

ImGui::SameLine();
ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.45f, 0.50f, 1.0f));
char favoriteKeyName[64] = "";

UINT favoriteScan = MapVirtualKeyA((UINT)g_SpawnFavoriteKey, MAPVK_VK_TO_VSC);
if (favoriteScan != 0) {
    GetKeyNameTextA((LONG)(favoriteScan << 16), favoriteKeyName, sizeof(favoriteKeyName));
}

if (favoriteKeyName[0] == '\0') {
    if ((g_SpawnFavoriteKey >= '0' && g_SpawnFavoriteKey <= '9') ||
        (g_SpawnFavoriteKey >= 'A' && g_SpawnFavoriteKey <= 'Z')) {
        favoriteKeyName[0] = (char)g_SpawnFavoriteKey;
        favoriteKeyName[1] = '\0';
    } else {
        snprintf(favoriteKeyName, sizeof(favoriteKeyName), "Unknown");
    }
}

ImGui::Text("Current VK: %d (%s)", g_SpawnFavoriteKey, favoriteKeyName);
ImGui::PopStyleColor();

            if (g_FavoriteVehicle.empty()) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.5f, 0.3f, 1.0f));
                ImGui::TextWrapped("No favorite selected. Click (*) next to a vehicle below to set it.");
                ImGui::PopStyleColor();
            } else {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 1.0f, 0.5f, 1.0f));
                ImGui::TextWrapped("Favorite: %s", g_FavoriteVehicle.c_str());
                ImGui::PopStyleColor();
                ImGui::SameLine();
                if (ImGui::SmallButton("Clear")) {
                    g_FavoriteVehicle.clear();
                }
                ImGui::SameLine();
                if (ImGui::SmallButton("Spawn Now")) {
                    TrySpawnVehicle(g_FavoriteVehicle);
                }
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            // --- Manual spawn section ---
            DrawSectionHeader("MANUAL SPAWN");
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.55f, 0.6f, 1.0f));
            ImGui::TextWrapped("Use this ONLY if the vehicle is NOT in the list below and you know its exact internal name.");
            ImGui::PopStyleColor();
            ImGui::Spacing();
            ImGui::SetNextItemWidth(-120.0f * g_UIScale);
            ImGui::InputTextWithHint("##ManualSpawn", "e.g. v000_car_atv_civilian_01", g_ManualSpawnBuf, sizeof(g_ManualSpawnBuf));
            ImGui::SameLine();
            if (ImGui::Button("Spawn", ImVec2(-1, 0))) {
                if (g_ManualSpawnBuf[0] != '\0') {
                    TrySpawnVehicle(g_ManualSpawnBuf);
                }
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            // --- Available list section ---
            DrawSectionHeader("AVAILABLE LIST");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##SpawnSearch", "Search (e.g. 'car sedan racing')...", g_SpawnSearchBuf, sizeof(g_SpawnSearchBuf));
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
            ImGui::TextWrapped("Tip: Separate keywords with spaces to narrow down results (e.g. 'car sedan racing')");
            ImGui::PopStyleColor();
            ImGui::Spacing();

            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
            ImGui::BeginChild("##SpawnScroll", ImVec2(0, 0), false);
            if (ImGui::BeginTable("##SpawnTable", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV)) {
                ImGui::TableSetupColumn("Fav", ImGuiTableColumnFlags_WidthFixed, 40.0f * g_UIScale);
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 70.0f * g_UIScale);
                ImGui::TableHeadersRow();

                // Split search query into lowercase individual word tokens
                std::vector<std::string> searchTokens;
                if (g_SpawnSearchBuf[0] != '\0') {
                    std::string searchLower = g_SpawnSearchBuf;
                    std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), [](unsigned char c){ return (char)std::tolower(c); });
                    std::stringstream ss(searchLower);
                    std::string token;
                    while (ss >> token) {
                        if (!token.empty()) searchTokens.push_back(token);
                    }
                }

                size_t hintsCount = sizeof(g_SpawnHints) / sizeof(g_SpawnHints[0]);
                for (size_t i = 0; i < hintsCount; i++) {
                    const char* hint = g_SpawnHints[i];
                    if (!searchTokens.empty()) {
                        std::string hintLower = hint;
                        std::transform(hintLower.begin(), hintLower.end(), hintLower.begin(), [](unsigned char c){ return (char)std::tolower(c); });
                        bool matchAll = true;
                        for (const auto& tok : searchTokens) {
                            if (hintLower.find(tok) == std::string::npos) {
                                matchAll = false;
                                break;
                            }
                        }
                        if (!matchAll) continue;
                    }

                    ImGui::PushID((int)i);
                    ImGui::TableNextRow();

                    // Star / favorite button
                    ImGui::TableSetColumnIndex(0);
                    bool isFav = (g_FavoriteVehicle == hint);
                    if (isFav) {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.85f, 0.0f, 1.0f));
                        if (ImGui::SmallButton("(*)")) {
                            g_FavoriteVehicle.clear();
                        }
                        ImGui::PopStyleColor();
                    } else {
                        if (ImGui::SmallButton("( )")) {
                            g_FavoriteVehicle = hint;
                        }
                    }

                    // Name
                    ImGui::TableSetColumnIndex(1);
                    ImGui::AlignTextToFramePadding();
                    ImGui::TextUnformatted(hint);

                    // Spawn button
                    ImGui::TableSetColumnIndex(2);
                    if (ImGui::SmallButton("Spawn")) {
                        TrySpawnVehicle(hint);
                    }

                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::EndChild();
            ImGui::PopStyleColor();
        }
        else if (g_CurrentTab == 5) {
            DrawSectionHeader("GLOBAL WORLD & ALTITUDE LIMITS");
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12.0f, 8.0f));

            // Display live Havok memory readings without clobbering configured user values
            float liveMemMaxAlt = 7000.0f, liveMemMinAlt = -1000.0f;
            if (g_ExeBase) {
                FastRead<float>(g_ExeBase + g_Addr_2CE3F38, liveMemMaxAlt);
                FastRead<float>(g_ExeBase + g_Addr_2AF1E68, liveMemMinAlt);
            }
            ImGui::TextDisabled("Live Havok Memory: Ceiling: %.0fm | Floor: %.0fm", liveMemMaxAlt, liveMemMinAlt);

            // Main Toggle
            if (ImGui::Checkbox("Overwrite global altitude limit", &g_OverrideAltitudeLimit)) {
                ApplyAltitudeOverride(g_OverrideAltitudeLimit);
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            // Grey out the inputs if the toggle is disabled
            if (!g_OverrideAltitudeLimit) {
                ImGui::BeginDisabled();
            }

            // Input: Max Altitude (Reads real-time when disabled, editable when enabled)
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Max Altitude (Meters):");
            ImGui::SameLine(220.0f * g_UIScale);
            ImGui::SetNextItemWidth(180.0f * g_UIScale);
            if (ImGui::InputFloat("##MaxAltitudeVal", &g_LiveMaxAltitude, 100.0f, 1000.0f, "%.1f")) {
                if (g_OverrideAltitudeLimit && g_ExeBase) {
                    FastWrite<float>(g_ExeBase + g_Addr_2CE3F38, g_LiveMaxAltitude);
                    SyncBroadphaseInputToSpan();
                    FastWrite<float>(g_ExeBase + g_Addr_2AF1E64, EffectiveBroadphaseSize());
                }
            }

            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
            ImGui::TextWrapped("Controls the height ceiling. Approaching this limit gradually dampens and halts all vertical (Y-axis) velocity. Also increases the height altitude where rico will freeze in the air. High values (>10000) make loading screens load forever, use with caution.");
            ImGui::PopStyleColor();

            ImGui::Spacing();
            ImGui::Spacing();

            // Input: Min Altitude (Reads real-time when disabled, editable when enabled)
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Min Altitude (Meters):");
            ImGui::SameLine(220.0f * g_UIScale);
            ImGui::SetNextItemWidth(180.0f * g_UIScale);
            if (ImGui::InputFloat("##MinAltitudeVal", &g_LiveMinAltitude, 100.0f, 1000.0f, "%.1f")) {
                if (g_OverrideAltitudeLimit && g_ExeBase) {
                    FastWrite<float>(g_ExeBase + g_Addr_2AF1E68, g_LiveMinAltitude);
                    SyncBroadphaseInputToSpan();
                    FastWrite<float>(g_ExeBase + g_Addr_2AF1E64, EffectiveBroadphaseSize());
                }
            }

            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
            ImGui::TextWrapped("Controls the lower altitude floor (negative elevation). Also increases the height altitude where rico will freeze in the air. High values (>20000) will make loading screens load forever, use with caution.");
            ImGui::PopStyleColor();

            ImGui::Spacing();
            ImGui::Spacing();

            // Input: Broadphase Box Size (auto: (max-min)+500, display-only)
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Broadphase Box Size:");
            ImGui::SameLine(220.0f * g_UIScale);
            ImGui::SetNextItemWidth(180.0f * g_UIScale);
            ImGui::BeginDisabled();
            ImGui::InputFloat("##BroadphaseSizeVal", &g_LiveBroadphaseSize, 100.0f, 1000.0f, "%.1f");
            ImGui::EndDisabled();

            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.52f, 0.58f, 1.0f));
            ImGui::TextWrapped("Displays the outer physics simulation boundary.");
            ImGui::PopStyleColor();

            if (!g_OverrideAltitudeLimit) {
                ImGui::EndDisabled();
            }

            // ====================================================================
            // SUB-SECTION: ENTITY SPAWN LIMITS & CUSTOM CATEGORY POOLS
            // ====================================================================
            DrawSectionHeader("SPAWN LIMITS & CUSTOM CATEGORY POOLS");

            // Master Toggle. The warmup gate owns the actual apply/restore so the
            // budget is never pushed into the engine before the world settles.
            ImGui::Checkbox("Override default spawn limits", &g_OverrideSpawnLimits);

            // Performance & RAM Impact Warning Note
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.45f, 0.35f, 1.0f));
            ImGui::TextWrapped("Warning: Expect performance issues after enabling this and setting the below numbers high.");
            ImGui::PopStyleColor();

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            if (!g_OverrideSpawnLimits) {
                ImGui::BeginDisabled();
            }

            auto DrawBudgetRow = [&](const char* label, const char* id, int32_t& liveVal, int32_t defVal, int step, int stepFast, int minVal, const char* tooltip) {
                ImGui::AlignTextToFramePadding();
                ImGui::TextUnformatted(label);
                if (tooltip) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("[?]");
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", tooltip);
                }
                ImGui::SameLine(250.0f * g_UIScale);
                ImGui::SetNextItemWidth(120.0f * g_UIScale);
                int val = (int)liveVal;
                if (ImGui::InputInt(id, &val, step, stepFast)) {
                    if (val < minVal) val = minVal;
                    liveVal = (int32_t)val;
                    if (g_OverrideSpawnLimits) ApplySpawnLimitOverrides(true);
                }
                ImGui::SameLine();
                char btnId[32];
                snprintf(btnId, sizeof(btnId), "Reset##%s", id);
                if (ImGui::SmallButton(btnId)) {
                    liveVal = (int32_t)defVal;
                    if (g_OverrideSpawnLimits) ApplySpawnLimitOverrides(true);
                }
                ImGui::SameLine();
                ImGui::TextDisabled("(Default: %d)", defVal);
            };

            // Master Vehicle Simulation Budget Input: Controls the active vehicle ceiling
            DrawBudgetRow("Vehicle Simulation Budget:", "##MasterSimBudget", *(int32_t*)&g_LiveSimBudget, 35, 1, 25, 1,
                          "The target number of vehicles the world simulator will spawn up to. When disabled, restores default of 35.");

            DrawBudgetRow("Spawn Cycle Delay (ms):", "##SpawnDelayVal", *(int32_t*)&g_LiveSpawnDelayMs, 5000, 100, 500, 50,
              "Cooldown delay between spawn attempts. Vanilla default is 5000ms (5s). Lower values (e.g. 50-250ms) populate traffic rapidly.");
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            // Live Category Breakdown Telemetry
            size_t liveLand = 0, liveSea = 0, liveAir = 0;
            uintptr_t activeSim = 0;
            FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D98, activeSim);
            if (!activeSim) activeSim = GetWorldSimManager();
            if (activeSim) {
                auto ReadCount = [&](uintptr_t offset) -> size_t {
                    uintptr_t bgn = 0, end = 0;
                    if (FastRead<uintptr_t>(activeSim + offset, bgn) && FastRead<uintptr_t>(activeSim + offset + 8, end)) {
                        if (end >= bgn) return (end - bgn) / 16;
                    }
                    return 0;
                };
                liveLand = ReadCount(0x5C0);
                liveSea  = ReadCount(0x6D8);
                liveAir  = ReadCount(0x7F0);
            }

            int32_t engineLiveVehicles = 0;
            int32_t engineDeadWrecks   = 0;
            uintptr_t vRec = GetVehicleBudgetRecord();
            if (vRec) {
                FastRead<int32_t>(vRec + 0x84, engineLiveVehicles); // m_InstanceUsedAlive
                FastRead<int32_t>(vRec + 0x88, engineDeadWrecks);   // m_InstanceUsedDead
            }

            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "LIVE VEHICLE TELEMETRY:");
            ImGui::Text("Land Vehicles : %zu / %d", liveLand, g_SpawnLimitsActive ? g_LiveSimBudget : 25);
            ImGui::Text("Sea Vessels   : %zu", liveSea);
            ImGui::Text("Air Aircraft  : %zu", liveAir);
            ImGui::Text("Total Active  : %d / %d (Dead Wrecks: %d)", engineLiveVehicles, g_SpawnLimitsActive ? g_LiveSimBudget : g_DefSimBudget, engineDeadWrecks);

            if (!g_OverrideSpawnLimits) {
                ImGui::EndDisabled();
            }

            ImGui::PopStyleVar();
        }

        // Bottom padding filler for all tabs
        ImGui::Dummy(ImVec2(0.0f, 35.0f * g_UIScale));

        ImGui::EndChild();
    }
    ImGui::EndChild();
    ImGui::End();
    ImGui::PopStyleVar();
}
// ============================================================================
// KEY POLLING THREAD
// ============================================================================
DWORD WINAPI KeyPollingThread(LPVOID) {
    static bool key_pressed = false;
    static bool fav_key_pressed = false;
    static DWORD lastTickTime = GetTickCount();

    while (true) {
        // Do not process keys or retries unless the game process window is currently focused
        HWND fg = GetForegroundWindow();
        DWORD fgPid = 0;
        if (fg) GetWindowThreadProcessId(fg, &fgPid);
        if (fgPid != GetCurrentProcessId()) {
            Sleep(100);
            continue;
        }

        DWORD now = GetTickCount();

        

        // Background Spawn Retry System (waits 0.35s per retry, 10s max timeout)
        if (!g_PendingSpawnVehicle.empty() && GetPlayerPtr()) {
            if (now - g_PendingSpawnStartTime > 10000) {
                std::cout << "[Spawn] FAILED: Could not spawn '" << g_PendingSpawnVehicle << "' within 10s timeout.\n";
                g_PendingSpawnVehicle.clear();
                g_SpawnInProgress = false;
            } else if (!g_SpawnInProgress && (now - g_LastSpawnAttemptTime >= 350)) {
                g_LastSpawnAttemptTime = now;
                DoSpawnVehicle(g_PendingSpawnVehicle);
            }
        }

        // Tornado tab keybinds (only active when mod menu is closed)
        if (!g_ShowMenu) {
            TornadoHandleKeys();
        }

        // Noclip, Freecam & First Person Shortcuts (only active when mod menu is closed)
        static bool noclip_key_down = false;
        static bool freecam_key_down = false;
        static bool fp_key_down = false;

        if (!g_ShowMenu && !g_AssigningNoclipKey && !g_AssigningFreeCamKey && !g_AssigningFirstPersonKey && !g_AssigningFavoriteKey && !g_TorUiTyping) {
            if (g_NoclipKey > 0 && (GetAsyncKeyState(g_NoclipKey) & 0x8000)) {
                if (!noclip_key_down) {
                    g_Noclip = !g_Noclip;
                    if (g_Noclip && g_FreeCam) g_FreeCam = false;
                    noclip_key_down = true;
                }
            } else {
                noclip_key_down = false;
            }

            if (g_FreeCamKey > 0 && (GetAsyncKeyState(g_FreeCamKey) & 0x8000)) {
                if (!freecam_key_down) {
                    g_FreeCam = !g_FreeCam;
                    if (g_FreeCam && g_Noclip) g_Noclip = false;
                    freecam_key_down = true;
                }
            } else {
                freecam_key_down = false;
            }

            if (g_FirstPersonKey > 0 && (GetAsyncKeyState(g_FirstPersonKey) & 0x8000)) {
                if (!fp_key_down) {
                    g_FirstPerson = !g_FirstPerson;
                    if (g_FirstPerson && g_FreeCam) g_FreeCam = false;
                    fp_key_down = true;
                }
            } else {
                fp_key_down = false;
            }

            // Chaos Object crosshair spawn shortcut
            static bool chaos_key_down = false;
            if (!g_AssigningChaosKey && g_SpawnChaosKey > 0 && (GetAsyncKeyState(g_SpawnChaosKey) & 0x8000)) {
                if (!chaos_key_down) {
                    size_t count = sizeof(g_ChaosObjects) / sizeof(g_ChaosObjects[0]);
                    if (g_SelectedChaosIndex >= 0 && g_SelectedChaosIndex < (int)count) {
                        DoSpawnChaosAtCrosshair(g_ChaosObjects[g_SelectedChaosIndex].tag);
                    }
                    chaos_key_down = true;
                }
            } else {
                chaos_key_down = false;
            }
        }

        // Favorite vehicle spawn keybind (only active when mod menu is closed)
        if (!g_ShowMenu && !g_AssigningFavoriteKey && (GetAsyncKeyState(g_SpawnFavoriteKey) & 0x8000)) {
            if (!fav_key_pressed && !g_FavoriteVehicle.empty()) {
                fav_key_pressed = true;
                TrySpawnVehicle(g_FavoriteVehicle);
            }
        } else {
            fav_key_pressed = false;
        }
        if (!g_AssigningFavoriteKey && (GetAsyncKeyState(g_ToggleKey) & 0x8000)) {
            if (!key_pressed) {
                g_ShowMenu = !g_ShowMenu;
                key_pressed = true;

                // Send key-up for WASD on BOTH menu open AND menu close (no WM_KILLFOCUS)
                if (g_HWnd) {
                    const UINT movementKeys[] = { 'W', 'A', 'S', 'D', VK_SHIFT, VK_SPACE, VK_CONTROL };
                    for (UINT k : movementKeys) {
                        PostMessage(g_HWnd, WM_KEYUP, k, 0xC0000001);
                    }
                }

                std::cout << "[*] Toggle key pressed! g_ShowMenu = " << (g_ShowMenu ? "TRUE" : "FALSE") << "\n";
            }
        } else {
            key_pressed = false;
        }
        Sleep(20);
    }
    return 0;
}

static IDXGISwapChain* g_LastSwapChain = nullptr;
UINT64 g_FrameCount = 0;
static DWORD g_LastLogTime = 0;

void CheckLoadedOverlays() {
    static bool checked = false;
    if (checked) return;
    checked = true;

    const char* overlays[] = {
        "nvspcap64.dll",             // NVIDIA ShadowPlay
        "GameOverlayRenderer64.dll", // Steam
        "DiscordHook64.dll",         // Discord
        "RTSSHook64.dll",            // RivaTuner / MSI
        "SpecialK64.dll"             // SpecialK
    };

    for (const char* dll : overlays) {
        HMODULE h = GetModuleHandleA(dll);
        if (h) {
            std::cout << "\033[1;33m[!] DETECTED OVERLAY INTERFERENCE: " << dll << " (Base: " << h << ")\033[0m\n";
        }
    }
}

HWND FindRealGameWindow() {
    struct EnumData { DWORD pid; HWND hwnd; };
    EnumData data = { GetCurrentProcessId(), NULL };
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        EnumData* pData = (EnumData*)lParam;
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == pData->pid && IsWindowVisible(hwnd)) {
            RECT r;
            GetClientRect(hwnd, &r);
            if ((r.right - r.left) > 300 && (r.bottom - r.top) > 300) {
                pData->hwnd = hwnd;
                return FALSE;
            }
        }
        return TRUE;
    }, (LPARAM)&data);
    return data.hwnd;
}

static HWND g_ImGuiBoundHwnd = NULL;
static ID3D11Device* g_ImGuiBoundDevice = NULL;
void SafeInitImGui(HWND hwnd, ID3D11Device* dev, ID3D11DeviceContext* ctx) {
    if (!hwnd || !dev || !ctx) return;
    if (!g_ImGuiInited) {
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        ApplyEnhancedStyle();
        io.FontGlobalScale = g_UIScale;
        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(dev, ctx);
        g_ImGuiBoundHwnd = hwnd;
        g_ImGuiBoundDevice = dev;
        g_ImGuiInited = true;
        std::cout << "\033[1;32m[+] ImGui Successfully Initialized for HWND: " << hwnd << "\033[0m\n";
    } else {
        if (hwnd == g_ImGuiBoundHwnd && dev == g_ImGuiBoundDevice) return;
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(dev, ctx);
        ImGui::GetIO().FontGlobalScale = g_UIScale;
        g_ImGuiBoundHwnd = hwnd;
        g_ImGuiBoundDevice = dev;
        std::cout << "\033[1;33m[!] Re-bound ImGui to New Game HWND: " << hwnd << "\033[0m\n";
    }
}

// Loading Screen Dismissal Trackers
static volatile bool g_LoadingScreenLifted = false;

typedef void(__thiscall* CLoadUI_OnHide_t)(uintptr_t);
static CLoadUI_OnHide_t o_CLoadUI_OnHide = nullptr;

static void __fastcall hk_CLoadUI_OnHide(uintptr_t thisptr) {
    g_LoadingScreenLifted = true;
    if (o_CLoadUI_OnHide) {
        o_CLoadUI_OnHide(thisptr);
    }
}

void hk_SendEvent(const char* eventName, void* param_2) {
    JC4UltraFastLoad::OnEvent(eventName);
    if (eventName) {
        if (strstr(eventName, "loading_screen_start") || strstr(eventName, "game_loading_initiated")) {
            g_LoadingScreenLifted = false;
        } else if (strstr(eventName, "loading_screen_fully_lifted") || strstr(eventName, "loading_screen_end")) {
            g_LoadingScreenLifted = true;
        }
    }
    if (o_SendEvent) {
        o_SendEvent(eventName, param_2);
    }
}

HRESULT __stdcall hkPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags) {
    if (!pSwapChain) return oPresent(pSwapChain, SyncInterval, Flags);

    g_FrameCount++;
    DWORD now = GetTickCount();

    // If player is null (during Fast Travel / loading screen), clear cached pointers
    // to prevent memory corruption and use-after-free crashes.
    uintptr_t playerPtr = GetPlayerPtr();
    JC4UltraFastLoad::OnFrame(playerPtr);
    if (!playerPtr) {
        g_CachedWingsuitPtr = 0;
        g_CachedWorldSimMgr = 0;
        g_CachedGraphicsCamMgr = 0;
        g_ActiveWingsuitWeapon = 0; // Clear so new character instance resolves fresh weapon
    } else {
        if (g_LockOxygen) {
            FastWrite<float>(playerPtr + 0x5F8, g_OxygenValue);
        }
        if (g_LockHealth) {
            uintptr_t characterPtr = 0;
            if (FastRead<uintptr_t>(playerPtr + 0x68, characterPtr) && characterPtr) {
                FastWrite<int16_t>(characterPtr + 0x3AC, (int16_t)g_HealthValue);
            }
        }
        // NOTE: Desired FOV enforcement lives in hk_CameraUpdateRender (entry hook), not here.
        // Keep live player context in sync after respawns / fast-travel.
        // NOTE: altitude/spawn overrides are NOT re-applied here: they go
        // solely through the canApplyToggles-gated path below (world ready +
        // warmup). Applying the Havok exit-hook RET during loading/fast-
        // travel streaming freezes all loading screens (saved config with
        // override ON hit this on restart). The gated path picks up the
        // state change once settled via s_LastAltitudeState.
        static uintptr_t s_lastPlayer = 0;
        if (playerPtr != s_lastPlayer) {
            s_lastPlayer = playerPtr;
            // ApplyHavokPhysicsSettings() and ApplySpawnLimitOverrides() are no
            // longer run here: both wait for the warmup gate, which re-applies
            // them once the (re)spawned world settles.
            // Refresh altitude/box after respawns (death re-caches the ceiling
            // at spawn): only once loading has lifted, never mid-streaming.
            // Per-frame gated enforcement alone leaves a stale 7000 cache in
            // the new character when it spawns during the loading gate.
            if (g_OverrideAltitudeLimit && g_LoadingScreenLifted && playerPtr) {
                ApplyAltitudeOverride(true);
            }
        }

        // Continuously enforce custom wingsuit settings against engine resets
        uintptr_t wingsuitPtr = GetWingsuitSettingsPtr();
        if (wingsuitPtr) {
            ApplyWingsuitSettings(wingsuitPtr);
        }

        // (Missile properties are set once on spawn in HookMissileInit - do not touch in present)
    }

    static bool s_LastSpawnLimitsState = false;
    // The ENABLE arm is fully owned by the warmup gate below, so the simulation
    // budget is not pushed into the engine during loading or before the gate
    // finishes (this was the source of the "0 / 1" showing up mid-warmup).
    // Only the disable/restore arm stays here: turning the override off while the
    // world is still loading must still undo the .text + world-sim patches.
    if (!g_OverrideSpawnLimits && s_LastSpawnLimitsState) {
        ApplySpawnLimitOverrides(false);
        s_LastSpawnLimitsState = false;
        g_SpawnLimitsActive = false;
    }

    

    // Read live, un-clamped variables directly from game memory
    if (g_ActiveNvWaveWorkSimulation) {
        // Rate-limit passive diagnostic scans to every 2.5 seconds to eliminate system-call overhead
        static DWORD lastCaptureTime = 0;
        if (now - lastCaptureTime > 2500) {
            lastCaptureTime = now;
            FastRead<float>(g_ActiveNvWaveWorkSimulation + 0x90, g_LiveWaveAmplitude);
            FastRead<float>(g_ActiveNvWaveWorkSimulation + 0x9C, g_LiveWindSpeed);
            FastRead<float>(g_ActiveNvWaveWorkSimulation + 0xA4, g_LiveChoppyScale);
            FastRead<float>(g_ActiveNvWaveWorkSimulation + 0xA8, g_LiveSmallWaveFraction);
        }

        // Active overrides bypass the rate-limiter so sliders respond instantly
        if (g_ForceWaveWorksUpdate) {
            FastWrite<float>(g_ActiveNvWaveWorkSimulation + 0xC0, -999.0f); // Corrupt active state to fail memcmp
            g_ForceWaveWorksUpdate = false;
        }
    }
    

    CheckLoadedOverlays();

    // Auto-detect real window if current window is dead or missing
    if (!IsWindow(g_HWnd) || g_HWnd == NULL) {
        HWND realHWnd = FindRealGameWindow();
        if (realHWnd && realHWnd != g_HWnd) {
            std::cout << "\033[1;32m[+] AUTO-RECOVERED REAL GAME WINDOW HWND: " << realHWnd << "\033[0m\n";
            g_HWnd = realHWnd;
            HookWndProc(g_HWnd);
            
                    if (g_pd3dDevice && g_pd3dContext) {
            SafeInitImGui(g_HWnd, g_pd3dDevice, g_pd3dContext);

            
            
        }
        }
    }

    

    // SwapChain Switch Detection
    if (pSwapChain != g_LastSwapChain) {
        std::cout << "\033[1;33m[!] SWAPCHAIN CHANGED! Old: " << g_LastSwapChain << " -> New: " << pSwapChain << "\033[0m\n";
        g_LastSwapChain = pSwapChain;

        ID3D11Device* pNewDev = nullptr;
        if (FAILED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&pNewDev)) || !pNewDev) {
            g_LastSwapChain = nullptr;
            return oPresent(pSwapChain, SyncInterval, Flags);
        }
        ID3D11DeviceContext* pNewCtx = nullptr;
        pNewDev->GetImmediateContext(&pNewCtx);
        if (!pNewCtx) {
            pNewDev->Release();
            g_LastSwapChain = nullptr;
            return oPresent(pSwapChain, SyncInterval, Flags);
        }
        if (g_mainRenderTargetView) {
            g_mainRenderTargetView->Release();
            g_mainRenderTargetView = nullptr;
        }
        if (g_pd3dContext) g_pd3dContext->Release();
        if (g_pd3dDevice) g_pd3dDevice->Release();
        g_pd3dDevice = pNewDev;
        g_pd3dContext = pNewCtx;

        DXGI_SWAP_CHAIN_DESC sd;
        pSwapChain->GetDesc(&sd);
        HWND newHWnd = sd.OutputWindow;

        if (newHWnd && IsWindow(newHWnd)) {
            g_HWnd = newHWnd;
            HookWndProc(g_HWnd);
        }

        ID3D11Texture2D* pBackBuffer = nullptr;
        if (SUCCEEDED(pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer))) {
            g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
            pBackBuffer->Release();
        }

        SafeInitImGui(g_HWnd, g_pd3dDevice, g_pd3dContext);
    } else {
        HookWndProc(g_HWnd);
    }

    if (!g_mainRenderTargetView) {
        ID3D11Texture2D* pBackBuffer = nullptr;
        if (SUCCEEDED(pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer))) {
            g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
            pBackBuffer->Release();
        }
    }

        if (!g_ImGuiInited || !g_pd3dContext || !g_mainRenderTargetView) return oPresent(pSwapChain, SyncInterval, Flags);
        g_MenuAlpha = g_ShowMenu ? 1.0f : 0.0f;

    // ---- Settled world state (invoked only inside the warmup gate) ----
    // The fog/haze/atmosphere/blur/cloud toggles and the heat-system enforcement
    // below used to run on EVERY present (i.e. during loading and streaming too).
    // They are now wrapped in a lambda that the canApplyToggles gate calls once
    // the world has settled, so nothing touches world singletons early.
    auto ApplySettledWorldState = [](uintptr_t playerPtr, DWORD now) {
    // Enforce independent Fog, Haze, and Atmospheric Toggles
    if (g_ExeBase) {
        static bool distFogPatched = false;
        static bool groundHazePatched = false;
        static bool atmoScatteringPatched = false;
        
        static uint8_t origFogRender = 0;
        static uint8_t origAtmoFogGlobal = 1;
        static uint8_t origGroundHaze = 0;
        static uint8_t origSkyAtmoGlobal = 1;
        static uint8_t origAtmoDraw = 0;
        static uint8_t origAtmoCompute = 0;

        uint8_t retByte = 0xC3;
        uint8_t falseByte = 0x0;

        // 1. Distance Fog Toggle
                // 5. Blur & Reflection Toggles
        static bool motionBlurPatched = false;
        static uint8_t origMotionBlur = 1;
        if (g_DisableMotionBlur && !motionBlurPatched) {
            if (FastRead<uint8_t>(g_ExeBase + g_Addr_2AE55F0, origMotionBlur)) FastWrite<uint8_t>(g_ExeBase + g_Addr_2AE55F0, 0);
            motionBlurPatched = true;
        } else if (!g_DisableMotionBlur && motionBlurPatched) {
            FastWrite<uint8_t>(g_ExeBase + g_Addr_2AE55F0, origMotionBlur);
            motionBlurPatched = false;
        }

        static bool radialBlurPatched = false;
        static uint8_t origRadialBlur = 1;
        if (g_DisableRadialBlur && !radialBlurPatched) {
            if (FastRead<uint8_t>(g_ExeBase + g_Addr_2AE5610, origRadialBlur)) FastWrite<uint8_t>(g_ExeBase + g_Addr_2AE5610, 0);
            radialBlurPatched = true;
        } else if (!g_DisableRadialBlur && radialBlurPatched) {
            FastWrite<uint8_t>(g_ExeBase + g_Addr_2AE5610, origRadialBlur);
            radialBlurPatched = false;
        }

        static bool velocityReprojPatched = false;
        static uint8_t origVelocityReproj = 1;
        if (g_DisableVelocityReprojection && !velocityReprojPatched) {
            if (FastRead<uint8_t>(g_ExeBase + g_Addr_2AE55F9, origVelocityReproj)) FastWrite<uint8_t>(g_ExeBase + g_Addr_2AE55F9, 0);
            velocityReprojPatched = true;
        } else if (!g_DisableVelocityReprojection && velocityReprojPatched) {
            FastWrite<uint8_t>(g_ExeBase + g_Addr_2AE55F9, origVelocityReproj);
            velocityReprojPatched = false;
        }

        static bool edgeStencilPatched = false;
        static uint8_t origEdgeStencil = 1;
        if (g_DisableEdgeStencil && !edgeStencilPatched) {
            if (FastRead<uint8_t>(g_ExeBase + g_Addr_2AE55F8, origEdgeStencil)) FastWrite<uint8_t>(g_ExeBase + g_Addr_2AE55F8, 0);
            edgeStencilPatched = true;
        } else if (!g_DisableEdgeStencil && edgeStencilPatched) {
            FastWrite<uint8_t>(g_ExeBase + g_Addr_2AE55F8, origEdgeStencil);
            edgeStencilPatched = false;
        }

        static bool waterReflPatched = false;
        static uint8_t origWaterRefl = 1;
        if (g_DisableWaterReflections && !waterReflPatched) {
            if (FastRead<uint8_t>(g_ExeBase + g_Addr_2CAD92D, origWaterRefl)) FastWrite<uint8_t>(g_ExeBase + g_Addr_2CAD92D, 0);
            waterReflPatched = true;
        } else if (!g_DisableWaterReflections && waterReflPatched) {
            FastWrite<uint8_t>(g_ExeBase + g_Addr_2CAD92D, origWaterRefl);
                     waterReflPatched = false;
        }

        static bool shadowsPatched = false;
        static float origSunRadius[5] = {0};
        if (g_DisableShadows && !shadowsPatched) {
            for (int i = 0; i < 5; i++) {
                FastRead<float>(g_ExeBase + g_Addr_2AE9720 + (i * 4), origSunRadius[i]);
                FastWrite<float>(g_ExeBase + g_Addr_2AE9720 + (i * 4), 0.001f);
            }
            shadowsPatched = true;
        } else if (!g_DisableShadows && shadowsPatched) {
            for (int i = 0; i < 5; i++) {
                FastWrite<float>(g_ExeBase + g_Addr_2AE9720 + (i * 4), origSunRadius[i]);
            }
            shadowsPatched = false;
        }
        if (g_DisableDistanceFog && !distFogPatched) {
            if (FastRead<uint8_t>(g_ExeBase + g_Addr_2AE9818, origAtmoFogGlobal)) SafePatchBytes(g_ExeBase + g_Addr_2AE9818, &falseByte, 1);
            distFogPatched = true;
        } else if (!g_DisableDistanceFog && distFogPatched) {
            SafePatchBytes(g_ExeBase + g_Addr_2AE9818, &origAtmoFogGlobal, 1);
            distFogPatched = false;
        }

        // 2. Ground Haze / Fog Toggle — only touches TWO values:
        // HeightFogDensity and AerialPerspectiveScale, both forced to 0 on
        // activation. While active those two are re-read every 250 ms; if
        // either comes back non-zero it was changed externally (weather debug
        // tab) -> stop enforcing, adopt the user's value and auto-disable the
        // toggle so the UI reflects reality. Nothing else is written or
        // checked. Toggle-off restores just these two to their defaults.
        if (g_DisableGroundHaze) {
            static DWORD lastHazeEnforce = 0;
            auto isHazeFloat = [](const std::string& n) {
                return n == "HeightFogDensity" || n == "AerialPerspectiveScale";
            };
            if (!groundHazePatched) {
                for (auto& [name, v] : g_WeatherSettings) {
                    if (isHazeFloat(name)) {
                        v.f_cur = 0.0f; v.modified = true; FastWrite<float>(g_ExeBase + v.offset, 0.0f);
                    }
                }
                groundHazePatched = true;
                lastHazeEnforce = now;
            } else if (now - lastHazeEnforce >= 250) {
                lastHazeEnforce = now;
                bool externallyChanged = false;
                for (auto& [name, v] : g_WeatherSettings) {
                    if (isHazeFloat(name)) {
                        float live = 0.0f;
                        if (FastRead<float>(g_ExeBase + v.offset, live) && live != 0.0f) {
                            v.f_cur = live; v.modified = true; externallyChanged = true;
                        }
                    }
                }
                if (externallyChanged) {
                    g_DisableGroundHaze = false;
                    groundHazePatched = false;
                    std::cout << "[GroundFog] haze/fog values changed externally -> auto-disabling 'Disable Ground Fog'\n" << std::flush;
                }
            }
        } else if (groundHazePatched) {
            for (auto& [name, v] : g_WeatherSettings) {
                if (name == "HeightFogDensity" || name == "AerialPerspectiveScale") {
                    v.f_cur = v.f_def; v.modified = true; FastWrite<float>(g_ExeBase + v.offset, v.f_def);
                }
            }
            groundHazePatched = false;
        }

        // 3. Atmospheric Scattering Toggle
        if (g_DisableAtmosphericScattering && !atmoScatteringPatched) {
            if (FastRead<uint8_t>(g_ExeBase + g_Addr_2AD4492, origSkyAtmoGlobal)) SafePatchBytes(g_ExeBase + g_Addr_2AD4492, &falseByte, 1);
            atmoScatteringPatched = true;
        } else if (!g_DisableAtmosphericScattering && atmoScatteringPatched) {
            SafePatchBytes(g_ExeBase + g_Addr_2AD4492, &origSkyAtmoGlobal, 1);
            atmoScatteringPatched = false;
        }

        // 4. Volumetric Clouds Toggle — zeroes g_CloudDensityMultiplier
        // (weather-map global, exe+0x2AD4584) instead of gating
        // g_RenderVolumetricClouds, so clouds fade out live with no code patching.
        // Ghidra (JustCause4.exe): the volumetric-cloud constant setup
        // (FUN_147a46670 / SetupCommonCloudConstants) reads g_CloudDensityMultiplier
        // straight into the per-frame cloud constant buffer, so a single .data
        // write takes effect immediately. The engine does NOT rewrite the global
        // itself, so any non-zero value observed while we hold it at 0 is a real
        // user edit (weather debug tab) -> we stop overwriting and switch the
        // toggle off so the UI reflects reality.
        // Re-assert every 250 ms as cheap insurance against any settings reload.
        if (g_ExeBase) {
            auto itCloud = g_WeatherSettings.find("CloudDensityMultiplier");
            uintptr_t cloudDensityAddr =
                (itCloud != g_WeatherSettings.end()) ? (g_ExeBase + itCloud->second.offset) : 0;

            static bool  cloudDensityCaptured = false;
            static float origCloudDensity = 1.0f;
            static DWORD lastCloudEnforce = 0;

            if (cloudDensityAddr) {
                float live = 0.0f;
                bool haveLive = FastRead<float>(cloudDensityAddr, live);
                if (g_DisableClouds) {
                    if (haveLive) {
                        if (!cloudDensityCaptured) {
                            // First frame ON: remember the pristine density, then
                            // zero it. No user-edit detection on this frame.
                            origCloudDensity = (live != 0.0f) ? live : 1.0f;
                            cloudDensityCaptured = true;
                            lastCloudEnforce = now;
                            FastWrite<float>(cloudDensityAddr, 0.0f);
                            itCloud->second.f_cur = 0.0f;
                            itCloud->second.modified = true; // keep the 10s capture from poisoning f_def
                        } else if (live != 0.0f) {
                            // Held at 0 and it came back non-zero without us
                            // writing it -> the user changed it. Stop overwriting
                            // and turn the actual toggle off.
                            g_DisableClouds = false;
                            cloudDensityCaptured = false;
                            itCloud->second.f_cur = live;
                            itCloud->second.modified = true; // user value: don't let the 10s capture overwrite it
                            std::cout << "[Clouds] density set externally to " << live
                                      << " -> auto-disabling 'Disable Volumetric Clouds'\n" << std::flush;
                        } else if (now - lastCloudEnforce >= 250) {
                            lastCloudEnforce = now;
                            FastWrite<float>(cloudDensityAddr, 0.0f);
                        }
                    }
                } else if (cloudDensityCaptured) {
                    // Toggle turned off normally: only heal our own 0 back to the
                    // captured pristine value (never stomp a user's custom value).
                    if (haveLive && live == 0.0f) {
                        FastWrite<float>(cloudDensityAddr, origCloudDensity);
                        itCloud->second.f_cur = origCloudDensity;
                        itCloud->second.modified = false;
                    }
                    cloudDensityCaptured = false;
                }
            }
        }

        // Rain Everywhere + Game Speed enforcement. The outer warmup gate already
        // guarantees world-ready + settle, so these are unconditional.
        // 4b. Rain Everywhere Toggle.
        // Ghidra (JustCause4.exe, indexed search_functions + decompile, no string scans):
        // - CWeather::GetPrecipitationDensity body (FUN_147a4cf50) reads +0x1190 for
        //   PRECIPITATION_TYPE_RAIN(0), +0x1194 for SNOW(1), +0x1198 otherwise/ALL(2).
        // - CWeather::SetOverriddenWeatherType body (FUN_147a5ccb0) writes +0x1150.
        // - CWeather layout: +0x1150 m_OverriddenWeatherType (EWeatherType: RAIN=2),
        //   +0x1180 m_RainPrecipitation, +0x1190 m_MaxRainPrecipitation,
        //   +0x1198 m_MaxPrecipitation. CWeather* singleton lives at g_Addr_2CADA68
        //   (same pointer the tornado code dereferences for +0xAF0 = m_TornadoManager).
        // - Ground/road wetness is a SEPARATE channel: CRenderEngine::GetWetProperties
        //   (FUN_14a5636e0) feeds the shaders from m_Wetness (+0x1654, gated by +0x165C
        //   m_WetnessGloballyEnabled) unless m_WetOverride (+0x1650) is set, in which
        //   case m_WetAmount (+0x1658) / m_WetEnabled (+0x1651) win outright.
        //   CWeather::Update copies m_MaxPrecipitation into m_PrecipitationDensity
        //   (+0x153C, FUN_14a57c020) every frame, so forcing +0x1198 covers that side;
        //   but nothing copies precipitation into m_Wetness, hence the override below.
        //   CRenderEngine* singleton at g_Addr_2C84BE8 (CWeather::Update tail:
        //   MOV RCX,[0x142c84be8] just before CALL SetPrecipitationDensity).
        // Written every frame while enabled because the sims overwrite these.
        static bool rainPatched = false;
        static uint32_t origOverriddenWeatherType = 0;
        static float origRainPrecip = 0.0f, origMaxRainPrecip = 0.0f, origMaxPrecip = 0.0f;
        static bool rainWetPatched = false;
        static uint8_t origWetOverride = 0, origWetEnabled = 0;
        static float origWetness = 0.0f, origWetAmount = 0.0f;
        if (g_RainEverywhere) {
            uintptr_t weatherPtr = 0;
            if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CADA68, weatherPtr) && weatherPtr) {
                if (!rainPatched) {
                    bool ok = FastRead<uint32_t>(weatherPtr + 0x1150, origOverriddenWeatherType) &&
                              FastRead<float>(weatherPtr + 0x1180, origRainPrecip) &&
                              FastRead<float>(weatherPtr + 0x1190, origMaxRainPrecip) &&
                              FastRead<float>(weatherPtr + 0x1198, origMaxPrecip);
                    if (ok) rainPatched = true;
                }
                if (rainPatched) {
                    FastWrite<uint32_t>(weatherPtr + 0x1150, 2); // E_WEATHER_TYPE_RAIN
                    FastWrite<float>(weatherPtr + 0x1180, 1.0f); // m_RainPrecipitation
                    FastWrite<float>(weatherPtr + 0x1190, 1.0f); // m_MaxRainPrecipitation
                    FastWrite<float>(weatherPtr + 0x1198, 1.0f); // m_MaxPrecipitation
                }
            }
            uintptr_t renderEngine = 0;
            if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2C84BE8, renderEngine) && renderEngine) {
                if (!rainWetPatched) {
                    bool ok = FastRead<uint8_t>(renderEngine + 0x1650, origWetOverride) &&
                              FastRead<uint8_t>(renderEngine + 0x1651, origWetEnabled) &&
                              FastRead<float>(renderEngine + 0x1654, origWetness) &&
                              FastRead<float>(renderEngine + 0x1658, origWetAmount);
                    if (ok) rainWetPatched = true;
                }
                if (rainWetPatched) {
                    FastWrite<uint8_t>(renderEngine + 0x1650, 1); // m_WetOverride
                    FastWrite<uint8_t>(renderEngine + 0x1651, 1); // m_WetEnabled
                    FastWrite<float>(renderEngine + 0x1654, 1.0f); // m_Wetness
                    FastWrite<float>(renderEngine + 0x1658, 1.0f); // m_WetAmount
                }
            }
        } else {
            if (rainPatched) {
                uintptr_t weatherPtr = 0;
                if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CADA68, weatherPtr) && weatherPtr) {
                    FastWrite<uint32_t>(weatherPtr + 0x1150, origOverriddenWeatherType);
                    FastWrite<float>(weatherPtr + 0x1180, origRainPrecip);
                    FastWrite<float>(weatherPtr + 0x1190, origMaxRainPrecip);
                    FastWrite<float>(weatherPtr + 0x1198, origMaxPrecip);
                    rainPatched = false;
                }
            }
            if (rainWetPatched) {
                uintptr_t renderEngine = 0;
                if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2C84BE8, renderEngine) && renderEngine) {
                    FastWrite<uint8_t>(renderEngine + 0x1650, origWetOverride);
                    FastWrite<uint8_t>(renderEngine + 0x1651, origWetEnabled);
                    FastWrite<float>(renderEngine + 0x1654, origWetness);
                    FastWrite<float>(renderEngine + 0x1658, origWetAmount);
                    rainWetPatched = false;
                }
            }
        }

        // 4c. Game Speed override (literal slow-mo / fast-forward) via CSlowMotionManager.
        // Ghidra: CSlowMotionManager layout +0x14 m_DurationLeft, +0x18 m_GameSpeed;
        // ApplyEffect(this,easeIn,sustain,easeOut,speed) sets DurationLeft=sum, GameSpeed=speed
        // (pause-menu path calls it with 0.001 for slow-down). CSingle<CSlowMotionManager>::
        // Instance at g_Addr_2CAFD90 (state machine FUN_148fe6520: MOV RCX,[0x142cafd90]
        // just before CALL ApplyEffect @0x140269890; Epic slot 0x2CB6150 resolved by the same
        // anchored static method). Direct field writes (no game call, so no Epic function
        // address needed). The float sanity check stays as cheap insurance on the pointer.
        // DurationLeft is pinned high so game-side expiry never decays our speed.
        static bool speedPatched = false;
        static float origGameSpeed = 1.0f, origDurationLeft = 0.0f;
        static DWORD lastSpeedRead = 0;
        if (now - lastSpeedRead > 1000) {
            lastSpeedRead = now;
            uintptr_t slowMoLive = 0;
            float liveSpeed = 0.0f;
            if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CAFD90, slowMoLive) && slowMoLive &&
                FastRead<float>(slowMoLive + 0x18, liveSpeed) && std::isfinite(liveSpeed)) {
                g_LiveGameSpeed = liveSpeed;
            }
        }
        if (g_CustomGameSpeed >= 0.0f) {
            uintptr_t slowMo = 0;
            if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CAFD90, slowMo) && slowMo) {
                float curSpeed = 0.0f;
                if (FastRead<float>(slowMo + 0x18, curSpeed) && std::isfinite(curSpeed) &&
                    curSpeed >= 0.0f && curSpeed <= 1000.0f) {
                    if (!speedPatched) {
                        float durationLeft = 0.0f;
                        if (FastRead<float>(slowMo + 0x14, durationLeft)) {
                            origGameSpeed = curSpeed;
                            origDurationLeft = durationLeft;
                            speedPatched = true;
                        }
                    }
                    if (speedPatched) {
                        FastWrite<float>(slowMo + 0x18, g_CustomGameSpeed); // m_GameSpeed
                        FastWrite<float>(slowMo + 0x14, 3600000.0f); // m_DurationLeft (~1000h)
                    }
                }
            }
        } else if (speedPatched) {
            uintptr_t slowMo = 0;
            if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CAFD90, slowMo) && slowMo) {
                FastWrite<float>(slowMo + 0x18, origGameSpeed);
                FastWrite<float>(slowMo + 0x14, origDurationLeft);
                speedPatched = false;
            }
        }

                // SSR is now handled via MinHook
    }

    // Heat System State & Reinforcement Distance Enforcement (In-Game Only)
    uintptr_t activeHeatMgr = 0;
    if (playerPtr && g_ExeBase && FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D38, activeHeatMgr) && activeHeatMgr) {
        FastWrite<uint8_t>(activeHeatMgr + 0x478, g_HeatSystemActive ? 1 : 0);
        if (g_CustomDetectionRange > 0.0f) FastWrite<float>(activeHeatMgr + 0x3E8, g_CustomDetectionRange);
        if (g_CustomVisionThreshold > 0.0f) FastWrite<float>(activeHeatMgr + 0x3E4, g_CustomVisionThreshold);

        // Capture genuine game defaults ONCE before applying any custom overrides to RAM
        if (!g_HeatDistCaptured) {
            for (int d = 0; d < 4; d++) {
                uintptr_t baseRange = activeHeatMgr + g_HeatDomainOffsets[d];
                for (int i = 0; i < 8; i++) {
                    FastRead<float>(baseRange + (i * 4), g_DefHeatDistances[d][i]);
                }
            }
            g_HeatDistCaptured = true;
        }

        // ONLY write to memory if the key in the INI has a value (g_HeatDistHasCustom == true).
        // If the key is empty, this loop does NOTHING. It never touches game memory.
        bool anyCustom = false;
        for (int d = 0; d < 4; d++) {
            uintptr_t baseRange = activeHeatMgr + g_HeatDomainOffsets[d];
            for (int i = 0; i < 8; i++) {
                if (g_HeatDistHasCustom[d][i]) {
                    FastWrite<float>(baseRange + (i * 4), g_HeatDistances[d][i]);
                    anyCustom = true;
                }
            }
        }
        if (anyCustom) {
            FastWrite<uint8_t>(activeHeatMgr + 0xEA, 1);
        }
    }
    }; // end ApplySettledWorldState lambda

    // Safe In-Game Cheat Synchronization: Native Loading Screen State & Engine Readiness
    uintptr_t characterPtr = GetPlayerCharacterPtr();

    // Reset curtain flag if character is destroyed (fast-travel, death, reloading)
    if (!characterPtr) {
        g_LoadingScreenLifted = false;
    }

    // World is ready ONLY when Rico is in the world AND CLoadUI::OnHide has executed
    bool isWorldReady = (characterPtr != 0) && g_LoadingScreenLifted;

    // Capture pristine Havok bounds on first world-ready, before the warmup
    // lets any patch land (no hardcoded defaults anywhere).
    if (isWorldReady && !s_DefAltCaptured && g_ExeBase) {
        float vMax = 0, vMin = 0, vBox = 0;
        bool ok = FastRead<float>(g_ExeBase + g_Addr_2CE3F38, vMax)
               && FastRead<float>(g_ExeBase + g_Addr_2AF1E68, vMin)
               && FastRead<float>(g_ExeBase + g_Addr_2AF1E64, vBox)
               && vMax > 1000.0f && vMax < 50000.0f
               && vBox > 1000.0f && vBox < 100000.0f;
        if (ok) {
            s_DefMaxAlt = vMax; s_DefMinAlt = vMin; s_DefBroadSize = vBox;
            s_DefAltCaptured = true;
        }
    }

    static bool s_GodModeState = false;
    static DWORD s_worldSpawnTime = 0;
    // Re-apply altitude/box + exit bypass immediately on settled respawns (new
    // character after loading lifted): per-frame gated enforcement waits out
    // the warmup, leaving vanilla 7000 under you if you climb fast.
    // Loading itself is covered above (vanilla restore while !isWorldReady).
    static uintptr_t s_lastAltCharacter = 0;
    if (isWorldReady && characterPtr && characterPtr != s_lastAltCharacter) {
        s_lastAltCharacter = characterPtr;
        if (g_OverrideAltitudeLimit && g_ExeBase) ApplyAltitudeOverride(true);
    }
    if (!isWorldReady) {
        s_worldSpawnTime = 0;
        s_GodModeState = false; // Reset state so God Mode re-triggers on the new player instance
        s_lastAltCharacter = 0;
        g_SpawnLimitsActive = false; // UI must not claim a budget that isn't applied yet
        // Death/loading: restore vanilla Havok bounds (memory + exit hook) so
        // respawn streaming initializes cleanly. UI customs (g_Live*) are kept;
        // the gated path re-applies them after the warmup once settled.
        // Only after defaults were captured (else we'd write Steam fallbacks).
        if (s_DefAltCaptured && g_ExeBase) {
            FastWrite<float>(g_ExeBase + g_Addr_2CE3F38, s_DefMaxAlt);
            FastWrite<float>(g_ExeBase + g_Addr_2AF1E68, s_DefMinAlt);
            FastWrite<float>(g_ExeBase + g_Addr_2AF1E64, s_DefBroadSize);
            SafePatchBytes(g_ExeBase + g_Addr_F3660, kExitOrigBytes, 5);
        }
    } else if (s_worldSpawnTime == 0) {
        s_worldSpawnTime = GetTickCount();
    }

    int warmupSec = 0;
    DWORD warmupElapsed = 0;
    if (isWorldReady && s_worldSpawnTime != 0) {
        warmupElapsed = GetTickCount() - s_worldSpawnTime;
        if (warmupElapsed < 2000) {
            warmupSec = (int)((1999 - warmupElapsed) / 1000);
        }
    }

    // One second into the countdown (between the "1" and "0" of the on-screen
    // timer): recapture weather defaults from the settled world.
    static bool s_WeatherDefaultsRecaptured = false;
    if (!isWorldReady) {
        s_WeatherDefaultsRecaptured = false;
    } else if (s_worldSpawnTime != 0 && warmupElapsed >= 1000) {
        if (!s_WeatherDefaultsRecaptured) {
            CaptureWeatherDefaults();
            s_WeatherDefaultsRecaptured = true;
        }
    }

    bool canApplyToggles = isWorldReady && (s_worldSpawnTime != 0) && ((GetTickCount() - s_worldSpawnTime) >= 2000);
    g_FovWorldSettled = canApplyToggles; // FOV detour gate mirrors the warmup gate
    g_NoRagdollCachedPlayerChar.store(canApplyToggles ? GetPlayerCharacterPtr() : 0, std::memory_order_relaxed);
    // Keep the native ragdoll/stumble flag off while noclip or No Ragdoll is active;
    // the captured native value is restored once both are switched off.
    UpdateNoclipRagdollGate(playerPtr, canApplyToggles && (g_Noclip || SuppressRagdoll()));

    // The gate fires 2 s after Rico spawns, while the world is frequently still
    // streaming terrain/models. Slamming the terrain/model LODs, the render-feature
    // flips and the Havok sweep onto that exact frame produced a brief hitch, so
    // the heavy work waits a short grace period for streaming to calm down. Cheap
    // state (altitude, god mode, gameplay toggles, HUD) still applies on the gate
    // frame itself.
    bool canApplyHeavyWorld = canApplyToggles &&
        ((GetTickCount() - s_worldSpawnTime) >= 2300);

    if (canApplyToggles) {
        // 0. Global Altitude Limits (continuous enforcement against Havok map resets)
        static bool s_LastAltitudeState = false;
        if (g_OverrideAltitudeLimit != s_LastAltitudeState) {
            ApplyAltitudeOverride(g_OverrideAltitudeLimit);
            s_LastAltitudeState = g_OverrideAltitudeLimit;
        } else if (g_OverrideAltitudeLimit && g_ExeBase) {
            FastWrite<float>(g_ExeBase + g_Addr_2CE3F38, g_LiveMaxAltitude);
            FastWrite<float>(g_ExeBase + g_Addr_2AF1E68, g_LiveMinAltitude);
            FastWrite<float>(g_ExeBase + g_Addr_2AF1E64, EffectiveBroadphaseSize());
        }

        // 1. Invincibility (ply.jesus)
        if (g_GodMode != s_GodModeState) {
            TriggerEvent(g_GodMode ? "ply.jesus.enable" : "ply.jesus.disable");
            s_GodModeState = g_GodMode;
        }

        // 2. Combat AI blackboard limits & heat patches
        static bool s_AILimitsApplied = false;
        if (!s_AILimitsApplied && g_ExeBase) {
            if (g_CustomMaxHeatEntities > 0) FastWrite<int>(g_ExeBase + g_Addr_2AEAD0C, g_CustomMaxHeatEntities);
            if (g_CustomMaxVisibilityDist > 0) FastWrite<int>(g_ExeBase + g_Addr_2AEAD10, g_CustomMaxVisibilityDist);
            ApplyHeatDetermineSpawnPatches();
            s_AILimitsApplied = true;
        }

        // 3. Ground LOD (gated strictly to live in-game world).
        // Held back until the heavy-work grace so the terrain streams do not
        // pile onto the gate frame.
        static bool s_LastGroundLOD = false;
        if (canApplyHeavyWorld) {
            if (g_ForceMaxGroundLOD != s_LastGroundLOD) {
                ApplyGlobalGroundLOD(g_ForceMaxGroundLOD);
                s_LastGroundLOD = g_ForceMaxGroundLOD;
            }
        }

        // 4. Foliage Toggle (installs hook cave only after world is loaded)
        //    The flip is rate-limited by a 5 s cooldown: FoliageToggleLocked() is
        //    true for 5 s after an accepted change and any change made while it is
        //    locked is reverted. This is the ONLY place the cooldown is armed, so
        //    the UI check and this gate can never consume it twice.
        static bool s_LastDisableFoliage = false;
        if (g_DisableFoliage != s_LastDisableFoliage) {
            if (FoliageToggleLocked()) {
                g_DisableFoliage = s_LastDisableFoliage; // rejected, still cooling down
            } else {
                ArmFoliageToggleCooldown();
                if (g_DisableFoliage) InstallFoliageHook();
                s_LastDisableFoliage = g_DisableFoliage;
                std::cout << "[Foliage] toggle -> " << (g_DisableFoliage ? 1 : 0)
                          << " (hook=" << (s_FoliageHooked ? "installed" : "NOT installed") << ")\n";
            }
        }

        // 5. Ocean, Water & Rivers
        static bool s_LastDisableOcean = false;
        if (g_DisableOcean != s_LastDisableOcean) {
            UpdateOceanPatches();
            s_LastDisableOcean = g_DisableOcean;
        }

        static bool s_LastDisableRivers = false;
        if (g_DisableRivers != s_LastDisableRivers) {
            ToggleDisableRivers(g_DisableRivers);
            s_LastDisableRivers = g_DisableRivers;
        }

        // 6. Gameplay Toggles
        static bool s_LastInfBoost = false;
        if (g_InfBoost != s_LastInfBoost) {
            ToggleInfBoost(g_InfBoost);
            s_LastInfBoost = g_InfBoost;
        }

        static bool s_LastInfMissiles = false;
        if (g_InfMissiles != s_LastInfMissiles) {
            ToggleInfMissiles(g_InfMissiles);
            s_LastInfMissiles = g_InfMissiles;
        }

        static bool s_LastFullAuto = false;
        if (g_FullAutoMissiles != s_LastFullAuto) {
            ToggleFullAutoMissiles(g_FullAutoMissiles);
            s_LastFullAuto = g_FullAutoMissiles;
        }

        static bool s_LastVehInvincible = false;
        if (g_VehiclesInvincible != s_LastVehInvincible) {
            ToggleVehiclesInvincible(g_VehiclesInvincible);
            s_LastVehInvincible = g_VehiclesInvincible;
        }

        static bool s_LastMountainShadows = false;
        if (g_DisableMountainShadows != s_LastMountainShadows) {
            ToggleMountainShadows(g_DisableMountainShadows);
            s_LastMountainShadows = g_DisableMountainShadows;
        }

        // 6b. Shadow Resolution (native settings-manager pipeline): pins the
        // engine's lo_q/hi_q tables and fires the engine's own settings
        // applier until the live atlas matches. All GPU work stays inside
        // CSettingsManager::UpdateSettings on the main thread - the engine's
        // own call site, exactly like an in-game quality change.
        UpdateShadowResolutionDriver();

        static bool s_LastHideUI = false;
        if (g_HideUI != s_LastHideUI) {
            ApplyHideUI(g_HideUI);
            s_LastHideUI = g_HideUI;
        }

        // ---- Vehicle spawn limits / simulation budget (post-gate) ----
        // Enable arm + per-frame enforcement live here so the budget is never
        // pushed into the engine before the warmup gate finishes. When the override
        // is off, the pre-gate restore arm has already undone everything.
        if (g_OverrideSpawnLimits && g_ExeBase) {
            if (!s_LastSpawnLimitsState) {
                ApplySpawnLimitOverrides(true);
                s_LastSpawnLimitsState = true;
            }
            uintptr_t worldSim = 0;
            FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D98, worldSim);
            if (!worldSim) worldSim = GetWorldSimManager();
            if (worldSim) {
                FastWrite<int32_t>(worldSim + 0x648, g_LiveSimBudget);
                FastWrite<int32_t>(worldSim + 0x64C, g_LiveSimBudget);
                FastWrite<int32_t>(worldSim + 0x650, (g_LiveSimBudget < 1) ? 1 : g_LiveSimBudget);
                FastWrite<int32_t>(worldSim + 0x604, g_LiveSimBudget);
            }
            // Continuously enforce budget on the low-level factory record so fast-travel can't reset it to 35
            uintptr_t vRec = GetVehicleBudgetRecord();
            if (vRec) {
                FastWrite<int32_t>(vRec + 0xCC, g_LiveSimBudget);
                FastWrite<int32_t>(vRec + 0x48, g_LiveSimBudget);
            }
            g_SpawnLimitsActive = true;
        }

        // ---- Settled world state ----
        // Graphics/weather toggles + heat enforcement + rain + game speed (lambda),
        // plus the Havok motion limits and the vehicle-nitro code patches. These
        // were previously applied at boot / on player-spawn, which froze loading
        // screens and stomped engine state mid-stream; now they wait for the gate
        // (world ready + warmup) before touching the engine, and the batch is held
        // back a few frames (canApplyHeavyWorld) so it does not hitch the gate frame.
        if (canApplyHeavyWorld) {
            ApplySettledWorldState(playerPtr, now);
            if (g_ExeBase) ApplyHavokPhysicsSettings();
            ToggleInfiniteNitro(g_InfiniteNitro);
            ToggleAllVehiclesNitroJump(g_AllVehiclesNitroJump);
        }
    }

    // Heat Toggles: Never Wanted (patch Add + reset) & Always Wanted (force COMBAT + Level 5)
    static bool neverWantedPatched = false;
    static uint8_t origHeatAddByte = 0;
    uintptr_t heatAddAddr = g_ExeBase + g_Addr_423030;
    static DWORD lastHeatUpdate = 0;

    if (g_NeverWanted && characterPtr) {
        // 1. Patch Heat_AddHeatPoints so the game cannot increase heat
        if (!neverWantedPatched) {
            if (FastRead<uint8_t>(heatAddAddr, origHeatAddByte)) {
                uint8_t retByte = 0xC3; // x64 ret instruction
                SafePatchBytes(heatAddAddr, &retByte, 1);
            }
            // Call Heat_Reset ONCE to clear current heat, then rely on the 0xC3 patch
            if (o_Heat_Reset) {
                uintptr_t heatManager = 0;
                if (FastRead<uintptr_t>(g_ExeBase + g_Addr_2CB1D38, heatManager) && heatManager) {
                    o_Heat_Reset(heatManager);
                }
            }
            neverWantedPatched = true;
        }
    } else {
        // Never Wanted is off: unpatch Heat_AddHeatPoints
        if (neverWantedPatched) {
            SafePatchBytes(heatAddAddr, &origHeatAddByte, 1);
            neverWantedPatched = false;
        }
    }

    // FREEZE GAME LOGIC
    if (g_ShowMenu && g_FreezeGame) {
        while (g_ShowMenu && g_FreezeGame) {
            MSG msg;
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }

            ImGuiIO& io = ImGui::GetIO();
            io.MouseDrawCursor = true;
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();
            DrawMenuUI();
            g_TorUiTyping = ImGui::IsAnyItemActive(); // tornado typing guard (render thread)
            ImGui::Render();

            uintptr_t force_settings = GetWingsuitSettingsPtr();
            if (force_settings) {
                for (auto& [n, f] : g_WingsuitSettings) {
                    if (f.is_u32) {
                        FastWrite<uint8_t>(force_settings + f.offset, (uint8_t)f.current_u32);
                    } else {
                        for (int i = 0; i < f.num_values && i < 5; i++) {
                            FastWrite<float>(force_settings + f.offset + (uintptr_t)(i * 4), f.current[i]);
                        }
                    }
                }
            }

            ID3D11Texture2D* pBackBuffer = nullptr;
            pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer);
            if (pBackBuffer) {
                if (!g_FrozenTexture) {
                    D3D11_TEXTURE2D_DESC desc;
                    pBackBuffer->GetDesc(&desc);
                    desc.Usage = D3D11_USAGE_DEFAULT;
                    desc.BindFlags = 0;
                    desc.CPUAccessFlags = 0;
                    desc.MiscFlags = 0;
                    g_pd3dDevice->CreateTexture2D(&desc, nullptr, &g_FrozenTexture);
                    g_pd3dContext->CopyResource(g_FrozenTexture, pBackBuffer);
                }
                g_pd3dContext->OMSetRenderTargets(0, nullptr, nullptr);
                g_pd3dContext->CopyResource(pBackBuffer, g_FrozenTexture);
                g_pd3dContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
                pBackBuffer->Release();
            }

            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
            oPresent(pSwapChain, SyncInterval, Flags);
            Sleep(16);
        }

        uintptr_t unfreeze_settings = GetWingsuitSettingsPtr();
        if (unfreeze_settings) {
            for (auto& [n, f] : g_WingsuitSettings) {
                if (f.is_u32) {
                    FastWrite<uint8_t>(unfreeze_settings + f.offset, (uint8_t)f.current_u32);
                } else {
                    for (int i = 0; i < f.num_values && i < 5; i++) {
                        FastWrite<float>(unfreeze_settings + f.offset + (uintptr_t)(i * 4), f.current[i]);
                    }
                }
            }
        }

        if (g_FrozenTexture) {
            g_FrozenTexture->Release();
            g_FrozenTexture = nullptr;
        }
        return oPresent(pSwapChain, SyncInterval, Flags);
    }

    

    // Frame-synchronized Noclip & Freecam Flight
    static DWORD s_lastNoclipTick = GetTickCount();
    DWORD noclipNow = GetTickCount();
    float noclipDt = (float)(noclipNow - s_lastNoclipTick) / 1000.0f;
    if (noclipDt <= 0.0f || noclipDt > 0.1f) noclipDt = 0.016f;
    s_lastNoclipTick = noclipNow;
    UpdateNoclip(noclipDt);
    UpdateFreeCam(noclipDt);
    UpdateRainbowVehicles();
    UpdateGrappleTuning();

    // Continuous runtime enforcement for all simulated vehicles (traffic + player)
    // Gated on playerPtr to prevent traversing m_GameObjects during loading screens/reloads
    if (playerPtr && g_AllVehiclesNitroJump && g_ExeBase) {
        uintptr_t m_GameObjects_Addr = g_ExeBase + g_Addr_2CB1938;
        uintptr_t myFirst = 0, myLast = 0;
        if (FastRead<uintptr_t>(m_GameObjects_Addr + 0x0, myFirst) &&
            FastRead<uintptr_t>(m_GameObjects_Addr + 0x8, myLast) &&
            myFirst && myLast > myFirst && (myLast - myFirst) <= 0x10000) {
            
            size_t count = (myLast - myFirst) / 8;
            if (count > 500) count = 500;

            for (size_t i = 0; i < count; i++) {
                uintptr_t veh = 0;
                if (!FastRead<uintptr_t>(myFirst + (i * 8), veh) || !veh) continue;
                if (!IsLikelyGameObject(veh)) continue;

                FastWrite<uint8_t>(veh + 0x13D34, 1); // m_ForceModsOn = true
                FastWrite<int32_t>(veh + 0x13CFC, 1); // m_NitrousMinUpgrade = 1
                FastWrite<int32_t>(veh + 0x13D24, 1); // m_TurboJumpMinUpgrade = 1
            }
        }
    }

    // Keep active player vehicle topped up (gated on playerPtr for streaming safety)
    if (playerPtr) {
        uintptr_t playerVeh = GetPlayerVehiclePtr();
        if (playerVeh) {
            if (g_InfiniteNitro) {
                FastWrite<float>(playerVeh + 0x13D00, 1.0f); // m_NitrousBar full
            }
            if (g_InfiniteTurboJump) {
                FastWrite<float>(playerVeh + 0x13D28, 0.0f); // m_TurboJumpCooldownTimer ready
            }
        }
        // Base-engine live tuning (no nitro required): enforce Rico's current vehicle
        // CPfxCar.m_LandVehicleEngine / transmission / m_TopSpeedKmph every present.
        ApplyVehBaseTuning();
    }
    // NORMAL RENDERING
    g_TorUiTyping = false; // reset every frame; re-set below only while the menu is drawn
    if (g_MenuAlpha > 0.01f || g_VehicleESP || g_CarSplineESP || g_ShowSpeedometer || g_ShowHeatStatus || g_ResizeMode != RESIZE_NONE || warmupSec > 0) {
        ImGuiIO& io = ImGui::GetIO();
        io.MouseDrawCursor = g_ShowMenu || (g_ResizeMode != RESIZE_NONE);
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        UpdateHUDResolutionScaling();

        if (warmupSec > 0) {
            float screenW = io.DisplaySize.x;
            float boxW = 270.0f * g_UIScale;
            float boxH = 34.0f * g_UIScale;
            float posX = (screenW - boxW) * 0.5f;
            float posY = 20.0f * g_UIScale;

            ImDrawList* dl = ImGui::GetForegroundDrawList();
            dl->AddRectFilled(ImVec2(posX, posY), ImVec2(posX + boxW, posY + boxH), IM_COL32(12, 16, 24, 215), 6.0f * g_UIScale);
            dl->AddRect(ImVec2(posX, posY), ImVec2(posX + boxW, posY + boxH), IM_COL32(0, 210, 220, 180), 6.0f * g_UIScale, 0, 1.2f);

            char buf[64];
            snprintf(buf, sizeof(buf), "ACTIVATING MOD SETTINGS: %ds", warmupSec);
            ImFont* font = ImGui::GetFont();
            float fontSize = 13.0f * g_UIScale;
            ImVec2 txtSz = font->CalcTextSizeA(fontSize, FLT_MAX, 0.0f, buf);
            float txtX = posX + (boxW - txtSz.x) * 0.5f;
            float txtY = posY + (boxH - txtSz.y) * 0.5f;
            dl->AddText(font, fontSize, ImVec2(txtX, txtY), IM_COL32(235, 245, 255, 245), buf);
        }

        if (g_ShowMenu) {
            DrawMenuUI();
            DrawSaveConfigPopup();
        }
        g_TorUiTyping = g_ShowMenu && ImGui::IsAnyItemActive(); // tornado typing guard (render thread)
        if (g_VehicleESP || g_ResizeMode == RESIZE_VEHICLE_ESP) DrawVehicleESP();
        if (g_CarSplineESP) DrawCarSplineESP();
        if (g_ShowSpeedometer || g_ResizeMode == RESIZE_SPEEDOMETER) DrawSpeedometerHUD();
        if (g_ShowHeatStatus || g_ResizeMode == RESIZE_HEAT) DrawHeatStatusHUD();
        if (g_ResizeMode != RESIZE_NONE) UpdateResizeMode();
        ImGui::Render();
        g_pd3dContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    } else {
        ImGui::GetIO().MouseDrawCursor = false;
    }

    return oPresent(pSwapChain, SyncInterval, Flags);
}

bool HookDX11_VMT() {
    if (g_HookedPresent) return true;

    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, DefWindowProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, "DX11Dummy", NULL };
    RegisterClassEx(&wc);
    HWND hWnd = CreateWindow("DX11Dummy", NULL, WS_OVERLAPPEDWINDOW, 100, 100, 100, 100, NULL, NULL, wc.hInstance, NULL);

    D3D_FEATURE_LEVEL featureLevel;
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 1;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    IDXGISwapChain* pSwapChain = nullptr;
    ID3D11Device* pDevice = nullptr;
    ID3D11DeviceContext* pContext = nullptr;

    HRESULT hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &sd, &pSwapChain, &pDevice, &featureLevel, &pContext);
    if (FAILED(hr)) {
        hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_WARP, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &sd, &pSwapChain, &pDevice, &featureLevel, &pContext);
    }

    if (SUCCEEDED(hr) && pSwapChain) {
        void** pVTable = *reinterpret_cast<void***>(pSwapChain);

        void* targetPresent = pVTable[8];
        void* targetResize  = pVTable[13];

        // Hook using MinHook instead of VirtualProtect VMT overwrite
        if (MH_CreateHook(targetPresent, (void*)&hkPresent, reinterpret_cast<LPVOID*>(&oPresent)) == MH_OK) {
            MH_EnableHook(targetPresent);
        }

        if (MH_CreateHook(targetResize, (void*)&hkResizeBuffers, reinterpret_cast<LPVOID*>(&oResizeBuffers)) == MH_OK) {
            MH_EnableHook(targetResize);
        }

        g_HookedPresent = true;

        pSwapChain->Release();
        if (pDevice) pDevice->Release();
        if (pContext) pContext->Release();
        DestroyWindow(hWnd);
        UnregisterClass("DX11Dummy", wc.hInstance);
        return true;
    }

    DestroyWindow(hWnd);
    UnregisterClass("DX11Dummy", wc.hInstance);
    return false;
}

// ============================================================================
// MAIN THREAD
// ============================================================================
void SetupConsole() {
    // Check if process was launched with --debug-console-mod-menu
    const char* cmdLine = GetCommandLineA();
    if (!cmdLine || strstr(cmdLine, "--debug-console-mod-menu") == nullptr) {
        return; // Run silently (no terminal window)
    }

    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    freopen_s(&fp, "CONIN$", "r", stdin);

    // Disable stream buffering so text outputs immediately
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Re-bind and clear error state bits on C++ iostreams
    std::ios::sync_with_stdio(true);
    std::cout.clear();
    std::cerr.clear();
    std::cin.clear();

    SetConsoleTitleA("JC4 Mod Menu - Debug Terminal");

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
        SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    std::cout << "\033[1;32m[+] Debug Terminal Enabled via --debug-console-mod-menu\033[0m\n" << std::flush;
}

// ============================================================================
// Deprecated dxgi.dll blocker
// ============================================================================
// Some old releases of this mod menu shipped as a dxgi.dll proxy. Those
// versions must never be loaded alongside the current winmm.dll build, so at
// startup we hash every dxgi.dll found in the game directory (recursively) and
// refuse to run if one of them matches a known-deprecated hash.
//
// >>> TO BLACKLIST ANOTHER BUILD: append its SHA-256 (uppercase hex, 64 chars)
// >>> as a new string in g_DeprecatedDxgiHashes below.
// ============================================================================

static const char* g_DeprecatedDxgiHashes[] = {
    "725971C24527438E91AE83DEE2BDEB63AF7875728766FAAD2CC393F18D36F58E",
    "B595D7394EC0C0A102D7C6F9B45021B2EA989F3434C43E4DD4E392A102DEF953",
    "72FC6ABEF2E523447DBD02FB73E5F6E8FC911FB60A0241AEC91C159DA2665478"
    // add more deprecated dxgi.dll SHA-256 hashes here, one per line
};

// --- Minimal self-contained SHA-256 (FIPS 180-4), uppercase-hex digest ------
struct Sha256Ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    uint32_t buflen;
};

static const uint32_t kSha256K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SHA_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void Sha256Init(Sha256Ctx* c) {
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
    c->bitlen = 0; c->buflen = 0;
}

static void Sha256Transform(Sha256Ctx* c, const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = SHA_ROTR(w[i-15], 7) ^ SHA_ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = SHA_ROTR(w[i-2], 17) ^ SHA_ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->state[0], b=c->state[1], cc=c->state[2], d=c->state[3];
    uint32_t e=c->state[4], f=c->state[5], g=c->state[6], h=c->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = SHA_ROTR(e, 6) ^ SHA_ROTR(e, 11) ^ SHA_ROTR(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + kSha256K[i] + w[i];
        uint32_t S0 = SHA_ROTR(a, 2) ^ SHA_ROTR(a, 13) ^ SHA_ROTR(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

static void Sha256Update(Sha256Ctx* c, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    c->bitlen += (uint64_t)len * 8;
    while (len > 0) {
        uint32_t take = (uint32_t)((len < 64 - c->buflen) ? len : 64 - c->buflen);
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take; p += take; len -= take;
        if (c->buflen == 64) { Sha256Transform(c, c->buf); c->buflen = 0; }
    }
}

static void Sha256Final(Sha256Ctx* c, char out[65]) {
    uint8_t pad = 0x80;
    uint8_t lenbe[8];
    for (int i = 0; i < 8; i++) lenbe[i] = (uint8_t)(c->bitlen >> (56 - i * 8));
    Sha256Update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56) Sha256Update(c, &zero, 1);
    c->bitlen = 0; // length bytes must not be counted again
    Sha256Update(c, lenbe, 8);
    static const char* hexd = "0123456789ABCDEF";
    for (int i = 0; i < 8; i++) {
        out[i*8+0] = hexd[(c->state[i] >> 28) & 0xF]; out[i*8+1] = hexd[(c->state[i] >> 24) & 0xF];
        out[i*8+2] = hexd[(c->state[i] >> 20) & 0xF]; out[i*8+3] = hexd[(c->state[i] >> 16) & 0xF];
        out[i*8+4] = hexd[(c->state[i] >> 12) & 0xF]; out[i*8+5] = hexd[(c->state[i] >>  8) & 0xF];
        out[i*8+6] = hexd[(c->state[i] >>  4) & 0xF]; out[i*8+7] = hexd[(c->state[i])       & 0xF];
    }
    out[64] = '\0';
}

// Hash a file in 64 KB chunks. Returns false if the file can't be opened.
static bool HashFileSha256(const std::string& path, char out[65]) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    Sha256Ctx c; Sha256Init(&c);
    uint8_t chunk[65536];
    DWORD got = 0;
    while (ReadFile(h, chunk, sizeof(chunk), &got, NULL) && got > 0)
        Sha256Update(&c, chunk, got);
    CloseHandle(h);
    Sha256Final(&c, out);
    return true;
}

// Recursively collect every dxgi.dll (any casing) under 'dir'.
static void FindDxgiFilesRecursive(const std::string& dir, std::vector<std::string>& out) {
    WIN32_FIND_DATAA fd;
    std::string pat = dir + "\\*";
    HANDLE h = FindFirstFileExA(pat.c_str(), FindExInfoBasic, &fd,
                                FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        std::string full = dir + "\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) // skip junctions/symlinks
                FindDxgiFilesRecursive(full, out);
        } else if (_stricmp(fd.cFileName, "dxgi.dll") == 0) {
            out.push_back(full);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

// Our own HMODULE (set in DllMain) / popup-host mode flag (rundll32 loader).
static HMODULE g_OurModule   = nullptr;
static bool    g_PopupHostMode = false;

// Shows the fatal notice. In the deprecated-dxgi abort path this is only ever
// called from the CLEAN rundll32 host process (see JC4DeprecatedPopup); the
// in-process fallback exists only if the host spawn itself failed.
//
// Why not a plain in-process MessageBoxA from DllMain, even though DllMain "freezes"
// the process? Because DllMain holds the LOADER LOCK, and MessageBoxA pumps a
// modal message loop: every dispatched message is a user callback. On the
// Epic install (Koaloader + ScreamAPI proxies + the old dxgi.dll itself
// already loaded by the loader) one of those dispatched callbacks raised and
// killed the process with 0xC000041D ("unhandled exception during a user
// callback") before the popup ever painted. DllMain must therefore NEVER
// pump messages. Instead, AbortDeprecatedDxgi spawns a detached rundll32.exe
// that loads THIS dll again (popup-host mode, see DllMain) and calls the
// exported JC4DeprecatedPopup below: the popup is shown by a clean process
// with no loader lock, no game threads and no injected hooks, and the game
// process terminates immediately after the spawn.
static void ShowDeprecatedPopup(const std::string& msg) {
    MessageBoxA(NULL, msg.c_str(), "JC4 Mod Menu - Deprecated dxgi.dll Detected",
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND);
}

// --- Popup host entry (runs inside a detached rundll32.exe) -----------------
// rundll32 loads this dll and calls this export with the command line
//   "<our winmm.dll path>",JC4DeprecatedPopup <dxgi path> | <dxgi path> | ...
// The notice lists the full absolute paths of the deprecated files (no hash)
// and is shown from this clean process. ExitProcess when the user
// acknowledges.
static std::string JC4TrimQuotes(std::string s) {
    size_t a = s.find_first_not_of(" \t\r\n\"");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n\"");
    return s.substr(a, b - a + 1);
}

extern "C" __declspec(dllexport)
void CALLBACK JC4DeprecatedPopup(HWND /*hwnd*/, HINSTANCE /*hinst*/, LPSTR lpszCmdLine, int /*nCmdShow*/) {
    std::string args = lpszCmdLine ? lpszCmdLine : "";
    std::string listing;
    size_t start = 0;
    while (start <= args.size()) {
        size_t end = args.find('|', start);
        std::string one = JC4TrimQuotes(args.substr(start,
            (end == std::string::npos ? args.size() : end) - start));
        if (!one.empty()) {
            listing += "    " + one + "\n\n";
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (listing.empty()) listing = "    (unknown file)\n\n";

    std::string msg =
        "A deprecated version of the JC4 Mod Menu was detected in the game directory.\n\n"
        "The following file is an old, deprecated build of this mod menu and must be\n"
        "removed before the current version can run:\n\n" + listing +
        "Please delete that file manually then start the game again.\n\n"
        "The game will now close.";
    ShowDeprecatedPopup(msg);
    ExitProcess(0);
}

// Hashes 'path' and appends "path\n  SHA256: ...\n\n" to 'hits' if it is a
// blacklisted build. Logs every hash to the console.
static void CheckOneDxgi(const std::string& path, std::string& hits) {
    char hex[65];
    if (!HashFileSha256(path, hex)) return;
    std::cout << "[dxgi-check] " << path << " SHA256 " << hex << "\n" << std::flush;
    for (const char* bad : g_DeprecatedDxgiHashes) {
        if (_stricmp(hex, bad) == 0) {
            hits += path;
            hits += "\n\n";
            break;
        }
    }
}

// Shows the fatal popup from a clean host process, then terminates this
// (game) process. Never returns.
static void AbortDeprecatedDxgi(const std::string& hits) {
    std::cout << "[!] DEPRECATED mod menu dxgi.dll detected. Aborting.\n" << std::flush;

    // Re-format hits ("path\n\n" chunks) into '|'-separated quoted arguments.
    std::string args;
    {
        std::string item;
        for (size_t i = 0; i <= hits.size(); ++i) {
            if (i == hits.size() || hits[i] == '\n') {
                std::string one = JC4TrimQuotes(item);
                if (!one.empty()) {
                    if (!args.empty()) args += " | ";
                    args += "\"" + one + "\"";
                }
                item.clear();
            } else {
                item += hits[i];
            }
        }
    }

    // Spawn the popup host: rundll32 loads OUR dll in a clean process and
    // calls JC4DeprecatedPopup. No message pump ever runs inside this
    // (loader-locked, hook-laden) process.
    char ourPath[MAX_PATH] = {0};
    char sysDir[MAX_PATH]  = {0};
    if (g_OurModule && args.size() < 8000 &&
        GetModuleFileNameA(g_OurModule, ourPath, MAX_PATH) &&
        GetSystemDirectoryA(sysDir, MAX_PATH)) {
        std::string cmdline = std::string("\"") + sysDir + "\\rundll32.exe\" \""
                              + ourPath + "\",JC4DeprecatedPopup " + args;
        STARTUPINFOA si;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi;
        memset(&pi, 0, sizeof(pi));
        if (CreateProcessA(NULL, (LPSTR)cmdline.c_str(), NULL, NULL, FALSE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            Sleep(250); // give the host a beat to spin up before we die
            TerminateProcess(GetCurrentProcess(), 0xDEAD); // never returns
        }
    }

    // Fallback (host spawn failed): in-process popup is the lesser evil here.
    std::string msg =
        "A deprecated version of the JC4 Mod Menu was detected in the game directory.\n\n"
        "The following file is an old, deprecated build of this mod menu and must be\n"
        "removed before the current version can run:\n\n" + hits +
        "Please delete that file manually then start the game again.\n\n"
        "The game will now close.";
    ShowDeprecatedPopup(msg);
    TerminateProcess(GetCurrentProcess(), 0xDEAD);
}

static bool g_DxgiCheckDone = false;

// Scans the game directory (and the actually-loaded dxgi.dll, when it is not
// the system copy) for blacklisted builds. If one is found, shows a fatal
// popup and terminates the process. Returns true if the process was terminated.
//
// Runs ONCE (guarded), and is called from DllMain(DLL_PROCESS_ATTACH) — as
// early as physically possible. That matters: a deprecated dxgi.dll sitting
// in the game directory is loaded by the Windows loader from the app dir and
// its own (old) hook code crashes the game if it gets time to initialize, so
// we must find it and terminate before that happens. The fast path below
// checks the game-root dxgi.dll FIRST (the 99% case) so the abort can happen
// within milliseconds of DllMain.
static bool CheckDeprecatedDxgi() {
    if (g_DxgiCheckDone) return false;
    g_DxgiCheckDone = true;

    // Game directory = directory of the running executable.
    char exePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string gameDir(exePath);
    size_t slash = gameDir.find_last_of("\\/");
    if (slash != std::string::npos) gameDir.resize(slash);

    // --- Fast path: dxgi.dll in the game root (typical location). ---------
    std::string rootDxgi = gameDir + "\\dxgi.dll";
    DWORD attr = GetFileAttributesA(rootDxgi.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        std::string hits;
        CheckOneDxgi(rootDxgi, hits);
        if (!hits.empty()) {
            AbortDeprecatedDxgi(hits); // never returns
            return true;
        }
    }

    // --- Slow path: full recursive scan + loaded-module check. ------------
    std::string hits;
    std::vector<std::string> candidates;
    FindDxgiFilesRecursive(gameDir, candidates);

    // Also cover a dxgi.dll that is already loaded from somewhere else
    // (never flag the Windows system copy).
    HMODULE hDxgi = GetModuleHandleA("dxgi.dll");
    if (hDxgi) {
        char modPath[MAX_PATH] = {0};
        if (GetModuleFileNameA(hDxgi, modPath, MAX_PATH)) {
            char sysDir[MAX_PATH] = {0};
            GetSystemDirectoryA(sysDir, MAX_PATH);
            if (_strnicmp(modPath, sysDir, strlen(sysDir)) != 0) {
                std::string mp(modPath);
                bool already = false;
                for (const auto& c : candidates)
                    if (_stricmp(c.c_str(), mp.c_str()) == 0) { already = true; break; }
                if (!already) candidates.push_back(mp);
            }
        }
    }

    for (const auto& f : candidates)
        CheckOneDxgi(f, hits);
    if (!hits.empty()) {
        AbortDeprecatedDxgi(hits); // never returns
        return true;
    }
    return false;
}

DWORD WINAPI MainThread(LPVOID lpParam) {
    if (g_PopupHostMode) return 0; // rundll32 popup host: no mod init
    JC4UltraFastLoad::Initialize();
    SetUnhandledExceptionFilter(ModCrashHandler);
    SetConsoleCtrlHandler([](DWORD) -> BOOL { TerminateProcess(GetCurrentProcess(), 0); return TRUE; }, TRUE);
    JC4Terrain16x16::InitTerrain16x16Hooks();
    SetupConsole();

    // 0. Block deprecated mod-menu builds shipped as dxgi.dll BEFORE doing
    //    anything else (hash every dxgi.dll in the game directory).
    CheckDeprecatedDxgi();

    // 1. Wait until game main executable and DirectX 11 are fully loaded in memory
    while (!GetModuleHandleA("JustCause4.exe") && !GetModuleHandleA("JustCause4GameCL.exe")) {
        Sleep(100);
    }
    while (!GetModuleHandleA("d3d11.dll")) {
        Sleep(100);
    }

    // Give engine 1 extra second to settle internal memory structures
    Sleep(1000);

    g_ExeBase = (uintptr_t)GetModuleHandleA("JustCause4.exe");
    InitializePlatformAddresses();
    if (!g_ExeBase) g_ExeBase = (uintptr_t)GetModuleHandleA("JustCause4GameCL.exe");

    // Platform enforcement: only Steam and Epic builds are supported. Poll
    // briefly so late-loading modules (EOS/Steamworks) can't false-trigger.
    // A spoofed Unknown skips the grace wait so the test popup fires at once.
    {
        JC4Platform spoofVal;
        bool haveSpoof = GetPlatformSpoof(spoofVal);
        JC4Platform plat = DetectJC4Platform();
        if (haveSpoof) {
            std::cout << "[!] --spoof-platform active, forcing: "
                      << (spoofVal == JC4Platform::Steam ? "Steam" : spoofVal == JC4Platform::Epic ? "Epic" : "UNKNOWN")
                      << "\n" << std::flush;
        }
        if (!(haveSpoof && spoofVal == JC4Platform::Unknown)) {
            for (int i = 0; i < 10 && plat == JC4Platform::Unknown; i++) {
                Sleep(500);
                plat = DetectJC4Platform();
            }
        }
        std::cout << "[+] Platform: "
                  << (plat == JC4Platform::Steam ? "Steam" : plat == JC4Platform::Epic ? "Epic" : "UNKNOWN")
                  << "\n" << std::flush;
        if (plat == JC4Platform::Unknown) {
            MessageBoxA(NULL,
                "Unsupported Just Cause 4 version.\n\nThis mod menu only supports the Steam and Epic Games builds.\n\nTo play the game normally, please delete the 'winmm.dll' file of the game folder.\n\nThe game will now close.",
                "JC4 Mod Menu - Unsupported Platform",
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND);
            TerminateProcess(GetCurrentProcess(), 0xDEAD);
            return 0;
        }
    }

    // Check command line parameter --debug-no-login
    const char* cmdLine = GetCommandLineA();
    if (cmdLine && strstr(cmdLine, "--debug-no-login") != nullptr) {
        g_DebugNoLogin = true;
        std::cout << "[+] Fast No-Login mode enabled via command line argument --debug-no-login\n";
    }

    // Initialize Event Sender for Player Cheats
    bool is_steam = (GetModuleHandleA("steam_api64.dll") != nullptr);
    uintptr_t sendEventRVA = g_Addr_286930;
    o_SendEvent = (SendEvent_t)(g_ExeBase + sendEventRVA);

    // Initialize Heat_Reset for Never Wanted (RVA 0x424310)
    o_Heat_Reset = (Heat_Reset_t)(g_ExeBase + g_Addr_424310);
// Initialize WORLDTIME_SET_TIME (Steam: 0x322720, Non-Steam / Epic: 0x324070)
o_WorldTime_SetTime = (WorldTime_SetTime_t)(g_ExeBase + (g_Addr_322720));
    // Initialize Native CAiHeatManager Functions
    o_Heat_SetLevel      = (Heat_SetLevel_t)(g_ExeBase + g_Addr_4246E0);
    o_Heat_SetStatus     = (Heat_SetStatus_t)(g_ExeBase + g_Addr_424910);
    o_Heat_AddHeatPoints = (Heat_AddHeatPoints_t)(g_ExeBase + g_Addr_423030);
    o_Heat_ClearAllSets  = (Heat_ClearAllSets_t)(g_ExeBase + g_Addr_4230D0);
    o_Heat_ActivateSet   = (Heat_ActivateSet_Worker_t)(g_ExeBase + g_Addr_422D60);

    // Initialize Native CCharacter Physics & Teleportation Functions
    o_SetWorldAndPhysicsPosition = (SetWorldAndPhysicsPosition_t)(g_ExeBase + g_Addr_578F60);
    o_SetGhostMode = (SetGhostMode_t)(g_ExeBase + g_Addr_573520);
    o_SetCharacterGravity = (SetCharacterGravity_t)(g_ExeBase + g_Addr_5722C0); // 0x5722C0 Steam, 0x5741E0 Epic

    

    // Check if MinHook is already initialized by another mod (like xinput9_1_0.dll)
    MH_STATUS mhStatus = MH_Initialize();
    if (mhStatus != MH_OK && mhStatus != MH_ERROR_ALREADY_INITIALIZED) return 0;
    // Hook keyboard polling functions to prevent movement while menu is open
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (hUser32) {
        void* pGetAsyncKeyState = reinterpret_cast<void*>(GetProcAddress(hUser32, "GetAsyncKeyState"));
        if (pGetAsyncKeyState && MH_CreateHook(pGetAsyncKeyState, reinterpret_cast<void*>(&hkGetAsyncKeyState), reinterpret_cast<LPVOID*>(&o_GetAsyncKeyState)) == MH_OK) {
            MH_EnableHook(pGetAsyncKeyState);
        }
        void* pGetKeyState = reinterpret_cast<void*>(GetProcAddress(hUser32, "GetKeyState"));
        if (pGetKeyState && MH_CreateHook(pGetKeyState, reinterpret_cast<void*>(&hkGetKeyState), reinterpret_cast<LPVOID*>(&o_GetKeyState)) == MH_OK) {
            MH_EnableHook(pGetKeyState);
        }
    }
    // 1. Init Wingsuit & Weather Map Defaults
    InitWingsuitSettings();
    InitWeatherSettings();
    CaptureWeatherDefaults(); // Overwrite static defaults with live game values

    // 2. Capture Original Game Physics Defaults
    if (g_ExeBase) {
        SafeReadMemory<float>(g_ExeBase + g_Addr_1CB8220, default_thrust);
        SafeReadMemory<float>(g_ExeBase + g_Addr_1D083E0, default_floor);
        SafeReadMemory<float>(g_ExeBase + g_Addr_2AE2760, default_maxspeed);
        SafeReadMemory<float>(g_ExeBase + g_Addr_1CAE1C4, default_havok_max_speed);
        SafeReadMemory<float>(g_ExeBase + g_Addr_1CAE1CC, default_havok_max_accel);
        g_Thrust          = default_thrust;
        g_Floor           = default_floor;
        g_MaxSpeed        = default_maxspeed;
        g_HavokMaxSpeed   = default_havok_max_speed;
        g_HavokMaxAccel   = default_havok_max_accel;
        g_DefaultsCaptured = true;
    }

    // Start background key listener
    CreateThread(NULL, 0, KeyPollingThread, NULL, 0, NULL);

    // Bypass the 4 MINSS clamp instructions in CNvWaveWorkSimulation::UpdateSimulationProperties
    if (g_ExeBase) {
        uintptr_t a1 = g_ExeBase + g_Addr_1D1877; // Wave Amplitude Clamp (5.0f max)
        uintptr_t a2 = g_ExeBase + g_Addr_1D1888; // Small Wave Fraction Clamp (5.0f max)
        uintptr_t a3 = g_ExeBase + g_Addr_1D189E; // Wind Speed Clamp (40.0f max)
        uintptr_t a4 = g_ExeBase + g_Addr_1D18C5; // Choppy Scale Clamp (1.25f max)

        static const uint8_t nop_8[8] = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
        static const uint8_t nop_9[9] = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};

        SafePatchBytes(a1, nop_8, 8);
        SafePatchBytes(a2, nop_9, 9);
        SafePatchBytes(a3, nop_8, 8);
        SafePatchBytes(a4, nop_8, 8);
        std::cout << "[+] Successfully bypassed all WaveWorks parameter clamps.\n";
    }

    // 3. Read Config (Overrides defaults and applies patches)
    ReadConfig();
    TorLoadBinds();

    // Apply fast no-login bypass early if enabled via command line or config
    if (g_DebugNoLogin) {
        ToggleNoLogin(true);
    }

    // Inject stand-alone physical assembly code caves
    InstallVehicleHooks();
    ApplyMissileSpeedHook();

    // Initial menu visibility on startup (closed by default)
    g_ShowMenu = false;

    // 4. Apply Physics overrides to memory
    if (g_Thrust == 0.0f)          g_Thrust          = default_thrust;
    if (g_Floor == 0.0f)           g_Floor           = default_floor;
    if (g_MaxSpeed == 0.0f)        g_MaxSpeed        = default_maxspeed;
    if (g_HavokMaxSpeed == 0.0f)   g_HavokMaxSpeed   = default_havok_max_speed;
    if (g_HavokMaxAccel == 0.0f)   g_HavokMaxAccel   = default_havok_max_accel;

    if (g_ExeBase) {
        FastWrite<float>(g_ExeBase + g_Addr_1CB8220, g_Thrust);
        FastWrite<float>(g_ExeBase + g_Addr_1D083E0, g_Floor);
        FastWrite<float>(g_ExeBase + g_Addr_2AE2760, g_MaxSpeed);
        // ApplyHavokPhysicsSettings() / ApplySpawnLimitOverrides() deliberately
        // NOT called at boot: the Havok motion-limit writes and the exit-hook RET
        // freeze boot loading screens when a saved config has them on. The
        // canApplyToggles-gated warmup path applies them once the world settles.
    }

    // 5. Hook D3D11 / Present.
    // Wait only for d3d11.dll (DXGI is loaded as its dependency). We must NOT wait
    // on GetModuleHandleA("dxgi.dll") any more: ReShade now occupies that name, so
    // that test would silently poll forever.
    while (!GetModuleHandleA("d3d11.dll")) Sleep(100);
    HookDX11_VMT();
    if (g_ExeBase) {
        // Intercept compiler stack canary failure before INT 0x29 kills the process
    void* pReportGsFailure = (void*)(g_ExeBase + g_Addr_1AF9274);
    if (MH_CreateHook(pReportGsFailure, (void*)&hk_report_gsfailure, (void**)&o_report_gsfailure) == MH_OK) {
        MH_EnableHook(pReportGsFailure);
        std::cout << "[+] Successfully hooked __report_gsfailure (0x1AF9274).\n";
    }
        // Hook CMissionManager::Update for main-thread synchronized mission execution
        { // 0x92004C0 Steam, 0x154A6290 Epic
        void* pMissionUpdate = (void*)(g_ExeBase + g_Addr_92004C0);
        if (MH_CreateHook(pMissionUpdate, (void*)&hk_MissionManager_Update, (void**)&o_MissionManager_Update) == MH_OK) {
            MH_EnableHook(pMissionUpdate);
            std::cout << "[+] Successfully hooked CMissionManager::Update on the main thread.\n";
        }
        }

        // 1. Hook CLoadUI::OnHide directly at 0x14A6BCD30 (verified with debugger)
        if (g_IsSteam) { // EPIC: 0xA6BCD30 not yet mapped (Steam-only for now)
        void* pLoadUIOnHide = (void*)(g_ExeBase + g_Addr_A6BCD30);
        if (MH_CreateHook(pLoadUIOnHide, (void*)&hk_CLoadUI_OnHide, (void**)&o_CLoadUI_OnHide) == MH_OK) {
            MH_EnableHook(pLoadUIOnHide);
            std::cout << "[+] Successfully hooked CLoadUI::OnHide (0xA6BCD30).\n";
        }
        }

        // 2. Hook PostMsg / SendEvent bus
        void* pSendEvent = (void*)(g_ExeBase + sendEventRVA);
        if (MH_CreateHook(pSendEvent, (void*)&hk_SendEvent, (void**)&o_SendEvent) == MH_OK) {
            MH_EnableHook(pSendEvent);
            std::cout << "[+] Successfully hooked NEvent::CSendEvent<>::PostMsg.\n";
        }

        void* pSSR_Draw = (void*)(g_ExeBase + g_Addr_D75D70);
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(pSSR_Draw, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pSSR_Draw, (void*)&hk_SSR_Draw, (void**)&o_SSR_Draw) == MH_OK) MH_EnableHook(pSSR_Draw);
        }
        
        { // 0x1B8810 mapped (fuzzy)
        void* pUpdateProperties = (void*)(g_ExeBase + g_Addr_1B8810);
        if (VirtualQuery(pUpdateProperties, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pUpdateProperties, (void*)&hk_UpdateProperties, (void**)&o_UpdateProperties) == MH_OK) {
                MH_EnableHook(pUpdateProperties);
            }
        }
        }

        void* pUpdateSimulationProperties = (void*)(g_ExeBase + g_Addr_1D1640);
        if (VirtualQuery(pUpdateSimulationProperties, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pUpdateSimulationProperties, (void*)&hk_UpdateSimulationProperties, (void**)&o_UpdateSimulationProperties) == MH_OK) {
                MH_EnableHook(pUpdateSimulationProperties);
            }
        }

        void* pSetMagazineAmmo = (void*)(g_ExeBase + g_Addr_761BE0);
        if (VirtualQuery(pSetMagazineAmmo, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pSetMagazineAmmo, (void*)&hk_SetMagazineAmmo, (void**)&o_SetMagazineAmmo) == MH_OK) {
                MH_EnableHook(pSetMagazineAmmo);
            }
        }

        // Subclass overrides the base hook misses (same 999 detour logic, own originals).
        void* pSetMagazineAmmoPinner = (void*)(g_ExeBase + g_Addr_761C30);
        if (VirtualQuery(pSetMagazineAmmoPinner, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pSetMagazineAmmoPinner, (void*)&hk_SetMagazineAmmoPinner, (void**)&o_SetMagazineAmmoPinner) == MH_OK) {
                MH_EnableHook(pSetMagazineAmmoPinner);
            }
        }

        void* pSetMagazineAmmoRPG = (void*)(g_ExeBase + g_Addr_761CE0);
        if (VirtualQuery(pSetMagazineAmmoRPG, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pSetMagazineAmmoRPG, (void*)&hk_SetMagazineAmmoRPG, (void**)&o_SetMagazineAmmoRPG) == MH_OK) {
                MH_EnableHook(pSetMagazineAmmoRPG);
            }
        }

        void* pOrbitModifier = (void*)(g_ExeBase + g_Addr_4E6DA0);
        if (VirtualQuery(pOrbitModifier, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pOrbitModifier, (void*)&hk_ProcessCameraContext_Orbit, (void**)&o_ProcessCameraContext_Orbit) == MH_OK) {
                MH_EnableHook(pOrbitModifier);
            }
        }

        // First Person Mode helper pointers and camera/character hooks
        fn_GetInterpolatedWorldTransform = (GetInterpolatedWorldTransform_t)(g_ExeBase + g_Addr_2AC6E0);
        fn_GetBoneIndexForNameHash = (GetBoneIndexForNameHash_t)(g_ExeBase + g_Addr_53DF40);
        fn_GetBoneMatrix = (GetBoneMatrix_t)(g_ExeBase + g_Addr_244860);
        fn_GetPreviousBoneMatrix = (GetBoneMatrix_t)(g_ExeBase + g_Addr_246470);
        fn_IsInCinematicCamera = (IsInCinematicCamera_t)(g_ExeBase + g_Addr_5570D0);
        fn_GetWieldingWeapon = (GetWieldingWeapon_t)(g_ExeBase + g_Addr_5509E0);
        fn_WeaponSetVisible = (WeaponSetVisible_t)(g_ExeBase + g_Addr_7B3200);

        auto installFpHook = [&](uintptr_t targetAddr, void* detour, void** orig) {
            if (!targetAddr) return;
            MEMORY_BASIC_INFORMATION hmbi = {};
            if (VirtualQuery((void*)targetAddr, &hmbi, sizeof(hmbi)) && hmbi.State == MEM_COMMIT &&
                (hmbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                if (MH_CreateHook((void*)targetAddr, detour, orig) == MH_OK) {
                    MH_EnableHook((void*)targetAddr);
                }
            }
        };
        installFpHook(g_ExeBase + g_Addr_2530B0, (void*)&hk_UpdateCameraContexts, (void**)&o_UpdateCameraContexts);
        installFpHook(g_ExeBase + g_Addr_253E20, (void*)&hk_UpdateRenderContexts, (void**)&o_UpdateRenderContexts);
        installFpHook(g_ExeBase + g_Addr_594D00, (void*)&hk_CharacterUpdateRender, (void**)&o_CharacterUpdateRender);
        installFpHook(ResolveJmpThunk(g_ExeBase + g_Addr_574350), (void*)&hk_CharacterSetOpacity, (void**)&o_CharacterSetOpacity);

        // NGraphicsEngine::CCamera::UpdateRender real body (FUN_1475c5e60, RVA 0x75C5E60).
        // Entry hook for the additive Desired-FOV bump.
        void* pCameraUpdateRender = (void*)(g_ExeBase + g_Addr_75C5E60);
        if (VirtualQuery(pCameraUpdateRender, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pCameraUpdateRender, (void*)&hk_CameraUpdateRender, (void**)&o_CameraUpdateRender) == MH_OK) {
                MH_EnableHook(pCameraUpdateRender);
            }
        }

        // Vehicle invincibility. Installed once here so the toggle is a pure
        // flag flip at runtime (see InstallFeatureHooks).
        InstallFeatureHooks();

        // Initialize native CVehicle::SetSelectedPaletteTintIndex (RVA 0x9F8E980)
        o_SetSelectedPaletteTintIndex = (SetSelectedPaletteTintIndex_t)(g_ExeBase + g_Addr_9F8E980);

        // Resolve native CGrapplingHookWire::Break for the Detach buttons
        o_WireBreak = (WireBreak_t)(g_ExeBase + g_Addr_6A7630); // mapped (fuzzy)

        // Hook 1: CTransform::ToMatrix4 (FUN_1476014e0)
        { // 0x76014E0 mapped (freecam camera hook)
        void* pCamToMat = (void*)(g_ExeBase + g_Addr_76014E0);
        if (VirtualQuery(pCamToMat, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pCamToMat, (void*)&hk_CameraToMatrix, (void**)&o_CameraToMatrix) == MH_OK) {
                MH_EnableHook(pCamToMat);
            }
        }
        }

        // Hook 3: Camera context transition copier (FUN_147b0c3d0)
        void* pCamCtxCopy = (void*)(g_ExeBase + g_Addr_7B0C3D0);
        if (VirtualQuery(pCamCtxCopy, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pCamCtxCopy, (void*)&hk_CameraContextCopy, (void**)&o_CameraContextCopy) == MH_OK) {
                MH_EnableHook(pCamCtxCopy);
            }
        }

        // Hook 4: Camera slerp transition (FUN_147b0b340)
        void* pCamSlerp = (void*)(g_ExeBase + g_Addr_7B0B340);
        if (VirtualQuery(pCamSlerp, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pCamSlerp, (void*)&hk_CameraSlerp, (void**)&o_CameraSlerp) == MH_OK) {
                MH_EnableHook(pCamSlerp);
            }
        }

        // EPIC-ONLY freecam pin: hook the camera-matrix writers (distinct from Steam's ToMatrix4 path)
        if (!g_IsSteam) {
            void* pW1 = (void*)(g_ExeBase + 0x247060);
            if (MH_CreateHook(pW1, (void*)&hk_EpicCamWriter1, (void**)&o_EpicCamWriter1) == MH_OK) {
                MH_EnableHook(pW1); std::cout << "[FreeCam] Epic camera-writer hook 1 installed (0x247060).\n";
            }
        }
// Hook CBoosterEngine::UpdateBoosterEngine (RVA 0x6F7F40) to enforce live speed, force, and spool
        { // 0x6F7F40 mapped (fuzzy)
        void* pBoosterUpdate = (void*)(g_ExeBase + g_Addr_6F7F40);
        if (VirtualQuery(pBoosterUpdate, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pBoosterUpdate, (void*)&hk_BoosterEngine_Update, (void**)&o_BoosterEngine_Update) == MH_OK) {
                MH_EnableHook(pBoosterUpdate);
                std::cout << "[+] Successfully hooked CBoosterEngine::UpdateBoosterEngine (0x6F7F40).\n";
            }
        }
        }
        { // CPlayer::SetOpacity (Steam 0xB28D30, Epic 0xB31FB0) for freecam opacity
        void* pSetOpacity = (void*)(g_ExeBase + g_Addr_B28D30);
        if (VirtualQuery(pSetOpacity, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pSetOpacity, (void*)&hk_PlayerSetOpacity, (void**)&o_PlayerSetOpacity) == MH_OK) {
                MH_EnableHook(pSetOpacity);
                std::cout << "[+] Successfully hooked CPlayer::SetOpacity.\n";
            }
        }
        }

        // 1. AdvanceTByDistance (Primary vehicle spline advancement)
        void* pAdvT = (void*)(g_ExeBase + g_Addr_4715D0);
        if (VirtualQuery(pAdvT, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pAdvT, (void*)&hk_AdvanceTByDistance, (void**)&o_AdvanceTByDistance) == MH_OK) {
                MH_EnableHook(pAdvT);
            }
        }

        void* pAdvT2 = (void*)(g_ExeBase + g_Addr_471790);
        if (VirtualQuery(pAdvT2, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pAdvT2, (void*)&hk_AdvanceTByDistance2, (void**)&o_AdvanceTByDistance2) == MH_OK) {
                MH_EnableHook(pAdvT2);
            }
        }

        // 2. GetNextT & GetNearestT (Continuous trajectory queries)
        if (g_IsSteam) { // EPIC: 0x78F10 not yet mapped (Steam-only for now)
        void* pNextT = (void*)(g_ExeBase + g_Addr_78F10);
        if (VirtualQuery(pNextT, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pNextT, (void*)&hk_GetNextT, (void**)&o_GetNextT) == MH_OK) {
                MH_EnableHook(pNextT);
            }
        }
        }

        void* pNearT = (void*)(g_ExeBase + g_Addr_78840);
        if (VirtualQuery(pNearT, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pNearT, (void*)&hk_GetNearestT, (void**)&o_GetNearestT) == MH_OK) {
                MH_EnableHook(pNearT);
            }
        }

        // 3. AI Planning Channels
        void* pGetSplineData = (void*)(g_ExeBase + g_Addr_480240);
        if (VirtualQuery(pGetSplineData, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pGetSplineData, (void*)&hk_GetSplineData, (void**)&o_GetSplineData) == MH_OK) {
                MH_EnableHook(pGetSplineData);
            }
        }

        void* pSampleSplineData = (void*)(g_ExeBase + g_Addr_48F5E0);
        if (VirtualQuery(pSampleSplineData, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pSampleSplineData, (void*)&hk_SampleSplineData, (void**)&o_SampleSplineData) == MH_OK) {
                MH_EnableHook(pSampleSplineData);
            }
        }

        void* pNavmeshPath = (void*)(g_ExeBase + g_Addr_42AE40);
        if (VirtualQuery(pNavmeshPath, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pNavmeshPath, (void*)&hk_Navmesh_CreatePathFromSpline, (void**)&o_Navmesh_CreatePathFromSpline) == MH_OK) {
                MH_EnableHook(pNavmeshPath);
                std::cout << "[+] Successfully hooked ALL AI Vehicle Spline & Stepping Channels.\n";
            }
        }
        // TrueKMH: stock HUD speedometer override (CUISpeedometerController::Update, RVA 0xEB4D00).
        // Always installed, gated at runtime by g_SpeedoReplaceGameHUD so no re-hook on toggle.
        void* pSpeedoUpdate = (void*)(g_ExeBase + g_Addr_EB4D00);
        if (VirtualQuery(pSpeedoUpdate, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (MH_CreateHook(pSpeedoUpdate, (void*)&hk_SpeedoUpdate, (void**)&o_SpeedoUpdate) == MH_OK) {
                MH_EnableHook(pSpeedoUpdate);
                std::cout << "[+] Successfully hooked CUISpeedometerController::Update (TrueKMH).\n";
            }
        }
    }

    // D3D11 hooks are initialized in hkPresent where the real device is guaranteed



    if (!g_HookedPresent) HookDX11_VMT();

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_OurModule = hModule;
        DisableThreadLibraryCalls(hModule);

        // Popup-host mode: this dll was loaded by the detached rundll32.exe
        // spawned from AbortDeprecatedDxgi (command line contains the marker).
        // Do NOT run the dxgi check, the winmm proxy or the mod thread here —
        // this process exists only to show the popup from JC4DeprecatedPopup.
        {
            const char* cl = GetCommandLineA();
            if (cl && strstr(cl, "JC4DeprecatedPopup")) {
                g_PopupHostMode = true;
                return TRUE;
            }
        }

        // Block deprecated dxgi.dll mod builds as early as physically possible:
        // synchronously, before ANY of our init and before the loader finishes
        // bringing in the app-dir dxgi.dll whose old hook code crashes the game
        // (0xc0000005 in JustCause4.exe on Epic). The check itself NEVER pumps
        // messages: on a match it spawns a detached rundll32 popup host and
        // terminates (an in-process MessageBoxA under the loader lock crashed
        // the Epic install with 0xC000041D — see ShowDeprecatedPopup).
        CheckDeprecatedDxgi();
        // Resolve the real system winmm and fill the trampoline slots BEFORE the
        // loader finishes resolving the executable's static winmm imports, so every
        // forwarded call (timeGetTime, PlaySoundA, waveOut*, ...) lands on the real
        // function from the very first instruction.
        InitWinmmProxy();
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        if (g_PopupHostMode) return TRUE;

        g_FirstPerson = false;

        ToggleAllVehiclesNitroJump(false);
        ToggleInfiniteNitro(false);
        ToggleInfiniteTurboJump(false, false);
        ApplyHideUI(false);
        ApplyFreeCamVehiclePatches(false);
        ApplySpawnLimitOverrides(false);
        UninstallVehicleHooks();
        UninstallTornadoHooks();
        UninstallFoliageHook();
        ShutdownWinmmProxy();
    }
    return TRUE;
}
