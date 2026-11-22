#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <d3d11.h>
#include <cstdint>
#include <cstddef>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>
#include <algorithm>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#include "minhook/include/MinHook.h"
#include "jc4_dxbc_patches.hpp"
#include "terrain_settings.hpp"
#include "addresses.h"

// ============================================================================
// Just Cause 4 - 16x16 (1024-Patch) Terrain Grid Support
// Early static CPU patches + Construct code cave + SetPatchStatus/Setup/CB2
// buffer sync + runtime DXBC substitution, with bounded 20-bit global quad IDs.
// ============================================================================

namespace JC4Terrain16x16 {

static uintptr_t g_ExeBase = 0;
static JC4NativeBuild g_NativeBuild = JC4NativeBuild::Unknown;

static constexpr uintptr_t NativeRva(bool epic, uintptr_t steam, uintptr_t epicRva) {
    return epic ? epicRva : steam;
}

static uintptr_t NativeRva(uintptr_t steam, uintptr_t epic) {
    return NativeRva(g_NativeBuild == JC4NativeBuild::Epic, steam, epic);
}

// Offsets are relative to matched native functions (not an image-wide delta).
// The Draw function uses three adjacent unwind ranges in both images.
static constexpr uintptr_t StaticPatchRva(bool epic, uintptr_t rva) {
    if (!epic) return rva;
    struct Region { uintptr_t first, end, epicFirst; };
    constexpr Region regions[] = {
        {0x01c0480, 0x01c0c3d, 0x01c0c50}, // LandscapeManagerCreate
        {0x01bef80, 0x01c01a7, 0x01bf750}, // InitSystemData
        {0x01be330, 0x01bea40, 0x01beb00}, // InitShaderData
        {0x01a6d70, 0x01a8b5f, 0x01a7470}, // Type::Create
        {0x7969f70, 0x796a36e, 0x43d4e10}, // terrain render targets
        {0x01bdb40, 0x01be06d, 0x01be310}, // InitCache
        {0x0f0b200, 0x0f0b5d8, 0x0f12ec0}, // quad allocation
        {0x79a99b0, 0x79a9bdc, 0x4426750}, // CreateLayers
        {0x7976def, 0x79778d9, 0x43e4cef}, // Draw body; first instructions differ before patched region
        {0x79778d9, 0x7977bdc, 0x43e57d9}, // Draw switch path
        {0x7977bdc, 0x79787c0, 0x43e5adc}, // Draw tail
    };
    for (const auto& r : regions)
        if (rva >= r.first && rva < r.end) return r.epicFirst + rva - r.first;
    return 0;
}

static uintptr_t StaticPatchRva(uintptr_t rva) {
    return StaticPatchRva(g_NativeBuild == JC4NativeBuild::Epic, rva);
}
static bool g_StaticPatchesApplied = false;
static bool g_HooksInitialized = false;
static bool g_StartupModeReported = false;
// Startup-only transaction. A failed activation is latched and D3D creation denied.
static SRWLOCK g_ActivationLock = SRWLOCK_INIT;
static LONG g_ActivationState = 0; // 0 = not attempted, 1 = ready, -1 = failed
static bool g_ConsoleReady = false;
static CRITICAL_SECTION g_LogLock;
static bool g_LogLockInit = false;
static char g_LogFilePath[MAX_PATH] = {};
static char g_EarlyLogBuf[32768] = {};
static size_t g_EarlyLogLen = 0;

static void InitLogPathOnce() {
    if (g_LogFilePath[0] != '\0') return;
    char exePath[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, exePath, MAX_PATH) > 0) {
        char* slash = strrchr(exePath, '\\');
        if (slash) {
            *(slash + 1) = '\0';
            snprintf(g_LogFilePath, sizeof(g_LogFilePath), "%sterrain_expand.log", exePath);
            return;
        }
    }
    snprintf(g_LogFilePath, sizeof(g_LogFilePath), "terrain_expand.log");
}

static void EarlyAppendFile(const char* text, size_t len) {
    InitLogPathOnce();
    HANDLE hFile = CreateFileA(
        g_LogFilePath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hFile, text, static_cast<DWORD>(len), &written, nullptr);
        CloseHandle(hFile);
    }
}

static void EarlyResetLogFile() {
    InitLogPathOnce();
    HANDLE hFile = CreateFileA(
        g_LogFilePath,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
}

static void EarlyLog(const char* fmt, ...) {
    char line[512];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(line, sizeof(line) - 2, fmt, args);
    va_end(args);
    if (n <= 0) return;
    size_t len = static_cast<size_t>(n);
    if (len >= sizeof(line) - 2) len = sizeof(line) - 2;
    line[len++] = '\n';
    line[len] = '\0';

    if (g_EarlyLogLen + len < sizeof(g_EarlyLogBuf)) {
        memcpy(g_EarlyLogBuf + g_EarlyLogLen, line, len);
        g_EarlyLogLen += len;
    }
    EarlyAppendFile(line, len);
}

static void TerrainLog(const char* fmt, ...) {
    char line[512];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(line, sizeof(line) - 2, fmt, args);
    va_end(args);
    if (n <= 0) return;
    size_t len = static_cast<size_t>(n);
    if (len >= sizeof(line) - 2) len = sizeof(line) - 2;
    line[len++] = '\n';
    line[len] = '\0';

    if (g_LogLockInit) EnterCriticalSection(&g_LogLock);
    EarlyAppendFile(line, len);
    if (g_ConsoleReady) {
        std::cout << line << std::flush;
    }
    if (g_LogLockInit) LeaveCriticalSection(&g_LogLock);
}

// ============================================================================
// Part 1: Static CPU Byte Patches
// ============================================================================

struct BytePatchSpec {
    uint32_t rva;
    uint8_t len;
    const uint8_t orig[17];
    const uint8_t repl[17];
    const char* tag;
};

#define P1(rva, o0, n0, tag) { rva, 1, {o0}, {n0}, tag }
#define P2(rva, o0,o1, n0,n1, tag) { rva, 2, {o0,o1}, {n0,n1}, tag }
#define P4(rva, o0,o1,o2,o3, n0,n1,n2,n3, tag) { rva, 4, {o0,o1,o2,o3}, {n0,n1,n2,n3}, tag }

static const BytePatchSpec kStaticBytePatches[] = {
    // LandscapeManagerCreate
    P1(0x01c061b, 0x0c, 0x18, "LMCreate_MaxUpdateFrustums"),
    P1(0x01c0622, 0x18, 0x30, "LMCreate_MaxUpdateBFBC"),
    P1(0x01c06d3, 0x08, 0x10, "LMCreate_Width0"),
    P1(0x01c06f4, 0x08, 0x10, "LMCreate_Width1"),
    P1(0x01c071b, 0x08, 0x10, "LMCreate_Width2"),
    P1(0x01c0742, 0x08, 0x10, "LMCreate_Width3"),
    P1(0x01c0769, 0x08, 0x10, "LMCreate_Width4"),
    P1(0x01c0771, 0x07, 0x0f, "LMCreate_MaxCapX"),
    P1(0x01c0779, 0x07, 0x0f, "LMCreate_MaxCapZ"),

    // InitializeSystem (SIDAllocator chunk caps)
    // Bound global quad IDs to 20 bits. The sort carrier has exactly
    // 20 quad + 2 level + 10 patch bits; a 21-bit quad pool cannot fit.
    P2(0x01bf073, 0xff,0x03, 0xff,0x07, "InitSys_QuadMetaCap20"),
    P2(0x01bf0a1, 0xff,0x0f, 0xff,0x3f, "InitSys_PaletteCap"),
    P2(0x01bf0cf, 0xff,0x04, 0xff,0x13, "InitSys_BaseMeshVertsCap"),

    // InitTerrainShader (GPU structured buffer counts)
    P4(0x01be81c, 0x00,0x01,0x00,0x00, 0x00,0x04,0x00,0x00, "InitShader_PatchMetaData"),
    P4(0x01be888, 0x00,0x00,0x08,0x00, 0x00,0x00,0x10,0x00, "InitShader_QuadMetaData20"),
    P4(0x01be8f4, 0x00,0x00,0x08,0x00, 0x00,0x00,0x10,0x00, "InitShader_QuadBoundingInfo20"),
    P4(0x01be960, 0x00,0x00,0x0a,0x00, 0x00,0x00,0x28,0x00, "InitShader_BaseMeshPositions"),
    // 16384 chunks * 16 palettes * 128 B = 0x800000 DWORDs (4x stock).
    // Construct stores the palette chunk in a full uint32; 0x3fff also fits uint16.
    P4(0x01be9cc, 0x00,0x00,0x20,0x00, 0x00,0x00,0x80,0x00, "InitShader_MaterialPalettes"),

    // CTerrainRenderBlockType::Create (m_DetailDispatchList Option A)
    P4(0x01a7363, 0xe0,0x3c,0x01,0x00, 0xe0,0x9c,0x04,0x00, "RenderBlockCreate_DDL_Malloc"),
    P4(0x01a7374, 0x00,0x02,0x00,0x00, 0x00,0x08,0x00,0x00, "RenderBlockCreate_DDL_Array1Count"),
    P4(0x01a73a2, 0x08,0x40,0x00,0x00, 0x08,0x00,0x01,0x00, "RenderBlockCreate_DDL_BaseShift"),
    P4(0x01a73d3, 0x08,0x4a,0x00,0x00, 0x08,0x0a,0x01,0x00, "RenderBlockCreate_DDL_TailPtr"),
    P4(0x01a73d8, 0x97,0x07,0x00,0x00, 0x97,0x1c,0x00,0x00, "RenderBlockCreate_DDL_TailZero"),
    P4(0x01a7422, 0x38,0x4f,0x00,0x00, 0x38,0x27,0x01,0x00, "RenderBlockCreate_DDL_ElemCount"),
    P4(0x01a748d, 0xe0,0x3c,0x01,0x00, 0xe0,0x9c,0x04,0x00, "RenderBlockCreate_DDL_BufferSize"),

    // PerFrameConstants CB2: native init calls are widened with a genuine 0x540
    // zero-tailed source by the Type::Create-scoped SetBufferData hook below.
    P2(0x01a85c6, 0x40,0x01, 0x40,0x05, "PerFrameCB_0"),
    P2(0x01a8623, 0x40,0x01, 0x40,0x05, "PerFrameCB_1"),
    P2(0x01a8679, 0x40,0x01, 0x40,0x05, "PerFrameCB_2"),
    P2(0x01a86cf, 0x40,0x01, 0x40,0x05, "PerFrameCB_3"),
    P2(0x01a8725, 0x40,0x01, 0x40,0x05, "PerFrameCB_4"),
    P2(0x01a877b, 0x40,0x01, 0x40,0x05, "PerFrameCB_5"),
    P2(0x01a87d1, 0x40,0x01, 0x40,0x05, "PerFrameCB_6"),
    P2(0x01a8827, 0x40,0x01, 0x40,0x05, "PerFrameCB_7"),

    // m_TB[0xf] PatchStatus structured buffer (0x3f400 -> 0xfd000, 256 -> 1024)
    P4(0x01a8ab1, 0x00,0xf4,0x03,0x00, 0x00,0xd0,0x0f,0x00, "mTB15_Malloc"),
    P4(0x01a8ac1, 0x00,0xf4,0x03,0x00, 0x00,0xd0,0x0f,0x00, "mTB15_SetBufferData"),
    P4(0x01a8ae6, 0x00,0x01,0x00,0x00, 0x00,0x04,0x00,0x00, "mTB15_ElemCount"),

    // Near/detail-only integer G-buffer: keep legacy XY exact and carry the
    // extra global-quad bit in Z. Both allocation and prepass must agree.
    // Native format tables already derive DXGI RGBA32_UINT views/accounting.
    P1(0x796a0f0, 0x45, 0x47, "TerrainNearDetailTarget_RGBA32UI"),
    P1(0x01a7da8, 0x45, 0x47, "TerrainNearDetailPrepassFormat_RGBA32UI"),
    // Far prepass retains its old packed X and carries sorted-address high bits in Y.
    P1(0x796a27a, 0x43, 0x45, "TerrainFarTarget_RG32UI"),
    P1(0x01a7db3, 0x43, 0x45, "TerrainFarPrepassFormat_RG32UI"),

    // Three independently indexed cache-reference banks, one per global quad.
    P4(0x01a725a, 0x00,0x00,0x08,0x00, 0x00,0x00,0x10,0x00, "InitCache_QuadBankCount20"),

    // Surface-cache classes 0..3, separate from far displaced vertices (8..11).
    // InitCache and SetDetailLevel use these to size and lay out both payloads.
    P4(0x01bdba3, 0x00,0x80,0x00,0x00, 0x00,0x80,0x01,0x00, "InitCache_SurfaceSlotsL0"),
    P4(0x01bdbaa, 0x00,0x80,0x00,0x00, 0x00,0x00,0x02,0x00, "InitCache_SurfaceSlotsL1"),
    P4(0x01bdbb1, 0x00,0xa0,0x00,0x00, 0x00,0x00,0x02,0x00, "InitCache_SurfaceSlotsL2"),
    P4(0x01bdbb8, 0x00,0x80,0x00,0x00, 0x00,0x00,0x02,0x00, "InitCache_SurfaceSlotsL3"),

    // Far displaced-vertex cache slots, classes 8..11. These are per-class,
    // not quad-pool limits. InitCache derives the header bases, reverse maps,
    // and the TB16 payload size from them. Keep slot IDs within the 18-bit field.
    P4(0x01bdbdb, 0x00,0x00,0x01,0x00, 0x00,0x80,0x02,0x00, "InitCache_FarSlotsL0"),
    P4(0x01bdbe2, 0x00,0x00,0x01,0x00, 0x00,0x80,0x02,0x00, "InitCache_FarSlotsL1"),
    P4(0x01bdbe9, 0x00,0x80,0x00,0x00, 0x00,0x80,0x01,0x00, "InitCache_FarSlotsL2"),
    P4(0x01bdbf0, 0x00,0x40,0x00,0x00, 0x00,0x00,0x01,0x00, "InitCache_FarSlotsL3"),
    P4(0x01a8a4b, 0x00,0x00,0x08,0x00, 0x00,0x00,0x10,0x00, "VisibleRunningQuads20"),
    // Each running quad can belong to all five sorted categories (proven by
    // actual classification/sort dispatches), so the shared destination is 5N.
    P4(0x01a8a71, 0x00,0x00,0x08,0x00, 0x00,0x00,0x50,0x00, "VisibleSortedQuads20_FiveCategories"),
    // Stock TB[0xc] already holds N=0x100000 enumerated IDs; leave it unchanged.

    // InitCache sentinel (0x7fffff -> 0x3fffff)
    P4(0x01bdf40, 0xff,0xff,0x7f,0x00, 0xff,0xff,0x3f,0x00, "InitCache_Sentinel"),

    // AllocateAndUploadQuads bitfield packing
    P1(0x0f0b364, 0x06, 0x08, "AllocQuads_LodShift"),
    P4(0x0f0b366, 0x40,0x02,0x00,0x00, 0x00,0x09,0x00,0x00, "AllocQuads_LodBias"),
    P1(0x0f0b370, 0x07, 0x0f, "AllocQuads_ZMask"),
    P1(0x0f0b373, 0x03, 0x04, "AllocQuads_ZShift"),
    P1(0x0f0b37c, 0x07, 0x0f, "AllocQuads_XMask"),
    P1(0x0f0b381, 0x18, 0x16, "AllocQuads_OutShift"),

    // TerrainPatchSystemCreateLayers
    P2(0x79a9a5e, 0x40,0x00, 0x00,0x01, "CreateLayers_PipelineWidth"),
    P1(0x79a9ab0, 0x07, 0x0f, "CreateLayers_CapX"),
    P1(0x79a9ab7, 0x07, 0x0f, "CreateLayers_CapZ"),
    P4(0x79a9ad8, 0x00,0x08,0x00,0x00, 0x00,0x20,0x00,0x00, "CreateLayers_QuadStride"),
    P1(0x79a9adf, 0x08, 0x10, "CreateLayers_Width"),
    P2(0x79a9afb, 0x40,0x00, 0x00,0x01, "CreateLayers_PatchesPerLod"),

    // Draw: 3x Dispatch(0x40,4,1) -> Dispatch(0x100,4,1)
    { 0x7977193, 16,
      {0xba,0x40,0x00,0x00,0x00,0x4c,0x89,0xf1,0x44,0x8d,0x4a,0xc1,0x44,0x8d,0x42,0xc4},
      {0xba,0x00,0x01,0x00,0x00,0x4c,0x89,0xf1,0x6a,0x01,0x41,0x59,0x6a,0x04,0x41,0x58},
      "Draw_Dispatch_s1607" },
    { 0x79771fd, 16,
      {0xba,0x40,0x00,0x00,0x00,0x4c,0x89,0xf1,0x44,0x8d,0x4a,0xc1,0x44,0x8d,0x42,0xc4},
      {0xba,0x00,0x01,0x00,0x00,0x4c,0x89,0xf1,0x6a,0x01,0x41,0x59,0x6a,0x04,0x41,0x58},
      "Draw_Dispatch_s1601" },
    { 0x797750b, 16,
      {0xba,0x40,0x00,0x00,0x00,0x4c,0x89,0xf1,0x44,0x8d,0x4a,0xc1,0x44,0x8d,0x42,0xc4},
      {0xba,0x00,0x01,0x00,0x00,0x4c,0x89,0xf1,0x6a,0x01,0x41,0x59,0x6a,0x04,0x41,0x58},
      "Draw_Dispatch_s1609" },

    // Draw: s_1612 Dispatch(5,1,1) -> Dispatch(5,4,1)
    { 0x79774a0, 17,
      {0x41,0xb9,0x01,0x00,0x00,0x00,0xba,0x05,0x00,0x00,0x00,0x45,0x89,0xc8,0x4c,0x89,0xf1},
      {0x6a,0x01,0x41,0x59,0xba,0x05,0x00,0x00,0x00,0x6a,0x04,0x41,0x58,0x4c,0x89,0xf1,0x90},
      "Draw_Dispatch_s1612" },

    // Draw: Fixed indirect offsets (+0xc000)
    P4(0x797733d, 0x00,0x4a,0x00,0x00, 0x00,0x0a,0x01,0x00, "Draw_DDL_0x4a00"),
    P4(0x7977698, 0x40,0x4a,0x00,0x00, 0x40,0x0a,0x01,0x00, "Draw_DDL_0x4a40"),
    P4(0x7977965, 0xa0,0x4b,0x00,0x00, 0xa0,0x0b,0x01,0x00, "Draw_DDL_0x4ba0"),
    P4(0x797796f, 0x00,0x4b,0x00,0x00, 0x00,0x0b,0x01,0x00, "Draw_DDL_0x4b00"),
    P4(0x7977c75, 0xc0,0x4a,0x00,0x00, 0xc0,0x0a,0x01,0x00, "Draw_DDL_0x4ac0"),
    P4(0x7977cd8, 0xe0,0x4a,0x00,0x00, 0xe0,0x0a,0x01,0x00, "Draw_DDL_0x4ae0"),
    P4(0x7977d39, 0x40,0x4c,0x00,0x00, 0x40,0x0c,0x01,0x00, "Draw_DDL_0x4c40"),
    P4(0x7977f14, 0xe0,0x4c,0x00,0x00, 0xe0,0x0c,0x01,0x00, "Draw_DDL_0x4ce0"),
    P4(0x7978173, 0x00,0x40,0x00,0x00, 0x00,0x00,0x01,0x00, "Draw_DDL_0x4000"),
    P4(0x79781bc, 0x00,0x42,0x00,0x00, 0x00,0x02,0x01,0x00, "Draw_DDL_0x4200"),
    P4(0x79781f3, 0x00,0x44,0x00,0x00, 0x00,0x04,0x01,0x00, "Draw_DDL_0x4400"),
    P2(0x7978561, 0x18,0x01, 0x18,0x04, "Draw_DDL_0x118_mul64"),
    P4(0x79785a3, 0x20,0x46,0x00,0x00, 0x20,0x06,0x01,0x00, "Draw_DDL_0x4620"),

    // Draw: Switch cases 7, 5, 6, 3, 4, 8 per-patch slot math
    P1(0x7977726, 0x07, 0x0f, "Draw_Sw7_ZMask"),
    P1(0x797772d, 0x07, 0x0f, "Draw_Sw7_XMask"),
    P1(0x7977730, 0x03, 0x04, "Draw_Sw7_ZShift"),
    P1(0x7977736, 0x06, 0x08, "Draw_Sw7_LodShift"),
    P4(0x797773a, 0xa7,0x06,0x00,0x00, 0xe7,0x17,0x00,0x00, "Draw_Sw7_Off"),

    P1(0x797776a, 0x07, 0x0f, "Draw_Sw5_ZMask"),
    P1(0x7977771, 0x07, 0x0f, "Draw_Sw5_XMask"),
    P1(0x7977774, 0x03, 0x04, "Draw_Sw5_ZShift"),
    P1(0x797777a, 0x06, 0x08, "Draw_Sw5_LodShift"),
    P4(0x797777e, 0xa7,0x00,0x00,0x00, 0xe7,0xff,0xff,0xff, "Draw_Sw5_Off"),

    P1(0x79777ae, 0x07, 0x0f, "Draw_Sw6_ZMask"),
    P1(0x79777b5, 0x07, 0x0f, "Draw_Sw6_XMask"),
    P1(0x79777b8, 0x03, 0x04, "Draw_Sw6_ZShift"),
    P1(0x79777be, 0x06, 0x08, "Draw_Sw6_LodShift"),
    P4(0x79777c2, 0xa7,0x01,0x00,0x00, 0xe7,0x03,0x00,0x00, "Draw_Sw6_Off"),

    P1(0x79777f1, 0x07, 0x0f, "Draw_Sw3_ZMask"),
    P1(0x79777f8, 0x07, 0x0f, "Draw_Sw3_XMask"),
    P1(0x79777fb, 0x03, 0x04, "Draw_Sw3_ZShift"),
    P1(0x7977801, 0x06, 0x08, "Draw_Sw3_LodShift"),
    P4(0x7977805, 0xa7,0x02,0x00,0x00, 0xe7,0x07,0x00,0x00, "Draw_Sw3_Off"),

    P1(0x7977835, 0x07, 0x0f, "Draw_Sw4_ZMask"),
    P1(0x797783c, 0x07, 0x0f, "Draw_Sw4_XMask"),
    P1(0x797783f, 0x03, 0x04, "Draw_Sw4_ZShift"),
    P1(0x7977845, 0x06, 0x08, "Draw_Sw4_LodShift"),
    P4(0x7977849, 0xa7,0x03,0x00,0x00, 0xe7,0x0b,0x00,0x00, "Draw_Sw4_Off"),

    P1(0x7977876, 0x07, 0x0f, "Draw_Sw8_ZMask"),
    P1(0x797787d, 0x07, 0x0f, "Draw_Sw8_XMask"),
    P1(0x7977880, 0x03, 0x04, "Draw_Sw8_ZShift"),
    P1(0x7977886, 0x06, 0x08, "Draw_Sw8_LodShift"),
    P4(0x797788a, 0xa7,0x05,0x00,0x00, 0xe7,0x13,0x00,0x00, "Draw_Sw8_Off"),

    // Draw: uVar20 == 0x16 (DrawInstancedIndirect Array #1)
    P1(0x79786bb, 0x07, 0x0f, "Draw_Indirect1_ZMask"),
    P1(0x79786c5, 0x07, 0x0f, "Draw_Indirect1_XMask"),
    P1(0x79786c8, 0x03, 0x04, "Draw_Indirect1_ZShift"),
    P1(0x7978706, 0x06, 0x08, "Draw_Indirect1_LodShift"),
};

#undef P1
#undef P2
#undef P4

static void* AllocNearExecutableMemory(uintptr_t targetAddr, size_t size) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    const uintptr_t minAddr = (targetAddr > 0x70000000ULL) ? (targetAddr - 0x70000000ULL) : gran;
    const uintptr_t maxAddr = targetAddr + 0x70000000ULL;

    uintptr_t probe = (targetAddr & ~(gran - 1));
    for (int dir = 0; dir < 2; ++dir) {
        uintptr_t addr = probe;
        while ((dir == 0 && addr < maxAddr) || (dir == 1 && addr > minAddr)) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) break;
            if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
                uintptr_t cand = (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + gran - 1) & ~(gran - 1);
                if (cand >= minAddr && cand + size <= maxAddr) {
                    void* mem = VirtualAlloc(reinterpret_cast<LPVOID>(cand), size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    if (mem) return mem;
                }
            }
            if (dir == 0) {
                uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= addr) break;
                addr = next;
            } else {
                uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                if (base <= gran) break;
                addr = base - gran;
            }
        }
    }
    return nullptr;
}

static bool ApplyPatchBytes(uintptr_t addr, const uint8_t* repl, size_t len) {
    DWORD oldProt = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(addr), len, PAGE_EXECUTE_READWRITE, &oldProt)) {
        return false;
    }
    memcpy(reinterpret_cast<void*>(addr), repl, len);
    DWORD dummy = 0;
    const bool restored = VirtualProtect(reinterpret_cast<LPVOID>(addr), len, oldProt, &dummy) != 0;
    const bool flushed = FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr), len) != 0;
    return restored && flushed && memcmp(reinterpret_cast<const void*>(addr), repl, len) == 0;
}

static const uint8_t kOrigConstruct[30] = {
    0x41,0x0f,0xbf,0x4f,0x12, 0x83,0xe1,0x07,
    0x41,0x0f,0xb6,0x47,0x1a, 0x83,0xc0,0xf7, 0x8d,0x3c,0xc1,
    0x41,0x0f,0xbf,0x47,0x10, 0x83,0xe0,0x07, 0x8d,0x3c,0xf8
};
static void* g_ConstructCave = nullptr;
static bool g_ConstructSiteTouched = false;
static size_t g_StaticPatchesTouched = 0;

static bool InstallConstructCave(uintptr_t exeBase) {
    const uintptr_t site = exeBase + NativeRva(0x0f0c5a3, 0x0f14263);
    if (memcmp(reinterpret_cast<const void*>(site), kOrigConstruct, sizeof(kOrigConstruct)) != 0) {
        EarlyLog("[Terrain16x16] ERROR: Construct cave signature mismatch at 0x%llx",
                 static_cast<unsigned long long>(site));
        return false;
    }

    // Machine code verified with objdump:
    //   movsx ecx, word ptr [r15+0x12]
    //   and   ecx, 0x0f
    //   movzx eax, byte ptr [r15+0x1a]
    //   add   eax, -9
    //   shl   eax, 4
    //   or    ecx, eax
    //   shl   ecx, 4
    //   movsx eax, word ptr [r15+0x10]
    //   and   eax, 0x0f
    //   lea   edi, [rax + rcx]
    //   jmp   qword ptr [rip+0] -> first untouched native instruction
    uint8_t caveCode[49] = {
        0x41,0x0f,0xbf,0x4f,0x12,
        0x83,0xe1,0x0f,
        0x41,0x0f,0xb6,0x47,0x1a,
        0x83,0xc0,0xf7,
        0xc1,0xe0,0x04,
        0x09,0xc1,
        0xc1,0xe1,0x04,
        0x41,0x0f,0xbf,0x47,0x10,
        0x83,0xe0,0x0f,
        0x8d,0x3c,0x08,
        0xff,0x25,0x00,0x00,0x00,0x00,
        0,0,0,0,0,0,0,0
    };
    const uint64_t retAddr = static_cast<uint64_t>(site + sizeof(kOrigConstruct));
    memcpy(caveCode + 41, &retAddr, sizeof(retAddr));

    void* caveMem = AllocNearExecutableMemory(site, sizeof(caveCode));
    if (!caveMem) {
        EarlyLog("[Terrain16x16] ERROR: AllocNearExecutableMemory failed for Construct cave");
        return false;
    }
    memcpy(caveMem, caveCode, sizeof(caveCode));
    if (!FlushInstructionCache(GetCurrentProcess(), caveMem, sizeof(caveCode))) {
        VirtualFree(caveMem, 0, MEM_RELEASE);
        return false;
    }

    const int64_t rel = static_cast<int64_t>(reinterpret_cast<uintptr_t>(caveMem)) -
                        static_cast<int64_t>(site + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) {
        EarlyLog("[Terrain16x16] ERROR: Construct cave displacement out of rel32 range");
        VirtualFree(caveMem, 0, MEM_RELEASE);
        return false;
    }

    uint8_t sitePatch[30];
    memset(sitePatch, 0x90, sizeof(sitePatch));
    sitePatch[0] = 0xe9;
    int32_t rel32 = static_cast<int32_t>(rel);
    memcpy(sitePatch + 1, &rel32, 4);
    g_ConstructCave = caveMem;
    g_ConstructSiteTouched = true; // include even an uncertain write in rollback
    if (!ApplyPatchBytes(site, sitePatch, sizeof(sitePatch))) {
        EarlyLog("[Terrain16x16] ERROR: ApplyPatchBytes failed for Construct cave site");
        return false;
    }
    EarlyLog("[Terrain16x16] Construct cave installed at 0x%llx -> cave 0x%llx",
             static_cast<unsigned long long>(site),
             static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(caveMem)));
    return true;
}

static bool IsReadableRange(uintptr_t addr, size_t len) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    const DWORD p = mbi.Protect & 0xFF;
    if (p == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) return false;
    const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return (addr + len) <= regionEnd;
}

static bool VerifyTerrain16x16StaticPatches() {
    HMODULE hExe = GetModuleHandleA("JustCause4.exe");
    if (!hExe) return false;

    g_ExeBase = reinterpret_cast<uintptr_t>(hExe);
    EarlyLog("[Terrain16x16] ApplyTerrain16x16StaticPatches start (base=0x%llx)",
             static_cast<unsigned long long>(g_ExeBase));

    // Verify ALL static byte patches AND Construct cave BEFORE applying anything.
    const size_t patchCount = sizeof(kStaticBytePatches) / sizeof(kStaticBytePatches[0]);
    for (size_t i = 0; i < patchCount; ++i) {
        const auto& p = kStaticBytePatches[i];
        const uintptr_t rva = StaticPatchRva(p.rva);
        const uintptr_t addr = g_ExeBase + rva;
        if (!rva || !IsReadableRange(addr, p.len)) {
            EarlyLog("[Terrain16x16] ERROR: Unreadable page on %s (RVA 0x%x)", p.tag, p.rva);
            return false;
        }
        if (memcmp(reinterpret_cast<const void*>(addr), p.orig, p.len) != 0) {
            EarlyLog("[Terrain16x16] ERROR: Byte signature mismatch on %s (RVA 0x%llx)",
                     p.tag, static_cast<unsigned long long>(rva));
            return false;
        }
    }

    const uintptr_t site = g_ExeBase + NativeRva(0x0f0c5a3, 0x0f14263);
    if (!IsReadableRange(site, sizeof(kOrigConstruct)) ||
        memcmp(reinterpret_cast<const void*>(site), kOrigConstruct, sizeof(kOrigConstruct)) != 0) {
        EarlyLog("[Terrain16x16] ERROR: Construct preflight signature mismatch");
        return false;
    }
    return true;
}

static bool ApplyTerrain16x16StaticPatches() {
    const size_t patchCount = sizeof(kStaticBytePatches) / sizeof(kStaticBytePatches[0]);
    if (!InstallConstructCave(g_ExeBase)) {
        return false;
    }

    size_t applied = 0;
    for (size_t i = 0; i < patchCount; ++i) {
        const auto& p = kStaticBytePatches[i];
        g_StaticPatchesTouched = i + 1; // rollback includes partially completed writes
        if (!ApplyPatchBytes(g_ExeBase + StaticPatchRva(p.rva), p.repl, p.len)) {
            EarlyLog("[Terrain16x16] ERROR: VirtualProtect/write failed on %s (RVA 0x%x)", p.tag, p.rva);
            return false;
        }
        ++applied;
    }

    EarlyLog("[Terrain16x16] Applied %zu/%zu static CPU patches + Construct cave cleanly (base=0x%llx)",
              applied, patchCount, static_cast<unsigned long long>(g_ExeBase));
    return true; // overall readiness is published only after every CPU hook enables
}

static bool RollbackTerrain16x16StaticPatches() {
    bool ok = true;
    while (g_StaticPatchesTouched != 0) {
        const auto& p = kStaticBytePatches[--g_StaticPatchesTouched];
        if (!ApplyPatchBytes(g_ExeBase + StaticPatchRva(p.rva), p.orig, p.len)) {
            TerrainLog("[Terrain16x16] FATAL: static rollback failed: %s", p.tag);
            ok = false;
        }
    }
    bool siteRestored = !g_ConstructSiteTouched;
    if (g_ConstructSiteTouched) {
        siteRestored = ApplyPatchBytes(g_ExeBase + NativeRva(0x0f0c5a3, 0x0f14263), kOrigConstruct, sizeof(kOrigConstruct));
        ok = siteRestored && ok;
        if (siteRestored) g_ConstructSiteTouched = false;
    }
    // Never release code which an unsuccessfully restored jump might still target.
    if (siteRestored && g_ConstructCave) {
        if (!VirtualFree(g_ConstructCave, 0, MEM_RELEASE)) ok = false;
        else g_ConstructCave = nullptr;
    }
    g_StaticPatchesApplied = false;
    return ok;
}

// ============================================================================
// Part 2: Dynamic Hooks (SetPatchStatus, Setup, LockBuffer/UnlockBuffer, D3D11)
// ============================================================================

struct alignas(8) SLockBufferParams {
    void*    m_Buffer;
    uint32_t m_LockType;
    uint32_t m_StateBefore;
    uint32_t m_StateAfter;
    uint32_t m_Offset;
    uint32_t m_Size;
    uint32_t _pad1c;
    uint64_t m_InternalLockContext;
};
static_assert(alignof(SLockBufferParams) == 8, "SLockBufferParams PDB alignment");
static_assert(offsetof(SLockBufferParams, m_Buffer) == 0x00, "SLockBufferParams buffer");
static_assert(offsetof(SLockBufferParams, m_LockType) == 0x08, "SLockBufferParams lock type");
static_assert(offsetof(SLockBufferParams, m_StateBefore) == 0x0c, "SLockBufferParams state before");
static_assert(offsetof(SLockBufferParams, m_StateAfter) == 0x10, "SLockBufferParams state after");
static_assert(offsetof(SLockBufferParams, m_Offset) == 0x14, "SLockBufferParams offset");
static_assert(offsetof(SLockBufferParams, m_Size) == 0x18, "SLockBufferParams size");
static_assert(offsetof(SLockBufferParams, m_InternalLockContext) == 0x20, "SLockBufferParams context");
static_assert(sizeof(SLockBufferParams) == 0x28, "SLockBufferParams size must be 0x28");

class ScopedExclusiveSRW {
    SRWLOCK* lock;
public:
    explicit ScopedExclusiveSRW(SRWLOCK& value) : lock(&value) { AcquireSRWLockExclusive(lock); }
    ~ScopedExclusiveSRW() { ReleaseSRWLockExclusive(lock); }
    ScopedExclusiveSRW(const ScopedExclusiveSRW&) = delete;
    ScopedExclusiveSRW& operator=(const ScopedExclusiveSRW&) = delete;
};

// A runtime contract violation must not return to a stock caller which will
// ignore failure and upload/free somebody else's allocation. Never used for a
// recoverable startup transaction failure (D3D creation returns E_FAIL there).
[[noreturn]] static void TerrainSafetyAbort(const char* reason) {
    TerrainLog("[Terrain16x16] FATAL CPU safety invariant: %s; refusing unsafe continuation", reason);
    std::abort();
}

static constexpr uintptr_t kOwnedCBOffsets[4] = {0x7d8U, 0x7e8U, 0x7f8U, 0x808U};

static int OwnedCBIndex(uintptr_t block, void* buffer) {
    if (!block || !buffer) return -1;
    for (int family = 0; family < 4; ++family) {
        for (uint32_t slot = 0; slot < 2; ++slot) {
            if (buffer == *reinterpret_cast<void**>(block + kOwnedCBOffsets[family] + slot * 8U))
                return family * 2 + static_cast<int>(slot);
        }
    }
    return -1;
}

struct ExtPatchStatusBlock {
    uint8_t status[2][1024]{};
    uint64_t epoch = 0;
    uint64_t uploads[4][2]{};
};

static SRWLOCK g_ExtStatusLock = SRWLOCK_INIT;
static std::unordered_map<uintptr_t, std::unique_ptr<ExtPatchStatusBlock>> g_ExtStatusMap;
static LONG g_LoggedFirstCB2Write = 0;
static LONG64 g_StatusEpoch = 0;

static void ResetExtPatchStatus(uintptr_t block) {
    try {
        auto fresh = std::make_unique<ExtPatchStatusBlock>();
        fresh->epoch = static_cast<uint64_t>(InterlockedIncrement64(&g_StatusEpoch));
        const uint64_t epoch = fresh->epoch;
        {
            ScopedExclusiveSRW guard(g_ExtStatusLock);
            g_ExtStatusMap[block] = std::move(fresh);
        }
        InterlockedExchange(&g_LoggedFirstCB2Write, 0);
        TerrainLog("[Terrain16x16] CPU status reset block=0x%llx epoch=%llu (both parities)",
                   static_cast<unsigned long long>(block), static_cast<unsigned long long>(epoch));
    } catch (...) {
        TerrainSafetyAbort("cannot allocate/reset external status storage");
    }
}

static void EraseExtPatchStatus(uintptr_t block, const char* site) {
    bool erased = false;
    {
        ScopedExclusiveSRW guard(g_ExtStatusLock);
        erased = g_ExtStatusMap.erase(block) != 0;
    }
    if (erased) TerrainLog("[Terrain16x16] CPU status erased block=0x%llx site=%s",
                          static_cast<unsigned long long>(block), site);
}

static constexpr uint32_t kFirstTerrainLod = 9;
static constexpr uint32_t kLastTerrainLod = 12;

static constexpr uint32_t ExpandedPatchIndex(int32_t x, int32_t z, uint32_t lod) {
    return ((lod - kFirstTerrainLod) << 8) |
           ((static_cast<uint32_t>(z) & 15U) << 4) | (static_cast<uint32_t>(x) & 15U);
}

// PDB layouts, also checked in both SetupRenderBlock bodies. This is the
// *source terrain* header (argument 7), not the smaller vegetation patch header.
struct VegSourcePatchHeader {
    uint8_t prefix[0x10];
    int16_t x, z;
    uint8_t middle[6];
    uint8_t lod;
};
static_assert(offsetof(VegSourcePatchHeader, x) == 0x10 && offsetof(VegSourcePatchHeader, z) == 0x12 &&
              offsetof(VegSourcePatchHeader, lod) == 0x1a, "SPatchHeader layout");
typedef void* (__fastcall *SetupVegSamplingBlock_t)(void*, void*, void*, uint32_t, void*, void*, const VegSourcePatchHeader*);
static SetupVegSamplingBlock_t o_SetupVegSamplingBlock = nullptr;
static LONG g_VegSamplingReported[4]{};

static void* __fastcall hkSetupVegSamplingBlock(void* context, void* world, void* vegetation,
                                               uint32_t index, void* terrainPatch, void* bounds,
                                               const VegSourcePatchHeader* source) {
    auto* block = static_cast<uint8_t*>(o_SetupVegSamplingBlock(context, world, vegetation, index,
                                                               terrainPatch, bounds, source));
    // Native generation publishes m_GpuStage only after SetupRenderBlock and
    // buffer creation return. Correct the producer before either shader reads it.
    if (!block || !source || source->lod < kFirstTerrainLod || source->lod > kLastTerrainLod)
        TerrainSafetyAbort("vegetation sampling source outside terrain metadata LODs 9..12");
    auto& patchIndex = *reinterpret_cast<uint32_t*>(block + 0xb8);
    const uint32_t old = patchIndex;
    patchIndex = ExpandedPatchIndex(source->x, source->z, source->lod);
    // One real wrong-slot example per source LOD, without logging per patch.
    if (old != patchIndex && InterlockedCompareExchange(&g_VegSamplingReported[source->lod - kFirstTerrainLod], 1, 0) == 0)
        TerrainLog("[Terrain16x16] Vegetation sample source x=%d z=%d lod=%u stale8x8=%u corrected=%u",
                   static_cast<int>(source->x), static_cast<int>(source->z), static_cast<unsigned>(source->lod), old, patchIndex);
    return block;
}

struct ThreadSetupState {
    int depth = 0;
    uintptr_t block = 0;
    uint32_t frameSlot = 0;
    uint32_t frameNumber = 0;
    void* lastBuf = nullptr;
    void* lastMapped = nullptr;
    void* lastCtx = nullptr;
    int lastFamily = -1;
    const SLockBufferParams* lastParams = nullptr;
};
static thread_local ThreadSetupState t_SetupState;

// Exact PDB argument widths/counts. Win64 uses the unified register ABI.
typedef void (__fastcall *SetPatchStatus_t)(uintptr_t block, int32_t patchX, int32_t patchZ, int32_t lod, uint32_t status);
typedef void (__fastcall *Setup_t)(uintptr_t block, uintptr_t renderCtx);
typedef void* (__fastcall *LockBuffer_t)(void* ctx, SLockBufferParams* params);
typedef void (__fastcall *UnlockBuffer_t)(void* ctx, SLockBufferParams* params);
typedef void (__fastcall *SetBufferData_t)(void* ctx, void* buffer, const void* source, uint64_t size,
                                         uint32_t stateBefore, uint32_t stateAfter, uint32_t flags);
typedef void (__fastcall *TypeCreate_t)(uintptr_t block, void* resourceCtx);
typedef void (__fastcall *TypeDestroy_t)(uintptr_t block, void* resourceCtx);
typedef void (__fastcall *TypeDtor_t)(uintptr_t block);
typedef void (__fastcall *SystemFree_t)(void* system);
typedef uint32_t (__fastcall *GetBufferSize_t)(void* buffer);
typedef bool (__fastcall *CreateRangeID_t)(void* allocator, uint32_t* result, uint32_t count);
typedef bool (__fastcall *DestroyRangeID_t)(void* allocator, uint32_t first, uint32_t count);

static SetPatchStatus_t o_SetPatchStatus = nullptr;
static Setup_t          o_Setup = nullptr;
static LockBuffer_t     o_LockBuffer = nullptr;
static UnlockBuffer_t   o_UnlockBuffer = nullptr;
static SetBufferData_t  o_SetBufferData = nullptr;
static TypeCreate_t     o_TypeCreate = nullptr;
static TypeDestroy_t    o_TypeDestroy = nullptr;
static TypeDtor_t       o_TypeDtor = nullptr;
static SystemFree_t     o_SystemFree = nullptr;
static CreateRangeID_t  o_CreateRangeID = nullptr;
static DestroyRangeID_t o_DestroyRangeID = nullptr;

static void __fastcall hkSetPatchStatus(uintptr_t block, int32_t patchX, int32_t patchZ, int32_t lod, uint32_t status) {
    if (!block || lod < 9 || lod > 12) TerrainSafetyAbort("invalid SetPatchStatus owner/LOD");
    const uint32_t slot = *reinterpret_cast<const volatile uint32_t*>(g_ExeBase + NativeRva(0x2ae46d0, 0x2aeb128)) & 1U;
    const uint32_t idx = ExpandedPatchIndex(patchX, patchZ, static_cast<uint32_t>(lod));
    bool found = false;
    {
        ScopedExclusiveSRW guard(g_ExtStatusLock);
        auto it = g_ExtStatusMap.find(block);
        if (it != g_ExtStatusMap.end() && it->second) {
            it->second->status[slot][idx] = static_cast<uint8_t>(status);
            found = true;
        }
    }
    if (!found) TerrainSafetyAbort("SetPatchStatus outside a live Type::Create epoch");

    // Preserve stock in-struct [0..7, 0..7] copy without letting >=8 alias/overwrite [0..7]
    if (o_SetPatchStatus && lod >= 9 && lod <= 12 &&
        (patchX & 0xfU) < 8U && (patchZ & 0xfU) < 8U) {
        o_SetPatchStatus(block, patchX, patchZ, lod, status);
    }
}

static void __fastcall hkSetup(uintptr_t block, uintptr_t renderCtx) {
    ThreadSetupState prev = t_SetupState;
    t_SetupState = ThreadSetupState{};
    t_SetupState.depth = prev.depth + 1;
    t_SetupState.block = block;
    t_SetupState.frameNumber = renderCtx ? *reinterpret_cast<const volatile uint32_t*>(renderCtx + 0x1040ULL) : 0U;
    t_SetupState.frameSlot = t_SetupState.frameNumber & 1U;
    try {
        o_Setup(block, renderCtx);
    } catch (...) {
        t_SetupState = prev;
        throw;
    }
    if (t_SetupState.lastMapped) TerrainSafetyAbort("Setup returned with an unmatched owned CB map");
    t_SetupState = prev;
}

static void* __fastcall hkLockBuffer(void* ctx, SLockBufferParams* params) {
    void* ptr = o_LockBuffer(ctx, params);
    if (t_SetupState.depth > 0 && params) {
        const int index = OwnedCBIndex(t_SetupState.block, params->m_Buffer);
        if (index < 0) return ptr;
        if (static_cast<uint32_t>(index & 1) != t_SetupState.frameSlot ||
            params->m_Offset != 0 || params->m_Size != 0x540 || !ptr || t_SetupState.lastMapped)
            TerrainSafetyAbort("owned CB map size/parity/pointer/pairing mismatch");
        t_SetupState.lastBuf = params->m_Buffer;
        t_SetupState.lastMapped = ptr;
        t_SetupState.lastParams = params;
        t_SetupState.lastCtx = ctx;
        t_SetupState.lastFamily = index / 2;
    }
    return ptr;
}

static void __fastcall hkUnlockBuffer(void* ctx, SLockBufferParams* params) {
    const int index = t_SetupState.depth > 0 && params ? OwnedCBIndex(t_SetupState.block, params->m_Buffer) : -1;
    if (index >= 0) {
        if (params->m_Offset != 0 || params->m_Size != 0x540 || params != t_SetupState.lastParams ||
            params->m_Buffer != t_SetupState.lastBuf || ctx != t_SetupState.lastCtx ||
            !t_SetupState.lastMapped || index / 2 != t_SetupState.lastFamily ||
            static_cast<uint32_t>(index & 1) != t_SetupState.frameSlot)
            TerrainSafetyAbort("owned CB unlock does not match its live map");
        uint8_t localStatus[1024];
        uint64_t epoch = 0, sequence = 0;
        {
            ScopedExclusiveSRW guard(g_ExtStatusLock);
            auto it = g_ExtStatusMap.find(t_SetupState.block);
            if (it != g_ExtStatusMap.end() && it->second) {
                auto& ext = *it->second;
                memcpy(localStatus, ext.status[t_SetupState.frameSlot], sizeof(localStatus));
                epoch = ext.epoch;
                sequence = ++ext.uploads[index / 2][t_SetupState.frameSlot];
            }
        }
        if (!epoch) TerrainSafetyAbort("owned CB upload has no live status epoch");
        // Setup wrote [0x000..0x0ff] legacy 256B status and [0x100..0x13f] (cb2[16..19]) projection matrix;
        // patched s_1601/s_1606 read 1024B PatchStatus at cb2[20..83] (+0x140..+0x53f).
        memcpy(static_cast<uint8_t*>(t_SetupState.lastMapped) + 0x140, localStatus, 1024);
        unsigned active[4]{};
        uint32_t hash = 2166136261U;
        for (unsigned i = 0; i < sizeof(localStatus); ++i) {
            active[i >> 8] += localStatus[i] != 0;
            hash = (hash ^ localStatus[i]) * 16777619U;
        }
        const bool firstActive = (active[0] || active[1] || active[2] || active[3]) &&
            InterlockedCompareExchange(&g_LoggedFirstCB2Write, 1, 0) == 0;
        // First two uploads for every family/parity, then 256/512/1024/... only.
        if (sequence <= 2 || (sequence >= 256 && (sequence & (sequence - 1)) == 0) || firstActive) {
            TerrainLog("[Terrain16x16] CB2 upload block=0x%llx buf=%p family=%d slot=%u frame=%u epoch=%llu n=%llu size=0x540 tailHash=%08x active=%u/%u/%u/%u",
                       static_cast<unsigned long long>(t_SetupState.block), params->m_Buffer, index / 2,
                       t_SetupState.frameSlot, t_SetupState.frameNumber, static_cast<unsigned long long>(epoch),
                       static_cast<unsigned long long>(sequence), hash, active[0], active[1], active[2], active[3]);
        }
        t_SetupState.lastBuf = nullptr;
        t_SetupState.lastMapped = nullptr;
        t_SetupState.lastParams = nullptr;
        t_SetupState.lastCtx = nullptr;
        t_SetupState.lastFamily = -1;
    }
    o_UnlockBuffer(ctx, params);
}

struct ThreadCreateState {
    uintptr_t block;
    uint32_t initializedMask;
};
static thread_local ThreadCreateState* t_CreateState = nullptr;

static void __fastcall hkSetBufferData(void* ctx, void* buffer, const void* source, uint64_t size,
                                       uint32_t stateBefore, uint32_t stateAfter, uint32_t flags) {
    const int index = t_CreateState ? OwnedCBIndex(t_CreateState->block, buffer) : -1;
    if (index < 0) {
        o_SetBufferData(ctx, buffer, source, size, stateBefore, stateAfter, flags);
        return;
    }
    const uintptr_t expectedSource = t_CreateState->block + 0x818U + (index & 1) * 0x140U;
    const auto getSize = reinterpret_cast<GetBufferSize_t>(g_ExeBase + NativeRva(0x0ad80170, 0x170f4740));
    if (size != 0x140 || reinterpret_cast<uintptr_t>(source) != expectedSource || getSize(buffer) != 0x540)
        TerrainSafetyAbort("Type::Create owned CB initialization source/size mismatch");
    // DEFAULT buffers use whole-resource UpdateSubresource. A size argument or
    // pitch of 0x140 does not make that a partial constant-buffer update.
    alignas(16) uint8_t initial[0x540]{};
    memcpy(initial, source, 0x140);
    o_SetBufferData(ctx, buffer, initial, sizeof(initial), stateBefore, stateAfter, flags);
    t_CreateState->initializedMask |= 1U << index;
    TerrainLog("[Terrain16x16] CB2 init block=0x%llx buf=%p family=%d slot=%d size=0x540 tail=zero",
               static_cast<unsigned long long>(t_CreateState->block), buffer, index / 2, index & 1);
}

// PDB SIDAllocator layout. Terrain call sites hold their existing native mutex
// across these hooks; snapshots do not introduce unsynchronized allocator reads.
struct SIDRangeView { uint32_t first, last; };
struct SIDAllocatorView { SIDRangeView* ranges; uint32_t count, capacity; };
static_assert(sizeof(SIDAllocatorView) == 16 && offsetof(SIDAllocatorView, count) == 8 &&
              offsetof(SIDAllocatorView, capacity) == 12, "SIDAllocator PDB layout");
static constexpr uint32_t kPoolChunks[3] = {2048, 5120, 16384};
static const char* const kPoolNames[3] = {"quads", "base-mesh", "palettes"};
struct PoolDiagnostic { void* allocator = nullptr; uint32_t highWater = 0; uint64_t allocations = 0, frees = 0; };
static_assert(sizeof(PoolDiagnostic) == 32 && offsetof(PoolDiagnostic, highWater) == 8 &&
              offsetof(PoolDiagnostic, allocations) == 16 && offsetof(PoolDiagnostic, frees) == 24,
              "diagnostic snapshot layout");
static SRWLOCK g_PoolDiagLock = SRWLOCK_INIT;
static PoolDiagnostic g_PoolDiagnostics[3];
struct PoolSnapshot { uint32_t used, free, largest; };

static PoolSnapshot SnapshotPool(void* allocator, int kind) {
    if (!allocator) TerrainSafetyAbort("null terrain SIDAllocator");
    const auto& a = *static_cast<const SIDAllocatorView*>(allocator);
    const uint32_t total = kPoolChunks[kind];
    if (!a.ranges || a.count == 0 || a.count > a.capacity || a.count > total + 1)
        TerrainSafetyAbort("invalid terrain SIDAllocator range vector");
    uint64_t free = 0;
    uint32_t largest = 0;
    for (uint32_t i = 0; i < a.count; ++i) {
        const auto r = a.ranges[i];
        if (r.last >= total || r.first > total || r.first > r.last + 1U)
            TerrainSafetyAbort("terrain SIDAllocator range exceeds backing capacity");
        const uint32_t length = r.first == r.last + 1U ? 0U : r.last - r.first + 1U;
        free += length;
        if (largest < length) largest = length;
    }
    if (free > total) TerrainSafetyAbort("overlapping/invalid terrain SIDAllocator accounting");
    return {total - static_cast<uint32_t>(free), static_cast<uint32_t>(free), largest};
}

static void RecordPool(void* allocator, int kind, const PoolSnapshot& snapshot, bool allocation) {
    bool report = false;
    uint32_t highWater = 0;
    uint64_t calls = 0;
    {
        ScopedExclusiveSRW guard(g_PoolDiagLock);
        auto& d = g_PoolDiagnostics[kind];
        if (d.allocator != allocator) { d = PoolDiagnostic{}; d.allocator = allocator; }
        const uint32_t oldHigh = d.highWater;
        if (d.highWater < snapshot.used) d.highWater = snapshot.used;
        calls = allocation ? ++d.allocations : ++d.frees;
        highWater = d.highWater;
        report = allocation && (calls == 1 || highWater * 16U / kPoolChunks[kind] > oldHigh * 16U / kPoolChunks[kind]);
    }
    if (report) TerrainLog("[Terrain16x16] CPU pool=%s allocator=%p used=%u/%u high=%u free=%u largest=%u allocations=%llu",
                           kPoolNames[kind], allocator, snapshot.used, kPoolChunks[kind], highWater,
                           snapshot.free, snapshot.largest, static_cast<unsigned long long>(calls));
}

#if defined(_MSC_VER)
#define JC4_TERRAIN_NOINLINE __declspec(noinline)
#else
#define JC4_TERRAIN_NOINLINE __attribute__((noinline))
#endif

static JC4_TERRAIN_NOINLINE bool __fastcall hkCreateRangeID(void* allocator, uint32_t* result, uint32_t count) {
#if defined(_MSC_VER)
    const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
#else
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
#endif
    // All three Ghidra-proven terrain call-return RVAs. Other callers pass through.
    const uintptr_t rva = caller - g_ExeBase;
    const int kind = rva == NativeRva(0x0f0b283, 0x0f12f43) ? 0 :
                     rva == NativeRva(0x0f11076, 0x0f18d36) ? 1 :
                     rva == NativeRva(0x0f0b511, 0x0f131d1) ? 2 : -1;
    // A zero-length stock request is a no-op (does not acquire ownership).
    if (kind < 0 || count == 0) return o_CreateRangeID(allocator, result, count);
    const auto before = SnapshotPool(allocator, kind);
    if (!result || before.largest < count) {
        TerrainLog("[Terrain16x16] CPU ALLOCATION FAILURE pool=%s request=%u used=%u/%u free=%u largest=%u caller=0x%llx",
                   kPoolNames[kind], count, before.used, kPoolChunks[kind], before.free, before.largest,
                   static_cast<unsigned long long>(rva));
        TerrainSafetyAbort("terrain allocation cannot be satisfied; stock caller ignores false");
    }
    const bool ok = o_CreateRangeID(allocator, result, count);
    if (!ok || static_cast<uint64_t>(*result) + count > kPoolChunks[kind]) {
        TerrainLog("[Terrain16x16] CPU ALLOCATION FAILURE pool=%s allocator=%p request=%u nativeOK=%d result=%u",
                   kPoolNames[kind], allocator, count, ok ? 1 : 0, ok ? *result : 0U);
        TerrainSafetyAbort("terrain CreateRangeID failed or returned an out-of-bounds chunk");
    }
    RecordPool(allocator, kind, SnapshotPool(allocator, kind), true);
    return ok;
}

static JC4_TERRAIN_NOINLINE bool __fastcall hkDestroyRangeID(void* allocator, uint32_t first, uint32_t count) {
#if defined(_MSC_VER)
    const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
#else
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
#endif
    const uintptr_t rva = caller - g_ExeBase;
    // Proven native free call sites use resources+0x1b8/0x1c8/0x1d8.
    // Do not classify by a cached raw allocator address that could be reused.
    const int kind = rva == NativeRva(0x0f109e9, 0x0f186a9) ? 0 :
                     rva == NativeRva(0x0f10bce, 0x0f1888e) ? 1 :
                     rva == NativeRva(0x0f10a4f, 0x0f1870f) ? 2 : -1;
    if (kind < 0) return o_DestroyRangeID(allocator, first, count);
    if (!count || static_cast<uint64_t>(first) + count > kPoolChunks[kind])
        TerrainSafetyAbort("out-of-bounds terrain DestroyRangeID");
    const bool ok = o_DestroyRangeID(allocator, first, count);
    if (!ok) {
        TerrainLog("[Terrain16x16] CPU FREE FAILURE pool=%s allocator=%p first=%u count=%u",
                   kPoolNames[kind], allocator, first, count);
        TerrainSafetyAbort("terrain DestroyRangeID rejected allocation ownership");
    }
    RecordPool(allocator, kind, SnapshotPool(allocator, kind), false);
    return ok;
}

#undef JC4_TERRAIN_NOINLINE

static void __fastcall hkTypeCreate(uintptr_t block, void* resourceCtx) {
    ResetExtPatchStatus(block); // native Create also resets both legacy frames
    {
        ScopedExclusiveSRW guard(g_PoolDiagLock);
        for (auto& d : g_PoolDiagnostics) d = PoolDiagnostic{};
    }
    ThreadCreateState state{block, 0};
    auto* previous = t_CreateState;
    t_CreateState = &state;
    try {
        o_TypeCreate(block, resourceCtx);
    } catch (...) {
        t_CreateState = previous;
        EraseExtPatchStatus(block, "Create exception");
        throw;
    }
    t_CreateState = previous;
    if (state.initializedMask != 0xffU) TerrainSafetyAbort("Type::Create did not initialize all eight owned CBs");
}

static void __fastcall hkTypeDestroy(uintptr_t block, void* resourceCtx) {
    o_TypeDestroy(block, resourceCtx);
    EraseExtPatchStatus(block, "Type::Destroy");
}

static void __fastcall hkTypeDtor(uintptr_t block) {
    o_TypeDtor(block);
    EraseExtPatchStatus(block, "Type destructor");
}

static void __fastcall hkSystemFree(void* system) {
    const uintptr_t block = *reinterpret_cast<const uintptr_t*>(g_ExeBase + NativeRva(0x2cad8f0, 0x2cb3cb0));
    o_SystemFree(system); // removes Type and clears global; never dereference system afterwards
    if (block) EraseExtPatchStatus(block, "TerrainPatchSystemFree");
}

// ============================================================================
// Part 3: D3D11CreateDevice -> ID3D11Device Shader Replacement Hooks
// ============================================================================

typedef HRESULT (STDMETHODCALLTYPE *CreateVertexShader_t)(
    ID3D11Device* This, const void* pShaderBytecode, SIZE_T BytecodeLength,
    ID3D11ClassLinkage* pClassLinkage, ID3D11VertexShader** ppVertexShader);
typedef HRESULT (STDMETHODCALLTYPE *CreatePixelShader_t)(
    ID3D11Device* This, const void* pShaderBytecode, SIZE_T BytecodeLength,
    ID3D11ClassLinkage* pClassLinkage, ID3D11PixelShader** ppPixelShader);
typedef HRESULT (STDMETHODCALLTYPE *CreateComputeShader_t)(
    ID3D11Device* This, const void* pShaderBytecode, SIZE_T BytecodeLength,
    ID3D11ClassLinkage* pClassLinkage, ID3D11ComputeShader** ppComputeShader);

static CreateVertexShader_t  o_CreateVertexShader  = nullptr;
static CreatePixelShader_t   o_CreatePixelShader   = nullptr;
static CreateComputeShader_t o_CreateComputeShader = nullptr;

typedef HRESULT (WINAPI *PFN_D3D11CreateDevice_t)(
    IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*, UINT,
    UINT, ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
typedef HRESULT (WINAPI *PFN_D3D11CreateDeviceAndSwapChain_t)(
    IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*, UINT,
    UINT, const DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**, ID3D11Device**,
    D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);

static PFN_D3D11CreateDevice_t             o_D3D11CreateDevice = nullptr;
static PFN_D3D11CreateDeviceAndSwapChain_t o_D3D11CreateDeviceAndSwapChain = nullptr;

static CRITICAL_SECTION g_D3D11HookLock;
static bool g_D3D11HookLockInit = false;
static std::vector<void*> g_HookedCreateVS;
static std::vector<void*> g_HookedCreatePS;
static std::vector<void*> g_HookedCreateCS;
static uint64_t g_MatchedShaderMask = 0;
static uint32_t g_TotalShaderSwaps = 0;

static const JC4PatchedDXBCEntry* FindPatchedShader(
    JC4ShaderStage stage, const void* bytecode, SIZE_T len, size_t* outIndex) {
    if (!g_StaticPatchesApplied || !bytecode || len < 20) return nullptr;
    const uint8_t* bytes = static_cast<const uint8_t*>(bytecode);
    // Check DXBC fourcc ('D','X','B','C') before comparing digest at [4..19]
    if (bytes[0] != 'D' || bytes[1] != 'X' || bytes[2] != 'B' || bytes[3] != 'C') {
        return nullptr;
    }
    constexpr size_t kCount = sizeof(kJC4PatchedDXBCs) / sizeof(kJC4PatchedDXBCs[0]);
    for (size_t i = 0; i < kCount; ++i) {
        const auto& e = kJC4PatchedDXBCs[i];
        if (e.stage == stage && memcmp(bytes + 4, e.orig_dxbc_digest, 16) == 0) {
            if (outIndex) *outIndex = i;
            if (stage == JC4ShaderStage::CS && JC4TerrainSettings::GetSnapshot().startupAltitudeDetail) {
                if (strncmp(e.name, "s_1601:", 7) == 0) {
                    static const JC4PatchedDXBCEntry variant{"s_1601:altitude_detail_child_mask", stage, {}, kAltitudeChildMaskDXBC, sizeof(kAltitudeChildMaskDXBC)};
                    return &variant;
                }
                if (strncmp(e.name, "s_1610:", 7) == 0) {
                    static const JC4PatchedDXBCEntry variant{"s_1610:altitude_detail_classifier", stage, {}, kAltitudeClassifierDXBC, sizeof(kAltitudeClassifierDXBC)};
                    return &variant;
                }
            }
            return &e;
        }
    }
    return nullptr;
}

static void LogShaderSwap(size_t idx, const char* stageName, const JC4PatchedDXBCEntry* e, SIZE_T origSize, HRESULT hr) {
    if (g_D3D11HookLockInit) EnterCriticalSection(&g_D3D11HookLock);
    const uint64_t bit = (idx < 64) ? (1ULL << idx) : 0ULL;
    const bool firstTime = (g_MatchedShaderMask & bit) == 0;
    if (hr == S_OK) g_MatchedShaderMask |= bit;
    ++g_TotalShaderSwaps;
    size_t uniqueMatched = 0;
    for (int b = 0; b < 64; ++b) {
        if ((g_MatchedShaderMask >> b) & 1ULL) ++uniqueMatched;
    }
    if (g_D3D11HookLockInit) LeaveCriticalSection(&g_D3D11HookLock);

    if (firstTime || FAILED(hr)) {
        TerrainLog("[ShaderSwap] %s %s orig=%zu patched=%zu hr=0x%08lx (%zu/%zu unique, total=%u)",
                   stageName, e->name, origSize, e->patched_size,
                   static_cast<unsigned long>(hr), uniqueMatched,
                   sizeof(kJC4PatchedDXBCs) / sizeof(kJC4PatchedDXBCs[0]), g_TotalShaderSwaps);
    }
}

static HRESULT STDMETHODCALLTYPE hkCreateVertexShader(
    ID3D11Device* This, const void* pShaderBytecode, SIZE_T BytecodeLength,
    ID3D11ClassLinkage* pClassLinkage, ID3D11VertexShader** ppVertexShader) {
    size_t idx = 0;
    if (const auto* e = FindPatchedShader(JC4ShaderStage::VS, pShaderBytecode, BytecodeLength, &idx)) {
        HRESULT hr = o_CreateVertexShader(This, e->patched_bytecode, e->patched_size, pClassLinkage, ppVertexShader);
        LogShaderSwap(idx, "VS", e, BytecodeLength, hr);
        return hr;
    }
    return o_CreateVertexShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppVertexShader);
}

static HRESULT STDMETHODCALLTYPE hkCreatePixelShader(
    ID3D11Device* This, const void* pShaderBytecode, SIZE_T BytecodeLength,
    ID3D11ClassLinkage* pClassLinkage, ID3D11PixelShader** ppPixelShader) {
    size_t idx = 0;
    if (const auto* e = FindPatchedShader(JC4ShaderStage::PS, pShaderBytecode, BytecodeLength, &idx)) {
        HRESULT hr = o_CreatePixelShader(This, e->patched_bytecode, e->patched_size, pClassLinkage, ppPixelShader);
        LogShaderSwap(idx, "PS", e, BytecodeLength, hr);
        return hr;
    }
    return o_CreatePixelShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppPixelShader);
}

static HRESULT STDMETHODCALLTYPE hkCreateComputeShader(
    ID3D11Device* This, const void* pShaderBytecode, SIZE_T BytecodeLength,
    ID3D11ClassLinkage* pClassLinkage, ID3D11ComputeShader** ppComputeShader) {
    size_t idx = 0;
    if (const auto* e = FindPatchedShader(JC4ShaderStage::CS, pShaderBytecode, BytecodeLength, &idx)) {
        HRESULT hr = o_CreateComputeShader(This, e->patched_bytecode, e->patched_size, pClassLinkage, ppComputeShader);
        LogShaderSwap(idx, "CS", e, BytecodeLength, hr);
        return hr;
    }
    return o_CreateComputeShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppComputeShader);
}

static bool EnsureDeviceShaderHooks(ID3D11Device* dev) {
    if (!dev) return false;
    void** vtbl = *reinterpret_cast<void***>(dev);
    if (!vtbl) return false;

    EnterCriticalSection(&g_D3D11HookLock);
    auto hookSlot = [](void* target, void* detour, LPVOID* origOut, std::vector<void*>& seen, const char* label) {
        if (!target) return false;
        if (std::find(seen.begin(), seen.end(), target) != seen.end()) return true;
        LPVOID tmpOrig = nullptr;
        MH_STATUS st = MH_CreateHook(target, detour, &tmpOrig);
        if (st != MH_OK) {
            TerrainLog("[Terrain16x16] ERROR: MH_CreateHook(ID3D11Device::%s) -> %d", label, static_cast<int>(st));
            return false;
        }
        // One original per stage is valid only for one implementation target.
        // Never call a first device's trampoline for a different implementation.
        if (*origOut && *origOut != tmpOrig) {
            MH_RemoveHook(target);
            TerrainLog("[Terrain16x16] ERROR: multiple shader implementations for %s", label);
            return false;
        }
        const LPVOID previous = *origOut;
        *origOut = tmpOrig;
        st = MH_EnableHook(target);
        if (st != MH_OK) {
            *origOut = previous;
            MH_RemoveHook(target);
            TerrainLog("[Terrain16x16] ERROR: MH_EnableHook(ID3D11Device::%s) -> %d", label, static_cast<int>(st));
            return false;
        }
        seen.push_back(target); // publish only a successfully enabled hook
        TerrainLog("[Terrain16x16] Hooked ID3D11Device::%s at 0x%llx",
                   label, static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(target)));
        return true;
    };

    const bool ok = hookSlot(vtbl[12], reinterpret_cast<void*>(&hkCreateVertexShader),
             reinterpret_cast<LPVOID*>(&o_CreateVertexShader), g_HookedCreateVS, "CreateVertexShader") &&
        hookSlot(vtbl[15], reinterpret_cast<void*>(&hkCreatePixelShader),
             reinterpret_cast<LPVOID*>(&o_CreatePixelShader), g_HookedCreatePS, "CreatePixelShader") &&
        hookSlot(vtbl[18], reinterpret_cast<void*>(&hkCreateComputeShader),
             reinterpret_cast<LPVOID*>(&o_CreateComputeShader), g_HookedCreateCS, "CreateComputeShader");
    LeaveCriticalSection(&g_D3D11HookLock);
    return ok;
}

inline bool ActivateTerrain16x16ExePatchesAndHooks();

static HRESULT WINAPI hkD3D11CreateDevice(
    IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    ID3D11Device** ppDevice, D3D_FEATURE_LEVEL* pFeatureLevel, ID3D11DeviceContext** ppImmediateContext) {
    if (!ActivateTerrain16x16ExePatchesAndHooks()) {
        if (ppDevice) *ppDevice = nullptr;
        if (ppImmediateContext) *ppImmediateContext = nullptr;
        return E_FAIL; // never enter D3D with a partial CPU patch/hook transaction
    }
    HRESULT hr = o_D3D11CreateDevice(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                                     SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
    if (SUCCEEDED(hr) && ppDevice && *ppDevice) {
        if (!EnsureDeviceShaderHooks(*ppDevice)) {
            if (ppImmediateContext && *ppImmediateContext) { (*ppImmediateContext)->Release(); *ppImmediateContext = nullptr; }
            (*ppDevice)->Release(); *ppDevice = nullptr;
            return E_FAIL;
        }
    }
    return hr;
}

static HRESULT WINAPI hkD3D11CreateDeviceAndSwapChain(
    IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    const DXGI_SWAP_CHAIN_DESC* pSwapChainDesc, IDXGISwapChain** ppSwapChain,
    ID3D11Device** ppDevice, D3D_FEATURE_LEVEL* pFeatureLevel, ID3D11DeviceContext** ppImmediateContext) {
    if (!ActivateTerrain16x16ExePatchesAndHooks()) {
        if (ppSwapChain) *ppSwapChain = nullptr;
        if (ppDevice) *ppDevice = nullptr;
        if (ppImmediateContext) *ppImmediateContext = nullptr;
        return E_FAIL;
    }
    HRESULT hr = o_D3D11CreateDeviceAndSwapChain(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                                                 SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice,
                                                 pFeatureLevel, ppImmediateContext);
    if (SUCCEEDED(hr) && ppDevice && *ppDevice) {
        if (!EnsureDeviceShaderHooks(*ppDevice)) {
            if (ppSwapChain && *ppSwapChain) { (*ppSwapChain)->Release(); *ppSwapChain = nullptr; }
            if (ppImmediateContext && *ppImmediateContext) { (*ppImmediateContext)->Release(); *ppImmediateContext = nullptr; }
            (*ppDevice)->Release(); *ppDevice = nullptr;
            return E_FAIL;
        }
    }
    return hr;
}

struct CpuHookRecord {
    uintptr_t address;
    void* detour;
    void** original;
    const char* name;
    uint8_t signatureLength;
    uint8_t signature[16];
    bool created = false;
};

static bool VerifyHookSet(const CpuHookRecord* hooks, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        const auto& h = hooks[i];
        if (!h.address || !h.detour || !h.original ||
            !IsReadableRange(h.address, h.signatureLength ? h.signatureLength : 1) ||
            (h.signatureLength && memcmp(reinterpret_cast<const void*>(h.address), h.signature, h.signatureLength) != 0)) {
            TerrainLog("[Terrain16x16] ERROR: hook preflight failed: %s", h.name);
            return false;
        }
    }
    return true;
}

static bool PrecreateHookSet(CpuHookRecord* hooks, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        auto& h = hooks[i];
        const MH_STATUS st = MH_CreateHook(reinterpret_cast<void*>(h.address), h.detour, h.original);
        if (st == MH_OK) h.created = true;
        if (st != MH_OK || !*h.original) {
            TerrainLog("[Terrain16x16] ERROR: pre-create %s failed (%d)", h.name, static_cast<int>(st));
            return false;
        }
    }
    return true;
}

static bool EnableHookSet(CpuHookRecord* hooks, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        const auto& h = hooks[i];
        const MH_STATUS st = MH_QueueEnableHook(reinterpret_cast<void*>(h.address));
        if (st != MH_OK) {
            TerrainLog("[Terrain16x16] ERROR: queue-enable %s failed (%d)", h.name, static_cast<int>(st));
            return false;
        }
    }
    const MH_STATUS st = MH_ApplyQueued();
    if (st != MH_OK) {
        TerrainLog("[Terrain16x16] ERROR: apply queued hook set failed (%d)", static_cast<int>(st));
        return false;
    }
    return true;
}

static bool RemoveHookSet(CpuHookRecord* hooks, size_t count) {
    bool ok = true;
    while (count != 0) {
        auto& h = hooks[--count];
        if (!h.created) continue; // never touch another user's pre-existing hook
        const MH_STATUS disabled = MH_DisableHook(reinterpret_cast<void*>(h.address));
        if (disabled != MH_OK && disabled != MH_ERROR_DISABLED) {
            TerrainLog("[Terrain16x16] FATAL: disable rollback %s failed (%d)", h.name, static_cast<int>(disabled));
            ok = false;
        }
        // Removing the owned record also removes its pending queue-enable flag.
        const MH_STATUS removed = MH_RemoveHook(reinterpret_cast<void*>(h.address));
        if (removed != MH_OK) {
            TerrainLog("[Terrain16x16] FATAL: remove rollback %s failed (%d)", h.name, static_cast<int>(removed));
            ok = false;
        } else {
            h.created = false;
            *h.original = nullptr;
        }
    }
    return ok;
}

inline void InitTerrain16x16Hooks() {
    static SRWLOCK bootstrapLock = SRWLOCK_INIT;
    ScopedExclusiveSRW bootstrap(bootstrapLock);
    if (g_HooksInitialized) return;
    // Read the saved startup choice before D3D and all terrain allocations.
    // A later menu change only persists the next-launch choice.
    const auto terrainChoice = JC4TerrainSettings::GetSnapshot();
    if (!g_StartupModeReported) {
        EarlyResetLogFile();
        EarlyLog("[TerrainGrid] saved=%d startup=%d environmentOverride=%d (startup-only setting)",
                 terrainChoice.savedWidth, terrainChoice.startupWidth, terrainChoice.overrideWidth);
        g_StartupModeReported = true;
    }
    if (terrainChoice.startupWidth != 16) {
        JC4TerrainSettings::MarkActive(8);
        EarlyLog("[TerrainGrid] Stock 8x8 selected: expansion CPU/GPU hooks and patches skipped");
        return;
    }
    g_NativeBuild = IdentifyJC4NativeBuild(reinterpret_cast<uintptr_t>(GetModuleHandleA("JustCause4.exe")));
    if (g_NativeBuild == JC4NativeBuild::Unknown) {
        EarlyLog("[TerrainGrid] No matching native build profile; keeping stock terrain (no patches)");
        return;
    }
    EarlyLog("[TerrainGrid] Native profile: %s", g_NativeBuild == JC4NativeBuild::Epic ? "Epic" : "Steam");

    InitializeCriticalSection(&g_LogLock);
    g_LogLockInit = true;
    InitializeCriticalSection(&g_D3D11HookLock);
    g_D3D11HookLockInit = true;
    g_ConsoleReady = true;

    TerrainLog("[Terrain16x16] InitTerrain16x16Hooks (MainThread, hooking D3D11CreateDevice early)");

    MH_STATUS mh = MH_Initialize();
    if (mh != MH_OK && mh != MH_ERROR_ALREADY_INITIALIZED) {
        TerrainLog("[Terrain16x16] ERROR: MH_Initialize failed (%d)", static_cast<int>(mh));
        TerrainSafetyAbort("cannot install opt-in D3D startup guards");
    }

    HMODULE hD3D11 = GetModuleHandleA("d3d11.dll");
    if (!hD3D11) hD3D11 = LoadLibraryA("d3d11.dll");
    if (!hD3D11) TerrainSafetyAbort("cannot locate d3d11.dll startup guards");
    CpuHookRecord guards[] = {
        {reinterpret_cast<uintptr_t>(GetProcAddress(hD3D11, "D3D11CreateDevice")),
         reinterpret_cast<void*>(&hkD3D11CreateDevice), reinterpret_cast<void**>(&o_D3D11CreateDevice),
         "D3D11CreateDevice", 0, {}},
        {reinterpret_cast<uintptr_t>(GetProcAddress(hD3D11, "D3D11CreateDeviceAndSwapChain")),
         reinterpret_cast<void*>(&hkD3D11CreateDeviceAndSwapChain), reinterpret_cast<void**>(&o_D3D11CreateDeviceAndSwapChain),
         "D3D11CreateDeviceAndSwapChain", 0, {}}
    };
    const size_t count = sizeof(guards) / sizeof(guards[0]);
    if (!VerifyHookSet(guards, count) || !PrecreateHookSet(guards, count) || !EnableHookSet(guards, count)) {
        const bool cleaned = RemoveHookSet(guards, count);
        TerrainLog("[Terrain16x16] D3D startup guard rollback=%s", cleaned ? "OK" : "FAILED");
        TerrainSafetyAbort("D3D startup interception incomplete; cannot guarantee fail-closed activation");
    }
    g_HooksInitialized = true;
    TerrainLog("[Terrain16x16] Both D3D startup guards enabled; CPU activation remains deferred until device creation");
}

inline bool ActivateTerrain16x16ExePatchesAndHooks() {
    ScopedExclusiveSRW transaction(g_ActivationLock);
    if (g_ActivationState != 0) return g_ActivationState == 1;
    // Failure is latched before doing any work, including preparation. Concurrent
    // D3D entry points wait for this transaction; none can observe half-ready CPU state.
    g_ActivationState = -1;
    TerrainLog("[Terrain16x16] CPU activation transaction starting before D3D creation");
    if (!VerifyTerrain16x16StaticPatches()) {
        TerrainLog("[Terrain16x16] CPU preflight failed; D3D creation denied (no writes)");
        return false;
    }
    const uintptr_t typeGlobal = g_ExeBase + NativeRva(0x2cad8f0, 0x2cb3cb0);
    if (!IsReadableRange(typeGlobal, sizeof(uintptr_t)) || *reinterpret_cast<const uintptr_t*>(typeGlobal) != 0) {
        TerrainLog("[Terrain16x16] CPU activation is too late: a terrain Type already exists; D3D creation denied (no writes)");
        return false;
    }
    // Guarded implementation addresses catch both PDB thunks and direct calls.
    // Type::Create/destructor/free are native PDB bodies. All signatures were
    // read from loaded /JustCause4.exe, not inferred from prior documentation.
    CpuHookRecord hooks[] = {
        {g_ExeBase + NativeRva(0x79a0940, 0x441bac0), reinterpret_cast<void*>(&hkSetPatchStatus), reinterpret_cast<void**>(&o_SetPatchStatus),
         "SetPatchStatus", 6, {0x8b,0x05,0x8a,0x3d,0x14,0xfb}},
        {g_ExeBase + NativeRva(0x79a3630, 0x441f700), reinterpret_cast<void*>(&hkSetup), reinterpret_cast<void**>(&o_Setup),
         "Setup", 5, {0x48,0x89,0x5c,0x24,0x20}},
        {g_ExeBase + NativeRva(0xadfc200, 0x171225b0), reinterpret_cast<void*>(&hkLockBuffer), reinterpret_cast<void**>(&o_LockBuffer),
         "LockBuffer", 4, {0x49,0x89,0xe3,0x57}},
        {g_ExeBase + NativeRva(0xadfc9d0, 0x17123120), reinterpret_cast<void*>(&hkUnlockBuffer), reinterpret_cast<void**>(&o_UnlockBuffer),
         "UnlockBuffer", 5, {0x48,0x89,0x5c,0x24,0x18}},
        {g_ExeBase + NativeRva(0xadfa500, 0x1711e2a0), reinterpret_cast<void*>(&hkSetBufferData), reinterpret_cast<void**>(&o_SetBufferData),
         "SetBufferData", 16, {0x53,0x55,0x56,0x57,0x41,0x56,0x41,0x57,0x48,0x81,0xec,0x98,0,0,0,0x48}},
        {g_ExeBase + NativeRva(0x01a6d70, 0x01a7470), reinterpret_cast<void*>(&hkTypeCreate), reinterpret_cast<void**>(&o_TypeCreate),
         "Type::Create", 16, {0x40,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8d,0xac,0x24}},
        {g_ExeBase + NativeRva(0x796ddd0, 0x43da400), reinterpret_cast<void*>(&hkTypeDestroy), reinterpret_cast<void**>(&o_TypeDestroy),
         "Type::Destroy", 16, {0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57}},
        {g_ExeBase + NativeRva(0x019c320, 0x019c930), reinterpret_cast<void*>(&hkTypeDtor), reinterpret_cast<void**>(&o_TypeDtor),
         "Type destructor", 16, {0x40,0x53,0x48,0x83,0xec,0x30,0x48,0xc7,0x44,0x24,0x20,0xfe,0xff,0xff,0xff,0x48}},
        {g_ExeBase + NativeRva(0x01cc610, 0x01cd000), reinterpret_cast<void*>(&hkSystemFree), reinterpret_cast<void**>(&o_SystemFree),
         "TerrainPatchSystemFree", 16, {0x40,0x57,0x48,0x83,0xec,0x30,0x48,0xc7,0x44,0x24,0x20,0xfe,0xff,0xff,0xff,0x48}},
        {g_ExeBase + NativeRva(0xa9d5360, 0x16f1a970), reinterpret_cast<void*>(&hkCreateRangeID), reinterpret_cast<void**>(&o_CreateRangeID),
         "SIDAllocator::CreateRangeID", 16, {0x53,0x48,0x83,0xec,0x20,0x48,0x8b,0x19,0x49,0x89,0xca,0x31,0xc0,0x66,0x90,0x44}},
        {g_ExeBase + NativeRva(0xa9d5990, 0x16f1ac60), reinterpret_cast<void*>(&hkDestroyRangeID), reinterpret_cast<void**>(&o_DestroyRangeID),
         "SIDAllocator::DestroyRangeID", 16, {0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57}},
        {g_ExeBase + NativeRva(0xa9dbac0, 0x16f236c0), reinterpret_cast<void*>(&hkSetupVegSamplingBlock), reinterpret_cast<void**>(&o_SetupVegSamplingBlock),
         "Vegetation SetupRenderBlock", 12, {0x48,0x89,0x5c,0x24,0x10,0x55,0x56,0x57,0x48,0x83,0xec,0x40}}
    };
    if (g_NativeBuild == JC4NativeBuild::Epic) {
        constexpr uint8_t statusSig[] = {0x8b,0x05,0x62,0xf6,0x6c,0xfe};
        memcpy(hooks[0].signature, statusSig, sizeof(statusSig));
        // Epic encodes PUSH RBX with an extra REX prefix at these two native entries.
        for (const size_t index : {size_t{4}, size_t{9}}) {
            memmove(hooks[index].signature + 1, hooks[index].signature, 15);
            hooks[index].signature[0] = 0x40;
        }
    }
    constexpr uint8_t getSizeSig[] = {0x8b,0x41,0x14,0x0f,0xaf,0x41,0x10,0xc3};
    const auto getSize = g_ExeBase + NativeRva(0x0ad80170, 0x170f4740);
    if (!IsReadableRange(getSize, sizeof(getSizeSig)) ||
        memcmp(reinterpret_cast<const void*>(getSize), getSizeSig, sizeof(getSizeSig)) != 0) {
        TerrainLog("[Terrain16x16] ERROR: GetBufferSize body preflight failed (no writes)");
        return false;
    }
    constexpr uint8_t vegStockIndexSig[] = {
        0x0f,0xbf,0x4b,0x12, 0x0f,0xbf,0x43,0x10, 0x83,0xe1,0x07, 0x83,0xe0,0x07,
        0x8d,0x04,0xc8, 0x89,0x87,0xb8,0x00,0x00,0x00
    };
    const auto vegStockIndex = g_ExeBase + NativeRva(0xa9dbb69, 0x16f23769);
    if (!IsReadableRange(vegStockIndex, sizeof(vegStockIndexSig)) ||
        memcmp(reinterpret_cast<const void*>(vegStockIndex), vegStockIndexSig, sizeof(vegStockIndexSig)) != 0) {
        TerrainLog("[Terrain16x16] ERROR: vegetation metadata producer preflight failed (no writes)");
        return false;
    }
    const size_t count = sizeof(hooks) / sizeof(hooks[0]);
    if (!VerifyHookSet(hooks, count) || !PrecreateHookSet(hooks, count) ||
        !ApplyTerrain16x16StaticPatches() || !EnableHookSet(hooks, count)) {
        const bool hooksRestored = RemoveHookSet(hooks, count);
        const bool bytesRestored = RollbackTerrain16x16StaticPatches();
        TerrainLog("[Terrain16x16] CPU activation FAILED: hook rollback=%s byte rollback=%s; all D3D creation denied",
                   hooksRestored ? "OK" : "FAILED", bytesRestored ? "OK" : "FAILED");
        return false;
    }
    g_StaticPatchesApplied = true; // also gates existing shader substitution until CPU is coherent
    g_ActivationState = 1;
    JC4TerrainSettings::MarkActive(16);
    TerrainLog("[Terrain16x16] CPU activation READY: %zu static patches + Construct + %zu checked hooks; quadIDs=20bit palettes=4x stock",
               sizeof(kStaticBytePatches) / sizeof(kStaticBytePatches[0]), count);
    return true;
}

} // namespace JC4Terrain16x16
