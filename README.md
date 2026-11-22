Mod menu for **Just Cause 4** (Steam & Epic Games).

## Installation
1. Download `winmm.dll` from [**Releases**](../../releases/latest) (or build `dist\winmm.dll` from source).
3. Copy **`winmm.dll`** into the directory containing `JustCause4.exe`:
   - **Steam:** Steam Library → right-click *Just Cause 4* → **Manage → Browse local files**.
   - **Epic Games:** Epic Games Library → *Just Cause 4* → **Manage → Installation → Open Install Location**.

### Runtime Notes
- **Configuration file:** Settings are persisted in `modmenu_jc4.ini` beside `JustCause4.exe`. Default menu toggle key is `ToggleKey=113` (`VK_F2`; Windows virtual-key code).
- **Crash dumps:** Unhandled fatal exceptions (`ACCESS_VIOLATION`, `ILLEGAL_INSTRUCTION`, `STACK_OVERFLOW`, `INT_DIVIDE_BY_ZERO`, `PRIV_INSTRUCTION`) are logged to `crash_dump.log` next to `JustCause4.exe`.
- **Uninstall:** Remove `winmm.dll` (and optionally `modmenu_jc4.ini`) from the game directory.
---
## Build Instructions

### Prerequisites

- **OS:** Windows (x64)
- **Toolchain:** 64-bit MinGW-w64 (`g++`, `gcc`, `ar` targeting `x86_64-w64-mingw32`) on `PATH` (e.g., MSYS2 `mingw-w64-x86_64-gcc` or WinLibs)
- **PowerShell** 

No external game files are required to compile `winmm.dll`.

---

### Automated Build (`build.ps1`)

From the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

What `build.ps1` does:
1. Verifies 64-bit MinGW-w64 (`g++`, `gcc`, `ar` targeting `x86_64*mingw*`) and required Windows import/runtime libraries (`d3d11`, `d3dcompiler`, `dwmapi`, `user32`, `gdi32`, `stdc++`).
2. Checks required inputs (`mod.cpp`, `addresses.cpp`, `addresses.h`, `winmm_proxy.cpp`, `winmm_proxy.s`, `winmm_proxy.def`, `terrain_expand.hpp`, `terrain_settings.hpp`, `jc4_dxbc_patches.hpp`, `ultrafastload.hpp`, `spawn_hints.inc`).
3. Links against `libdeps.a` if present; otherwise compiles `imgui/` and `minhook/` into `build\deps\libdeps.a`.
4. Outputs **`dist\winmm.dll`** and a build receipt at **`dist\build-manifest.json`** (never modifies the game directory).

To force rebuilding `imgui/` and `minhook/` from source into `build\deps\libdeps.a` (without overwriting a pre-existing root `libdeps.a`):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -RebuildDependencies
```

---

### Manual Build

Requires 64-bit MinGW-w64 (`g++`) on `PATH`. From the repository root in PowerShell:

```powershell
New-Item -ItemType Directory -Force dist | Out-Null
g++ -shared -o dist/winmm.dll mod.cpp addresses.cpp winmm_proxy.cpp winmm_proxy.s "-Wl,winmm_proxy.def" imgui/imgui.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp imgui/backends/imgui_impl_win32.cpp imgui/backends/imgui_impl_dx11.cpp minhook/src/buffer.c minhook/src/hook.c minhook/src/trampoline.c minhook/src/hde/hde64.c -I. -Iimgui -Iimgui/backends -Iminhook/include -Iminhook/src -Wno-attributes -ld3d11 -ld3dcompiler -ldwmapi -luser32 -lgdi32 -static -O1
```

If you already built `build\deps\libdeps.a` (or have `libdeps.a` at the root), you can pass that archive instead of the `imgui/` and `minhook/` source files.

