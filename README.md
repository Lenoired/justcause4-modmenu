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
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

What `build.ps1` does:
1. Verifies `g++ -dumpmachine` reports `x86_64*mingw*`.
2. Checks required inputs (`mod.cpp`, `addresses.cpp`, `addresses.h`, `winmm_proxy.cpp`, `winmm_proxy.s`, `winmm_proxy.def`, `terrain_expand.hpp`, `terrain_settings.hpp`, `jc4_dxbc_patches.hpp`, `ultrafastload.hpp`).
3. Links against `libdeps.a` if present; otherwise compiles `imgui/` and `minhook/` into `build\deps\libdeps.a`.
4. Outputs **`dist\winmm.dll`** and a build receipt at **`dist\build-manifest.json`** (never modifies the game directory).

To force rebuilding `imgui/` and `minhook/` from source into `build\deps\libdeps.a` (without overwriting a pre-existing root `libdeps.a`):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -RebuildDependencies
```

