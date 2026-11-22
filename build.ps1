param([switch]$RebuildDependencies)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$out = Join-Path $here 'dist'
$build = Join-Path $here 'build'

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

function Write-Step([int]$Index, [int]$Total, [string]$Message) {
    Write-Host "[$Index/$Total] $Message"
}

Push-Location -LiteralPath $here
try {
    $totalSteps = 5

    Write-Step 1 $totalSteps 'Checking 64-bit MinGW-w64 toolchain and required system libraries...'
    $compilerCmd = Get-Command g++ -ErrorAction SilentlyContinue
    if (!$compilerCmd) {
        throw 'g++ not found on PATH. Install 64-bit MinGW-w64 (e.g. MSYS2 mingw-w64-x86_64-gcc or WinLibs).'
    }
    $compiler = $compilerCmd.Source
    $machine = (& $compiler -dumpmachine).Trim()
    if ($LASTEXITCODE -ne 0 -or $machine -notlike 'x86_64*mingw*') {
        throw "Use 64-bit MinGW-w64 g++; detected: $machine"
    }
    foreach ($tool in @('gcc','ar')) {
        if (!(Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "$tool not found on PATH. Install the full 64-bit MinGW-w64 toolchain (g++, gcc, ar)."
        }
    }
    $requiredLibs = @('libd3d11.a','libd3dcompiler.a','libdwmapi.a','libuser32.a','libgdi32.a','libstdc++.a')
    foreach ($lib in $requiredLibs) {
        $resolvedLib = (& $compiler "-print-file-name=$lib").Trim()
        if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $resolvedLib -PathType Leaf)) {
            throw "Required MinGW library '$lib' was not found ($resolvedLib). Check your MinGW-w64 installation."
        }
    }
    $compilerVersion = (& $compiler -dumpfullversion).Trim()
    Write-Host "      g++ $compilerVersion ($machine) + gcc/ar + $($requiredLibs.Count) system libraries OK"

    Write-Step 2 $totalSteps 'Validating source files and embedded shader bytecode...'
    $required = @('mod.cpp','addresses.cpp','addresses.h','winmm_proxy.cpp','winmm_proxy.s','winmm_proxy.def',
                  'terrain_expand.hpp','terrain_settings.hpp','jc4_dxbc_patches.hpp','ultrafastload.hpp','spawn_hints.inc')
    foreach ($file in $required) {
        if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing build input: $file" }
    }
    $header = [IO.File]::ReadAllText((Join-Path $here 'jc4_dxbc_patches.hpp'))
    $shaderKeys = [regex]::Matches($header,'JC4ShaderStage::(?:VS|PS|CS)\s*,').Count
    if ($shaderKeys -ne 38 -or !$header.Contains('kAltitudeChildMaskDXBC') -or !$header.Contains('kAltitudeClassifierDXBC')) {
        throw 'The complete 38-key terrain header and both LOD-9 shader variants are required.'
    }
    if (![IO.File]::ReadAllText((Join-Path $here 'mod.cpp')).Contains('#include "terrain_expand.hpp"')) {
        throw 'mod.cpp is not the integrated LOD-9 source. Do not build an archived source variant.'
    }
    Write-Host "      Verified $($required.Count) inputs and $shaderKeys shader keys (+2 altitude variants)."
    New-Item -ItemType Directory -Force -Path $out,$build | Out-Null

    $dependencies = Join-Path $here 'libdeps.a'
    $rebuiltDependencies = $false
    if ($RebuildDependencies -or !(Test-Path -LiteralPath $dependencies)) {
        $reason = if ($RebuildDependencies) { '-RebuildDependencies requested' } else { 'libdeps.a not found' }
        Write-Step 3 $totalSteps "Building MinHook and Dear ImGui static archive ($reason)..."
        $rebuiltDependencies = $true
        $depDir = Join-Path $build 'deps'
        New-Item -ItemType Directory -Force -Path $depDir | Out-Null
        $gcc = (Get-Command gcc -ErrorAction Stop).Source
        $ar = (Get-Command ar -ErrorAction Stop).Source
        $cFiles = @('minhook/src/buffer.c','minhook/src/hook.c','minhook/src/trampoline.c','minhook/src/hde/hde64.c')
        $cppFiles = @('imgui/imgui.cpp','imgui/imgui_draw.cpp','imgui/imgui_tables.cpp','imgui/imgui_widgets.cpp',
                      'imgui/backends/imgui_impl_win32.cpp','imgui/backends/imgui_impl_dx11.cpp')
        $depFiles = $cFiles + $cppFiles
        $objects = @()
        for ($i = 0; $i -lt $depFiles.Count; $i++) {
            $file = $depFiles[$i]
            Write-Host "      ($($i + 1)/$($depFiles.Count)) Compiling $file"
            $object = Join-Path $depDir ((($file -replace '[/.]','_')) + '.o')
            $program = if ($file.EndsWith('.c')) { $gcc } else { $compiler }
            $arguments = @('-c',$file,'-o',$object,'-I.','-Iimgui','-Iimgui/backends','-Iminhook/include','-Iminhook/src','-O2')
            Invoke-Checked $program $arguments
            $objects += $object
        }
        # Exact object list: never accidentally archive old *.o files.
        $dependencies = Join-Path $depDir 'libdeps.a'
        Write-Host "      Archiving $dependencies"
        Invoke-Checked $ar (@('rcs',$dependencies) + $objects)
    } else {
        Write-Step 3 $totalSteps "Using prebuilt dependency archive: $dependencies"
    }

    Write-Step 4 $totalSteps 'Compiling and linking dist\winmm.dll (mod.cpp, addresses.cpp, winmm_proxy)...'
    $temporary = Join-Path $out 'winmm.build.dll'
    $arguments = @('-shared','-o',$temporary,'mod.cpp','addresses.cpp','winmm_proxy.cpp','winmm_proxy.s',
                   '-Wl,winmm_proxy.def',$dependencies,'-I.','-Iimgui','-Iimgui/backends','-Iminhook/include',
                   '-Wno-attributes','-ld3d11','-ld3dcompiler','-ldwmapi','-luser32','-lgdi32','-static','-O1')
    Invoke-Checked $compiler $arguments
    $result = Join-Path $out 'winmm.dll'
    Move-Item -LiteralPath $temporary -Destination $result -Force

    Write-Step 5 $totalSteps 'Computing SHA-256 hashes and writing dist\build-manifest.json...'
    $inputHashes = @($required + @('build.ps1') + @($dependencies)) | ForEach-Object {
        $p = if ([IO.Path]::IsPathRooted($_)) { $_ } else { Join-Path $here $_ }
        $h = Get-FileHash -LiteralPath $p -Algorithm SHA256
        [ordered]@{Path=$h.Path;SHA256=$h.Hash.ToLowerInvariant()}
    }
    $hash = (Get-FileHash -LiteralPath $result -Algorithm SHA256).Hash.ToLowerInvariant()
    [ordered]@{
        Output=$result;SHA256=$hash;Compiler=$compiler;Target=$machine;
        CompilerVersion=$compilerVersion;RebuiltDependencies=$rebuiltDependencies;
        ShaderKeys=$shaderKeys;OptionalAltitudeShaderVariants=2;InstalledIntoGame=$false;
        BuiltAtUtc=[DateTime]::UtcNow.ToString('o');Inputs=@($inputHashes)
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'build-manifest.json') -Encoding UTF8
    Write-Host "Built: $result"
    Write-Host "SHA-256: $hash"
    Write-Host 'The game directory was not changed. Close the game before installing the DLL.'
    if (![Console]::IsInputRedirected) {
        Write-Host 'Press any key to exit...' -NoNewline
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
} finally { Pop-Location }
