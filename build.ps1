param([switch]$RebuildDependencies)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$out = Join-Path $here 'dist'
$build = Join-Path $here 'build'

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

Push-Location -LiteralPath $here
try {
    $compiler = (Get-Command g++ -ErrorAction Stop).Source
    $machine = (& $compiler -dumpmachine).Trim()
    if ($LASTEXITCODE -ne 0 -or $machine -notlike 'x86_64*mingw*') {
        throw "Use 64-bit MinGW-w64 g++; detected: $machine"
    }
    $required = @('mod.cpp','addresses.cpp','addresses.h','winmm_proxy.cpp','winmm_proxy.s','winmm_proxy.def',
                  'terrain_expand.hpp','terrain_settings.hpp','jc4_dxbc_patches.hpp','ultrafastload.hpp')
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
    New-Item -ItemType Directory -Force -Path $out,$build | Out-Null
    $dependencies = Join-Path $here 'libdeps.a'
    $rebuiltDependencies = $false
    if ($RebuildDependencies -or !(Test-Path -LiteralPath $dependencies)) {
        $rebuiltDependencies = $true
        $depDir = Join-Path $build 'deps'
        New-Item -ItemType Directory -Force -Path $depDir | Out-Null
        $gcc = (Get-Command gcc -ErrorAction Stop).Source
        $ar = (Get-Command ar -ErrorAction Stop).Source
        $cFiles = @('minhook/src/buffer.c','minhook/src/hook.c','minhook/src/trampoline.c','minhook/src/hde/hde64.c')
        $cppFiles = @('imgui/imgui.cpp','imgui/imgui_draw.cpp','imgui/imgui_tables.cpp','imgui/imgui_widgets.cpp',
                      'imgui/backends/imgui_impl_win32.cpp','imgui/backends/imgui_impl_dx11.cpp')
        $objects = @()
        foreach ($file in $cFiles + $cppFiles) {
            $object = Join-Path $depDir ((($file -replace '[/.]','_')) + '.o')
            $program = if ($file.EndsWith('.c')) { $gcc } else { $compiler }
            $arguments = @('-c',$file,'-o',$object,'-I.','-Iimgui','-Iimgui/backends','-Iminhook/include','-Iminhook/src','-O2')
            Invoke-Checked $program $arguments
            $objects += $object
        }
        # Exact object list: never accidentally archive old *.o files.
        $dependencies = Join-Path $depDir 'libdeps.a'
        Invoke-Checked $ar (@('rcs',$dependencies) + $objects)
    }
    $temporary = Join-Path $out 'winmm.build.dll'
    $arguments = @('-shared','-o',$temporary,'mod.cpp','addresses.cpp','winmm_proxy.cpp','winmm_proxy.s',
                   '-Wl,winmm_proxy.def',$dependencies,'-I.','-Iimgui','-Iimgui/backends','-Iminhook/include',
                   '-Wno-attributes','-ld3d11','-ld3dcompiler','-ldwmapi','-luser32','-lgdi32','-static','-O1')
    Invoke-Checked $compiler $arguments
    $result = Join-Path $out 'winmm.dll'
    Move-Item -LiteralPath $temporary -Destination $result -Force
    $inputHashes = @($required + @('build.ps1') + @($dependencies)) | ForEach-Object {
        $p = if ([IO.Path]::IsPathRooted($_)) { $_ } else { Join-Path $here $_ }
        $h = Get-FileHash -LiteralPath $p -Algorithm SHA256
        [ordered]@{Path=$h.Path;SHA256=$h.Hash.ToLowerInvariant()}
    }
    $hash = (Get-FileHash -LiteralPath $result -Algorithm SHA256).Hash.ToLowerInvariant()
    [ordered]@{
        Output=$result;SHA256=$hash;Compiler=$compiler;Target=$machine;
        CompilerVersion=(& $compiler -dumpfullversion);RebuiltDependencies=$rebuiltDependencies;
        ShaderKeys=$shaderKeys;OptionalAltitudeShaderVariants=2;InstalledIntoGame=$false;
        BuiltAtUtc=[DateTime]::UtcNow.ToString('o');Inputs=@($inputHashes)
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'build-manifest.json') -Encoding UTF8
    Write-Host "Built: $result"
    Write-Host "SHA-256: $hash"
    Write-Host 'The game directory was not changed. Close the game before installing the DLL.'
	Write-Host 'Press any key to exit...' -NoNewline; $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
} finally { Pop-Location }
