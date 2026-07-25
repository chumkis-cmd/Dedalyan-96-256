# build.ps1 -- сборка C-части Dedalyan.
#
# Собирает:
#   build/dedalyan.dll        -- шифр + аналитические ядра, для ctypes
#   build/test_vectors.exe    -- проверка векторов раздела 8
#   build/bench.exe           -- замер циклов на байт
#
# Компилятор ищется в порядке: MSVC (vswhere / известные пути), clang, gcc.
# Запуск:  powershell -ExecutionPolicy Bypass -File build.ps1
#          powershell -ExecutionPolicy Bypass -File build.ps1 -Clean

param(
    [switch]$Clean,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $MyInvocation.MyCommand.Path
$src   = Join-Path $root 'c'
$build = Join-Path $root 'build'

function Say($msg) { if (-not $Quiet) { Write-Host $msg } }

if ($Clean) {
    if (Test-Path $build) { Remove-Item -Recurse -Force $build }
    Say "Cleaned $build"
    if (-not $PSBoundParameters.ContainsKey('Clean')) { return }
}

foreach ($d in @($build, "$build\obj\dll", "$build\obj\tv", "$build\obj\bench")) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}

# --- поиск MSVC ------------------------------------------------------------

function Find-VcVars {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $inst = & $vswhere -latest -products * `
                    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                    -property installationPath 2>$null
        if (-not $inst) { $inst = & $vswhere -latest -products * -property installationPath 2>$null }
        if ($inst) {
            $vc = Join-Path $inst 'VC\Auxiliary\Build\vcvars64.bat'
            if (Test-Path $vc) { return $vc }
        }
    }
    foreach ($p in @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    )) { if (Test-Path $p) { return $p } }
    return $null
}

$vcvars = Find-VcVars

if ($vcvars) {
    Say "Compiler: MSVC ($vcvars)"
    # vswhere.exe может отсутствовать в PATH внутри vcvars -- это не мешает сборке.
    # /Fo с несколькими исходниками требует каталог: путь обязан
    # заканчиваться разделителем, а перед закрывающей кавычкой он удваивается.
    $cmds = @(
        "cl /nologo /O2 /W3 /std:c11 /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DDEDALYAN_BUILD_DLL /LD dedalyan.c kernels.c gcm.c /Fo`"$build\obj\dll\\`" /Fe`"$build\dedalyan.dll`" /link /IMPLIB:`"$build\dedalyan.lib`"",
        "cl /nologo /O2 /W3 /std:c11 /DNDEBUG /D_CRT_SECURE_NO_WARNINGS dedalyan.c kernels.c test_vectors.c /Fo`"$build\obj\tv\\`" /Fe`"$build\test_vectors.exe`"",
        "cl /nologo /O2 /W3 /std:c11 /DNDEBUG /D_CRT_SECURE_NO_WARNINGS dedalyan.c kernels.c bench.c /Fo`"$build\obj\bench\\`" /Fe`"$build\bench.exe`""
    )
    # Только "&&": цепочка обрывается на первой ошибке, код возврата
    # приходит от упавшей команды. Смесь "||" и "&&" в cmd ведёт себя иначе.
    $script = $cmds -join " && "
    $full = "call `"$vcvars`" >nul 2>&1 && cd /d `"$src`" && $script"
    $out = cmd /c $full
    if ($LASTEXITCODE -ne 0) {
        $out | Write-Host
        throw "MSVC build failed (exit $LASTEXITCODE)"
    }
    if (-not $Quiet) { $out | Where-Object { $_ -match 'error|warning' } | Write-Host }
}
else {
    $cc = $null
    foreach ($c in @('clang', 'gcc')) {
        if (Get-Command $c -ErrorAction SilentlyContinue) { $cc = $c; break }
    }
    if (-not $cc) {
        throw "No C compiler found. Install Visual Studio Build Tools, or put clang/gcc on PATH."
    }
    Say "Compiler: $cc"
    $flags = @('-O3', '-std=c11', '-Wall', '-Wextra', '-DNDEBUG')

    # Имя разделяемой библиотеки зависит от платформы, и dedalyan_c.py ищет
    # именно его: на Linux libdedalyan.so, на macOS libdedalyan.dylib.
    # Собрать .dll под Linux -- значит собрать то, что никто не найдёт.
    if ($IsWindows -or $null -eq $IsWindows) {   # $IsWindows нет в PS 5.1
        $lib = 'dedalyan.dll'
        $pic = @()
    } elseif ($IsMacOS) {
        $lib = 'libdedalyan.dylib'
        $pic = @('-fPIC')
    } else {
        $lib = 'libdedalyan.so'
        $pic = @('-fPIC')
    }

    & $cc @flags @pic -shared -DDEDALYAN_BUILD_DLL `
        (Join-Path $src 'dedalyan.c') (Join-Path $src 'kernels.c') (Join-Path $src 'gcm.c') `
        -o (Join-Path $build $lib)
    if ($LASTEXITCODE -ne 0) { throw "shared library build failed" }
    & $cc @flags -I$src (Join-Path $src 'dedalyan.c') (Join-Path $src 'kernels.c') (Join-Path $src 'gcm.c') `
        (Join-Path $src 'test_vectors.c') -o (Join-Path $build 'test_vectors.exe')
    if ($LASTEXITCODE -ne 0) { throw "test_vectors build failed" }
    & $cc @flags -I$src (Join-Path $src 'dedalyan.c') (Join-Path $src 'kernels.c') (Join-Path $src 'gcm.c') `
        (Join-Path $src 'bench.c') -o (Join-Path $build 'bench.exe')
    if ($LASTEXITCODE -ne 0) { throw "bench build failed" }
}

Get-ChildItem $build -File |
    Where-Object { $_.Extension -in '.dll', '.exe', '.so', '.dylib' -or
                   $_.Name -in 'test_vectors', 'bench' } |
    ForEach-Object { Say ("  {0,-24} {1,10:N0} bytes" -f $_.Name, $_.Length) }

Say ""
Say "Build OK. Next:"
Say "  build\test_vectors.exe"
Say "  python tests\run_all.py"
