param([string]$Rom, [switch]$Runtime)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!(Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $environmentLines = & $env:ComSpec /d /c "`"$vs\Common7\Tools\VsDevCmd.bat`" -arch=x64 -host_arch=x64 >nul && set"
    if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the MSVC environment.' }
    foreach ($line in $environmentLines) {
        if ($line -match '^([^=]+)=(.*)$' -and $Matches[1] -notin @('HOME','CODEX_HOME')) {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }
}
$out = Join-Path $repo 'bin\x64\Release'
if ($Runtime) {
    if (!$Rom) { throw '-Runtime requires -Rom.' }
    $libs = @('nxemu-core','common','yuzu_common','fmt') | ForEach-Object { Join-Path $out "lib\$_.lib" }
    $includes = @('src','src\3rd_party','external\fmt\include','external\boost') | ForEach-Object { '/I' + (Join-Path $repo $_) }
    & cl.exe /nologo /std:c++20 /EHsc /MT /O2 /DNOMINMAX /DWIN32 /D_WIN32 /DBOOST_ALL_NO_LIB @includes (Join-Path $PSScriptRoot 'runtime_smoke.cpp') "/Fo$out\runtime_smoke.obj" "/Fe$out\runtime_smoke.exe" /link /OPT:REF /INCREMENTAL:NO @libs shell32.lib ole32.lib user32.lib advapi32.lib ws2_32.lib shlwapi.lib
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if (!$env:NXEMU_KEYS_DIR) { $env:NXEMU_KEYS_DIR = Join-Path $out 'user\keys' }
    $scratch = Join-Path $repo ('build\runtime-smoke-' + [guid]::NewGuid().ToString('N'))
    # Windows chooses portable data relative to the process executable, not AppInit's directory.
    $scratchUser = Join-Path $scratch 'user'
    New-Item -ItemType Directory -Path $scratchUser -Force | Out-Null
    Copy-Item -LiteralPath "$out\runtime_smoke.exe" -Destination $scratch
    Get-ChildItem -LiteralPath $out -Filter '*.dll' | Copy-Item -Destination $scratch
    Write-Host "Isolated runtime data and log: $scratchUser"
    & "$scratch\runtime_smoke.exe" $repo $scratchUser $Rom
    exit $LASTEXITCODE
}
$objects = @(Get-ChildItem (Join-Path $repo 'build\x64\Release\nxemu-loader') -Filter '*.obj' | ForEach-Object FullName)
if (!$objects.Count) { throw 'Build Release x64 nxemu.sln first.' }
$libs = @('common','yuzu_common','fmt','lz4','zlib') | ForEach-Object { Join-Path $out "lib\$_.lib" }
$includes = @('src','src\nxemu-loader','src\3rd_party','external\fmt\include','external\boost','external\openssl\include') | ForEach-Object { '/I' + (Join-Path $repo $_) }
& cl.exe /nologo /std:c++20 /EHsc /MT /O2 /DNOMINMAX /DWIN32 /D_WIN32 /D_CRT_SECURE_NO_WARNINGS /DBOOST_ALL_NO_LIB @includes (Join-Path $PSScriptRoot 'loader_crypto_tests.cpp') "/Fo$out\loader_crypto_tests.obj" "/Fe$out\loader_crypto_tests.exe" /link /OPT:REF /INCREMENTAL:NO @objects @libs (Join-Path $repo 'external\openssl\lib\libcrypto.lib') shell32.lib ole32.lib user32.lib advapi32.lib ws2_32.lib shlwapi.lib
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($Rom) { & "$out\loader_crypto_tests.exe" $Rom } else { & "$out\loader_crypto_tests.exe" }
exit $LASTEXITCODE
