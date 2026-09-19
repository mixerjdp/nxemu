# NxEmu

NxEmu is a free, open-source Nintendo Switch emulator for Windows, written in C++.

## Installation

The latest stable releases are available [here](https://www.nxemu.com/downloads.html).

## Building

```bash
git clone --recursive https://github.com/N3xoX1/nxemu.git
```

Open `nxemu.sln` in **Visual Studio** and build the **x64** configuration.

Encrypted `.xci` and `.nsp` dumps are supported. Keys are read from
`bin\x64\Release\user\keys\prod.keys` (and `title.keys` if present), or from the
directory pointed to by the `NXEMU_KEYS_DIR` environment variable.

## Testing

Build **Release|x64** first; the loader tests link against its object files.

```powershell
# Crypto unit tests, corrupted-container checks, plus a real ROM probe:
# decrypts the container, its embedded update (BKTR) and control metadata.
tests\run-loader-tests.ps1 -Rom "path\to\game.xci-or-.nsp"

# 20-second runtime smoke test: boots the game with the real modules and
# reports EmulationRunning/DisplayedFrames.
tests\run-loader-tests.ps1 -Runtime -Rom "path\to\game.xci-or-.nsp"
```

## Contributing

Contributions are welcome via pull requests.

## Links

- [Website](https://www.nxemu.com)
- [About](https://www.nxemu.com/about.html)
- [Discord](https://discord.gg/hEa4hNyFWU)

## License

NxEmu is licensed under the [GNU General Public License v3.0](./license.txt).
