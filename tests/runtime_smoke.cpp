// SPDX-License-Identifier: GPL-3.0-or-later
// Exercises the actual DLLs, not copies of the loader's object files.
#include <windows.h>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <cstdlib>
#include <iostream>
#include <process.h>
#include <thread>
#include <nxemu-core/app_init.h>
#include <nxemu-core/notification.h>
#include <nxemu-core/modules/system_modules.h>
#include <nxemu-core/settings/settings.h>
#include <nxemu-core/settings/identifiers.h>
#include <nxemu-module-spec/system_loader.h>

struct Notifications final : INotification {
    void DisplayError(const char* message, const char* title) const override {
        std::cerr << title << ": " << message << std::endl;
    }
    NotificationResponse Query(const char*, const char*) const override { return NotificationResponse::No; }
    void BreakPoint(const char* file, uint32_t line) override {
        std::cerr << "BREAKPOINT: " << file << ':' << line << std::endl;
    }
};
struct Window final : IRenderWindow {
    HWND handle{};
    std::atomic<unsigned> frames{};
    void* RenderSurface() const override { return handle; }
    void* DisplayConnection() const override { return nullptr; }
    RenderWindowSystem WindowSystem() const override { return RenderWindowSystem::Windows; }
    float PixelRatio() const override { return 1.0f; }
    void OnFramePresented(void*, uint32_t) override { ++frames; }
};
int main(int argc, char** argv) {
    if (argc != 4) { std::cerr << "Usage: runtime_smoke <repo> <isolated-user-dir> <rom>\n"; return 2; }
    // Emulation can deadlock inside guest services; bound the whole run.
    std::thread([] {
        std::this_thread::sleep_for(std::chrono::seconds(90));
        std::cerr << "TIMEOUT: emulation did not complete the smoke window\n";
        TerminateProcess(GetCurrentProcess(), 6);
    }).detach();
    std::cout << std::unitbuf;
    const auto repo = std::filesystem::path(argv[1]);
    std::filesystem::create_directories(argv[2]);
    Notifications notify;
    SetNotification(&notify);
    if (!AppInit((repo / "bin/x64/Release").string().c_str(), argv[2])) return 3;
    auto& settings = SettingsStore::GetInstance();
    settings.SetString(NXCoreSetting::ModuleDirectory, (repo / "modules/x64").string().c_str());
    const auto instance = GetModuleHandle(nullptr);
    WNDCLASSW wc{}; wc.lpfnWndProc = DefWindowProcW; wc.hInstance = instance; wc.lpszClassName = L"NxEmuXciSmoke";
    RegisterClassW(&wc);
    Window window;
    window.handle = CreateWindowW(wc.lpszClassName, L"NxEmu XCI smoke test", WS_OVERLAPPEDWINDOW,
        0, 0, 1280, 720, nullptr, nullptr, instance, nullptr); // hidden test surface
    int result = 4;
    {
        SystemModules modules;
        modules.Setup(window);
        std::cout << "Modules valid=" << modules.IsValid() << std::endl;
        if (modules.IsValid()) {
            settings.SetBool("nxloader:CheckForUpdatedFirmware", false);
            if (const char* filter = std::getenv("NXEMU_LOG_FILTER"))
                settings.SetString(NXCoreSetting::LogFilter, filter);
            const bool loaded = modules.Modules().Systemloader().LoadRom(argv[3], 0, 0, -1, ApplicationLaunchType::FrontendInitiated);
            std::cout << "LoadRom=" << loaded << std::endl;
            if (loaded) {
                const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(20);
                while (std::chrono::steady_clock::now() < until) {
                    MSG message;
                    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&message); DispatchMessageW(&message); }
                    Sleep(10);
                }
                const bool running = settings.GetBool(NXCoreSetting::EmulationRunning);
                const unsigned frames = window.frames.load();
                std::cout << "EmulationRunning=" << running << " PresentedFrames=" << frames << std::endl;
                result = running && frames > 0 ? 0 : 7;
            } else result = 5;
            // The verdict is already printed; emulation threads can deadlock while modules
            // shut down, so skip teardown and terminate without DLL detach.
            std::cout.flush();
            TerminateProcess(GetCurrentProcess(), result);
        }
    }
    DestroyWindow(window.handle);
    AppCleanup();
    return result;
}
