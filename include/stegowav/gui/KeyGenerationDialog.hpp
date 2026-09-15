#pragma once

#include "stegowav/gui/Settings.hpp"

#include <windows.h>

#include <string>

namespace stegowav::gui {

class KeyGenerationDialog {
public:
    struct Result {
        std::wstring publicKeyPath;
        std::wstring privateKeyPath;
        std::wstring rsaBits;
        std::wstring publicExponent;
    };

    KeyGenerationDialog(HINSTANCE instance, HWND owner, const Settings& settings);
    bool showModal(Result& result);

private:
    struct WorkerResult { bool success{}; std::wstring message; };
    static LRESULT CALLBACK procedure(HWND, UINT, WPARAM, LPARAM);
    LRESULT handleMessage(UINT, WPARAM, LPARAM);
    void createControls();
    void browse(HWND target);
    void startGeneration();
    void finishGeneration(WorkerResult* result);
    void close(bool accepted);

    HINSTANCE instance_{};
    HWND owner_{};
    HWND window_{};
    HFONT font_{};
    HBRUSH backgroundBrush_{};
    HBRUSH editBrush_{};
    Settings settings_;
    Result result_;
    bool accepted_{};
    bool running_{};
    HWND bits_{};
    HWND exponent_{};
    HWND publicPath_{};
    HWND privatePath_{};
    HWND generate_{};
    HWND cancel_{};
    HWND status_{};
};

} // namespace stegowav::gui
