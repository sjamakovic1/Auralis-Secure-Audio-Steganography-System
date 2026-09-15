#pragma once
#include "stegowav/gui/Settings.hpp"
#include <windows.h>
#include <functional>
#include <string>
namespace stegowav::gui {
class MainWindow {
public:
    explicit MainWindow(HINSTANCE instance);
    ~MainWindow();
    bool create(int showCommand);
    int run();
private:
    enum class Page { Home, Encrypt, Decrypt };
    enum class Operation { Encrypt, Decrypt };
    struct WorkerResult { Operation operation{}; bool success{}; std::wstring message; std::wstring output; };
    static LRESULT CALLBACK windowProcedure(HWND, UINT, WPARAM, LPARAM);
    LRESULT handleMessage(UINT, WPARAM, LPARAM);
    void createControls(); void layoutControls(); void showPage(Page);
    void handleCommand(int); void handleDroppedFiles(HDROP);
    void openKeyDialog();
    void chooseOpenFile(HWND, const wchar_t*, bool); void chooseSaveFile(HWND, const wchar_t*, const wchar_t*);
    void updateMessageInfo(); void startEncrypt(); void startDecrypt();
    void beginOperation(Operation, HWND, std::wstring, std::wstring, std::function<std::wstring()>);
    void completeOperation(WorkerResult*); void setStatus(const std::wstring&);
    void saveSettings(); void showError(const std::wstring&) const;
    HINSTANCE instance_{}; HWND window_{}; HFONT font_{}; HFONT titleFont_{}; HFONT heroFont_{};
    HBRUSH backgroundBrush_{}; HBRUSH panelBrush_{}; HBRUSH editBrush_{};
    std::filesystem::path settingsPath_; Settings settings_; Page page_{Page::Home};
    HWND homePanel_{}, homeBrand_{}, homeEncrypt_{}, homeDecrypt_{};
    HWND encryptPanel_{}, decryptPanel_{}, encryptBack_{}, decryptBack_{}, encryptTitle_{}, decryptTitle_{};
    HWND encryptInputLabel_{}, encryptInput_{}, encryptInputBrowse_{};
    HWND encryptKeyLabel_{}, encryptPublicKey_{}, encryptKeyBrowse_{}, encryptGenerate_{};
    HWND encryptMessageLabel_{}, encryptMessage_{}, encryptMessageInfo_{};
    HWND encryptOutputLabel_{}, encryptOutput_{}, encryptOutputBrowse_{}, encryptAction_{}, encryptStatus_{};
    HWND decryptInputLabel_{}, decryptInput_{}, decryptInputBrowse_{};
    HWND decryptKeyLabel_{}, decryptPrivateKey_{}, decryptKeyBrowse_{}, decryptAction_{};
    HWND decryptResultLabel_{}, decryptResult_{}, decryptStatus_{};
};
} // namespace stegowav::gui
