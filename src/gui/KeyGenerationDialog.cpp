#include "stegowav/gui/KeyGenerationDialog.hpp"

#include "stegowav/crypto/bigint/BigInteger.hpp"
#include "stegowav/crypto/rsa/RsaKeyFile.hpp"
#include "stegowav/crypto/rsa/RsaKeyGenerator.hpp"
#include "stegowav/gui/Theme.hpp"

#include <commdlg.h>

#include <array>
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

namespace stegowav::gui {
namespace {
constexpr wchar_t ClassName[] = L"AuralisKeyGenerationDialog";
constexpr UINT FinishedMessage = WM_APP + 21;
enum { BrowsePublic = 1, BrowsePrivate, Generate, Cancel };
constexpr wchar_t KeyFilter[] = L"StegoWAV key files (*.swkey)\0*.swkey\0All files (*.*)\0*.*\0";

std::wstring textOf(HWND control)
{
    const int size = GetWindowTextLengthW(control);
    std::wstring value(static_cast<std::size_t>(size) + 1, L'\0');
    GetWindowTextW(control, value.data(), size + 1);
    value.resize(size);
    return value;
}

std::string narrowAscii(const std::wstring& value)
{
    return {value.begin(), value.end()};
}

HWND control(HWND parent, const wchar_t* type, const wchar_t* text, DWORD style,
             int id, int x, int y, int width, int height, HFONT font)
{
    HWND result = CreateWindowExW(type == std::wstring(L"EDIT") ? WS_EX_CLIENTEDGE : 0,
        type, text, WS_CHILD | WS_VISIBLE | style, x, y, width, height, parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(parent, GWLP_HINSTANCE)), nullptr);
    if (!result) throw std::runtime_error("Could not create key dialog control.");
    SendMessageW(result, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return result;
}
} // namespace

KeyGenerationDialog::KeyGenerationDialog(HINSTANCE instance, HWND owner,
                                         const Settings& settings)
    : instance_(instance), owner_(owner), settings_(settings)
{
    font_ = CreateFontW(-17, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    backgroundBrush_ = CreateSolidBrush(PanelColor);
    editBrush_ = CreateSolidBrush(EditColor);
}

bool KeyGenerationDialog::showModal(Result& result)
{
    WNDCLASSEXW wc{sizeof(wc)};
    wc.lpfnWndProc = procedure;
    wc.hInstance = instance_;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = backgroundBrush_;
    wc.lpszClassName = ClassName;
    RegisterClassExW(&wc);

    RECT ownerRect{};
    GetWindowRect(owner_, &ownerRect);
    const int width = 660, height = 430;
    window_ = CreateWindowExW(WS_EX_DLGMODALFRAME, ClassName, L"Generate RSA Keys",
        WS_CAPTION | WS_SYSMENU, ownerRect.left + (ownerRect.right-ownerRect.left-width)/2,
        ownerRect.top + (ownerRect.bottom-ownerRect.top-height)/2, width, height,
        owner_, nullptr, instance_, this);
    if (!window_) return false;
    EnableWindow(owner_, FALSE);
    ShowWindow(window_, SW_SHOW);
    UpdateWindow(window_);
    MSG message{};
    while (IsWindow(window_) && GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(window_, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    EnableWindow(owner_, TRUE);
    SetForegroundWindow(owner_);
    if (accepted_) result = result_;
    DeleteObject(font_);
    DeleteObject(backgroundBrush_);
    DeleteObject(editBrush_);
    return accepted_;
}

LRESULT CALLBACK KeyGenerationDialog::procedure(HWND hwnd, UINT message,
                                                WPARAM wParam, LPARAM lParam)
{
    auto* self = reinterpret_cast<KeyGenerationDialog*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        self = static_cast<KeyGenerationDialog*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);
        self->window_ = hwnd;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    return self ? self->handleMessage(message, wParam, lParam)
                : DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT KeyGenerationDialog::handleMessage(UINT message, WPARAM wParam, LPARAM lParam)
{
    if (message == WM_CREATE) { createControls(); return 0; }
    if (message == WM_COMMAND && HIWORD(wParam) == BN_CLICKED) {
        try {
            if (LOWORD(wParam) == BrowsePublic) browse(publicPath_);
            else if (LOWORD(wParam) == BrowsePrivate) browse(privatePath_);
            else if (LOWORD(wParam) == Generate) startGeneration();
            else if (LOWORD(wParam) == Cancel && !running_) close(false);
        } catch (const std::exception& error) {
            MessageBoxA(window_, error.what(), "Auralis", MB_OK | MB_ICONERROR);
        }
        return 0;
    }
    if (message == WM_DRAWITEM) {
        return drawModernButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lParam), font_) ? TRUE : FALSE;
    }
    if (message == WM_CTLCOLORSTATIC) {
        SetTextColor(reinterpret_cast<HDC>(wParam), PrimaryTextColor);
        SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        return reinterpret_cast<LRESULT>(backgroundBrush_);
    }
    if (message == WM_CTLCOLOREDIT) {
        SetTextColor(reinterpret_cast<HDC>(wParam), BackgroundColor);
        SetBkColor(reinterpret_cast<HDC>(wParam), EditColor);
        return reinterpret_cast<LRESULT>(editBrush_);
    }
    if (message == FinishedMessage) { finishGeneration(reinterpret_cast<WorkerResult*>(lParam)); return 0; }
    if (message == WM_CLOSE) { if (!running_) close(false); return 0; }
    return DefWindowProcW(window_, message, wParam, lParam);
}

void KeyGenerationDialog::createControls()
{
    control(window_, L"STATIC", L"RSA modulus size", SS_LEFT, 0, 28, 28, 180, 22, font_);
    bits_ = control(window_, L"EDIT", settings_.rsaBits.c_str(), ES_AUTOHSCROLL, 0, 28, 52, 190, 32, font_);
    control(window_, L"STATIC", L"Public exponent", SS_LEFT, 0, 242, 28, 180, 22, font_);
    exponent_ = control(window_, L"EDIT", settings_.publicExponent.c_str(), ES_AUTOHSCROLL, 0, 242, 52, 190, 32, font_);
    control(window_, L"STATIC", L"Public key file", SS_LEFT, 0, 28, 105, 180, 22, font_);
    publicPath_ = control(window_, L"EDIT", settings_.lastPublicKey.empty() ? L"public.swkey" : settings_.lastPublicKey.c_str(), ES_AUTOHSCROLL, 0, 28, 129, 480, 32, font_);
    HWND browsePublic = control(window_, L"BUTTON", L"Browse", BS_OWNERDRAW, BrowsePublic, 520, 129, 100, 32, font_);
    control(window_, L"STATIC", L"Private key file", SS_LEFT, 0, 28, 180, 180, 22, font_);
    privatePath_ = control(window_, L"EDIT", settings_.lastPrivateKey.empty() ? L"private.swkey" : settings_.lastPrivateKey.c_str(), ES_AUTOHSCROLL, 0, 28, 204, 480, 32, font_);
    HWND browsePrivate = control(window_, L"BUTTON", L"Browse", BS_OWNERDRAW, BrowsePrivate, 520, 204, 100, 32, font_);
    status_ = control(window_, L"STATIC", L"Ready", SS_LEFT, 0, 28, 270, 350, 22, font_);
    cancel_ = control(window_, L"BUTTON", L"Cancel", BS_OWNERDRAW, Cancel, 382, 316, 110, 40, font_);
    generate_ = control(window_, L"BUTTON", L"Generate", BS_OWNERDRAW, Generate, 510, 316, 110, 40, font_);
    for (HWND button : {browsePublic, browsePrivate, cancel_, generate_}) enableModernButton(button);
}

void KeyGenerationDialog::browse(HWND target)
{
    std::array<wchar_t, 32768> path{};
    const auto current = textOf(target);
    std::copy_n(current.data(), std::min(current.size(), path.size() - 1), path.data());
    OPENFILENAMEW dialog{sizeof(dialog)};
    dialog.hwndOwner = window_; dialog.lpstrFilter = KeyFilter;
    dialog.lpstrFile = path.data(); dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrDefExt = L"swkey";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetSaveFileNameW(&dialog)) SetWindowTextW(target, path.data());
}

void KeyGenerationDialog::startGeneration()
{
    result_ = {textOf(publicPath_), textOf(privatePath_), textOf(bits_), textOf(exponent_)};
    if (result_.publicKeyPath.empty() || result_.privateKeyPath.empty())
        throw std::invalid_argument("Key output paths are required.");
    const auto bitsText = narrowAscii(result_.rsaBits);
    const auto exponentText = narrowAscii(result_.publicExponent);
    std::size_t bits{}; std::uint64_t exponent{};
    auto a = std::from_chars(bitsText.data(), bitsText.data()+bitsText.size(), bits);
    auto b = std::from_chars(exponentText.data(), exponentText.data()+exponentText.size(), exponent);
    if (a.ec != std::errc{} || a.ptr != bitsText.data()+bitsText.size() || bits == 0
        || b.ec != std::errc{} || b.ptr != exponentText.data()+exponentText.size())
        throw std::invalid_argument("Invalid RSA parameters.");
    running_ = true;
    EnableWindow(generate_, FALSE); EnableWindow(cancel_, FALSE);
    SetWindowTextW(status_, L"Generating RSA keys...");
    const HWND target = window_;
    const Result values = result_;
    std::thread([target, bits, exponent, values] {
        auto result = std::make_unique<WorkerResult>();
        try {
            const auto pair = crypto::rsa::RsaKeyGenerator::generate(bits, crypto::bigint::BigInteger{exponent});
            crypto::rsa::RsaKeyFile::savePublic(values.publicKeyPath, pair.publicKey());
            crypto::rsa::RsaKeyFile::savePrivate(values.privateKeyPath, pair.privateKey());
            result->success = true; result->message = L"RSA keys generated successfully.";
        } catch (const std::exception& error) {
            const int length = MultiByteToWideChar(CP_UTF8, 0, error.what(), -1, nullptr, 0);
            if (length > 1) {
                result->message.resize(static_cast<std::size_t>(length));
                MultiByteToWideChar(CP_UTF8, 0, error.what(), -1,
                                    result->message.data(), length);
                result->message.resize(static_cast<std::size_t>(length - 1));
            }
        }
        auto* raw = result.release();
        if (!PostMessageW(target, FinishedMessage, 0, reinterpret_cast<LPARAM>(raw))) delete raw;
    }).detach();
}

void KeyGenerationDialog::finishGeneration(WorkerResult* raw)
{
    std::unique_ptr<WorkerResult> result(raw);
    running_ = false;
    if (result && result->success) {
        MessageBoxW(window_, result->message.c_str(), L"Auralis", MB_OK | MB_ICONINFORMATION);
        close(true);
    } else {
        EnableWindow(generate_, TRUE); EnableWindow(cancel_, TRUE);
        SetWindowTextW(status_, L"Error");
        MessageBoxW(window_, result ? result->message.c_str() : L"Key generation failed.", L"Auralis", MB_OK | MB_ICONERROR);
    }
}

void KeyGenerationDialog::close(bool accepted)
{
    accepted_ = accepted;
    DestroyWindow(window_);
    window_ = nullptr;
}

} // namespace stegowav::gui
