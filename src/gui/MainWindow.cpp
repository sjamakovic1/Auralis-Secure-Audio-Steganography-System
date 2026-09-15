#include "stegowav/gui/MainWindow.hpp"
#include "stegowav/application/EmbedService.hpp"
#include "stegowav/application/ExtractService.hpp"
#include "stegowav/crypto/rsa/RsaKeyFile.hpp"
#include "stegowav/gui/KeyGenerationDialog.hpp"
#include "stegowav/gui/Theme.hpp"
#include "stegowav/wav/WavReader.hpp"
#include "stegowav/wav/WavWriter.hpp"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

namespace stegowav::gui {
namespace {
constexpr wchar_t WindowClass[] = L"AuralisMainWindow";
constexpr UINT WorkerFinished = WM_APP + 1;
enum Id { HomeEncrypt=100, HomeDecrypt, EncryptBack, DecryptBack, EncryptInputBrowse,
    EncryptKeyBrowse, EncryptGenerate, EncryptMessageEdit, EncryptOutputBrowse,
    EncryptAction, DecryptInputBrowse, DecryptKeyBrowse, DecryptAction };
constexpr wchar_t WavFilter[] = L"WAV audio files (*.wav)\0*.wav\0All files (*.*)\0*.*\0";
constexpr wchar_t KeyFilter[] = L"StegoWAV key files (*.swkey)\0*.swkey\0All files (*.*)\0*.*\0";

LRESULT CALLBACK panelProcedure(HWND panel, UINT message, WPARAM wParam, LPARAM lParam,
                                UINT_PTR id, DWORD_PTR)
{
    if (message == WM_COMMAND || message == WM_DRAWITEM || message == WM_CTLCOLORSTATIC
        || message == WM_CTLCOLOREDIT || message == WM_DROPFILES)
        return SendMessageW(GetParent(panel), message, wParam, lParam);
    if (message == WM_NCDESTROY) RemoveWindowSubclass(panel, panelProcedure, id);
    return DefSubclassProc(panel, message, wParam, lParam);
}

HWND makeControl(HINSTANCE instance, HWND parent, const wchar_t* type, const wchar_t* text,
                 DWORD style, int id, HFONT font, DWORD exStyle = 0)
{
    HWND result = CreateWindowExW(exStyle, type, text, WS_CHILD | WS_VISIBLE | style,
        0, 0, 0, 0, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance, nullptr);
    if (!result) throw std::runtime_error("Could not create GUI control.");
    SendMessageW(result, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return result;
}

std::wstring textOf(HWND control)
{
    const int length = GetWindowTextLengthW(control);
    std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
    GetWindowTextW(control, text.data(), length + 1); text.resize(length);
    return text;
}

std::string toUtf8(std::wstring_view text)
{
    if (text.empty()) return {};
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        throw std::length_error("Text is too long.");
    const int sourceLength = static_cast<int>(text.size());
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                                            sourceLength, nullptr, 0, nullptr, nullptr);
    if (length <= 0) throw std::runtime_error("Text contains invalid UTF-16.");
    std::string result(length, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), sourceLength,
                        result.data(), length, nullptr, nullptr);
    return result;
}

std::wstring fromUtf8(std::string_view text)
{
    if (text.empty()) return {};
    const int sourceLength = static_cast<int>(text.size());
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                            sourceLength, nullptr, 0);
    if (length <= 0) throw std::runtime_error("Decrypted message is not valid UTF-8.");
    std::wstring result(length, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), sourceLength,
                        result.data(), length);
    return result;
}

std::vector<std::byte> bytesOf(std::string_view text)
{
    std::vector<std::byte> result; result.reserve(text.size());
    for (char value : text) result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    return result;
}

std::wstring exceptionText(const std::exception& error)
{
    try { return fromUtf8(error.what()); } catch (...) { return L"Operation failed."; }
}

bool extensionIs(const std::filesystem::path& path, const std::wstring& expected)
{
    std::wstring actual = path.extension().wstring();
    std::transform(actual.begin(), actual.end(), actual.begin(), towlower);
    return actual == expected;
}
} // namespace

MainWindow::MainWindow(HINSTANCE instance) : instance_(instance)
{
    font_ = CreateFontW(-17,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    titleFont_ = CreateFontW(-32,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    heroFont_ = CreateFontW(-48,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    backgroundBrush_ = CreateSolidBrush(BackgroundColor); panelBrush_ = CreateSolidBrush(PanelColor);
    editBrush_ = CreateSolidBrush(EditColor);
    try { settingsPath_ = executableDirectory() / L"auralis.ini"; settings_ = Settings::load(settingsPath_); } catch (...) {}

}

MainWindow::~MainWindow()
{
    for (HGDIOBJ object : {reinterpret_cast<HGDIOBJ>(font_), reinterpret_cast<HGDIOBJ>(titleFont_),
         reinterpret_cast<HGDIOBJ>(heroFont_), reinterpret_cast<HGDIOBJ>(backgroundBrush_),
         reinterpret_cast<HGDIOBJ>(panelBrush_), reinterpret_cast<HGDIOBJ>(editBrush_)})
        if (object) DeleteObject(object);
}

bool MainWindow::create(int showCommand)
{
    WNDCLASSEXW wc{sizeof(wc)}; wc.lpfnWndProc=windowProcedure; wc.hInstance=instance_;
    wc.hCursor=LoadCursorW(nullptr,IDC_ARROW); wc.hIcon=LoadIconW(nullptr,IDI_APPLICATION);
    wc.hbrBackground=backgroundBrush_; wc.lpszClassName=WindowClass;
    if (!RegisterClassExW(&wc) && GetLastError()!=ERROR_CLASS_ALREADY_EXISTS) return false;
    window_=CreateWindowExW(0,WindowClass,L"Auralis - StegoWAV",WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,CW_USEDEFAULT,1200,760,nullptr,nullptr,instance_,this);
    if (!window_) return false;
    DragAcceptFiles(window_,TRUE); ShowWindow(window_,showCommand); UpdateWindow(window_); return true;
}

int MainWindow::run()
{
    MSG message{}; while(GetMessageW(&message,nullptr,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}
    return static_cast<int>(message.wParam);
}

LRESULT CALLBACK MainWindow::windowProcedure(HWND hwnd,UINT message,WPARAM wParam,LPARAM lParam)
{
    auto* self=reinterpret_cast<MainWindow*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA));
    if(message==WM_NCCREATE){self=static_cast<MainWindow*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);self->window_=hwnd;SetWindowLongPtrW(hwnd,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self));}
    return self?self->handleMessage(message,wParam,lParam):DefWindowProcW(hwnd,message,wParam,lParam);
}

LRESULT MainWindow::handleMessage(UINT message,WPARAM wParam,LPARAM lParam)
{
    switch(message){
    case WM_CREATE: try{createControls();layoutControls();showPage(Page::Home);}catch(const std::exception& e){showError(exceptionText(e));return -1;} return 0;
    case WM_SIZE: layoutControls(); InvalidateRect(window_,nullptr,TRUE); return 0;
    case WM_GETMINMAXINFO: reinterpret_cast<MINMAXINFO*>(lParam)->ptMinTrackSize={780,620}; return 0;
    case WM_COMMAND:
        if(LOWORD(wParam)==EncryptMessageEdit&&HIWORD(wParam)==EN_CHANGE){updateMessageInfo();return 0;}
        if(HIWORD(wParam)==BN_CLICKED)try{handleCommand(LOWORD(wParam));}catch(const std::exception& e){showError(exceptionText(e));}
        return 0;
    case WM_DROPFILES: handleDroppedFiles(reinterpret_cast<HDROP>(wParam)); return 0;
    case WM_DRAWITEM: return drawModernButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lParam),font_) ? TRUE : FALSE;
    case WM_CTLCOLORSTATIC:{HDC dc=reinterpret_cast<HDC>(wParam);HWND c=reinterpret_cast<HWND>(lParam);SetTextColor(dc,(c==encryptStatus_||c==decryptStatus_)?AccentColor:PrimaryTextColor);SetBkMode(dc,TRANSPARENT);bool panel=c==encryptPanel_||c==decryptPanel_||GetParent(c)==encryptPanel_||GetParent(c)==decryptPanel_;return reinterpret_cast<LRESULT>(panel?panelBrush_:backgroundBrush_);}
    case WM_CTLCOLOREDIT:{HDC dc=reinterpret_cast<HDC>(wParam);SetTextColor(dc,BackgroundColor);SetBkColor(dc,EditColor);return reinterpret_cast<LRESULT>(editBrush_);}
    case WM_PAINT:{PAINTSTRUCT ps{};HDC dc=BeginPaint(window_,&ps);RECT area{};GetClientRect(window_,&area);FillRect(dc,&area,backgroundBrush_);EndPaint(window_,&ps);return 0;}
    case WorkerFinished: completeOperation(reinterpret_cast<WorkerResult*>(lParam)); return 0;
    case WM_DESTROY: saveSettings(); PostQuitMessage(0); return 0;
    default:return DefWindowProcW(window_,message,wParam,lParam);}
}

void MainWindow::createControls()
{
    homeBrand_=makeControl(instance_,window_,L"STATIC",L"Auralis",SS_CENTER,0,heroFont_);
    homeEncrypt_=makeControl(instance_,window_,L"BUTTON",L"Encrypt",BS_OWNERDRAW,HomeEncrypt,font_);
    homeDecrypt_=makeControl(instance_,window_,L"BUTTON",L"Decrypt",BS_OWNERDRAW,HomeDecrypt,font_);
    enableModernButton(homeEncrypt_);enableModernButton(homeDecrypt_);
    encryptPanel_=makeControl(instance_,window_,L"STATIC",L"",0,0,font_);
    decryptPanel_=makeControl(instance_,window_,L"STATIC",L"",0,0,font_);
    SetWindowSubclass(encryptPanel_,panelProcedure,1,0);SetWindowSubclass(decryptPanel_,panelProcedure,2,0);
    DragAcceptFiles(encryptPanel_,TRUE);DragAcceptFiles(decryptPanel_,TRUE);
    auto button=[&](HWND parent,const wchar_t* text,int id){HWND h=makeControl(instance_,parent,L"BUTTON",text,BS_OWNERDRAW,id,font_);enableModernButton(h);return h;};
    auto label=[&](HWND parent,const wchar_t* text,HFONT font=nullptr){return makeControl(instance_,parent,L"STATIC",text,SS_LEFT,0,font?font:font_);};
    auto edit=[&](HWND parent,const wchar_t* text,DWORD style,int id=0){return makeControl(instance_,parent,L"EDIT",text,style,id,font_,WS_EX_CLIENTEDGE);};
    encryptBack_=button(window_,L"← Home",EncryptBack);encryptTitle_=label(window_,L"Encrypt message",titleFont_);
    encryptInputLabel_=label(encryptPanel_,L"Carrier WAV file");encryptInput_=edit(encryptPanel_,L"",ES_AUTOHSCROLL);encryptInputBrowse_=button(encryptPanel_,L"Browse",EncryptInputBrowse);
    encryptKeyLabel_=label(encryptPanel_,L"Public RSA key");encryptPublicKey_=edit(encryptPanel_,settings_.lastPublicKey.c_str(),ES_AUTOHSCROLL);encryptKeyBrowse_=button(encryptPanel_,L"Browse",EncryptKeyBrowse);encryptGenerate_=button(encryptPanel_,L"Generate",EncryptGenerate);
    encryptMessageLabel_=label(encryptPanel_,L"Secret message");encryptMessage_=edit(encryptPanel_,L"",ES_MULTILINE|ES_AUTOVSCROLL|ES_WANTRETURN|WS_VSCROLL,EncryptMessageEdit);encryptMessageInfo_=label(encryptPanel_,L"Message size: 0 bytes");
    encryptOutputLabel_=label(encryptPanel_,L"Output WAV");encryptOutput_=edit(encryptPanel_,L"",ES_AUTOHSCROLL);encryptOutputBrowse_=button(encryptPanel_,L"Browse",EncryptOutputBrowse);encryptAction_=button(encryptPanel_,L"Encrypt",EncryptAction);encryptStatus_=label(encryptPanel_,L"Ready");
    decryptBack_=button(window_,L"← Home",DecryptBack);decryptTitle_=label(window_,L"Decrypt message",titleFont_);
    decryptInputLabel_=label(decryptPanel_,L"Stego WAV");decryptInput_=edit(decryptPanel_,L"",ES_AUTOHSCROLL);decryptInputBrowse_=button(decryptPanel_,L"Browse",DecryptInputBrowse);
    decryptKeyLabel_=label(decryptPanel_,L"Private RSA key");decryptPrivateKey_=edit(decryptPanel_,settings_.lastPrivateKey.c_str(),ES_AUTOHSCROLL);decryptKeyBrowse_=button(decryptPanel_,L"Browse",DecryptKeyBrowse);decryptAction_=button(decryptPanel_,L"Decrypt",DecryptAction);
    decryptResultLabel_=label(decryptPanel_,L"Extracted message");decryptResult_=edit(decryptPanel_,L"",ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL);decryptStatus_=label(decryptPanel_,L"Ready");
}

void MainWindow::layoutControls()
{
    if(!window_||!homeEncrypt_)return;RECT r{};GetClientRect(window_,&r);int w=r.right,h=r.bottom;
    int heroTop=80,heroHeight=std::max(220,h-330);MoveWindow(homeBrand_,w/2-250,heroTop+heroHeight/2-45,500,65,TRUE);
    MoveWindow(homeEncrypt_,w/2-190,h-165,175,52,TRUE);MoveWindow(homeDecrypt_,w/2+15,h-165,175,52,TRUE);
    int cardW=std::min(900,w-80),cardH=std::min(570,h-150),cardX=(w-cardW)/2,cardY=105;
    for(HWND p:{encryptPanel_,decryptPanel_})MoveWindow(p,cardX,cardY,cardW,cardH,TRUE);
    MoveWindow(encryptBack_,cardX,34,110,38,TRUE);MoveWindow(decryptBack_,cardX,34,110,38,TRUE);
    MoveWindow(encryptTitle_,cardX+135,35,400,42,TRUE);MoveWindow(decryptTitle_,cardX+135,35,400,42,TRUE);
    const int m=28,labelW=155,bw=100,gap=10,editX=m+labelW,buttonX=cardW-m-bw,editW=buttonX-gap-editX;
    auto row=[&](HWND l,HWND e,HWND b,int y){MoveWindow(l,m,y+7,labelW-8,24,TRUE);MoveWindow(e,editX,y,editW,32,TRUE);MoveWindow(b,buttonX,y,bw,32,TRUE);};
    row(encryptInputLabel_,encryptInput_,encryptInputBrowse_,28);
    MoveWindow(encryptKeyLabel_,m,79,labelW-8,24,TRUE);int genX=buttonX-bw-gap;MoveWindow(encryptPublicKey_,editX,72,std::max(140,genX-gap-editX),32,TRUE);MoveWindow(encryptKeyBrowse_,genX,72,bw,32,TRUE);MoveWindow(encryptGenerate_,buttonX,72,bw,32,TRUE);
    MoveWindow(encryptMessageLabel_,m,125,180,24,TRUE);MoveWindow(encryptMessageInfo_,cardW-m-240,125,240,24,TRUE);int msgH=std::clamp(cardH-350,160,200);MoveWindow(encryptMessage_,m,151,cardW-2*m,msgH,TRUE);int oy=msgH+173;row(encryptOutputLabel_,encryptOutput_,encryptOutputBrowse_,oy);MoveWindow(encryptStatus_,m,oy+53,400,24,TRUE);MoveWindow(encryptAction_,cardW-m-150,oy+45,150,42,TRUE);
    row(decryptInputLabel_,decryptInput_,decryptInputBrowse_,28);row(decryptKeyLabel_,decryptPrivateKey_,decryptKeyBrowse_,79);MoveWindow(decryptAction_,cardW-m-150,130,150,42,TRUE);MoveWindow(decryptResultLabel_,m,192,220,24,TRUE);MoveWindow(decryptResult_,m,220,cardW-2*m,std::max(170,cardH-278),TRUE);MoveWindow(decryptStatus_,m,cardH-34,500,24,TRUE);
}

void MainWindow::showPage(Page page)
{
    page_=page;bool home=page==Page::Home,enc=page==Page::Encrypt,dec=page==Page::Decrypt;
    for(HWND c:{homeBrand_,homeEncrypt_,homeDecrypt_})ShowWindow(c,home?SW_SHOW:SW_HIDE);
    for(HWND c:{encryptBack_,encryptTitle_,encryptPanel_})ShowWindow(c,enc?SW_SHOW:SW_HIDE);
    for(HWND c:{decryptBack_,decryptTitle_,decryptPanel_})ShowWindow(c,dec?SW_SHOW:SW_HIDE);
    if(enc)SetWindowTextW(encryptStatus_,L"Ready");if(dec)SetWindowTextW(decryptStatus_,L"Ready");
    InvalidateRect(window_,nullptr,TRUE);
}

void MainWindow::handleCommand(int id)
{
    switch(id){case HomeEncrypt:showPage(Page::Encrypt);break;case HomeDecrypt:showPage(Page::Decrypt);break;case EncryptBack:case DecryptBack:showPage(Page::Home);break;
    case EncryptInputBrowse:chooseOpenFile(encryptInput_,WavFilter,true);break;case EncryptKeyBrowse:chooseOpenFile(encryptPublicKey_,KeyFilter,false);settings_.lastPublicKey=textOf(encryptPublicKey_);saveSettings();break;
    case EncryptGenerate:openKeyDialog();break;case EncryptOutputBrowse:chooseSaveFile(encryptOutput_,WavFilter,L"wav");break;case EncryptAction:startEncrypt();break;
    case DecryptInputBrowse:chooseOpenFile(decryptInput_,WavFilter,true);break;case DecryptKeyBrowse:chooseOpenFile(decryptPrivateKey_,KeyFilter,false);settings_.lastPrivateKey=textOf(decryptPrivateKey_);saveSettings();break;case DecryptAction:startDecrypt();break;}
}

void MainWindow::handleDroppedFiles(HDROP drop)
{
    UINT count=DragQueryFileW(drop,0xFFFFFFFF,nullptr,0);bool used=false;
    for(UINT i=0;i<count;++i){UINT n=DragQueryFileW(drop,i,nullptr,0);std::wstring p(n+1,L'\0');DragQueryFileW(drop,i,p.data(),n+1);p.resize(n);std::filesystem::path file(p);
        if(extensionIs(file,L".wav")){if(page_==Page::Encrypt)SetWindowTextW(encryptInput_,p.c_str());else if(page_==Page::Decrypt)SetWindowTextW(decryptInput_,p.c_str());else continue;settings_.lastInputWavDirectory=file.parent_path().wstring();used=true;}
        else if(extensionIs(file,L".swkey")){if(page_==Page::Encrypt){SetWindowTextW(encryptPublicKey_,p.c_str());settings_.lastPublicKey=p;}else if(page_==Page::Decrypt){SetWindowTextW(decryptPrivateKey_,p.c_str());settings_.lastPrivateKey=p;}else continue;used=true;}}
    DragFinish(drop);if(used){saveSettings();setStatus(L"File selected by drag and drop.");}
}

void MainWindow::openKeyDialog()
{
    KeyGenerationDialog dialog(instance_,window_,settings_);KeyGenerationDialog::Result result;
    if(dialog.showModal(result)){settings_.lastPublicKey=result.publicKeyPath;settings_.lastPrivateKey=result.privateKeyPath;settings_.rsaBits=result.rsaBits;settings_.publicExponent=result.publicExponent;SetWindowTextW(encryptPublicKey_,result.publicKeyPath.c_str());SetWindowTextW(decryptPrivateKey_,result.privateKeyPath.c_str());saveSettings();setStatus(L"RSA keys generated successfully.");}
}

void MainWindow::chooseOpenFile(HWND target,const wchar_t* filter,bool rememberDirectory)
{
    std::array<wchar_t,32768> path{};auto current=textOf(target);std::copy_n(current.data(),std::min(current.size(),path.size()-1),path.data());OPENFILENAMEW d{sizeof(d)};d.hwndOwner=window_;d.lpstrFilter=filter;d.lpstrFile=path.data();d.nMaxFile=path.size();d.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;if(current.empty()&&!settings_.lastInputWavDirectory.empty())d.lpstrInitialDir=settings_.lastInputWavDirectory.c_str();if(GetOpenFileNameW(&d)){SetWindowTextW(target,path.data());if(rememberDirectory){settings_.lastInputWavDirectory=std::filesystem::path(path.data()).parent_path().wstring();saveSettings();}}}
void MainWindow::chooseSaveFile(HWND target,const wchar_t* filter,const wchar_t* ext)
{
    std::array<wchar_t,32768> path{};auto current=textOf(target);std::copy_n(current.data(),std::min(current.size(),path.size()-1),path.data());OPENFILENAMEW d{sizeof(d)};d.hwndOwner=window_;d.lpstrFilter=filter;d.lpstrFile=path.data();d.nMaxFile=path.size();d.lpstrDefExt=ext;d.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;if(current.empty()&&!settings_.lastOutputWavDirectory.empty())d.lpstrInitialDir=settings_.lastOutputWavDirectory.c_str();if(GetSaveFileNameW(&d)){SetWindowTextW(target,path.data());settings_.lastOutputWavDirectory=std::filesystem::path(path.data()).parent_path().wstring();saveSettings();}}
void MainWindow::updateMessageInfo(){try{auto n=toUtf8(textOf(encryptMessage_)).size();auto s=L"Message size: "+std::to_wstring(n)+L" bytes";SetWindowTextW(encryptMessageInfo_,s.c_str());}catch(...){SetWindowTextW(encryptMessageInfo_,L"Message size: invalid text");}}

void MainWindow::startEncrypt()
{
    auto input=textOf(encryptInput_),output=textOf(encryptOutput_),keyPath=textOf(encryptPublicKey_);if(input.empty()||output.empty()||keyPath.empty())throw std::invalid_argument("Input WAV, output WAV, and public key are required.");auto message=toUtf8(textOf(encryptMessage_));settings_.lastPublicKey=keyPath;saveSettings();beginOperation(Operation::Encrypt,encryptAction_,L"Encrypting and embedding...",L"Message successfully hidden.",[input,output,keyPath,message]{auto key=crypto::rsa::RsaKeyFile::loadPublic(keyPath);wav::WavReader reader;auto file=reader.read(input);application::EmbedService::embed(file,bytesOf(message),key);wav::WavWriter{}.write(file,output);return std::wstring{};});
}
void MainWindow::startDecrypt()
{
    auto input=textOf(decryptInput_),keyPath=textOf(decryptPrivateKey_);if(input.empty()||keyPath.empty())throw std::invalid_argument("Stego WAV and private key are required.");settings_.lastPrivateKey=keyPath;saveSettings();beginOperation(Operation::Decrypt,decryptAction_,L"Extracting and decrypting...",L"Message successfully extracted.",[input,keyPath]{auto key=crypto::rsa::RsaKeyFile::loadPrivate(keyPath);wav::WavReader reader;auto file=reader.read(input);auto data=application::ExtractService::extract(file,key);std::string text;for(auto b:data)text.push_back(static_cast<char>(std::to_integer<unsigned char>(b)));return fromUtf8(text);});
}
void MainWindow::beginOperation(Operation operation,HWND button,std::wstring status,std::wstring success,std::function<std::wstring()> work)
{
    EnableWindow(button,FALSE);setStatus(status);auto result=std::make_unique<WorkerResult>();result->operation=operation;HWND target=window_;std::thread([target,success=std::move(success),work=std::move(work),result=std::move(result)]()mutable{try{result->output=work();result->message=success;result->success=true;}catch(const std::exception&e){result->message=exceptionText(e);}auto* raw=result.release();if(!PostMessageW(target,WorkerFinished,0,reinterpret_cast<LPARAM>(raw)))delete raw;}).detach();
}
void MainWindow::completeOperation(WorkerResult* raw)
{
    std::unique_ptr<WorkerResult> result(raw);if(!result)return;HWND button=result->operation==Operation::Encrypt?encryptAction_:decryptAction_;EnableWindow(button,TRUE);if(result->success){if(result->operation==Operation::Decrypt)SetWindowTextW(decryptResult_,result->output.c_str());setStatus(result->message);MessageBoxW(window_,result->message.c_str(),L"Auralis",MB_OK|MB_ICONINFORMATION);}else{setStatus(L"Error");showError(result->message);}
}
void MainWindow::setStatus(const std::wstring& status){if(page_==Page::Encrypt)SetWindowTextW(encryptStatus_,status.c_str());else if(page_==Page::Decrypt)SetWindowTextW(decryptStatus_,status.c_str());}
void MainWindow::saveSettings(){if(!settingsPath_.empty())settings_.save(settingsPath_);}
void MainWindow::showError(const std::wstring& message)const{MessageBoxW(window_,message.c_str(),L"Auralis - Error",MB_OK|MB_ICONERROR);}
} // namespace stegowav::gui
