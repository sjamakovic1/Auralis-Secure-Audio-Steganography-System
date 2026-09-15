#include "stegowav/gui/Theme.hpp"

#include <commctrl.h>

#include <algorithm>

namespace stegowav::gui {
namespace {

constexpr wchar_t HoverProperty[] = L"AuralisButtonHover";

LRESULT CALLBACK buttonProcedure(HWND button, UINT message, WPARAM wParam,
                                 LPARAM lParam, UINT_PTR id, DWORD_PTR)
{
    if (message == WM_MOUSEMOVE && GetPropW(button, HoverProperty) == nullptr) {
        SetPropW(button, HoverProperty, reinterpret_cast<HANDLE>(1));
        TRACKMOUSEEVENT tracking{sizeof(tracking), TME_LEAVE, button, 0};
        TrackMouseEvent(&tracking);
        InvalidateRect(button, nullptr, TRUE);
    } else if (message == WM_MOUSELEAVE) {
        RemovePropW(button, HoverProperty);
        InvalidateRect(button, nullptr, TRUE);
    } else if (message == WM_NCDESTROY) {
        RemovePropW(button, HoverProperty);
        RemoveWindowSubclass(button, buttonProcedure, id);
    }
    return DefSubclassProc(button, message, wParam, lParam);
}

COLORREF blend(COLORREF color, int amount)
{
    return RGB(std::min(255, static_cast<int>(GetRValue(color)) + amount),
               std::min(255, static_cast<int>(GetGValue(color)) + amount),
               std::min(255, static_cast<int>(GetBValue(color)) + amount));
}

} // namespace

void enableModernButton(HWND button)
{
    SetWindowLongPtrW(button, GWL_STYLE,
                      GetWindowLongPtrW(button, GWL_STYLE) | BS_OWNERDRAW);
    SetWindowSubclass(button, buttonProcedure,
                      reinterpret_cast<UINT_PTR>(button), 0);
}

bool drawModernButton(const DRAWITEMSTRUCT& item, HFONT font, COLORREF accent)
{
    if (item.CtlType != ODT_BUTTON) return false;
    const bool disabled = (item.itemState & ODS_DISABLED) != 0;
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    const bool hover = GetPropW(item.hwndItem, HoverProperty) != nullptr;
    COLORREF fill = disabled ? RGB(55, 70, 85) : accent;
    if (hover && !disabled) fill = blend(fill, 20);
    if (pressed && !disabled) fill = RGB(std::max(0, static_cast<int>(GetRValue(fill)) - 25),
                                        std::max(0, static_cast<int>(GetGValue(fill)) - 25),
                                        std::max(0, static_cast<int>(GetBValue(fill)) - 25));

    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, hover ? PrimaryTextColor : fill);
    HGDIOBJ oldBrush = SelectObject(item.hDC, brush);
    HGDIOBJ oldPen = SelectObject(item.hDC, pen);
    Rectangle(item.hDC, item.rcItem.left, item.rcItem.top,
              item.rcItem.right, item.rcItem.bottom);
    SelectObject(item.hDC, oldBrush);
    SelectObject(item.hDC, oldPen);
    DeleteObject(brush);
    DeleteObject(pen);

    wchar_t text[128]{};
    GetWindowTextW(item.hwndItem, text, 128);
    SetBkMode(item.hDC, TRANSPARENT);
    SetTextColor(item.hDC, disabled ? SecondaryTextColor : PrimaryTextColor);
    SelectObject(item.hDC, font);
    RECT rectangle = item.rcItem;
    DrawTextW(item.hDC, text, -1, &rectangle,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    return true;
}

} // namespace stegowav::gui
