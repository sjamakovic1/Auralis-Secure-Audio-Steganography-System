#pragma once

#include <windows.h>

namespace stegowav::gui {

inline constexpr COLORREF BackgroundColor = RGB(7, 20, 38);
inline constexpr COLORREF SecondaryColor = RGB(13, 32, 56);
inline constexpr COLORREF PanelColor = RGB(17, 43, 71);
inline constexpr COLORREF AccentColor = RGB(40, 184, 224);
inline constexpr COLORREF GoldColor = RGB(215, 176, 106);
inline constexpr COLORREF PrimaryTextColor = RGB(242, 245, 248);
inline constexpr COLORREF SecondaryTextColor = RGB(170, 184, 199);
inline constexpr COLORREF EditColor = RGB(238, 244, 249);

void enableModernButton(HWND button);
bool drawModernButton(const DRAWITEMSTRUCT& item, HFONT font,
                      COLORREF accent = AccentColor);

} // namespace stegowav::gui
