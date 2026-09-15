#include "stegowav/gui/MainWindow.hpp"

#include <commctrl.h>
#include <windows.h>

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand)
{
    INITCOMMONCONTROLSEX commonControls{};
    commonControls.dwSize = sizeof(commonControls);
    commonControls.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&commonControls);

    stegowav::gui::MainWindow mainWindow(instance);
    if (!mainWindow.create(showCommand)) {
        return 1;
    }
    return mainWindow.run();
}
