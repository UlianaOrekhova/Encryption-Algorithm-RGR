#include "console.h"

#ifdef _WIN32
#include <windows.h>
#endif

void initConsole()
{
#ifdef _WIN32
    // All string literals in the project are UTF-8. Make the Windows
    // console use UTF-8 directly instead of relying on the system code page.
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

#else
#endif
}
