#pragma once

#include <QString>
#include <QStringList>
#include <QVector>

#include <functional>

// Injects FzwyHook.dll into WeChatAppEx.exe, replacing frida's injection + hook role in vendor/wmpf.
//
// Process selection strategy matches frida's findWmpfProcess: among all WeChatAppEx.exe instances,
// pick the pid that appears most often as a parent — that's the main host process running the
// mini-program; the rest are renderer/tool processes that should not be hooked.
namespace wmpf {

struct HookInstallResult {
    bool ok = false;
    bool alreadyHooked = false; // target was already hooked (skipped, not a failure)
    QString message;
    QString hookLogTail;
};

// Inject and install hook. log can be null.
HookInstallResult installHook(const std::function<void(const QString &)> &log = {});

// Watchdog: ensure the current main host process is hooked by this version of the hook.
// WeChat rotates WeChatAppEx host processes (old processes exit, hooks disappear with them),
// so this must be called periodically; otherwise the next time the user opens a mini-program
// it will load without the hook — the scene ID won't be rewritten and debug mode won't activate.
// When already up-to-date, overhead is minimal (just process/module enumeration); no log spam.
HookInstallResult ensureHooked(const std::function<void(const QString &)> &log = {});

QString hookDllPath();

QString hookLogTail(int lines = 25);

// Trigger online unhook in all WeChatAppEx processes that have any
// FzwyHook variant loaded. Called on app exit to restore the hooked
// function entries so WeChatAppEx doesn't keep running with a hook.
// Returns the number of processes that were successfully commanded.
int unhookAll(const std::function<void(const QString &)> &log = {});

}  // namespace wmpf
