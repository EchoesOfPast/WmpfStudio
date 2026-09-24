#pragma once

#include <QString>
#include <QVector>

// WMPF version -> frida hook offset table (built into Qt resources; sourced from
// the wmpf project's frida/config/win32/addresses.<version>.json, format kept
// identical for easy addition of new versions).
namespace wmpf {

struct Offsets {
    int version = 0;
    quint64 loadStart = 0;      // AppletIndexContainer::OnLoadStart
    quint64 cdpFilter = 0;      // SendToClientFilter
    QVector<int> sceneOffsets;  // 6-level pointer chain offsets

    bool valid() const {
        return version > 0 && loadStart != 0 && cdpFilter != 0 && sceneOffsets.size() == 6;
    }
};

// Parse the WMPF version number from a path:
//   ...\xwechat\xplugin\Plugins\RadiumWMPF\25560\extracted\runtime\WeChatAppEx.exe -> 25560
int versionFromPath(const QString &path);

bool lookup(int version, Offsets *out);

QVector<int> availableVersions();

// For WMPF >= 13331, the hook target is flue.dll; otherwise it's the WeChatAppEx.exe main module
QString targetModuleFor(int version);

}  // namespace wmpf
