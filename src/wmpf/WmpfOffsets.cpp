#include "WmpfOffsets.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

namespace wmpf {
namespace {

const char *kOffsetResDir = ":/wmpf-offsets/win32";
const int kFlueDllFromVersion = 13331;

QString resPathFor(int version) {
    return QStringLiteral("%1/addresses.%2.json").arg(QLatin1String(kOffsetResDir)).arg(version);
}

}  // namespace

int versionFromPath(const QString &path) {
    // Only match the RadiumWMPF\<number>\ segment to avoid picking up other numbers in the path
    static const QRegularExpression re(
        QStringLiteral("RadiumWMPF[\\\\/](\\d+)[\\\\/]"),
        QRegularExpression::CaseInsensitiveOption);
    const auto m = re.match(path);
    if (m.hasMatch())
        return m.captured(1).toInt();
    return -1;
}

bool lookup(int version, Offsets *out) {
    if (!out)
        return false;
    *out = Offsets{};
    if (version <= 0)
        return false;
    QFile f(resPathFor(version));
    if (!f.open(QIODevice::ReadOnly))
        return false;
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject())
        return false;
    const QJsonObject o = doc.object();

    Offsets r;
    r.version = o.value(QStringLiteral("Version")).toInt();
    const QString ls = o.value(QStringLiteral("LoadStartHookOffset")).toString();
    const QString cf = o.value(QStringLiteral("CDPFilterHookOffset")).toString();
    bool ok1 = false, ok2 = false;
    r.loadStart = ls.toULongLong(&ok1, 16);
    r.cdpFilter = cf.toULongLong(&ok2, 16);
    for (const QJsonValue &v : o.value(QStringLiteral("SceneOffsets")).toArray())
        r.sceneOffsets.append(v.toInt());
    // valid() centrally rejects malformed tables (zero offsets / missing version / wrong chain length)
    if (!ok1 || !ok2 || !r.valid())
        return false;
    *out = r;
    return true;
}

QVector<int> availableVersions() {
    QVector<int> out;
    const QDir dir{QString::fromLatin1(kOffsetResDir)};
    static const QRegularExpression re(QStringLiteral("^addresses\\.(\\d+)\\.json$"));
    for (const QString &name : dir.entryList(QDir::Files)) {
        const auto m = re.match(name);
        if (m.hasMatch())
            out.append(m.captured(1).toInt());
    }
    std::sort(out.begin(), out.end());
    return out;
}

QString targetModuleFor(int version) {
    return version >= kFlueDllFromVersion ? QStringLiteral("flue.dll")
                                          : QStringLiteral("WeChatAppEx.exe");
}

}  // namespace wmpf
