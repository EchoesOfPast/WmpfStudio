#include <QApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QJsonDocument>
#include <QStringList>
#include <QTextStream>

#include <cstdio>
#include <cstring>

#if defined(Q_OS_WIN)
#include <windows.h>
#endif

#include "../WxPkg.h"
#include "StudioWindow.h"

namespace {

// Headless offline-unpack smoke test (--unpack-test <pkg.wxapkg> <appId> [outRoot]).
// Mirrors the "解包全部" flow: decrypt, unpack, then verify app-config.json is
// valid JSON. Returns the process exit code.
int unpackTest(const QString &pkgPath, const QString &appId, const QString &outRoot) {
#if defined(Q_OS_WIN)
    // GUI-subsystem apps get no console of their own. If stdout was not already
    // redirected (pipe/file), attach to the caller's console for visible output.
    const HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    const bool redirected =
        hOut != nullptr && hOut != INVALID_HANDLE_VALUE && GetFileType(hOut) != FILE_TYPE_UNKNOWN;
    if (!redirected && AttachConsole(ATTACH_PARENT_PROCESS) != 0)
        std::freopen("CONOUT$", "w", stdout);
#endif
    QTextStream ts(stdout);
    const QFileInfo fi(pkgPath);
    const QString outDir = outRoot + QLatin1Char('/') + appId + QLatin1Char('/') +
                           fi.dir().dirName() + QLatin1Char('/') + fi.completeBaseName();

    QString err;
    const QByteArray plain = WxPkg::decryptFile(pkgPath, appId, &err);
    if (plain.isEmpty()) {
        ts << "decrypt FAILED: " << err << "\n";
        return 1;
    }
    ts << "decrypt ok: " << plain.size() << " bytes, magic=0x"
       << QString::number(static_cast<uchar>(plain[0]), 16) << "\n";

    const int n = WxPkg::unpackToDir(plain, outDir, &err);
    if (n < 0) {
        ts << "unpack FAILED: " << err << "\n";
        return 1;
    }
    ts << "unpack ok: " << n << " files -> " << outDir << "\n";

    const QString cfgPath = outDir + QStringLiteral("/app-config.json");
    QFile cfg(cfgPath);
    if (!cfg.open(QIODevice::ReadOnly)) {
        ts << "app-config.json MISSING at " << cfgPath << "\n";
        return 1;
    }
    const QByteArray cfgBytes = cfg.readAll();
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(cfgBytes, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        ts << "app-config.json INVALID JSON: " << pe.errorString() << "\n";
        return 1;
    }
    ts << "app-config.json valid JSON (" << cfgBytes.size() << " bytes), first lines:\n";
    const QStringList lines = QString::fromUtf8(cfgBytes).split(QLatin1Char('\n'));
    for (int i = 0; i < qMin(5, lines.size()); ++i)
        ts << "  " << lines[i].left(160) << "\n";
    return 0;
}

}  // namespace

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    QApplication::setApplicationName(QStringLiteral("WmpfStudio"));
    a.setFont(QFont(QStringList{QStringLiteral("Inter"), QStringLiteral("Segoe UI"),
                                QStringLiteral("Microsoft YaHei")}));

    // Offscreen UI verification: --screenshot <png>
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--screenshot") == 0 && i + 1 < argc) {
            StudioWindow w;
            w.resize(640, 560);
            w.grab().save(QString::fromLocal8Bit(argv[i + 1]));
            return 0;
        }
    }

    // Headless offline unpack test: --unpack-test <pkg.wxapkg> <appId> [outRoot]
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--unpack-test") == 0 && i + 2 < argc) {
            const QString outRoot =
                i + 3 < argc ? QString::fromLocal8Bit(argv[i + 3])
                             : QCoreApplication::applicationDirPath() + QStringLiteral("/unpacked");
            return unpackTest(QString::fromLocal8Bit(argv[i + 1]),
                              QString::fromLocal8Bit(argv[i + 2]), outRoot);
        }
    }

    StudioWindow w;
    w.show();
    return QApplication::exec();
}
