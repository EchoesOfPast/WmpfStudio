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
#include "../wmpf/FxInstrument.h"
#include "../wmpf/WmpfInject.h"
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

#if defined(Q_OS_WIN)
QString hexDumpCli(quint64 base, const QByteArray &data) {
    QString out;
    QTextStream ts(&out);
    for (int off = 0; off < data.size(); off += 16) {
        const int n = qMin(16, int(data.size()) - off);
        ts << QString("0x%1  ").arg(base + quint64(off), 16, 16, QLatin1Char('0'));
        QString hex;
        for (int i = 0; i < n; ++i)
            hex += QString("%1 ").arg(uchar(data[off + i]), 2, 16, QLatin1Char('0'));
        ts << hex.leftJustified(16 * 3);
        for (int i = 0; i < n; ++i) {
            const uchar b = uchar(data[off + i]);
            ts << ((b >= 32 && b <= 126) ? QChar(char(b)) : QChar('.'));
        }
        ts << "\n";
    }
    return out;
}

// Memory-instrument self test (--fx-test). Loads FzwyHook.dll from our own
// directory (its worker thread brings up the IPC even though doInstall finds
// no flue.dll here), then exercises every op against this very process.
// Exit code 0 iff all checks pass.
int fxTest() {
    // Same console handling as --unpack-test (GUI subsystem app).
    const HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    const bool redirected =
        hOut != nullptr && hOut != INVALID_HANDLE_VALUE && GetFileType(hOut) != FILE_TYPE_UNKNOWN;
    if (!redirected && AttachConsole(ATTACH_PARENT_PROCESS) != 0)
        std::freopen("CONOUT$", "w", stdout);
    QTextStream ts(stdout);

    const QString dllPath = QCoreApplication::applicationDirPath() + QStringLiteral("/FzwyHook.dll");
    ts << "LoadLibrary: " << dllPath << "\n";
    const HMODULE hdll = LoadLibraryW(reinterpret_cast<const wchar_t *>(dllPath.utf16()));
    if (!hdll) {
        ts << "LoadLibrary FAILED: " << GetLastError() << "\n";
        return 1;
    }
    Sleep(1500);  // give the hook's worker thread time to bring up the IPC

    // The variant name is the loaded module's file name without extension.
    QString baseName;
    const QStringList own = wmpf::loadedHookDllNames(GetCurrentProcessId());
    for (const QString &n : own) {
        baseName = n;
        const int dot = baseName.lastIndexOf(QLatin1Char('.'));
        if (dot > 0)
            baseName = baseName.left(dot);
        break;
    }
    if (baseName.isEmpty()) {
        ts << "hook DLL not found in own module list\n";
        return 1;
    }
    ts << "hook variant: " << baseName << "\n";

    wmpf::FxInstrument fx;
    QString err;
    if (!fx.attach(GetCurrentProcessId(), baseName, &err)) {
        ts << "attach FAILED: " << err << "\n";
        return 1;
    }
    ts << "attach ok (pid=" << GetCurrentProcessId() << ")\n\n";

    int pass = 0, total = 0;
    const auto check = [&ts, &pass, &total](bool ok, const QString &name) {
        ++total;
        if (ok)
            ++pass;
        ts << (ok ? "[PASS] " : "[FAIL] ") << name << "\n";
    };

    // 1. modules
    QVector<wmpf::FxModuleInfo> mods;
    if (fx.modules(&mods, &err)) {
        ts << "modules: " << mods.size() << " entries, first 5:\n";
        for (int i = 0; i < qMin(5, int(mods.size())); ++i)
            ts << QString("  %1\t0x%2\t%3\n")
                      .arg(mods[i].name)
                      .arg(mods[i].base, 0, 16)
                      .arg(mods[i].size);
        check(mods.size() >= 3, "modules >= 3");
    } else {
        ts << "modules FAILED: " << err << "\n";
        check(false, "modules >= 3");
    }

    // 2. read own MZ header
    const quint64 selfBase = reinterpret_cast<quint64>(GetModuleHandleW(nullptr));
    QByteArray mz;
    if (fx.read(selfBase, 64, &mz, &err)) {
        ts << "\nread own MZ header, 64 bytes:\n" << hexDumpCli(selfBase, mz);
        check(mz.size() == 64 && mz[0] == 'M' && mz[1] == 'Z', "read MZ magic");
    } else {
        ts << "read FAILED: " << err << "\n";
        check(false, "read MZ magic");
    }

    // 3. write + read-back on a scratch page
    void *page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    const quint64 pageAddr = reinterpret_cast<quint64>(page);
    QByteArray wrote;
    for (int i = 0; i < 32; ++i)
        wrote.append(char(0xA0 + i));
    bool wroteOk = false, readBackOk = false;
    if (page && fx.write(pageAddr, wrote, &err)) {
        wroteOk = true;
        QByteArray back;
        if (fx.read(pageAddr, quint32(wrote.size()), &back, &err))
            readBackOk = (back == wrote);
        ts << QString("\nwrite+read-back @0x%1: %2\n").arg(pageAddr, 0, 16).arg(QString::fromLatin1(readBackOk ? back.toHex(' ') : QByteArray("<readback failed>")));
    } else {
        ts << "write FAILED: " << err << "\n";
    }
    check(wroteOk && readBackOk && page && memcmp(page, wrote.constData(), size_t(wrote.size())) == 0,
          "write+read-back match");
    if (page)
        VirtualFree(page, 0, MEM_RELEASE);

    // 4. scan own DOS stub for "This program"
    const QByteArray pat("This program");
    const QByteArray mask(pat.size(), 'x');
    quint64 hit = 0;
    if (fx.scan(selfBase, 0x1000, pat, mask, &hit, &err)) {
        ts << QString("scan \"This program\" in [0x%1, +0x1000): %2\n")
                  .arg(selfBase, 0, 16)
                  .arg(hit ? QString("hit @0x%1 (RVA 0x%2)").arg(hit, 0, 16).arg(hit - selfBase, 0, 16)
                           : QString("NOT FOUND"));
        check(hit != 0, "scan hit");
    } else {
        ts << "scan FAILED: " << err << "\n";
        check(false, "scan hit");
    }

    // 5. call kernel32!GetCurrentProcessId() inside ourselves via the instrument
    const HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    const quint64 fn = reinterpret_cast<quint64>(
        reinterpret_cast<void *>(GetProcAddress(k32, "GetCurrentProcessId")));
    quint64 ret = 0;
    if (fx.callAddr(fn, 0, 0, 0, 0, &ret, &err)) {
        ts << QString("call GetCurrentProcessId() -> %1 (real pid %2)\n")
                  .arg(ret)
                  .arg(GetCurrentProcessId());
        check(ret == GetCurrentProcessId(), "call returns real pid");
    } else {
        ts << "call FAILED: " << err << "\n";
        check(false, "call returns real pid");
    }

    // 6. exports of kernel32 (hand-parsed PE export directory in the hook DLL)
    QVector<wmpf::FxExportInfo> exps;
    if (fx.exports(reinterpret_cast<quint64>(k32), &exps, &err)) {
        bool hasPid = false;
        for (const wmpf::FxExportInfo &e : exps) {
            if (e.name == QLatin1String("GetCurrentProcessId")) {
                hasPid = true;
                break;
            }
        }
        ts << QString("exports(kernel32): %1 entries, first 3:\n").arg(exps.size());
        for (int i = 0; i < qMin(3, int(exps.size())); ++i)
            ts << QString("  %1\t0x%2\n").arg(exps[i].name).arg(exps[i].addr, 0, 16);
        check(!exps.isEmpty() && hasPid, "exports contain GetCurrentProcessId");
    } else {
        ts << "exports FAILED: " << err << "\n";
        check(false, "exports contain GetCurrentProcessId");
    }

    ts << QString("\nfx-test: %1/%2 passed\n").arg(pass).arg(total);
    return pass == total ? 0 : 1;
}
#endif  // Q_OS_WIN

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
            w.resize(760, 780);
            w.grab().save(QString::fromLocal8Bit(argv[i + 1]));
            return 0;
        }
    }

    // Memory-instrument self test: --fx-test
#if defined(Q_OS_WIN)
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--fx-test") == 0)
            return fxTest();
    }
#endif

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
