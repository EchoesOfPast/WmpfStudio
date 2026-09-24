#include "WmpfProbe.h"

#include <QFile>
#include <QFileInfo>
#include <QHash>

#include "WmpfOffsets.h"
#include "x64len.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace wmpf {
namespace {

const int kPrologueBytes = 32;
const int kPatchSize = 5;                    // E9 rel32
const quint64 kSearchRange = 0x70000000ull;  // +-1.75GB, within rel32 reachable range

quint16 le16(const QByteArray &b, int o) {
    return quint16(quint8(b.at(o))) | (quint16(quint8(b.at(o + 1))) << 8);
}
quint32 le32(const QByteArray &b, int o) {
    return quint32(quint8(b.at(o))) | (quint32(quint8(b.at(o + 1))) << 8) |
           (quint32(quint8(b.at(o + 2))) << 16) | (quint32(quint8(b.at(o + 3))) << 24);
}

// Disassemble a short snippet, for report readability only
QString disasmText(const quint8 *p, int len) {
    QStringList lines;
    int off = 0;
    while (off < len) {
        X64Insn ins;
        if (!x64_decode(p + off, len - off, &ins)) {
            lines << QStringLiteral("  +%1   %2   <不可用> %3")
                         .arg(off, 2, 10, QLatin1Char('0'))
                         .arg(QStringLiteral("%1").arg(p[off], 2, 16, QLatin1Char('0')))
                         .arg(QString::fromUtf8(x64_reason_text(ins.reason)));
            break;
        }
        QString hex;
        for (int k = 0; k < ins.length; ++k)
            hex += QStringLiteral("%1 ").arg(p[off + k], 2, 16, QLatin1Char('0'));
        lines << QStringLiteral("  +%1   %2  %3 字节%4")
                     .arg(off, 2, 10, QLatin1Char('0'))
                     .arg(hex.leftJustified(24, QLatin1Char(' ')))
                     .arg(ins.length)
                     .arg(ins.has_modrm ? QStringLiteral("  (ModRM)") : QString());
        off += ins.length;
    }
    return lines.join(QLatin1Char('\n'));
}

// Read bytes from a PE file on disk by RVA.
// Purpose: when the in-memory prologue has been overwritten by another tool (frida) with E9,
// we can still verify whether the "original prologue" can be safely displaced by reading from
// the on-disk module file. Once we switch to our own implementation, frida won't be running,
// and memory bytes will match disk bytes.
class PeFile {
public:
    bool open(const QString &path) {
        m_file.setFileName(path);
        if (!m_file.open(QIODevice::ReadOnly)) {
            m_err = QStringLiteral("打不开模块文件：%1（%2）").arg(path, m_file.errorString());
            return false;
        }
        const QByteArray hdr = m_file.read(0x1000);
        if (hdr.size() < 0x40 || !hdr.startsWith("MZ")) {
            m_err = QStringLiteral("不是 PE 文件");
            return false;
        }
        const quint32 pe = le32(hdr, 0x3C);
        if (pe + 24 > quint32(hdr.size()) || hdr.mid(pe, 4) != QByteArray("PE\0\0", 4)) {
            m_err = QStringLiteral("PE 头无效");
            return false;
        }
        const quint16 nsec = le16(hdr, pe + 6);
        const quint16 optSize = le16(hdr, pe + 20);
        const int sec0 = int(pe) + 24 + optSize;
        for (int i = 0; i < nsec; ++i) {
            const int o = sec0 + i * 40;
            if (o + 40 > hdr.size())
                break;
            Sec s;
            s.vsize = le32(hdr, o + 8);
            s.va = le32(hdr, o + 12);
            s.rawsize = le32(hdr, o + 16);
            s.rawptr = le32(hdr, o + 20);
            m_secs.append(s);
        }
        if (m_secs.isEmpty()) {
            m_err = QStringLiteral("节表为空");
            return false;
        }
        return true;
    }

    bool readAtRva(quint64 rva, int n, QByteArray *out) const {
        for (const Sec &s : m_secs) {
            const quint64 span = qMax(s.vsize, s.rawsize);
            if (rva >= s.va && rva < s.va + span) {
                if (!m_file.seek(qint64(s.rawptr + (rva - s.va))))
                    return false;
                *out = m_file.read(n);
                return !out->isEmpty();
            }
        }
        return false;
    }

    QString error() const { return m_err; }

private:
    struct Sec {
        quint64 va = 0, vsize = 0, rawptr = 0, rawsize = 0;
    };
    mutable QFile m_file;
    QVector<Sec> m_secs;
    QString m_err;
};

#ifdef _WIN32

QString winErr() { return QStringLiteral("Win32 错误 %1").arg(GetLastError()); }

struct ProcEntry {
    quint32 pid = 0;
    quint32 ppid = 0;
};

QVector<ProcEntry> findProcessEntries(const wchar_t *exeName) {
    QVector<ProcEntry> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) {
                ProcEntry p;
                p.pid = pe.th32ProcessID;
                p.ppid = pe.th32ParentProcessID;
                out.append(p);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

// Same strategy as pickMainProcess in WmpfInject.cpp (frida findWmpfProcess): the pid
// that occurs most often as a parent is the main host. Injection hooks only it, so the
// probe's overall verdict must be based on it too — otherwise a renderer passing its
// checks would falsely yield overallOk while the main host is not hookable.
quint32 pickMainProcessPid(const QVector<ProcEntry> &procs) {
    if (procs.isEmpty())
        return 0;
    QHash<quint32, int> freq;
    for (const ProcEntry &p : procs)
        freq[p.ppid]++;
    quint32 best = 0;
    int bestCount = -1;
    for (auto it = freq.begin(); it != freq.end(); ++it) {
        if (it.value() > bestCount) {
            bestCount = it.value();
            best = it.key();
        }
    }
    for (const ProcEntry &p : procs) {
        if (p.pid == best)
            return best;
    }
    return 0;
}

struct ModInfo {
    QString name;
    quint64 base = 0;
    quint64 size = 0;
    QString path;
};

QVector<ModInfo> listModules(quint32 pid) {
    QVector<ModInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return out;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            ModInfo m;
            m.name = QString::fromWCharArray(me.szModule);
            m.base = reinterpret_cast<quint64>(me.modBaseAddr);
            m.size = me.modBaseSize;
            m.path = QString::fromWCharArray(me.szExePath);
            out.append(m);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return out;
}

bool readMem(HANDLE h, quint64 addr, int n, QByteArray *out) {
    QByteArray buf(n, Qt::Uninitialized);
    SIZE_T got = 0;
    if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), buf.data(), n, &got) || got == 0)
        return false;
    buf.resize(int(got));
    *out = buf;
    return true;
}

// Locate a MEM_FREE region of size >= need within +-range of the target (query only, no allocation)
bool findFreeRegionNear(HANDLE h, quint64 target, quint64 range, quint64 need, quint64 *foundVa,
                        quint64 *foundSize) {
    const quint64 lo = target > range ? target - range : 0x10000ull;
    const quint64 hi = target + range;
    MEMORY_BASIC_INFORMATION mbi{};
    quint64 addr = lo;
    while (addr < hi) {
        if (VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
            break;
        const quint64 regionBase = reinterpret_cast<quint64>(mbi.BaseAddress);
        const quint64 regionSize = mbi.RegionSize;
        if (mbi.State == MEM_FREE && regionSize >= need) {
            if (foundVa)
                *foundVa = regionBase;
            if (foundSize)
                *foundSize = regionSize;
            return true;
        }
        const quint64 next = regionBase + regionSize;
        if (next <= addr)
            break;
        addr = next;
    }
    return false;
}

#endif  // _WIN32

HookSite examineSite(HANDLE h, const PeFile *pe, const QString &name, quint64 rva,
                     quint64 moduleBase) {
    HookSite s;
    s.name = name;
    s.rva = rva;
    s.va = moduleBase + rva;

    if (!readMem(h, s.va, kPrologueBytes, &s.bytes)) {
        s.failReason = QStringLiteral("读取序言失败（%1）").arg(winErr());
        return s;
    }
    if (s.bytes.isEmpty()) {
        s.failReason = QStringLiteral("序言为空");
        return s;
    }
    s.alreadyHooked = (quint8(s.bytes.at(0)) == 0xE9);

    const auto *p = reinterpret_cast<const quint8 *>(s.bytes.constData());
    char why[256] = {};
    const bool memOk = x64_measure_displacement(p, s.bytes.size(), kPatchSize, &s.displacedLen,
                                                &s.insnCount, why, sizeof(why));
    if (!memOk)
        s.failReason = QString::fromUtf8(why);
    s.disasm = disasmText(p, qMin(s.bytes.size(), s.displacedLen > 0 ? s.displacedLen + 16 : 16));

    // Memory is already hooked -> fall back to on-disk original bytes for the verdict
    if (s.alreadyHooked && pe) {
        QByteArray raw;
        s.diskChecked = true;
        if (pe->readAtRva(rva, kPrologueBytes, &raw)) {
            int dl = 0, ic = 0;
            char dw[256] = {};
            s.diskDecodable = x64_measure_displacement(
                reinterpret_cast<const quint8 *>(raw.constData()), raw.size(), kPatchSize, &dl, &ic,
                dw, sizeof(dw));
            s.diskNote = s.diskDecodable
                             ? QStringLiteral("磁盘原始序言可搬移 %1 字节").arg(dl)
                             : QStringLiteral("磁盘原始序言不可搬移：%1").arg(QString::fromUtf8(dw));
        } else {
            s.diskNote = QStringLiteral("按 RVA 读取模块文件失败");
        }
    }

    s.decodable = memOk || (s.alreadyHooked && s.diskDecodable);

    findFreeRegionNear(h, s.va, kSearchRange, 0x10000, &s.freeRegionVa, &s.freeRegionSize);
    s.jumpRel32Reachable = (s.freeRegionVa != 0);
    return s;
}

}  // namespace

bool readModuleBytesFromDisk(const QString &modulePath, quint64 rva, int n, QByteArray *out) {
    PeFile pe;
    if (!pe.open(modulePath))
        return false;
    return pe.readAtRva(rva, n, out);
}

ProbeReport runProbe(const std::function<void(const QString &)> &log) {
    const auto lg = [&log](const QString &m) {
        if (log)
            log(m);
    };

    ProbeReport rep;
    const QVector<int> vers = availableVersions();
    rep.offsetTableVersions = vers.size();
    if (!vers.isEmpty())
        rep.offsetTableRange = {vers.first(), vers.last()};
    lg(QStringLiteral("内置偏移表：%1 个版本（%2 – %3）")
           .arg(rep.offsetTableVersions)
           .arg(rep.offsetTableRange.value(0))
           .arg(rep.offsetTableRange.value(1)));

#ifdef _WIN32
    const QVector<ProcEntry> procs = findProcessEntries(L"WeChatAppEx.exe");
    rep.wechatProcessCount = procs.size();
    lg(QStringLiteral("找到 WeChatAppEx.exe 进程 %1 个").arg(procs.size()));
    if (procs.isEmpty()) {
        rep.verdict = QStringLiteral("未发现 WeChatAppEx.exe —— 请先登录 PC 微信并打开一次小程序");
        return rep;
    }
    // Injection hooks only the main host selected by pickMainProcessPid, so the overall verdict is based on it
    const quint32 mainPid = pickMainProcessPid(procs);

    for (const ProcEntry &proc : procs) {
        const quint32 pid = proc.pid;
        ProcessReport pr;
        pr.pid = pid;
        pr.mainHost = (pid == mainPid);

        const QVector<ModInfo> mods = listModules(pid);
        if (mods.isEmpty()) {
            pr.note = QStringLiteral("枚举模块失败（权限不足？）");
            rep.processes.append(pr);
            continue;
        }
        ModInfo exeMod;
        for (const ModInfo &m : mods) {
            if (m.name.compare(QStringLiteral("WeChatAppEx.exe"), Qt::CaseInsensitive) == 0) {
                exeMod = m;
                break;
            }
        }
        pr.version = versionFromPath(exeMod.path);
        if (pr.version <= 0) {
            pr.note = QStringLiteral("无法从路径解析 WMPF 版本：%1").arg(exeMod.path);
            rep.processes.append(pr);
            continue;
        }
        const QString target = targetModuleFor(pr.version);
        ModInfo tgt;
        bool found = false;
        for (const ModInfo &m : mods) {
            if (m.name.compare(target, Qt::CaseInsensitive) == 0) {
                tgt = m;
                found = true;
                break;
            }
        }
        if (!found) {
            pr.note = QStringLiteral("版本 %1 需要模块 %2，但该进程未加载")
                          .arg(pr.version)
                          .arg(target);
            rep.processes.append(pr);
            continue;
        }
        pr.moduleName = tgt.name;
        pr.moduleBase = tgt.base;
        pr.moduleSize = tgt.size;

        Offsets off;
        pr.offsetsFound = lookup(pr.version, &off);
        if (!pr.offsetsFound) {
            pr.note = QStringLiteral("偏移表里没有版本 %1（内置范围 %2–%3）")
                          .arg(pr.version)
                          .arg(rep.offsetTableRange.value(0))
                          .arg(rep.offsetTableRange.value(1));
            rep.processes.append(pr);
            continue;
        }

        PeFile pe;
        if (!tgt.path.isEmpty() && !pe.open(tgt.path))
            lg(QStringLiteral("pid %1：磁盘模块校验不可用（%2）").arg(pid).arg(pe.error()));

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) {
            pr.note = QStringLiteral("OpenProcess 失败（%1）").arg(winErr());
            rep.processes.append(pr);
            continue;
        }
        pr.sites.append(examineSite(h, &pe, QStringLiteral("OnLoadStart"), off.loadStart, tgt.base));
        pr.sites.append(examineSite(h, &pe, QStringLiteral("SendToClientFilter"), off.cdpFilter,
                                    tgt.base));
        CloseHandle(h);

        bool allOk = true;
        for (const HookSite &s : pr.sites)
            allOk = allOk && s.decodable && s.jumpRel32Reachable;
        pr.ok = allOk;
        rep.processes.append(pr);
    }

    // overallOk reflects the main host's result, not "any process OK": injection hooks
    // only the main host, so a renderer passing its checks proves nothing.
    for (const ProcessReport &pr : rep.processes) {
        if (pr.mainHost) {
            rep.overallOk = pr.ok;
            break;
        }
    }
    if (rep.overallOk) {
        rep.verdict = QStringLiteral("主宿主进程（pid=%1）的序言可安全搬移，且目标附近有可放跳板的空闲内存 → 可以挂钩。")
                          .arg(mainPid);
    } else {
        rep.verdict = QStringLiteral("主宿主进程（pid=%1）未同时满足「序言可搬移」和「附近有空闲内存」→ 暂不可挂钩。")
                          .arg(mainPid);
    }
#else
    rep.verdict = QStringLiteral("只支持 Windows");
#endif

    return rep;
}

QString formatProbeReport(const ProbeReport &r) {
    QStringList out;
    out << QStringLiteral("========== WMPF 通道只读体检 ==========");
    out << QStringLiteral("内置偏移表：%1 个版本，范围 %2 – %3")
               .arg(r.offsetTableVersions)
               .arg(r.offsetTableRange.value(0))
               .arg(r.offsetTableRange.value(1));
    out << QStringLiteral("WeChatAppEx.exe 进程数：%1").arg(r.wechatProcessCount);
    out << QString();

    for (const ProcessReport &p : r.processes) {
        out << QStringLiteral("--- pid %1 %2---")
                   .arg(p.pid)
                   .arg(p.mainHost ? QStringLiteral("（主宿主）") : QString());
        if (!p.note.isEmpty())
            out << QStringLiteral("  说明：%1").arg(p.note);
        if (p.moduleBase == 0) {
            out << QString();
            continue;
        }
        out << QStringLiteral("  模块：%1  base=0x%2  size=0x%3")
                   .arg(p.moduleName)
                   .arg(p.moduleBase, 0, 16)
                   .arg(p.moduleSize, 0, 16);
        out << QStringLiteral("  WMPF 版本：%1   偏移表：%2")
                   .arg(p.version)
                   .arg(p.offsetsFound ? QStringLiteral("命中") : QStringLiteral("缺失"));
        out << QStringLiteral("  结论：%1")
                   .arg(p.ok ? QStringLiteral("[可挂钩]") : QStringLiteral("[不可挂钩]"));
        for (const HookSite &s : p.sites) {
            out << QStringLiteral("  · %1  RVA=0x%2  VA=0x%3")
                       .arg(s.name)
                       .arg(s.rva, 0, 16)
                       .arg(s.va, 0, 16);
            out << QStringLiteral("      内存已挂钩=%1  可搬移=%2  搬移 %3 字节/%4 条  跳板空闲区=%5")
                       .arg(s.alreadyHooked ? QStringLiteral("是(E9)") : QStringLiteral("否"))
                       .arg(s.decodable ? QStringLiteral("是") : QStringLiteral("否"))
                       .arg(s.displacedLen)
                       .arg(s.insnCount)
                       .arg(s.jumpRel32Reachable
                                ? QStringLiteral("有 0x%1 (0x%2)")
                                      .arg(s.freeRegionVa, 0, 16)
                                      .arg(s.freeRegionSize, 0, 16)
                                : QStringLiteral("无"));
            if (!s.failReason.isEmpty())
                out << QStringLiteral("      内存判定失败：%1").arg(s.failReason);
            if (s.diskChecked)
                out << QStringLiteral("      磁盘原始序言：%1").arg(s.diskNote);
            out << s.disasm;
        }
        out << QString();
    }

    out << QStringLiteral("======================================");
    out << QStringLiteral("总判定：%1").arg(r.verdict);
    return out.join(QLatin1Char('\n'));
}

}  // namespace wmpf
