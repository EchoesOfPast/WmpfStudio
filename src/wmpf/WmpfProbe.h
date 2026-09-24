#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVector>

#include <functional>

// WMPF debug channel read-only probe.
//
// Only does reads (OpenProcess + ReadProcessMemory + VirtualQueryEx);
// never writes a single byte — zero crash risk. Used to confirm before actually hooking:
//   - Can we locate WeChatAppEx / flue.dll; is the version number correct?
//   - Does the offset table have this version?
//   - Can the prologue of both hook points be safely displaced (instruction length decode passes)?
//   - Is there free memory within +-2GB of the target for a trampoline (prerequisite for rel32 jump)?
//   - Has it already been hooked by another tool (first byte is E9)?
namespace wmpf {

struct HookSite {
    QString name;
    quint64 rva = 0;
    quint64 va = 0;
    int displacedLen = 0;     // bytes that need to be displaced (>= 5-byte rel32 jmp)
    int insnCount = 0;
    bool decodable = false;   // final verdict: displacement is feasible
    bool alreadyHooked = false;  // first byte in memory is E9 (hooked by another tool)
    bool jumpRel32Reachable = false;  // free region for a trampoline within +-2GB
    quint64 freeRegionVa = 0;
    quint64 freeRegionSize = 0;
    QString failReason;
    QByteArray bytes;         // original prologue in memory (32 bytes)
    QString disasm;

    // When memory is already hooked, use the on-disk module file to verify whether the
    // "original" prologue can be displaced. Once we switch to our own implementation,
    // frida won't be running and memory bytes will match disk bytes.
    bool diskChecked = false;
    bool diskDecodable = false;
    QString diskNote;
};

struct ProcessReport {
    quint32 pid = 0;
    QString moduleName;
    quint64 moduleBase = 0;
    quint64 moduleSize = 0;
    int version = -1;
    bool offsetsFound = false;
    bool ok = false;
    bool mainHost = false;  // main host selected by pickMainProcess (injection hooks only it; overallOk is based on it)
    QString note;
    QVector<HookSite> sites;
};

struct ProbeReport {
    int offsetTableVersions = 0;
    QVector<int> offsetTableRange;  // {min, max}
    int wechatProcessCount = 0;
    QVector<ProcessReport> processes;
    bool overallOk = false;
    QString verdict;
};

// Run the read-only probe; log can be null
ProbeReport runProbe(const std::function<void(const QString &)> &log = {});

// Read original bytes from the on-disk module file by RVA.
// Purpose: cleaning up leftover hooks — when the previous tool (frida) was killed
// with taskkill /F, the agent had no time to restore the target function entry,
// leaving E9 in the WeChat process. This retrieves the original bytes from disk for restoration.
bool readModuleBytesFromDisk(const QString &modulePath, quint64 rva, int n, QByteArray *out);

QString formatProbeReport(const ProbeReport &r);

}  // namespace wmpf
