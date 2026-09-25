#pragma once

#include <QByteArray>
#include <QMutex>
#include <QString>
#include <QVector>

// Client side of the FzwyHook.dll memory-instrument IPC (see FzwyHook.cpp).
// Thin Qt + Win32 wrapper over the FxIpcShm_<pid>_<dllBaseName> shared-memory
// block and the FxIpcReq_/FxIpcResp_ events. Every call is synchronous with a
// 3s timeout and returns a plain error string — call from a worker thread,
// never the UI thread.
namespace wmpf {

struct FxModuleInfo {
    QString name;
    quint64 base = 0;
    quint64 size = 0;
};

struct FxExportInfo {
    QString name;
    quint64 addr = 0;
};

class FxInstrument {
public:
    FxInstrument();
    ~FxInstrument();

    // Open the SHM + both events created by the hook DLL inside process `pid`.
    // dllBaseName is the hook DLL's file name without extension
    // (e.g. "FzwyHook_ab12cd34ef56"). Missing objects -> explicit error.
    bool attach(quint32 pid, const QString &dllBaseName, QString *err);
    bool attached() const { return m_view != nullptr; }
    void detach();

    // FxRead: read len bytes (<= 0x10000, effectively ~55KB) at addr.
    bool read(quint64 addr, quint32 len, QByteArray *out, QString *err);
    // FxWrite: write data (<= 4096 bytes) at addr.
    bool write(quint64 addr, const QByteArray &data, QString *err);
    // FxModules: enumerate all loaded modules of the target process.
    bool modules(QVector<FxModuleInfo> *out, QString *err);
    // FxExports: parse the export directory of moduleBase (0 = flue.dll / hook DLL).
    bool exports(quint64 moduleBase, QVector<FxExportInfo> *out, QString *err);
    // FxScan: pattern match in [start, start+length). mask bytes are 'x' (exact)
    // or '?' (wildcard), one per pattern byte. Returns true when the IPC round
    // trip succeeded; *hit == 0 means "not found".
    bool scan(quint64 start, quint64 length, const QByteArray &pattern, const QByteArray &mask,
              quint64 *hit, QString *err);
    // FxCall: call the function at fnAddr with up to 4 integer args (x64 ABI
    // rcx/rdx/r8/r9). WARNING: an arbitrary call target can crash the target
    // process — that is inherent to what this instrument is for.
    bool callAddr(quint64 fnAddr, quint64 a0, quint64 a1, quint64 a2, quint64 a3, quint64 *ret,
                  QString *err);

private:
    // One full request/response round trip; outPayload may be null.
    bool request(quint32 op, quint64 addr, quint64 arg2, quint64 arg3, const void *payload,
                 quint32 payloadLen, int *status, quint64 *value, QByteArray *outPayload,
                 QString *err);

    void *m_mapping = nullptr;  // HANDLEs kept as void* to keep windows.h out of the header
    void *m_view = nullptr;
    void *m_reqEv = nullptr;
    void *m_respEv = nullptr;
    QMutex m_mutex;  // serialize round trips if used from several threads
};

}  // namespace wmpf
