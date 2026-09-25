#include "FxInstrument.h"

#include <QMutexLocker>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace wmpf {

namespace {

// Layout constants — must match FzwyHook.cpp exactly.
constexpr quint32 kReqMagic = 0x46585251u;   // 'FXRQ'
constexpr quint32 kRespMagic = 0x46585253u;  // 'FXRS'
constexpr size_t kShmSize = 64 * 1024;
constexpr size_t kReqPayloadOff = 4096;
constexpr size_t kReqPayloadCap = 4096;
constexpr size_t kRespHdrOff = 8192;
constexpr size_t kRespPayloadOff = 8224;
constexpr size_t kRespPayloadCap = kShmSize - kRespPayloadOff;
constexpr quint32 kTimeoutMs = 3000;

constexpr quint32 kOpRead = 1;
constexpr quint32 kOpWrite = 2;
constexpr quint32 kOpModules = 3;
constexpr quint32 kOpExports = 4;
constexpr quint32 kOpScan = 5;
constexpr quint32 kOpCall = 6;

#pragma pack(push, 1)
struct ReqHdr {
    quint32 magic;
    quint32 op;
    quint64 addr;
    quint64 arg2;
    quint64 arg3;
    quint32 reserved;
};
struct RespHdr {
    quint32 magic;
    qint32 status;
    quint64 value;
    quint32 outLen;
    quint32 reserved;
};
#pragma pack(pop)
static_assert(sizeof(ReqHdr) == 36, "ReqHdr layout");
static_assert(sizeof(RespHdr) == 24, "RespHdr layout");

#ifdef _WIN32
QString winErr(DWORD code = GetLastError()) {
    wchar_t text[512] = {};
    const DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                   nullptr, code, 0, text,
                                   static_cast<DWORD>(sizeof(text) / sizeof(text[0])), nullptr);
    QString message = n ? QString::fromWCharArray(text).trimmed()
                        : QStringLiteral("未知错误");
    return QStringLiteral("Win32 错误 %1：%2").arg(code).arg(message);
}
#endif

}  // namespace

FxInstrument::FxInstrument() = default;

FxInstrument::~FxInstrument() {
    detach();
}

bool FxInstrument::attach(quint32 pid, const QString &dllBaseName, QString *err) {
    detach();
#ifdef _WIN32
    const QString suffix = QStringLiteral("_%1_%2").arg(pid).arg(dllBaseName);

    const QString shmName = QStringLiteral("FxIpcShm") + suffix;
    HANDLE mapping =
        OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE,
                         reinterpret_cast<const wchar_t *>(shmName.utf16()));
    if (!mapping) {
        if (err)
            *err = QStringLiteral("找不到仪器共享内存 %1（%2）——hook 未安装/仪器通道未建立，请先启动通道")
                       .arg(shmName, winErr());
        return false;
    }
    void *view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, kShmSize);
    if (!view) {
        if (err)
            *err = QStringLiteral("MapViewOfFile 失败（%1）").arg(winErr());
        CloseHandle(mapping);
        return false;
    }
    HANDLE ev[2] = {nullptr, nullptr};
    const QString names[2] = {QStringLiteral("FxIpcReq") + suffix,
                              QStringLiteral("FxIpcResp") + suffix};
    for (int i = 0; i < 2; ++i) {
        ev[i] = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE,
                           reinterpret_cast<const wchar_t *>(names[i].utf16()));
        if (!ev[i]) {
            if (err)
                *err = QStringLiteral("找不到仪器事件 %1（%2）——hook 未安装/仪器通道未建立，请先启动通道")
                           .arg(names[i], winErr());
            if (ev[0])
                CloseHandle(ev[0]);
            UnmapViewOfFile(view);
            CloseHandle(mapping);
            return false;
        }
    }
    m_mapping = mapping;
    m_view = view;
    m_reqEv = ev[0];
    m_respEv = ev[1];
    return true;
#else
    Q_UNUSED(pid);
    Q_UNUSED(dllBaseName);
    if (err)
        *err = QStringLiteral("只支持 Windows");
    return false;
#endif
}

void FxInstrument::detach() {
#ifdef _WIN32
    if (m_reqEv) {
        CloseHandle(m_reqEv);
        m_reqEv = nullptr;
    }
    if (m_respEv) {
        CloseHandle(m_respEv);
        m_respEv = nullptr;
    }
    if (m_view) {
        UnmapViewOfFile(m_view);
        m_view = nullptr;
    }
    if (m_mapping) {
        CloseHandle(m_mapping);
        m_mapping = nullptr;
    }
#endif
}

bool FxInstrument::request(quint32 op, quint64 addr, quint64 arg2, quint64 arg3,
                           const void *payload, quint32 payloadLen, int *status, quint64 *value,
                           QByteArray *outPayload, QString *err) {
#ifdef _WIN32
    QMutexLocker lk(&m_mutex);
    if (!m_view || !m_reqEv || !m_respEv) {
        if (err)
            *err = QStringLiteral("仪器未连接");
        return false;
    }
    if (payloadLen > kReqPayloadCap) {
        if (err)
            *err = QStringLiteral("请求负载过大（%1 > %2）").arg(payloadLen).arg(kReqPayloadCap);
        return false;
    }
    auto *view = static_cast<quint8 *>(m_view);

    // Consume any stale response signal left over from a previous timed-out
    // request before issuing a new one; otherwise we'd read yesterday's answer.
    WaitForSingleObject(m_respEv, 0);

    ReqHdr req{};
    req.magic = kReqMagic;
    req.op = op;
    req.addr = addr;
    req.arg2 = arg2;
    req.arg3 = arg3;
    memcpy(view, &req, sizeof(req));
    if (payloadLen)
        memcpy(view + kReqPayloadOff, payload, payloadLen);
    if (!SetEvent(m_reqEv)) {
        if (err)
            *err = QStringLiteral("SetEvent(req) 失败（%1）").arg(winErr());
        return false;
    }
    const DWORD w = WaitForSingleObject(m_respEv, kTimeoutMs);
    if (w != WAIT_OBJECT_0) {
        if (err) {
            if (w == WAIT_TIMEOUT)
                *err = QStringLiteral("等待仪器响应超时（%1 ms）——目标进程内的 hook DLL 可能已失效")
                           .arg(kTimeoutMs);
            else
                *err = QStringLiteral("等待仪器响应失败（%1）").arg(winErr());
        }
        return false;
    }
    RespHdr resp{};
    memcpy(&resp, view + kRespHdrOff, sizeof(resp));
    if (resp.magic != kRespMagic) {
        if (err)
            *err = QStringLiteral("响应 magic 不匹配（0x%1）——通道另一端的 DLL 版本过旧")
                       .arg(resp.magic, 0, 16);
        return false;
    }
    if (status)
        *status = resp.status;
    if (value)
        *value = resp.value;
    if (outPayload) {
        outPayload->clear();
        const quint32 n = resp.outLen < quint32(kRespPayloadCap) ? resp.outLen
                                                                 : quint32(kRespPayloadCap);
        if (n)
            outPayload->append(reinterpret_cast<const char *>(view + kRespPayloadOff), int(n));
    }
    return true;
#else
    Q_UNUSED(op);
    if (err)
        *err = QStringLiteral("只支持 Windows");
    return false;
#endif
}

bool FxInstrument::read(quint64 addr, quint32 len, QByteArray *out, QString *err) {
    int status = 0;
    quint64 value = 0;
    if (!request(kOpRead, addr, len, 0, nullptr, 0, &status, &value, out, err))
        return false;
    if (status != 0) {
        if (err)
            *err = status == -2
                       ? QStringLiteral("参数非法（地址为空或长度超上限）")
                       : QStringLiteral("目标内存 0x%1 不可读（未提交或保护页）").arg(addr, 0, 16);
        return false;
    }
    return true;
}

bool FxInstrument::write(quint64 addr, const QByteArray &data, QString *err) {
    if (data.isEmpty() || data.size() > int(kReqPayloadCap)) {
        if (err)
            *err = QStringLiteral("写入长度须为 1–%1 字节（当前 %2）").arg(kReqPayloadCap).arg(data.size());
        return false;
    }
    int status = 0;
    if (!request(kOpWrite, addr, quint32(data.size()), 0, data.constData(),
                 quint32(data.size()), &status, nullptr, nullptr, err))
        return false;
    if (status != 0) {
        if (err)
            *err = status == -2
                       ? QStringLiteral("参数非法（地址为空或长度超上限）")
                       : QStringLiteral("目标内存 0x%1 不可写（VirtualProtect 也无法放开）")
                             .arg(addr, 0, 16);
        return false;
    }
    return true;
}

bool FxInstrument::modules(QVector<FxModuleInfo> *out, QString *err) {
    QByteArray text;
    int status = 0;
    if (!request(kOpModules, 0, 0, 0, nullptr, 0, &status, nullptr, &text, err))
        return false;
    if (status != 0) {
        if (err)
            *err = QStringLiteral("模块枚举失败（Toolhelp 快照不可用）");
        return false;
    }
    out->clear();
    const QList<QByteArray> lines = text.split('\n');
    for (const QByteArray &ln : lines) {
        if (ln.isEmpty())
            continue;
        const QList<QByteArray> f = ln.split('\t');
        if (f.size() < 3)
            continue;
        FxModuleInfo mi;
        mi.name = QString::fromUtf8(f[0]);
        mi.base = f[1].toULongLong(nullptr, 16);
        mi.size = f[2].toULongLong();
        out->append(mi);
    }
    return true;
}

bool FxInstrument::exports(quint64 moduleBase, QVector<FxExportInfo> *out, QString *err) {
    QByteArray text;
    int status = 0;
    if (!request(kOpExports, 0, 0, moduleBase, nullptr, 0, &status, nullptr, &text, err))
        return false;
    if (status != 0) {
        if (err)
            *err = QStringLiteral("导出解析失败：0x%1 不是可读的 PE 映像").arg(moduleBase, 0, 16);
        return false;
    }
    out->clear();
    const QList<QByteArray> lines = text.split('\n');
    for (const QByteArray &ln : lines) {
        if (ln.isEmpty())
            continue;
        const QList<QByteArray> f = ln.split('\t');
        if (f.size() < 2)
            continue;
        FxExportInfo ei;
        ei.name = QString::fromUtf8(f[0]);
        ei.addr = f[1].toULongLong(nullptr, 16);
        out->append(ei);
    }
    return true;
}

bool FxInstrument::scan(quint64 start, quint64 length, const QByteArray &pattern,
                        const QByteArray &mask, quint64 *hit, QString *err) {
    if (pattern.isEmpty() || pattern.size() > 256 || pattern.size() != mask.size()) {
        if (err)
            *err = QStringLiteral("模式长度须为 1–256 且与掩码等长（当前模式 %1 / 掩码 %2）")
                       .arg(pattern.size())
                       .arg(mask.size());
        return false;
    }
    QByteArray payload = pattern + mask;
    int status = 0;
    quint64 value = 0;
    if (!request(kOpScan, start, length, quint32(pattern.size()), payload.constData(),
                 quint32(payload.size()), &status, &value, nullptr, err))
        return false;
    if (status == -2) {
        if (err)
            *err = QStringLiteral("参数非法（模式长度或扫描范围超上限）");
        return false;
    }
    if (hit)
        *hit = (status == 0) ? value : 0;
    return true;
}

bool FxInstrument::callAddr(quint64 fnAddr, quint64 a0, quint64 a1, quint64 a2, quint64 a3,
                            quint64 *ret, QString *err) {
    const quint64 args[4] = {a0, a1, a2, a3};
    int status = 0;
    quint64 value = 0;
    if (!request(kOpCall, fnAddr, 0, 0, args, sizeof(args), &status, &value, nullptr, err))
        return false;
    if (status != 0) {
        if (err)
            *err = status == -2
                       ? QStringLiteral("参数非法（函数地址为空）")
                       : QStringLiteral("0x%1 不是可执行的提交内存").arg(fnAddr, 0, 16);
        return false;
    }
    if (ret)
        *ret = value;
    return true;
}

}  // namespace wmpf
