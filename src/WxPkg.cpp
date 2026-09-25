#include "WxPkg.h"

#include <windows.h>
#include <bcrypt.h>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QVector>

namespace {

constexpr int kEncHeaderLen = 6;    // "V1MMWX"
constexpr int kAesChunkLen = 1024;  // encrypted prefix covering plain[0:1023]
constexpr int kPlainHeadLen = 1023;
constexpr int kSha1Len = 20;

bool hmacSha1(BCRYPT_ALG_HANDLE hAlg, const QByteArray &key, const QByteArray &msg,
              QByteArray *out) {
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                         reinterpret_cast<PUCHAR>(const_cast<char *>(key.constData())),
                         static_cast<ULONG>(key.size()), 0) != 0)
        return false;
    const bool ok =
        BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char *>(msg.constData())),
                       static_cast<ULONG>(msg.size()), 0) == 0 &&
        BCryptFinishHash(hHash, reinterpret_cast<PUCHAR>(out->data()), kSha1Len, 0) == 0;
    BCryptDestroyHash(hHash);
    return ok;
}

// RFC 2898 PBKDF2 with HMAC-SHA1, implemented on Windows CNG.
QByteArray pbkdf2HmacSha1(const QByteArray &password, const QByteArray &salt, int iterations,
                          int dkLen, QString *err) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        if (err)
            *err = QStringLiteral("BCryptOpenAlgorithmProvider(SHA1-HMAC) 失败");
        return {};
    }
    QByteArray dk;
    quint32 blockIndex = 1;
    bool ok = true;
    while (dk.size() < dkLen && ok) {
        QByteArray msg = salt;
        const char be[4] = {static_cast<char>((blockIndex >> 24) & 0xff),
                            static_cast<char>((blockIndex >> 16) & 0xff),
                            static_cast<char>((blockIndex >> 8) & 0xff),
                            static_cast<char>(blockIndex & 0xff)};
        msg.append(be, 4);
        QByteArray u(kSha1Len, 0);
        ok = hmacSha1(hAlg, password, msg, &u);  // U_1
        QByteArray t = u;
        for (int k = 1; ok && k < iterations; ++k) {
            ok = hmacSha1(hAlg, password, u, &u);  // U_{k+1}
            for (int j = 0; ok && j < kSha1Len; ++j)
                t[j] = static_cast<char>(static_cast<uchar>(t[j]) ^ static_cast<uchar>(u[j]));
        }
        if (ok) {
            dk.append(t);
            ++blockIndex;
        }
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!ok) {
        if (err)
            *err = QStringLiteral("PBKDF2-HMAC-SHA1 计算失败");
        return {};
    }
    dk.resize(dkLen);
    return dk;
}

// AES-CBC decrypt via CNG. With blockPadding=true PKCS7 padding is stripped.
QByteArray aesCbcDecrypt(const QByteArray &key, QByteArray iv, const QByteArray &data,
                         bool blockPadding) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        return {};
    QByteArray out;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    do {
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_CBC)),
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0)
            break;
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                       reinterpret_cast<PUCHAR>(const_cast<char *>(key.constData())),
                                       static_cast<ULONG>(key.size()), 0) != 0)
            break;
        const ULONG flags = blockPadding ? BCRYPT_BLOCK_PADDING : 0;
        ULONG outLen = 0, done = 0;
        if (BCryptDecrypt(hKey, reinterpret_cast<PUCHAR>(const_cast<char *>(data.constData())),
                          static_cast<ULONG>(data.size()), nullptr,
                          reinterpret_cast<PUCHAR>(iv.data()), static_cast<ULONG>(iv.size()),
                          nullptr, 0, &outLen, flags) != 0)
            break;
        out.resize(static_cast<int>(outLen));
        if (BCryptDecrypt(hKey, reinterpret_cast<PUCHAR>(const_cast<char *>(data.constData())),
                          static_cast<ULONG>(data.size()), nullptr,
                          reinterpret_cast<PUCHAR>(iv.data()), static_cast<ULONG>(iv.size()),
                          reinterpret_cast<PUCHAR>(out.data()), outLen, &done, flags) != 0) {
            out.clear();
            break;
        }
        out.resize(static_cast<int>(done));
    } while (false);
    if (hKey)
        BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

quint32 readBe32(const QByteArray &d, qsizetype off) {
    return (static_cast<quint32>(static_cast<uchar>(d[off])) << 24) |
           (static_cast<quint32>(static_cast<uchar>(d[off + 1])) << 16) |
           (static_cast<quint32>(static_cast<uchar>(d[off + 2])) << 8) |
           static_cast<quint32>(static_cast<uchar>(d[off + 3]));
}

// Keep a container entry name inside outDir: drop "."/".." segments and leading slashes.
QString safeRelPath(const QString &name) {
    QString out;
    const QStringList parts = name.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    for (const QString &p : parts) {
        if (p == QLatin1String(".") || p == QLatin1String(".."))
            continue;
        if (!out.isEmpty())
            out += QLatin1Char('/');
        out += p;
    }
    return out;
}

}  // namespace

namespace WxPkg {

QByteArray decryptFile(const QString &path, const QString &appId, QString *err) {
    auto fail = [&](const QString &m) {
        if (err)
            *err = m;
        return QByteArray{};
    };
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return fail(QStringLiteral("无法读取文件：%1").arg(path));
    const QByteArray enc = f.readAll();
    if (enc.size() < kEncHeaderLen + kAesChunkLen)
        return fail(QStringLiteral("文件过小（%1 字节），不是有效的加密包").arg(enc.size()));
    if (!enc.startsWith("V1MMWX"))
        return fail(QStringLiteral("缺少 V1MMWX 头，不是 PC 微信加密包（可能本身即明文 wxapkg）"));

    const QByteArray key =
        pbkdf2HmacSha1(appId.toUtf8(), QByteArrayLiteral("saltiest"), 1000, 32, err);
    if (key.isEmpty())
        return {};
    const QByteArray iv(QByteArrayLiteral("the iv: 16 bytes"));

    QByteArray head = aesCbcDecrypt(key, iv, enc.mid(kEncHeaderLen, kAesChunkLen), true);
    if (head.size() != kPlainHeadLen) {
        // Fallback for files whose AES chunk is not PKCS7-padded: raw decrypt + slice.
        head = aesCbcDecrypt(key, iv, enc.mid(kEncHeaderLen, kAesChunkLen), false);
        if (head.size() < kPlainHeadLen)
            return fail(QStringLiteral("AES-256-CBC 解密失败（appId 可能不正确）"));
        head.resize(kPlainHeadLen);
    }

    QByteArray out = head;
    const qsizetype tail = enc.size() - (kEncHeaderLen + kAesChunkLen);
    out.reserve(out.size() + static_cast<int>(tail));
    const char xb = appId.size() >= 2 ? appId.at(appId.size() - 2).toLatin1()
                                      : static_cast<char>(0x66);
    for (qsizetype i = kEncHeaderLen + kAesChunkLen; i < enc.size(); ++i)
        out.append(static_cast<char>(static_cast<uchar>(enc[i]) ^ static_cast<uchar>(xb)));
    return out;
}

int unpackToDir(const QByteArray &data, const QString &outDir, QString *err) {
    auto fail = [&](const QString &m) {
        if (err)
            *err = m;
        return -1;
    };
    if (data.size() < 18)
        return fail(QStringLiteral("解密结果过小（%1 字节），不是有效的 wxapkg").arg(data.size()));
    if (static_cast<uchar>(data[0]) != 0xBE)
        return fail(QStringLiteral("wxapkg 魔数应为 0xBE，实际 0x%1（appId 可能填错）")
                        .arg(static_cast<uchar>(data[0]), 2, 16, QLatin1Char('0')));

    // infoLen / idxLen / bodyLen sit at [1:13]; an 0xED lastMark byte follows in
    // the classic layout, so the file index starts at 13 or 14.
    qsizetype base = 13;
    if (static_cast<uchar>(data[base]) == 0xED)
        base = 14;
    if (base + 4 > data.size())
        return fail(QStringLiteral("wxapkg 头部越界"));
    const quint32 count = readBe32(data, base);
    if (count == 0)
        return fail(QStringLiteral("wxapkg 内没有文件条目"));
    if (count > 100000)
        return fail(QStringLiteral("文件条目数异常（%1），索引解析失败").arg(count));

    struct Entry {
        QString name;
        quint32 offset;
        quint32 size;
    };
    QVector<Entry> entries;
    entries.reserve(static_cast<int>(count));
    qsizetype p = base + 4;
    for (quint32 i = 0; i < count; ++i) {
        if (p + 4 > data.size())
            return fail(QStringLiteral("条目 #%1 名称长度越界").arg(i));
        const quint32 nameLen = readBe32(data, p);
        p += 4;
        if (nameLen == 0 || nameLen > 4096 || p + nameLen + 8 > data.size())
            return fail(QStringLiteral("条目 #%1 名称异常（长度 %2）").arg(i).arg(nameLen));
        const QString name = QString::fromUtf8(data.mid(p, nameLen));
        p += nameLen;
        const quint32 off = readBe32(data, p);
        const quint32 size = readBe32(data, p + 4);
        p += 8;
        if (static_cast<quint64>(off) + size > static_cast<quint64>(data.size()))
            return fail(QStringLiteral("条目偏移越界：%1（off=%2 size=%3）")
                            .arg(name)
                            .arg(off)
                            .arg(size));
        entries.push_back({name, off, size});
    }

    int written = 0;
    int writeFailed = 0;
    for (const Entry &e : entries) {
        const QString rel = safeRelPath(e.name);
        if (rel.isEmpty()) {
            ++writeFailed;
            continue;
        }
        const QString target = outDir + QLatin1Char('/') + rel;
        QDir().mkpath(QFileInfo(target).absolutePath());
        QFile fo(target);
        if (!fo.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            ++writeFailed;
            continue;
        }
        if (fo.write(data.mid(e.offset, e.size)) < 0) {
            ++writeFailed;
            continue;
        }
        ++written;
    }
    if (writeFailed > 0 && err)
        *err = QStringLiteral("有 %1 个文件写入失败").arg(writeFailed);
    return written;
}

}  // namespace WxPkg
