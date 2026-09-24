#include "WarRemoteDebug.h"

#include <QByteArray>

namespace wmpf {
namespace {

struct Reader {
    const quint8 *p = nullptr;
    int n = 0;
    int i = 0;

    bool eof() const { return i >= n; }

    bool varint(quint64 *out) {
        quint64 v = 0;
        int shift = 0;
        while (i < n) {
            const quint8 b = p[i++];
            v |= quint64(b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                *out = v;
                return true;
            }
            shift += 7;
            if (shift > 63)
                return false;
        }
        return false;
    }

    bool tag(quint32 *field, quint32 *wire) {
        quint64 t = 0;
        if (!varint(&t))
            return false;
        *field = quint32(t >> 3);
        *wire = quint32(t & 7);
        return true;
    }

    bool bytes(QByteArray *out) {
        quint64 len = 0;
        if (!varint(&len))
            return false;
        if (len > quint64(n - i))
            return false;
        *out = QByteArray(reinterpret_cast<const char *>(p + i), int(len));
        i += int(len);
        return true;
    }

    bool skip(quint32 wire) {
        quint64 v = 0;
        switch (wire) {
            case 0: return varint(&v);
            case 1:
                if (i + 8 > n) return false;
                i += 8;
                return true;
            case 2: {
                QByteArray tmp;
                return bytes(&tmp);
            }
            case 5:
                if (i + 4 > n) return false;
                i += 4;
                return true;
            default: return false;
        }
    }
};

void putVarint(QByteArray *out, quint64 v) {
    while (v >= 0x80) {
        out->append(char(quint8(v) | 0x80));
        v >>= 7;
    }
    out->append(char(quint8(v)));
}

void putTag(QByteArray *out, quint32 field, quint32 wire) {
    putVarint(out, (quint64(field) << 3) | wire);
}

void putBytesField(QByteArray *out, quint32 field, const QByteArray &v) {
    if (v.isEmpty())
        return;
    putTag(out, field, 2);
    putVarint(out, quint64(v.size()));
    out->append(v);
}

void putUint(QByteArray *out, quint32 field, quint64 v) {
    if (v == 0)
        return;  // proto3: don't write default values
    putTag(out, field, 0);
    putVarint(out, v);
}

}  // namespace

bool decodeDebugMessage(const QByteArray &in, DebugMessage *out) {
    *out = DebugMessage{};
    Reader r{reinterpret_cast<const quint8 *>(in.constData()), int(in.size()), 0};
    while (!r.eof()) {
        quint32 field = 0, wire = 0;
        if (!r.tag(&field, &wire))
            return false;
        quint64 v = 0;
        QByteArray b;
        switch (field) {
            case 1:
                if (!r.varint(&v)) return false;
                out->seq = quint32(v);
                break;
            case 2:
                if (!r.varint(&v)) return false;
                out->after = quint32(v);
                break;
            case 3:
                if (!r.bytes(&b)) return false;
                out->category = QString::fromUtf8(b);
                break;
            case 4:
                if (!r.bytes(&b)) return false;
                out->data = b;
                break;
            case 5:
                if (!r.varint(&v)) return false;
                out->compressAlgo = quint32(v);
                break;
            case 6:
                if (!r.varint(&v)) return false;
                out->originalSize = quint32(v);
                break;
            default:
                if (!r.skip(wire))
                    return false;
                break;
        }
    }
    return true;
}

QByteArray encodeDebugMessage(const DebugMessage &m) {
    QByteArray out;
    putUint(&out, 1, m.seq);
    putUint(&out, 2, m.after);
    putBytesField(&out, 3, m.category.toUtf8());
    putBytesField(&out, 4, m.data);
    putUint(&out, 5, m.compressAlgo);
    putUint(&out, 6, m.originalSize);
    return out;
}

bool decodeChromeDevtools(const QByteArray &in, ChromeDevtoolsMsg *out) {
    *out = ChromeDevtoolsMsg{};
    Reader r{reinterpret_cast<const quint8 *>(in.constData()), int(in.size()), 0};
    while (!r.eof()) {
        quint32 field = 0, wire = 0;
        if (!r.tag(&field, &wire))
            return false;
        quint64 v = 0;
        QByteArray b;
        switch (field) {
            case 1:
                if (!r.varint(&v)) return false;
                out->opId = v;
                break;
            case 2:
                if (!r.bytes(&b)) return false;
                out->payload = QString::fromUtf8(b);
                break;
            case 3:
                if (!r.bytes(&b)) return false;
                out->jscontextId = QString::fromUtf8(b);
                break;
            default:
                if (!r.skip(wire))
                    return false;
                break;
        }
    }
    return true;
}

QByteArray encodeChromeDevtools(const ChromeDevtoolsMsg &m) {
    QByteArray out;
    putUint(&out, 1, m.opId);
    putBytesField(&out, 2, m.payload.toUtf8());
    putBytesField(&out, 3, m.jscontextId.toUtf8());
    return out;
}

QByteArray inflateIfNeeded(const QByteArray &data, quint32 algo, quint32 originalSize) {
    // The reference implementation (RemoteDebugCodex.js) tests a bitmask:
    // compressAlgo & Zlib(=1) (RemoteDebugConstants.js) — not algo == 1.
    if ((algo & 1u) == 0)
        return data;
    // originalSize is peer-controlled and qUncompress pre-allocates by it, so a
    // malformed frame could request an astronomical size — cap it (normal CDP
    // messages are far smaller).
    constexpr quint32 kMaxInflateSize = 64u * 1024u * 1024u;
    if (originalSize == 0 || originalSize > kMaxInflateSize)
        return {};
    // The data is a zlib stream (with zlib header). qUncompress requires a 4-byte
    // big-endian decompressed length prefix, and the message conveniently carries
    // originalSize — just prepend it.
    QByteArray framed;
    framed.reserve(data.size() + 4);
    const quint32 sz = originalSize;
    framed.append(char(quint8(sz >> 24)));
    framed.append(char(quint8(sz >> 16)));
    framed.append(char(quint8(sz >> 8)));
    framed.append(char(quint8(sz)));
    framed.append(data);
    return qUncompress(framed);
}

}  // namespace wmpf
