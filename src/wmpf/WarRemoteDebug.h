#pragma once

#include <QByteArray>
#include <QString>

// WARemoteDebug protocol subset (hand-written protobuf, no protobuf library dependency).
//
// Field numbers extracted from wmpf's src/third-party/WARemoteDebugProtobuf.js:
//
//   message WARemoteDebug_DebugMessage {      // outer frame on :9421
//     uint32 seq = 1;
//     uint32 after = 2;
//     string category = 3;                    // string! not an enum
//     bytes  data = 4;
//     uint32 compressAlgo = 5;                // bitmask: bit0 (Zlib=1) = zlib
//     uint32 originalSize = 6;                // for zlib: decompressed length
//   }
//   message WARemoteDebug_ChromeDevtools        { uint64 opId = 1; string payload = 2; string jscontextId = 3; }
//   message WARemoteDebug_ChromeDevtoolsResult  { uint64 opId = 1; string payload = 2; string jscontextId = 3; }
//
// category values: "chromeDevtools" (us -> mini-program), "chromeDevtoolsResult" (mini-program -> us).
// Other categories (ping/pong/setupContext/domOp/...) are also ignored in the original implementation;
// no login/joinRoom handshake is needed.
namespace wmpf {

struct DebugMessage {
    quint32 seq = 0;
    quint32 after = 0;
    QString category;
    QByteArray data;
    quint32 compressAlgo = 0;
    quint32 originalSize = 0;
};

struct ChromeDevtoolsMsg {
    quint64 opId = 0;
    QString payload;
    QString jscontextId;
};

bool decodeDebugMessage(const QByteArray &in, DebugMessage *out);
QByteArray encodeDebugMessage(const DebugMessage &m);
bool decodeChromeDevtools(const QByteArray &in, ChromeDevtoolsMsg *out);
QByteArray encodeChromeDevtools(const ChromeDevtoolsMsg &m);

// Inflate per originalSize when compressAlgo has the Zlib bit set (bitmask semantics,
// matching the reference implementation); refuses originalSize > 64MB
QByteArray inflateIfNeeded(const QByteArray &data, quint32 algo, quint32 originalSize);

}  // namespace wmpf
