#pragma once

#include <QByteArray>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QString>

#include <atomic>
#include <functional>

class QWebSocket;
class QWebSocketServer;

// Custom WMPF debug channel, replacing the two WebSocket servers that node ran in vendor/wmpf.
//
//   :9421  <- mini-program connects here (WMPF's built-in remote debug client; requires
//            the hook to have put the mini-program into debug mode). Binary frames,
//            content is WARemoteDebug protobuf.
//   :62000 <- our CDP client connects here; plain-text CDP JSON.
//
// Protocol translation in the middle:
//   mini-program -> us: decode DebugMessage; when category == "chromeDevtoolsResult", extract
//                  payload (CDP reply text) and forward to the 62000 client; other categories
//                  are ignored (the original implementation didn't handle them either;
//                  no login/joinRoom handshake needed).
//   us -> mini-program: wrap CDP text in ChromeDevtools -> then in DebugMessage and send it.
namespace wmpf {

class Channel : public QObject {
    Q_OBJECT
public:
    explicit Channel(QObject *parent = nullptr);
    ~Channel() override;

    // Defaults to 9421 / 62000, matching the original implementation
    bool start(quint16 miniappPort = 9421, quint16 cdpPort = 62000, QString *err = nullptr);
    void stop();
    bool isRunning() const;

    // Whether the mini-program has connected (active connection on 9421).
    // Uses atomic counter: caller may be on another thread (Backend tasks run in a QThread without an event loop).
    bool hasMiniapp() const { return m_miniappCount.load() > 0; }

    QString statsText() const;

    std::function<void(const QString &)> log;

private:
    void onMiniappConnected();
    void onMiniappBinary(const QByteArray &raw);
    void onCdpConnected();
    void onCdpText(const QString &text);

    QWebSocketServer *m_miniappServer = nullptr;
    QWebSocketServer *m_cdpServer = nullptr;
    QList<QWebSocket *> m_miniapps;
    QList<QWebSocket *> m_cdpClients;
    std::atomic<int> m_miniappCount{0};

    quint32 m_seq = 0;
    quint64 m_opId = 0;

    // Statistics.
    // Counters are atomic and m_lastCategory is mutex-guarded: they are written on the
    // channel thread (slots) while statsText() reads them from the caller's
    // thread (Backend tasks run in a QThread without an event loop) — plain quint64/QString
    // would be a data race (UB).
    std::atomic<quint64> m_miniappFrames{0};
    std::atomic<quint64> m_toClient{0};
    std::atomic<quint64> m_toMiniapp{0};
    std::atomic<quint64> m_ignored{0};
    std::atomic<quint64> m_decodeFail{0};
    std::atomic<quint64> m_noMiniapp{0};
    std::atomic<quint64> m_inflated{0};
    std::atomic<quint64> m_bytesIn{0};
    std::atomic<quint64> m_bytesOut{0};
    QString m_lastCategory;
    mutable QMutex m_categoryMutex;
};

}  // namespace wmpf
