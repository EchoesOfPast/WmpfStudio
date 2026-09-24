#include "WmpfChannel.h"

#include <QHostAddress>
#include <QMutexLocker>
#include <QWebSocket>
#include <QWebSocketServer>

#include "WarRemoteDebug.h"

namespace wmpf {

Channel::Channel(QObject *parent) : QObject(parent) {}

Channel::~Channel() { stop(); }

bool Channel::start(quint16 miniappPort, quint16 cdpPort, QString *err) {
    // Idempotent: if already listening on the same ports, do nothing.
    // Calling stop()+rebuild would drop the mini-program's debug connection.
    if (m_miniappServer && m_cdpServer &&
        m_miniappServer->isListening() && m_cdpServer->isListening() &&
        m_miniappServer->serverPort() == miniappPort &&
        m_cdpServer->serverPort() == cdpPort)
        return true;
    stop();

    // Bind to localhost only: the mini-program connects to 127.0.0.1; no need to expose the port to the LAN
    m_miniappServer = new QWebSocketServer(QStringLiteral("fzwy-miniapp"),
                                           QWebSocketServer::NonSecureMode, this);
    if (!m_miniappServer->listen(QHostAddress::LocalHost, miniappPort)) {
        if (err)
            *err = QStringLiteral("监听 %1 失败：%2").arg(miniappPort).arg(m_miniappServer->errorString());
        stop();
        return false;
    }
    connect(m_miniappServer, &QWebSocketServer::newConnection, this, &Channel::onMiniappConnected);

    m_cdpServer = new QWebSocketServer(QStringLiteral("fzwy-cdp"),
                                       QWebSocketServer::NonSecureMode, this);
    if (!m_cdpServer->listen(QHostAddress::LocalHost, cdpPort)) {
        if (err)
            *err = QStringLiteral("监听 %1 失败：%2").arg(cdpPort).arg(m_cdpServer->errorString());
        stop();
        return false;
    }
    connect(m_cdpServer, &QWebSocketServer::newConnection, this, &Channel::onCdpConnected);

    if (log) {
        log(QStringLiteral("通道已启动：小程序端 ws://127.0.0.1:%1/  CDP 端 ws://127.0.0.1:%2/")
                .arg(miniappPort)
                .arg(cdpPort));
    }
    return true;
}

void Channel::stop() {
    for (QWebSocket *ws : m_miniapps)
        ws->deleteLater();
    m_miniapps.clear();
    m_miniappCount.store(0);
    for (QWebSocket *ws : m_cdpClients)
        ws->deleteLater();
    m_cdpClients.clear();

    if (m_miniappServer) {
        m_miniappServer->close();
        m_miniappServer->deleteLater();
        m_miniappServer = nullptr;
    }
    if (m_cdpServer) {
        m_cdpServer->close();
        m_cdpServer->deleteLater();
        m_cdpServer = nullptr;
    }
}

bool Channel::isRunning() const { return m_miniappServer && m_miniappServer->isListening(); }

void Channel::onMiniappConnected() {
    while (m_miniappServer && m_miniappServer->hasPendingConnections()) {
        QWebSocket *ws = m_miniappServer->nextPendingConnection();
        m_miniapps.append(ws);
        m_miniappCount.store(m_miniapps.size());
        connect(ws, &QWebSocket::binaryMessageReceived, this, &Channel::onMiniappBinary);
        connect(ws, &QWebSocket::disconnected, this, [this, ws] {
            m_miniapps.removeAll(ws);
            m_miniappCount.store(m_miniapps.size());
            ws->deleteLater();
            if (log)
                log(QStringLiteral("小程序端断开（剩余 %1）").arg(m_miniapps.size()));
        });
        if (log)
            log(QStringLiteral("小程序已接入调试通道 ✓"));
    }
}

void Channel::onMiniappBinary(const QByteArray &raw) {
    m_bytesIn += quint64(raw.size());
    ++m_miniappFrames;

    DebugMessage dm;
    if (!decodeDebugMessage(raw, &dm)) {
        ++m_decodeFail;
        return;
    }
    {
        QMutexLocker lk(&m_categoryMutex);
        m_lastCategory = dm.category;
    }

    // The original implementation only handles chromeDevtoolsResult; others (ping/pong/setupContext/domOp/...) are ignored
    if (dm.category != QLatin1String("chromeDevtoolsResult")) {
        ++m_ignored;
        return;
    }
    if (dm.compressAlgo != 0)
        ++m_inflated;
    const QByteArray payload = inflateIfNeeded(dm.data, dm.compressAlgo, dm.originalSize);
    ChromeDevtoolsMsg cd;
    if (!decodeChromeDevtools(payload, &cd)) {
        ++m_decodeFail;
        return;
    }
    const QString text = cd.payload;
    if (text.isEmpty())
        return;
    for (QWebSocket *ws : m_cdpClients) {
        if (ws->isValid()) {
            ws->sendTextMessage(text);
            m_bytesOut += quint64(text.size());
        }
    }
    ++m_toClient;
}

void Channel::onCdpConnected() {
    while (m_cdpServer && m_cdpServer->hasPendingConnections()) {
        QWebSocket *ws = m_cdpServer->nextPendingConnection();
        m_cdpClients.append(ws);
        connect(ws, &QWebSocket::textMessageReceived, this, &Channel::onCdpText);
        connect(ws, &QWebSocket::disconnected, this, [this, ws] {
            m_cdpClients.removeAll(ws);
            ws->deleteLater();
        });
        // No connect log here: every eval opens a new CDP connection, so logging would spam.
    }
}

void Channel::onCdpText(const QString &text) {
    if (m_miniapps.isEmpty()) {
        ++m_noMiniapp;
        return;
    }
    ChromeDevtoolsMsg cd;
    cd.opId = ++m_opId;
    cd.payload = text;
    cd.jscontextId = QString();

    DebugMessage dm;
    dm.seq = ++m_seq;
    dm.category = QStringLiteral("chromeDevtools");
    dm.data = encodeChromeDevtools(cd);
    dm.compressAlgo = 0;
    dm.originalSize = quint32(dm.data.size());

    const QByteArray frame = encodeDebugMessage(dm);
    for (QWebSocket *ws : m_miniapps) {
        if (ws->isValid()) {
            ws->sendBinaryMessage(frame);
            m_bytesOut += quint64(frame.size());
        }
    }
    ++m_toMiniapp;
}

QString Channel::statsText() const {
    QString lastCategory;
    {
        QMutexLocker lk(&m_categoryMutex);
        lastCategory = m_lastCategory;
    }
    return QStringLiteral("小程序帧 %1（忽略 %2 / 解压 %3 / 解码失败 %4）| 转发给 CDP %5 | "
                          "转发给小程序 %6（无小程序 %7）| 字节 入 %8 出 %9 | 最近 category=%10")
        .arg(m_miniappFrames.load())
        .arg(m_ignored.load())
        .arg(m_inflated.load())
        .arg(m_decodeFail.load())
        .arg(m_toClient.load())
        .arg(m_toMiniapp.load())
        .arg(m_noMiniapp.load())
        .arg(m_bytesIn.load())
        .arg(m_bytesOut.load())
        .arg(lastCategory.isEmpty() ? QStringLiteral("-") : lastCategory);
}

}  // namespace wmpf
