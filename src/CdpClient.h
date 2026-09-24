#pragma once

#include <QHash>
#include <QJsonObject>
#include <QObject>
#include <QWebSocket>

// Blocking calls (nested event loops): use from a worker thread, never the GUI thread.
class CdpClient : public QObject {
    Q_OBJECT
public:
    explicit CdpClient(QObject *parent = nullptr);

    bool open(int timeoutMs = 10000);

    QJsonObject send(const QString &method, const QJsonObject &params = {},
                     const QString &sessionId = {}, int timeoutMs = 12000);

signals:
    void gotMessage();

private:
    void onTextMessage(const QString &message);

    QWebSocket m_ws;
    QHash<qint64, QJsonObject> m_replies;
    qint64 m_nextId = 0;
    bool m_opened = false;
};

// Only NoChannel means the channel itself is broken; the other codes are recoverable.
enum class EvalError {
    None = 0,
    NoChannel,
    NoPage,
    NoContext,
    EvalFailed,
    Timeout,
};

QJsonValue evalAppService(const QString &expr, bool awaitPromise, int timeoutMs, QString *err,
                          EvalError *code, const QString &pageUrlPattern = {});
