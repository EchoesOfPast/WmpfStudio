#include "CdpClient.h"

#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonArray>
#include <QThread>
#include <QTimer>

#include "Config.h"

namespace {
const char* kEndpoint = "ws://127.0.0.1:62000";

// In a Qt-adopted thread (std::thread), a QAbstractSocket created before the thread's
// first QEventLoop::exec gets no socket notifier, so the WS handshake silently hangs
// until timeout. Warm up the event loop once.
void ensureEventDispatcher() {
    QEventLoop warm;
    QMetaObject::invokeMethod(&warm, "quit", Qt::QueuedConnection);
    warm.exec();
}
}

CdpClient::CdpClient(QObject *parent) : QObject(parent) {
    connect(&m_ws, &QWebSocket::textMessageReceived, this, &CdpClient::onTextMessage);
}

bool CdpClient::open(int timeoutMs) {
    ensureEventDispatcher();
    QElapsedTimer elapsed;
    elapsed.start();
    for (int attempt = 0; attempt < 2; ++attempt) {
        const int perTry = (attempt == 0) ? qMin(timeoutMs, 1500) : timeoutMs;
        m_replies.clear();
        m_ws.abort();
        m_ws.open(QUrl(QString::fromLatin1(kEndpoint)));
        QEventLoop loop;
        connect(&m_ws, &QWebSocket::connected, &loop, &QEventLoop::quit);
        connect(&m_ws, &QWebSocket::errorOccurred, &loop, &QEventLoop::quit);
        QTimer::singleShot(perTry, &loop, &QEventLoop::quit);
        loop.exec();
        m_opened = (m_ws.state() == QAbstractSocket::ConnectedState);
        if (m_opened)
            return true;
        if (elapsed.elapsed() >= timeoutMs)
            break;
    }
    return false;
}

void CdpClient::onTextMessage(const QString &message) {
    QJsonParseError pe{};
    QJsonDocument doc = QJsonDocument::fromJson(message.toUtf8(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject())
        return;
    QJsonObject msg = doc.object();
    // Only command responses (with id) are useful: WeChat's SendToClientFilter
    // replaces CDP notifications (e.g. Runtime.executionContextCreated) with {}.
    if (msg.contains("id"))
        m_replies.insert(msg["id"].toVariant().toLongLong(), msg);
    emit gotMessage();
}

QJsonObject CdpClient::send(const QString &method, const QJsonObject &params,
                            const QString &sessionId, int timeoutMs) {
    if (m_ws.state() != QAbstractSocket::ConnectedState)
        return QJsonObject{{"error", QStringLiteral("NotConnected")}};
    qint64 id = ++m_nextId;
    QJsonObject payload{{"id", static_cast<double>(id)}, {"method", method}, {"params", params}};
    if (!sessionId.isEmpty())
        payload["sessionId"] = sessionId;
    m_ws.sendTextMessage(QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    QElapsedTimer t;
    t.start();
    while (!m_replies.contains(id)) {
        qint64 remain = timeoutMs - t.elapsed();
        if (remain <= 0)
            break;
        QEventLoop loop;
        QTimer::singleShot(static_cast<int>(remain), &loop, &QEventLoop::quit);
        QMetaObject::Connection c =
            connect(this, &CdpClient::gotMessage, &loop, &QEventLoop::quit);
        loop.exec();
        disconnect(c);
    }
    if (!m_replies.contains(id))
        return QJsonObject{{"error", QStringLiteral("TimeoutError")}};
    return m_replies.take(id);
}

QJsonValue evalAppService(const QString &expr, bool awaitPromise, int timeoutMs, QString *err,
                          EvalError *code, const QString &pageUrlPattern) {
    if (err)
        err->clear();
    if (code)
        *code = EvalError::None;

    auto fail = [&](EvalError c, const QString &m) -> QJsonValue {
        if (err)
            *err = m;
        if (code)
            *code = c;
        return {};
    };

    const QString pattern = pageUrlPattern.isEmpty() ? g_config.appId : pageUrlPattern;
    CdpClient cdp;
    if (!cdp.open()) {
        return fail(EvalError::NoChannel, QStringLiteral("Failed to connect to debug channel"));
    }
    if (pattern.isEmpty()) {
        return fail(EvalError::NoPage,
                    QStringLiteral("appId is empty in config.json — cannot locate mini-program page"));
    }
    QJsonObject t = cdp.send(QStringLiteral("Target.getTargets"));
    QJsonArray targets = t["result"].toObject()["targetInfos"].toArray();
    QJsonObject page;
    QStringList pageUrls;
    for (const auto &ti : targets) {
        QJsonObject o = ti.toObject();
        if (o["type"].toString() == QLatin1String("page"))
            pageUrls << o["url"].toString().left(80);
        if (o["type"].toString() == QLatin1String("page") &&
            o["url"].toString().contains(pattern)) {
            page = o;
            break;
        }
    }
    if (page.isEmpty()) {
        return fail(EvalError::NoPage,
                    QStringLiteral("Mini-program page not found (%1 pages, pattern=%2). Pages: %3")
                        .arg(targets.size())
                        .arg(pattern)
                        .arg(pageUrls.join(QStringLiteral(" | "))));
    }
    QJsonObject att = cdp.send(QStringLiteral("Target.attachToTarget"),
                               QJsonObject{{"targetId", page["targetId"].toString()},
                                           {"flatten", true}});
    QString sid = att["result"].toObject()["sessionId"].toString();
    if (sid.isEmpty()) {
        return fail(EvalError::NoPage, QStringLiteral("Failed to attach to mini-program"));
    }
    QJsonObject re = cdp.send(QStringLiteral("Runtime.enable"), {}, sid);
    if (re.contains("error")) {
        return fail(EvalError::NoContext,
                    QStringLiteral("Runtime.enable failed: %1")
                        .arg(QString::fromUtf8(QJsonDocument(re).toJson(QJsonDocument::Compact))));
    }

    // WeChat's SendToClientFilter blanks Runtime.executionContextCreated, and hooking
    // that function crashes under CET (0xc0000409 at ret), so the AppService contextId
    // (where both wx and getApp exist) is found by brute-force probing instead.
    // The JS runtime needs time to init after attach: retry 8 x 500ms.
    int ctxId = -1;
    QStringList probeResults;
    for (int attempt = 0; attempt < 8 && ctxId < 0; ++attempt) {
        // Event loop, not msleep: the QWebSocket must keep processing messages.
        {
            QEventLoop loop;
            QTimer::singleShot(500, &loop, &QEventLoop::quit);
            loop.exec();
        }
        probeResults.clear();
        for (int cid = 1; cid <= 24; ++cid) {
            const QJsonObject r = cdp.send(QStringLiteral("Runtime.evaluate"),
                                           QJsonObject{{"expression",
                                                        QStringLiteral("typeof wx+','+typeof getApp")},
                                                       {"returnByValue", true},
                                                       {"contextId", cid}},
                                           sid, 800);
            if (r.contains("error") && !r["result"].toObject().contains("result")) {
                if (attempt == 0) probeResults << QStringLiteral("%1:err").arg(cid);
                continue;
            }
            const QString val = r["result"].toObject()["result"].toObject()["value"].toString();
            if (attempt == 0) probeResults << QStringLiteral("%1:%2").arg(cid).arg(val.left(20));
            if (val.startsWith(QLatin1String("object,function"))) {
                ctxId = cid;
                break;
            }
        }
    }
    if (ctxId < 0) {
        return fail(EvalError::NoContext,
                    QStringLiteral("AppService context not found (page=%1, probes: %2)")
                        .arg(page["url"].toString().left(60))
                        .arg(probeResults.join(QStringLiteral(", "))));
    }
    QJsonObject r = cdp.send(QStringLiteral("Runtime.evaluate"),
                             QJsonObject{{"expression", expr},
                                         {"returnByValue", true},
                                         {"awaitPromise", awaitPromise},
                                         {"contextId", ctxId}},
                             sid, timeoutMs);
    QJsonObject res = r["result"].toObject();
    if (res.contains("exceptionDetails")) {
        return fail(EvalError::EvalFailed,
                    QString::fromUtf8(
                        QJsonDocument(res["exceptionDetails"].toObject()).toJson(QJsonDocument::Compact))
                        .left(300));
    }
    if (r.contains("error") && !res.contains("result")) {
        return fail(EvalError::Timeout, QStringLiteral("CDP call timed out or failed"));
    }
    return res["result"].toObject()["value"];
}
