#include "WmpfSession.h"

#include <QMutexLocker>
#include <QThread>

#include "WmpfInject.h"

namespace wmpf {

Session::Session(QObject *parent) : QObject(parent) {
    // This lambda runs on the channel thread and must go through emitLog (locked read of
    // m_log): the worker thread may be inside setLog concurrently.
    m_chan.log = [this](const QString &m) { emitLog(m); };
    // The channel thread is created here, on the object's home thread: moveToThread only
    // works as a "push" from the object's current thread. Doing it later in ensure()
    // (a worker thread) is rejected by Qt, leaving the channel on the caller's thread -
    // a same-thread BlockingQueuedConnection in stop() then deadlocks the GUI on close.
    m_chanThread = new QThread;
    m_chanThread->setObjectName(QStringLiteral("wmpf-channel"));
    m_chan.moveToThread(m_chanThread);
    m_chanThread->start();  // QThread::run defaults to exec(), establishing the event loop
}

Session::~Session() {
    m_alive->store(false);
    stopWatch();
    stopChannelServers();
    if (m_chanThread) {
        m_chanThread->quit();
        if (m_chanThread->wait(3000)) {
            delete m_chanThread;
        } else {
            // Deleting a running QThread triggers qFatal and crashes the process;
            // leak the thread object instead (reclaimed by the OS at process exit).
            emitLog(QStringLiteral("通道线程 3 秒内未退出，放弃 delete（泄漏以防崩溃）"));
        }
        m_chanThread = nullptr;
    }
}

void Session::setLog(const std::function<void(const QString &)> &fn) {
    QMutexLocker lk(&m_logMutex);
    m_log = fn;
}

void Session::emitLog(const QString &m) const {
    // Copy under the lock, call after unlocking: avoids UB from concurrent std::function
    // access, and never runs an external callback while holding the lock (a callback that
    // indirectly touches Session would deadlock).
    std::function<void(const QString &)> fn;
    {
        QMutexLocker lk(&m_logMutex);
        fn = m_log;
    }
    if (fn)
        fn(m);
}

void Session::startWatch() {
    if (m_watch.joinable())
        return;
    // stopWatch() clears m_alive; it must be re-armed before restarting the watchdog,
    // otherwise after stop()+ensure() the watchdog thread would exit immediately and
    // silently do nothing.
    m_alive->store(true);
    auto alive = m_alive;
    // Watchdog logging also goes through emitLog (locked), never reads m_log directly.
    auto lg = [this, alive](const QString &m) {
        if (alive->load())
            emitLog(m);
    };
    m_watch = std::thread([this, alive, lg] {
        // The watchdog thread doesn't need a Qt event loop: ensureHooked is all Win32 calls.
        // Can't use QTimer — Backend tasks run in a QThread without exec().
        QString lastMsg;
        for (;;) {
            if (!alive->load())
                return;
            const HookInstallResult hr = ensureHooked();
            m_hookOk = hr.ok;
            // Log only on state change: a persistent failure retried every 2s would
            // otherwise spam the GUI log with identical lines.
            QString msg;
            if (hr.ok && !hr.alreadyHooked)
                msg = QStringLiteral("[hook 看护] %1").arg(hr.message);
            else if (!hr.ok)
                msg = QStringLiteral("[hook 看护] 失败：%1").arg(hr.message);
            if (!msg.isEmpty() && msg != lastMsg)
                lg(msg);
            lastMsg = msg;
            for (int i = 0; i < 20; ++i) {
                if (!alive->load())
                    return;
                QThread::msleep(100);
            }
        }
    });
}

void Session::stopWatch() {
    m_alive->store(false);
    if (m_watch.joinable()) {
        m_watch.join();
    }
}

bool Session::ensure() {
    // The channel server runs on its dedicated thread (created in the constructor):
    // QWebSocketServer needs an event loop, and Backend tasks run on a JobThread without one.
    bool started = false;
    QString err;
    if (QThread::currentThread() == m_chanThread) {
        started = m_chan.start(9421, 62000, &err);
    } else {
        QMetaObject::invokeMethod(
            &m_chan, [&] { started = m_chan.start(9421, 62000, &err); },
            Qt::BlockingQueuedConnection);
    }
    if (!started) {
        m_lastError = QStringLiteral("通道启动失败：%1").arg(err);
        emitLog(m_lastError);
        return false;
    }
    // Install once synchronously first, so the hook is already armed when the user opens a mini-program.
    // ensureHooked runs the callback synchronously on this (worker) thread; wrap it so m_log is read through emitLog under lock.
    const HookInstallResult hr = ensureHooked([this](const QString &m) { emitLog(m); });
    m_hookOk = hr.ok;
    if (!hr.ok) {
        m_lastError = QStringLiteral("hook 安装失败：%1").arg(hr.message);
        emitLog(m_lastError);
    }
    startWatch();
    return true;
}

Session::State Session::probe(int) const {
    if (!m_chan.isRunning())
        return State::Down;
    return m_hookOk ? State::Alive : State::Zombie;
}

bool Session::pageReady(int) const { return m_chan.hasMiniapp(); }

bool Session::waitForPage(int timeoutSec, const std::function<void(int)> &tick) const {
    for (int i = 0; i < timeoutSec * 4; ++i) {
        if (m_chan.hasMiniapp())
            return true;
        if (tick && i % 4 == 0)
            tick(timeoutSec - i / 4);
        QThread::msleep(250);
    }
    return m_chan.hasMiniapp();
}

bool Session::restart() {
    stopWatch();
    // m_alive is re-armed by startWatch() (also reached via ensure).
    stopChannelServers();
    return ensure();
}

// Stops the WebSocket servers (releasing ports 9421/62000) but keeps the channel
// thread alive: the thread's lifetime is tied to the Session, not to the servers.
void Session::stopChannelServers() {
    if (m_chanThread && m_chanThread->isRunning()) {
        QMetaObject::invokeMethod(&m_chan, [this] { m_chan.stop(); },
                                  Qt::BlockingQueuedConnection);
    }
}

void Session::stop() {
    stopWatch();
    stopChannelServers();
}

QString Session::statsText() const {
    return QStringLiteral("hook=%1 | %2")
        .arg(m_hookOk ? QStringLiteral("已挂") : QStringLiteral("未挂"))
        .arg(m_chan.statsText());
}

}  // namespace wmpf
