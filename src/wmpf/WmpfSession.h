#pragma once

#include <QMutex>
#include <QObject>
#include <QString>
#include <QThread>

#include <atomic>
#include <functional>
#include <memory>
#include <thread>

#include "WmpfChannel.h"

// Full lifecycle management for the custom debug channel, replacing the old
// vendor/wmpf-based Channel:
//   - Start two WebSocket servers (9421 for mini-program / 62000 for CDP client)
//   - Inject FzwyHook.dll into the current WeChatAppEx host process
//     (scene ID -> 1101, putting the mini-program into debug mode)
//   - Persistent watchdog: WeChat rotates host processes; hooks disappear with
//     the process, so we must keep re-installing. Otherwise the next time the
//     user opens a mini-program it loads without the hook (verified the hard way).
namespace wmpf {

class Session : public QObject {
    Q_OBJECT
public:
    enum class State { Down, Alive, Zombie };

    explicit Session(QObject *parent = nullptr);
    ~Session() override;

    // The log callback is accessed from multiple threads: the worker thread writes via
    // setLog (when a Backend task starts), the channel thread (forwarder lambda in the
    // ctor) and the watchdog thread call emitLog. Concurrent read+write of a
    // std::function is UB, so all access goes through the locked setLog/emitLog.
    void setLog(const std::function<void(const QString &)> &fn);
    void emitLog(const QString &m) const;

    bool ensure();
    // Non-destructive probe: server listening + hook installed = Alive (timeoutMs is for backward compat with the old interface)
    State probe(int timeoutMs = 4000) const;
    // Whether the mini-program has connected to 9421 (timeoutMs is for backward compat)
    bool pageReady(int timeoutMs = 3000) const;
    bool waitForPage(int timeoutSec, const std::function<void(int)> &tick = {}) const;
    // Restart servers (hook doesn't need to be touched; the watchdog maintains it)
    bool restart();
    void stop();

    QString statsText() const;

private:
    void startWatch();
    void stopWatch();
    // Stops the WebSocket servers but keeps the channel thread alive; the thread's
    // lifetime is tied to the Session (created in the ctor, torn down in the dtor).
    void stopChannelServers();

    Channel m_chan;
    std::function<void(const QString &)> m_log;
    mutable QMutex m_logMutex;  // guards m_log: written by the worker thread, read by the channel/watchdog threads
    // QWebSocketServer must live in a thread with an event loop.
    // Backend tasks run in a QThread without exec() (JobThread), so the channel gets its own
    // thread, created in the ctor on the object's home thread: moveToThread only works as a
    // "push" from the object's current thread, and ensure() runs on a worker thread.
    QThread *m_chanThread = nullptr;
    std::thread m_watch;
    std::shared_ptr<std::atomic_bool> m_alive = std::make_shared<std::atomic_bool>(true);
    std::atomic<bool> m_hookOk{false};  // written by the watchdog thread, read by probe()/statsText()
    QString m_lastError;
};

}  // namespace wmpf
