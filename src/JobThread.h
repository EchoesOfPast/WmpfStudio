#pragma once

#include <QThread>

#include <functional>

// Must be QThread, not std::thread: only QThreadPrivate::start sets up the event
// dispatcher; in a std::thread the first QAbstractSocket creation silently fails,
// so healthy channels get misdiagnosed as zombies and killed.
class JobThread : public QThread {
public:
    explicit JobThread(std::function<void()> fn) : m_fn(std::move(fn)) {}

protected:
    void run() override {
        if (m_fn)
            m_fn();
    }

private:
    std::function<void()> m_fn;
};
