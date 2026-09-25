#pragma once

#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPushButton>
#include <QTextEdit>

#include <atomic>
#include <memory>

#include "../JobThread.h"
#include "../wmpf/WmpfSession.h"

// WmpfStudio: a generic WeChat mini-program debug console.
// Attach to any mini-program page via the WMPF channel, evaluate JS in its
// AppService context, and dump wx storage. Reuses the FzwyTask channel as-is.
class StudioWindow : public QMainWindow {
    Q_OBJECT
public:
    StudioWindow();
    ~StudioWindow() override;

protected:
    void closeEvent(QCloseEvent *e) override;

private slots:
    void appendLog(const QString &msg);

private:
    void buildUi();
    void setBusy(bool busy, const QString &label);
    // kind: 0=start channel, 1=refresh pages, 2=eval, 3=export storage,
    //       4=scan local packages, 5=decrypt+unpack all,
    //       6=fx read, 7=fx write, 8=fx modules, 9=fx exports, 10=fx scan, 11=fx call
    void startJob(int kind, const QString &expr = {});
    QString pagePattern() const;

    wmpf::Session m_chan;
    std::function<void(const QString &)> m_log;
    bool m_busy = false;
    JobThread *m_worker = nullptr;
    std::shared_ptr<std::atomic_bool> m_alive = std::make_shared<std::atomic_bool>(true);

    QComboBox *m_pages = nullptr;
    QLineEdit *m_keyword = nullptr;
    QLineEdit *m_expr = nullptr;
    QPushButton *m_btnChannel = nullptr;
    QPushButton *m_btnPages = nullptr;
    QPushButton *m_btnRun = nullptr;
    QPushButton *m_btnStorage = nullptr;
    QLabel *m_status = nullptr;
    QTextEdit *m_console = nullptr;

    QLineEdit *m_appId = nullptr;
    QPushButton *m_btnScan = nullptr;
    QPushButton *m_btnUnpack = nullptr;

    // Memory instrument card (talks to FzwyHook.dll inside the target process)
    QLineEdit *m_fxAddr = nullptr;
    QLineEdit *m_fxLen = nullptr;
    QLineEdit *m_fxWriteVal = nullptr;
    QLineEdit *m_fxModule = nullptr;
    QLineEdit *m_fxPattern = nullptr;
    QLineEdit *m_fxScanStart = nullptr;
    QLineEdit *m_fxScanLen = nullptr;
    QLineEdit *m_fxCallAddr = nullptr;
    QLineEdit *m_fxArgs[4] = {};
    QPushButton *m_btnFxRead = nullptr;
    QPushButton *m_btnFxWrite = nullptr;
    QPushButton *m_btnFxModules = nullptr;
    QPushButton *m_btnFxExports = nullptr;
    QPushButton *m_btnFxScan = nullptr;
    QPushButton *m_btnFxCall = nullptr;
};
