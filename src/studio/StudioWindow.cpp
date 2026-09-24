#include "StudioWindow.h"

#include <QApplication>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QDateTime>
#include <QFile>
#include <QFrame>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMessageBox>
#include <QVBoxLayout>

#include "../CdpClient.h"

namespace {
const char *kStyle = R"CSS(
QWidget { color: #134E4A; font-family: "Inter", "Segoe UI", "Microsoft YaHei", sans-serif; font-size: 13px; }
QWidget#root { background: #F0FDFA; }
QLabel#title { font-size: 17px; font-weight: 600; }
QLabel#status { font-size: 12px; color: #475569; }
QFrame#card { background: #FFFFFF; border: 1px solid #99F6E4; border-radius: 10px; }
QComboBox, QLineEdit {
    border: 1px solid #99F6E4; border-radius: 6px; padding: 6px 8px; background: #FFFFFF;
}
QComboBox:focus, QLineEdit:focus { border-color: #0D9488; }
QPushButton {
    border-radius: 8px; font-weight: 600; padding: 8px 14px;
    background: #0F766E; color: #FFFFFF; border: none;
}
QPushButton:hover:!disabled { background: #0D9488; }
QPushButton:disabled { background: #E8F1F4; color: #94A3B8; }
QPushButton#ghost { background: #FFFFFF; color: #134E4A; border: 1px solid #CBD5E1; }
QPushButton#ghost:hover:!disabled { border-color: #0D9488; color: #0F766E; }
QTextEdit {
    background: #FFFFFF; border: 1px solid #99F6E4; border-radius: 8px;
    font-family: "JetBrains Mono", Consolas, "Courier New", "Microsoft YaHei", monospace;
    font-size: 12px; padding: 6px 8px;
}
)CSS";

QString ts() { return QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")); }

// Pretty-print if the string happens to be JSON; otherwise return as-is.
QString prettyJson(const QString &s) {
    QJsonParseError pe{};
    QJsonDocument doc = QJsonDocument::fromJson(s.toUtf8(), &pe);
    if (pe.error == QJsonParseError::NoError && (doc.isObject() || doc.isArray()))
        return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
    return s;
}

const char *kStorageJs = R"JS(
(function(){
  var keys=[];
  try { keys = (wx.getStorageInfoSync().keys)||[]; } catch(e){ return JSON.stringify({err:String(e)}); }
  var o={};
  for (var i=0;i<keys.length;i++){ try { o[keys[i]]=wx.getStorageSync(keys[i]); } catch(e){ o[keys[i]]='<'+e+'>'; } }
  return JSON.stringify(o);
})()
)JS";
}  // namespace

StudioWindow::StudioWindow() {
    buildUi();
}

StudioWindow::~StudioWindow() {
    m_alive->store(false);
    if (m_worker && m_worker->isRunning())
        m_worker->wait(3000);
    m_chan.stop();
}

void StudioWindow::buildUi() {
    setWindowTitle(QStringLiteral("WmpfStudio · 小程序调试台"));
    resize(640, 560);
    setMinimumSize(520, 460);
    qApp->setStyleSheet(QString::fromLatin1(kStyle));

    auto *root = new QWidget(this);
    root->setObjectName(QStringLiteral("root"));
    auto *lay = new QVBoxLayout(root);
    lay->setContentsMargins(14, 12, 14, 10);
    lay->setSpacing(8);

    auto *head = new QHBoxLayout;
    auto *title = new QLabel(QStringLiteral("WmpfStudio · 小程序调试台"));
    title->setObjectName(QStringLiteral("title"));
    head->addWidget(title);
    head->addStretch();
    m_status = new QLabel(QStringLiteral("通道未启动"));
    m_status->setObjectName(QStringLiteral("status"));
    head->addWidget(m_status);
    lay->addLayout(head);

    auto *card = new QFrame;
    card->setObjectName(QStringLiteral("card"));
    auto *cl = new QVBoxLayout(card);
    cl->setContentsMargins(12, 10, 12, 10);
    cl->setSpacing(6);

    auto *r1 = new QHBoxLayout;
    r1->setSpacing(8);
    m_keyword = new QLineEdit;
    m_keyword->setPlaceholderText(QStringLiteral("页面关键词（appId 或 URL 片段，留空用下拉页或自动识别）"));
    r1->addWidget(m_keyword, 1);
    m_btnChannel = new QPushButton(QStringLiteral("启动通道"));
    m_btnChannel->setCursor(Qt::PointingHandCursor);
    connect(m_btnChannel, &QPushButton::clicked, this, [this] { startJob(0); });
    r1->addWidget(m_btnChannel);
    cl->addLayout(r1);

    auto *r2 = new QHBoxLayout;
    r2->setSpacing(8);
    m_pages = new QComboBox;
    m_pages->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    m_pages->addItem(QStringLiteral("（先启动通道，再刷新页面）"));
    r2->addWidget(m_pages, 1);
    m_btnPages = new QPushButton(QStringLiteral("刷新页面"));
    m_btnPages->setObjectName(QStringLiteral("ghost"));
    m_btnPages->setCursor(Qt::PointingHandCursor);
    connect(m_btnPages, &QPushButton::clicked, this, [this] { startJob(1); });
    r2->addWidget(m_btnPages);
    cl->addLayout(r2);
    lay->addWidget(card);

    m_console = new QTextEdit;
    m_console->setReadOnly(true);
    m_console->document()->setMaximumBlockCount(10000);
    lay->addWidget(m_console, 1);

    auto *r3 = new QHBoxLayout;
    r3->setSpacing(8);
    m_expr = new QLineEdit;
    m_expr->setPlaceholderText(
        QStringLiteral("JS 表达式，如 typeof getApp / JSON.stringify(wx.getSystemInfoSync())，回车执行"));
    r3->addWidget(m_expr, 1);
    m_btnRun = new QPushButton(QStringLiteral("执行"));
    m_btnRun->setCursor(Qt::PointingHandCursor);
    connect(m_btnRun, &QPushButton::clicked, this, [this] { startJob(2, m_expr->text()); });
    r3->addWidget(m_btnRun);
    m_btnStorage = new QPushButton(QStringLiteral("导出 Storage"));
    m_btnStorage->setObjectName(QStringLiteral("ghost"));
    m_btnStorage->setCursor(Qt::PointingHandCursor);
    connect(m_btnStorage, &QPushButton::clicked, this, [this] { startJob(3); });
    r3->addWidget(m_btnStorage);
    lay->addLayout(r3);

    connect(m_expr, &QLineEdit::returnPressed, this, [this] {
        if (!m_busy)
            startJob(2, m_expr->text());
    });

    setCentralWidget(root);
    setBusy(false, QStringLiteral("就绪"));
}

void StudioWindow::setBusy(bool busy, const QString &label) {
    m_busy = busy;
    m_btnChannel->setEnabled(!busy);
    m_btnPages->setEnabled(!busy);
    m_btnRun->setEnabled(!busy);
    m_btnStorage->setEnabled(!busy);
    m_status->setText(label);
}

QString StudioWindow::pagePattern() const {
    const QString kw = m_keyword->text().trimmed();
    if (!kw.isEmpty())
        return kw;
    const QString cur = m_pages->currentText().trimmed();
    if (!cur.isEmpty() && !cur.startsWith(QLatin1String("（")))
        return cur;
    return QStringLiteral("servicewechat.com");
}

void StudioWindow::appendLog(const QString &msg) {
    m_console->append(QStringLiteral("<span style='color:#64748b;'>%1</span> %2")
                          .arg(ts(), msg.toHtmlEscaped()));
}

void StudioWindow::startJob(int kind, const QString &expr) {
    if (m_busy)
        return;
    if (kind == 2 && expr.trimmed().isEmpty())
        return;
    const QString label = kind == 0 ? QStringLiteral("正在启动通道…")
                                    : (kind == 1 ? QStringLiteral("正在刷新页面…")
                                                 : (kind == 2 ? QStringLiteral("正在执行…")
                                                              : QStringLiteral("正在导出 Storage…")));
    setBusy(true, label);

    m_log = [this](const QString &m) {
        auto alive = m_alive;
        if (!alive->load())
            return;
        QMetaObject::invokeMethod(this, "appendLog", Qt::QueuedConnection, Q_ARG(QString, m));
    };
    m_chan.setLog(m_log);

    auto alive = m_alive;
    const QString pattern = pagePattern();
    auto *job = new JobThread([this, kind, expr, pattern, alive] {
        QStringList pages;
        if (kind == 0) {
            const bool ok = m_chan.ensure();
            if (ok) {
                m_log(QStringLiteral("通道已启动"));
            } else {
                QMetaObject::invokeMethod(
                    this, [this] { appendLog(QStringLiteral("通道启动失败")); },
                    Qt::QueuedConnection);
            }
        }
        if (kind == 0 || kind == 1) {
            // Also fetch the page list (mini-program targets) for the combo box.
            CdpClient cdp;
            if (cdp.open(4000)) {
                QJsonObject t = cdp.send(QStringLiteral("Target.getTargets"), {}, {}, 5000);
                for (const auto &ti : t["result"].toObject()["targetInfos"].toArray()) {
                    QJsonObject o = ti.toObject();
                    if (o["type"].toString() == QLatin1String("page"))
                        pages << o["url"].toString();
                }
            }
            QMetaObject::invokeMethod(
                this, [this, pages] {
                    m_pages->clear();
                    if (pages.isEmpty())
                        m_pages->addItem(QStringLiteral("（未发现页面——先打开小程序）"));
                    else
                        m_pages->addItems(pages);
                },
                Qt::QueuedConnection);
        } else if (kind == 2) {
            QString err;
            EvalError ec = EvalError::None;
            const QJsonValue v = evalAppService(expr, true, 10000, &err, &ec, pattern);
            const QString exprHtml = expr.toHtmlEscaped();
            if (!v.isUndefined()) {
                const QString out = v.isString() ? prettyJson(v.toString())
                                                 : v.toVariant().toString();
                QMetaObject::invokeMethod(
                    this, [this, exprHtml, out] {
                        m_console->append(QStringLiteral("<span style='color:#64748b;'>%1</span> "
                                                         "<span style='color:#0F766E;'>› %2</span>")
                                              .arg(ts(), exprHtml));
                        m_console->append(out.toHtmlEscaped());
                    },
                    Qt::QueuedConnection);
            } else {
                QMetaObject::invokeMethod(
                    this, [this, exprHtml, err] {
                        m_console->append(QStringLiteral("<span style='color:#64748b;'>%1</span> "
                                                         "<span style='color:#0F766E;'>› %2</span>")
                                              .arg(ts(), exprHtml));
                        m_console->append(QStringLiteral("<span style='color:#DC2626;'>%1</span>")
                                              .arg(err.toHtmlEscaped()));
                    },
                    Qt::QueuedConnection);
            }
        } else if (kind == 3) {
            QString err;
            EvalError ec = EvalError::None;
            const QJsonValue v =
                evalAppService(QString::fromLatin1(kStorageJs), false, 10000, &err, &ec, pattern);
            if (v.isString()) {
                const QString path = QCoreApplication::applicationDirPath() +
                                     QStringLiteral("/storage-dump-%1.json")
                                         .arg(QDateTime::currentDateTime()
                                                  .toString(QStringLiteral("yyyyMMdd-HHmmss")));
                QFile f(path);
                if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                    f.write(prettyJson(v.toString()).toUtf8());
                    f.close();
                    QMetaObject::invokeMethod(
                        this, [this, path] { appendLog(QStringLiteral("已导出：%1").arg(path)); },
                        Qt::QueuedConnection);
                }
            } else {
                QMetaObject::invokeMethod(
                    this, [this, err] {
                        appendLog(QStringLiteral("导出失败：%1").arg(err));
                    },
                    Qt::QueuedConnection);
            }
        }
        const QString doneLabel = kind == 0 ? QStringLiteral("通道运行中") : QStringLiteral("就绪");
        QMetaObject::invokeMethod(
            this, [this, doneLabel] {
                setBusy(false, doneLabel);
                m_worker = nullptr;
            },
            Qt::QueuedConnection);
    });
    m_worker = job;
    connect(job, &QThread::finished, job, &QObject::deleteLater);
    job->start();
}

void StudioWindow::closeEvent(QCloseEvent *e) {
    if (!m_busy || !m_worker) {
        e->accept();
        m_chan.stop();
        return;
    }
    const auto ret = QMessageBox::question(
        this, QStringLiteral("任务进行中"),
        QStringLiteral("正在执行，确定关闭吗？"));
    if (ret != QMessageBox::Yes) {
        e->ignore();
        return;
    }
    if (!m_worker->wait(5000)) {
        e->ignore();
        return;
    }
    m_worker = nullptr;
    m_chan.stop();
    e->accept();
}
