#include "StudioWindow.h"

#include <QApplication>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLocale>
#include <QMessageBox>
#include <QVBoxLayout>

#include "../CdpClient.h"
#include "../WxPkg.h"

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

// One cached mini-program package found on disk.
struct LocalPkg {
    QString appId;
    QString version;
    QString path;
    qint64 size = 0;
};

// Enumerate %APPDATA%/Tencent/xwechat/radium/users/<hash>/applet/packages/
// <appId>/<version>/*.wxapkg. Empty appIdFilter scans every appId directory;
// the appId of each package is inferred from the directory name.
QList<LocalPkg> scanLocalPkgs(const QString &appIdFilter) {
    QList<LocalPkg> out;
    const QString root =
        qEnvironmentVariable("APPDATA") + QStringLiteral("/Tencent/xwechat/radium/users");
    const QDir usersDir(root);
    const QStringList users = usersDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    for (const QString &user : users) {
        const QString pkgsRoot = root + QLatin1Char('/') + user + QStringLiteral("/applet/packages");
        const QDir pkgsDir(pkgsRoot);
        const QStringList appIds =
            appIdFilter.isEmpty()
                ? pkgsDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name)
                : QStringList{appIdFilter};
        for (const QString &aid : appIds) {
            const QDir aidDir(pkgsRoot + QLatin1Char('/') + aid);
            const QStringList versions =
                aidDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
            for (const QString &ver : versions) {
                const QDir verDir(aidDir.filePath(ver));
                const QFileInfoList files =
                    verDir.entryInfoList({QStringLiteral("*.wxapkg")}, QDir::Files, QDir::Name);
                for (const QFileInfo &fi : files)
                    out.push_back({aid, ver, fi.absoluteFilePath(), fi.size()});
            }
        }
    }
    return out;
}
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

    auto *pkgCard = new QFrame;
    pkgCard->setObjectName(QStringLiteral("card"));
    auto *pl = new QVBoxLayout(pkgCard);
    pl->setContentsMargins(12, 10, 12, 10);
    pl->setSpacing(6);

    auto *pr = new QHBoxLayout;
    pr->setSpacing(8);
    auto *pkgLabel = new QLabel(QStringLiteral("离线解包"));
    pr->addWidget(pkgLabel);
    m_appId = new QLineEdit;
    m_appId->setPlaceholderText(QStringLiteral("小程序 appId（如 wx3130e983e955b53e）"));
    pr->addWidget(m_appId, 1);
    m_btnScan = new QPushButton(QStringLiteral("扫描本地包"));
    m_btnScan->setObjectName(QStringLiteral("ghost"));
    m_btnScan->setCursor(Qt::PointingHandCursor);
    connect(m_btnScan, &QPushButton::clicked, this, [this] { startJob(4); });
    pr->addWidget(m_btnScan);
    m_btnUnpack = new QPushButton(QStringLiteral("解包全部"));
    m_btnUnpack->setCursor(Qt::PointingHandCursor);
    connect(m_btnUnpack, &QPushButton::clicked, this, [this] { startJob(5); });
    pr->addWidget(m_btnUnpack);
    pl->addLayout(pr);
    lay->addWidget(pkgCard);

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
    m_btnScan->setEnabled(!busy);
    m_btnUnpack->setEnabled(!busy);
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
    QString label;
    switch (kind) {
    case 0: label = QStringLiteral("正在启动通道…"); break;
    case 1: label = QStringLiteral("正在刷新页面…"); break;
    case 2: label = QStringLiteral("正在执行…"); break;
    case 3: label = QStringLiteral("正在导出 Storage…"); break;
    case 4: label = QStringLiteral("正在扫描本地包…"); break;
    case 5: label = QStringLiteral("正在离线解包…"); break;
    default: return;
    }
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
    const QString appId = m_appId->text().trimmed();
    auto *job = new JobThread([this, kind, expr, pattern, appId, alive] {
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
        } else if (kind == 4 || kind == 5) {
            const QList<LocalPkg> pkgs = scanLocalPkgs(appId);
            if (pkgs.isEmpty()) {
                m_log(appId.isEmpty()
                          ? QStringLiteral("未找到任何本地包（确认 %APPDATA%/Tencent/xwechat/"
                                           "radium 下存在 packages 缓存）")
                          : QStringLiteral("未找到 appId %1 的本地包").arg(appId));
            } else if (kind == 4) {
                m_log(QStringLiteral("找到 %1 个本地包：").arg(pkgs.size()));
                QString lastKey;
                for (const LocalPkg &p : pkgs) {
                    const QString key = p.appId + QLatin1Char('/') + p.version;
                    if (key != lastKey) {
                        m_log(QStringLiteral("  %1 版本目录 %2").arg(p.appId, p.version));
                        lastKey = key;
                    }
                    m_log(QStringLiteral("    %1  %2")
                              .arg(QFileInfo(p.path).fileName(),
                                   QLocale().formattedDataSize(p.size)));
                }
                m_log(QStringLiteral("提示：appId 留空时按目录名自动推断"));
            } else {
                const QString outRoot = QCoreApplication::applicationDirPath() +
                                        QStringLiteral("/unpacked");
                m_log(QStringLiteral("开始解包 %1 个包，输出目录 %2").arg(pkgs.size()).arg(outRoot));
                int okCount = 0;
                int failCount = 0;
                for (const LocalPkg &p : pkgs) {
                    const QString pkgName = QFileInfo(p.path).completeBaseName();
                    QString err;
                    const QByteArray plain = WxPkg::decryptFile(p.path, p.appId, &err);
                    if (plain.isEmpty()) {
                        m_log(QStringLiteral("  解密失败 %1/%2/%3：%4")
                                  .arg(p.appId, p.version, pkgName, err));
                        ++failCount;
                        continue;
                    }
                    const QString outDir = outRoot + QLatin1Char('/') + p.appId +
                                           QLatin1Char('/') + p.version + QLatin1Char('/') +
                                           pkgName;
                    err.clear();
                    const int n = WxPkg::unpackToDir(plain, outDir, &err);
                    if (n < 0) {
                        m_log(QStringLiteral("  解包失败 %1/%2/%3：%4")
                                  .arg(p.appId, p.version, pkgName, err));
                        ++failCount;
                        continue;
                    }
                    m_log(QStringLiteral("  %1/%2/%3 写出 %4 个文件 → %5")
                              .arg(p.appId, p.version, pkgName)
                              .arg(n)
                              .arg(outDir));
                    if (!err.isEmpty())
                        m_log(QStringLiteral("    警告：%1").arg(err));
                    ++okCount;
                }
                m_log(QStringLiteral("离线解包完成：成功 %1 个，失败 %2 个")
                          .arg(okCount)
                          .arg(failCount));
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
