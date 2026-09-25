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
#include "../wmpf/FxInstrument.h"
#include "../wmpf/WmpfInject.h"

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

// Parse a hex number ("0x1A2B" or "1A2B"); empty string fails.
bool parseHex(const QString &s, quint64 *out) {
    QString t = s.trimmed();
    if (t.startsWith(QLatin1String("0x"), Qt::CaseInsensitive))
        t = t.mid(2);
    if (t.isEmpty())
        return false;
    bool ok = false;
    const quint64 v = t.toULongLong(&ok, 16);
    if (ok)
        *out = v;
    return ok;
}

// Parse a hex byte string. Accepts spaced ("4D 5A ?? 00") and compact
// ("4D5A??00") forms; "??"/"?" bytes become wildcards in the mask.
bool parseHexPattern(const QString &s, QByteArray *pattern, QByteArray *mask) {
    QString t = s;
    t.remove(QLatin1Char(' '));
    t.remove(QLatin1Char('\t'));
    if (t.isEmpty() || t.size() % 2 != 0)
        return false;
    pattern->clear();
    mask->clear();
    for (int i = 0; i + 2 <= t.size(); i += 2) {
        const QString tok = t.mid(i, 2);
        if (tok == QLatin1String("??") || tok == QLatin1String("**")) {
            pattern->append('\0');
            mask->append('?');
            continue;
        }
        bool ok = false;
        const uint v = tok.toUInt(&ok, 16);
        if (!ok)
            return false;
        pattern->append(char(v));
        mask->append('x');
    }
    return !pattern->isEmpty();
}

// Hex dump for the log: 16 bytes per line, address prefix, ASCII gutter.
QStringList hexDump(quint64 base, const QByteArray &data) {
    QStringList lines;
    for (int off = 0; off < data.size(); off += 16) {
        const int n = qMin(16, int(data.size()) - off);
        QString hex;
        QString ascii;
        for (int i = 0; i < n; ++i) {
            const uchar b = uchar(data[off + i]);
            hex += QStringLiteral("%1 ").arg(b, 2, 16, QLatin1Char('0'));
            ascii += (b >= 32 && b <= 126) ? QLatin1Char(char(b)) : QLatin1Char('.');
        }
        while (hex.size() < 16 * 3)
            hex += QLatin1Char(' ');
        lines << QStringLiteral("0x%1  %2 %3")
                     .arg(base + quint64(off), 16, 16, QLatin1Char('0'))
                     .arg(hex, ascii);
    }
    if (lines.isEmpty())
        lines << QStringLiteral("（0 字节）");
    return lines;
}

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
    resize(760, 780);
    setMinimumSize(620, 640);
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

    // Memory instrument card: drives the FxInstrument IPC of FzwyHook.dll
    // running inside the target WeChatAppEx process.
    auto *fxCard = new QFrame;
    fxCard->setObjectName(QStringLiteral("card"));
    auto *fl = new QVBoxLayout(fxCard);
    fl->setContentsMargins(12, 10, 12, 10);
    fl->setSpacing(6);
    const auto mkBtn = [this](QPushButton **btn, const QString &text, bool ghost, int kind) {
        *btn = new QPushButton(text);
        if (ghost)
            (*btn)->setObjectName(QStringLiteral("ghost"));
        (*btn)->setCursor(Qt::PointingHandCursor);
        connect(*btn, &QPushButton::clicked, this, [this, kind] { startJob(kind); });
    };

    auto *fr1 = new QHBoxLayout;
    fr1->setSpacing(8);
    fr1->addWidget(new QLabel(QStringLiteral("内存仪器")));
    m_fxAddr = new QLineEdit;
    m_fxAddr->setPlaceholderText(QStringLiteral("地址（hex，如 0x7FF612340000）"));
    fr1->addWidget(m_fxAddr, 2);
    m_fxLen = new QLineEdit;
    m_fxLen->setText(QStringLiteral("0x100"));
    fr1->addWidget(m_fxLen, 1);
    mkBtn(&m_btnFxRead, QStringLiteral("读取"), false, 6);
    fr1->addWidget(m_btnFxRead);
    fl->addLayout(fr1);

    auto *fr2 = new QHBoxLayout;
    fr2->setSpacing(8);
    m_fxWriteVal = new QLineEdit;
    m_fxWriteVal->setPlaceholderText(QStringLiteral("写入字节（hex 串，如 90 90 CC）"));
    fr2->addWidget(m_fxWriteVal, 2);
    mkBtn(&m_btnFxWrite, QStringLiteral("写入"), false, 7);
    fr2->addWidget(m_btnFxWrite);
    m_fxModule = new QLineEdit;
    m_fxModule->setPlaceholderText(QStringLiteral("模块名（如 flue.dll；导出列表用，留空=默认）"));
    fr2->addWidget(m_fxModule, 2);
    mkBtn(&m_btnFxModules, QStringLiteral("模块列表"), true, 8);
    fr2->addWidget(m_btnFxModules);
    mkBtn(&m_btnFxExports, QStringLiteral("导出列表"), true, 9);
    fr2->addWidget(m_btnFxExports);
    fl->addLayout(fr2);

    auto *fr3 = new QHBoxLayout;
    fr3->setSpacing(8);
    m_fxPattern = new QLineEdit;
    m_fxPattern->setPlaceholderText(QStringLiteral("模式（hex 串，?? 通配，如 4D 5A ?? 00）"));
    fr3->addWidget(m_fxPattern, 2);
    m_fxScanStart = new QLineEdit;
    m_fxScanStart->setPlaceholderText(QStringLiteral("起始地址（默认 0）"));
    fr3->addWidget(m_fxScanStart, 1);
    m_fxScanLen = new QLineEdit;
    m_fxScanLen->setText(QStringLiteral("0x2000000"));
    fr3->addWidget(m_fxScanLen, 1);
    mkBtn(&m_btnFxScan, QStringLiteral("扫描"), false, 10);
    fr3->addWidget(m_btnFxScan);
    fl->addLayout(fr3);

    auto *fr4 = new QHBoxLayout;
    fr4->setSpacing(8);
    m_fxCallAddr = new QLineEdit;
    m_fxCallAddr->setPlaceholderText(QStringLiteral("函数地址（hex）——调用任意指针可能崩目标进程，谨慎使用"));
    fr4->addWidget(m_fxCallAddr, 2);
    for (int i = 0; i < 4; ++i) {
        m_fxArgs[i] = new QLineEdit;
        m_fxArgs[i]->setPlaceholderText(QStringLiteral("参数%1（hex，可空）").arg(i));
        fr4->addWidget(m_fxArgs[i], 1);
    }
    mkBtn(&m_btnFxCall, QStringLiteral("调用"), false, 11);
    fr4->addWidget(m_btnFxCall);
    fl->addLayout(fr4);
    lay->addWidget(fxCard);

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
    m_btnFxRead->setEnabled(!busy);
    m_btnFxWrite->setEnabled(!busy);
    m_btnFxModules->setEnabled(!busy);
    m_btnFxExports->setEnabled(!busy);
    m_btnFxScan->setEnabled(!busy);
    m_btnFxCall->setEnabled(!busy);
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
    if (kind == 6) {
        // The read needs an address up front; fail fast before spawning a thread.
        quint64 addr = 0;
        if (!parseHex(m_fxAddr->text(), &addr)) {
            appendLog(QStringLiteral("内存仪器：地址格式不对（hex，如 0x7FF612340000）"));
            return;
        }
    }
    QString label;
    switch (kind) {
    case 0: label = QStringLiteral("正在启动通道…"); break;
    case 1: label = QStringLiteral("正在刷新页面…"); break;
    case 2: label = QStringLiteral("正在执行…"); break;
    case 3: label = QStringLiteral("正在导出 Storage…"); break;
    case 4: label = QStringLiteral("正在扫描本地包…"); break;
    case 5: label = QStringLiteral("正在离线解包…"); break;
    case 6: label = QStringLiteral("正在读取目标内存…"); break;
    case 7: label = QStringLiteral("正在写入目标内存…"); break;
    case 8: label = QStringLiteral("正在枚举模块…"); break;
    case 9: label = QStringLiteral("正在解析导出表…"); break;
    case 10: label = QStringLiteral("正在扫描目标内存…"); break;
    case 11: label = QStringLiteral("正在调用目标函数…"); break;
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
    // Memory-instrument inputs, snapshotted before the worker thread starts:
    // 0=addr 1=len 2=writeBytes 3=module 4=scanPattern 5=scanStart 6=scanLen
    // 7=callAddr 8..11=call args
    const QStringList fxIn{
        m_fxAddr->text().trimmed(),   m_fxLen->text().trimmed(),
        m_fxWriteVal->text().trimmed(), m_fxModule->text().trimmed(),
        m_fxPattern->text().trimmed(),  m_fxScanStart->text().trimmed(),
        m_fxScanLen->text().trimmed(),  m_fxCallAddr->text().trimmed(),
        m_fxArgs[0]->text().trimmed(),  m_fxArgs[1]->text().trimmed(),
        m_fxArgs[2]->text().trimmed(),  m_fxArgs[3]->text().trimmed(),
    };
    auto *job = new JobThread([this, kind, expr, pattern, appId, alive, fxIn] {
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
        } else if (kind >= 6 && kind <= 11) {
            // Memory instrument: attach to the FzwyHook IPC inside the target
            // WeChatAppEx host process, then run the requested op.
            wmpf::FxInstrument fx;
            QString err;
            const quint32 pid = wmpf::pickMainHostPid();
            bool attached = false;
            if (!pid) {
                err = QStringLiteral("当前没有 WeChatAppEx 主宿主进程（请先启动通道）");
            } else {
                // Try every loaded hook variant (newest hash suffix last): versions
                // predating the instrument have no IPC objects, so keep falling
                // through to the next variant on attach failure.
                const QStringList names = wmpf::loadedHookDllNames(pid);
                if (names.isEmpty()) {
                    err = QStringLiteral("hook 未安装/仪器通道未建立，请先启动通道");
                } else {
                    for (int i = names.size() - 1; i >= 0 && !attached; --i) {
                        QString base = names[i];
                        const int dot = base.lastIndexOf(QLatin1Char('.'));
                        if (dot > 0)
                            base = base.left(dot);
                        QString e2;
                        if (fx.attach(pid, base, &e2))
                            attached = true;
                        else
                            err = e2;
                    }
                    if (!attached)
                        err = QStringLiteral("仪器通道未建立（%1）——hook 可能是旧版本，请重新启动通道")
                                  .arg(err);
                }
            }
            if (!attached) {
                m_log(QStringLiteral("内存仪器连接失败：%1").arg(err));
            } else if (kind == 6) {  // read
                quint64 addr = 0, len = 0x100;
                parseHex(fxIn[0], &addr);  // pre-validated in startJob
                if (!fxIn[1].isEmpty() && !parseHex(fxIn[1], &len)) {
                    m_log(QStringLiteral("长度格式不对：%1（hex，如 0x100）").arg(fxIn[1]));
                } else if (len == 0 || len > 0x10000) {
                    m_log(QStringLiteral("长度须在 1–0x10000 之间（当前 0x%1）").arg(len, 0, 16));
                } else {
                    QByteArray data;
                    if (fx.read(addr, quint32(len), &data, &err)) {
                        m_log(QStringLiteral("从 pid=%1 的 0x%2 读到 %3 字节：")
                                  .arg(pid)
                                  .arg(addr, 0, 16)
                                  .arg(data.size()));
                        const QStringList rows = hexDump(addr, data);
                        for (const QString &r : rows)
                            m_log(r);
                    } else {
                        m_log(QStringLiteral("读取失败：%1").arg(err));
                    }
                }
            } else if (kind == 7) {  // write
                quint64 addr = 0;
                QByteArray bytes, mask;
                if (!parseHex(fxIn[0], &addr)) {
                    m_log(QStringLiteral("地址格式不对（hex，如 0x7FF612340000）"));
                } else if (!parseHexPattern(fxIn[2], &bytes, &mask) || mask.contains('?')) {
                    m_log(QStringLiteral("写入值格式不对（hex 字节串，不支持通配）"));
                } else if (bytes.size() > 4096) {
                    m_log(QStringLiteral("单次最多写 4096 字节（当前 %1）").arg(bytes.size()));
                } else if (fx.write(addr, bytes, &err)) {
                    m_log(QStringLiteral("已写入 %1 字节 → pid=%2 的 0x%3")
                              .arg(bytes.size())
                              .arg(pid)
                              .arg(addr, 0, 16));
                } else {
                    m_log(QStringLiteral("写入失败：%1").arg(err));
                }
            } else if (kind == 8) {  // modules
                QVector<wmpf::FxModuleInfo> mods;
                if (fx.modules(&mods, &err)) {
                    m_log(QStringLiteral("pid=%1 共 %2 个模块：").arg(pid).arg(mods.size()));
                    for (const wmpf::FxModuleInfo &m : mods)
                        m_log(QStringLiteral("  %1\t0x%2\t%3")
                                  .arg(m.name)
                                  .arg(m.base, 0, 16)
                                  .arg(QLocale().formattedDataSize(qint64(m.size))));
                } else {
                    m_log(QStringLiteral("模块枚举失败：%1").arg(err));
                }
            } else if (kind == 9) {  // exports
                quint64 base = 0;
                const QString modName = fxIn[3];
                if (!modName.isEmpty()) {
                    QVector<wmpf::FxModuleInfo> mods;
                    if (fx.modules(&mods, &err)) {
                        for (const wmpf::FxModuleInfo &m : mods) {
                            if (m.name.compare(modName, Qt::CaseInsensitive) == 0) {
                                base = m.base;
                                break;
                            }
                        }
                        if (!base)
                            m_log(QStringLiteral("目标进程里没有模块 %1，请先用模块列表确认名称")
                                      .arg(modName));
                    } else {
                        m_log(QStringLiteral("模块枚举失败：%1").arg(err));
                    }
                }
                if (base || modName.isEmpty()) {
                    QVector<wmpf::FxExportInfo> exps;
                    if (fx.exports(base, &exps, &err)) {
                        m_log(QStringLiteral("共 %1 个导出（%2）：")
                                  .arg(exps.size())
                                  .arg(modName.isEmpty()
                                           ? QStringLiteral("flue.dll，缺省回退到 hook DLL 自身")
                                           : modName));
                        const int show = qMin(200, int(exps.size()));
                        for (int i = 0; i < show; ++i)
                            m_log(QStringLiteral("  %1\t0x%2")
                                      .arg(exps[i].name)
                                      .arg(exps[i].addr, 0, 16));
                        if (exps.size() > show)
                            m_log(QStringLiteral("  … 其余 %1 项省略").arg(exps.size() - show));
                    } else {
                        m_log(QStringLiteral("导出解析失败：%1").arg(err));
                    }
                }
            } else if (kind == 10) {  // scan
                QByteArray pat, mask;
                quint64 start = 0, len = 0;
                if (!parseHexPattern(fxIn[4], &pat, &mask)) {
                    m_log(QStringLiteral("模式格式不对（hex 串，?? 通配，如 4D 5A ?? 00）"));
                } else if (pat.size() > 256) {
                    m_log(QStringLiteral("模式最长 256 字节（当前 %1）").arg(pat.size()));
                } else if (!fxIn[5].isEmpty() && !parseHex(fxIn[5], &start)) {
                    m_log(QStringLiteral("起始地址格式不对：%1").arg(fxIn[5]));
                } else if (!parseHex(fxIn[6], &len) || len == 0 || len > 0x4000000ull) {
                    m_log(QStringLiteral("扫描长度须在 1–0x4000000 之间（hex）"));
                } else {
                    m_log(QStringLiteral("在 pid=%1 的 [0x%2, 0x%3) 扫描 %4 字节模式…")
                              .arg(pid)
                              .arg(start, 0, 16)
                              .arg(start + len, 0, 16)
                              .arg(pat.size()));
                    quint64 hit = 0;
                    if (fx.scan(start, len, pat, mask, &hit, &err)) {
                        if (hit)
                            m_log(QStringLiteral("命中：0x%1").arg(hit, 0, 16));
                        else
                            m_log(QStringLiteral("未命中（范围内没有找到该模式）"));
                    } else {
                        m_log(QStringLiteral("扫描失败：%1").arg(err));
                    }
                }
            } else if (kind == 11) {  // call
                quint64 fn = 0;
                quint64 args[4] = {0, 0, 0, 0};
                bool argsOk = true;
                for (int i = 0; i < 4 && argsOk; ++i) {
                    if (!fxIn[8 + i].isEmpty() && !parseHex(fxIn[8 + i], &args[i]))
                        argsOk = false;
                }
                if (!parseHex(fxIn[7], &fn)) {
                    m_log(QStringLiteral("函数地址格式不对（hex）"));
                } else if (!argsOk) {
                    m_log(QStringLiteral("参数格式不对（hex，可空）"));
                } else {
                    m_log(QStringLiteral("调用 0x%1(%2, %3, %4, %5)…")
                              .arg(fn, 0, 16)
                              .arg(args[0], 0, 16)
                              .arg(args[1], 0, 16)
                              .arg(args[2], 0, 16)
                              .arg(args[3], 0, 16));
                    quint64 ret = 0;
                    if (fx.callAddr(fn, args[0], args[1], args[2], args[3], &ret, &err))
                        m_log(QStringLiteral("返回 0x%1（十进制 %2）")
                                  .arg(ret, 0, 16)
                                  .arg(ret));
                    else
                        m_log(QStringLiteral("调用失败：%1").arg(err));
                }
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
