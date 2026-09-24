#include "Config.h"

#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

AppConfig g_config;

AppConfig AppConfig::loadFrom(const QString &path) {
    AppConfig cfg;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        cfg.loadError = QStringLiteral("缺少 config.json（请参照 config.example.json 创建并放在程序同目录）");
        qWarning() << "Config file not found:" << path
                   << "- using empty defaults. Create config.json from config.example.json.";
        return cfg;
    }
    QJsonParseError pe{};
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        cfg.loadError = QStringLiteral("config.json 解析失败：%1").arg(pe.errorString());
        qWarning() << "Config parse error:" << pe.errorString();
        return cfg;
    }
    QJsonObject o = doc.object();
    cfg.aesKey = o["aesKey"].toString();
    cfg.aesIv = o["aesIv"].toString();
    cfg.serverPubKey = o["serverPubKey"].toString();
    cfg.appId = o["appId"].toString();
    cfg.mpCode = o["mpCode"].toString();
    cfg.baseUrl = o["baseUrl"].toString();
    cfg.mpVersion = o["mpVersion"].toInt(0);
    return cfg;
}

// Embedded default config (optional): CMake injects these from config.defaults.json,
// a local gitignored file (CI writes it from a secret). A real config.json next to the
// exe still overrides field by field; a missing config.json is only an error when no
// embedded defaults got compiled in.
#ifndef FZWY_CFG_AESKEY
#define FZWY_CFG_AESKEY ""
#endif
#ifndef FZWY_CFG_AESIV
#define FZWY_CFG_AESIV ""
#endif
#ifndef FZWY_CFG_SERVERPUBKEY
#define FZWY_CFG_SERVERPUBKEY ""
#endif
#ifndef FZWY_CFG_APPID
#define FZWY_CFG_APPID ""
#endif
#ifndef FZWY_CFG_MPCODE
#define FZWY_CFG_MPCODE ""
#endif
#ifndef FZWY_CFG_BASEURL
#define FZWY_CFG_BASEURL ""
#endif
#ifndef FZWY_CFG_MPVERSION
#define FZWY_CFG_MPVERSION 0
#endif

AppConfig AppConfig::load() {
    AppConfig cfg = loadFrom(QCoreApplication::applicationDirPath() + QStringLiteral("/config.json"));
    if (cfg.aesKey.isEmpty())
        cfg.aesKey = QStringLiteral(FZWY_CFG_AESKEY);
    if (cfg.aesIv.isEmpty())
        cfg.aesIv = QStringLiteral(FZWY_CFG_AESIV);
    if (cfg.serverPubKey.isEmpty())
        cfg.serverPubKey = QStringLiteral(FZWY_CFG_SERVERPUBKEY);
    if (cfg.appId.isEmpty())
        cfg.appId = QStringLiteral(FZWY_CFG_APPID);
    if (cfg.mpCode.isEmpty())
        cfg.mpCode = QStringLiteral(FZWY_CFG_MPCODE);
    if (cfg.baseUrl.isEmpty())
        cfg.baseUrl = QStringLiteral(FZWY_CFG_BASEURL);
    if (cfg.mpVersion == 0)
        cfg.mpVersion = FZWY_CFG_MPVERSION;
    if (!cfg.aesKey.isEmpty() && !cfg.serverPubKey.isEmpty())
        cfg.loadError.clear();
    return cfg;
}
