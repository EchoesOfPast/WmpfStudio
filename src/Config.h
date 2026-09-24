#pragma once

#include <QString>

// Configuration loaded from config.json at startup; protocol constants are
// externalized so the source tree contains no hardcoded secrets.
struct AppConfig {
    QString aesKey;       // AES-128-CBC key (16 bytes, ASCII)
    QString aesIv;        // AES-128-CBC IV (16 bytes, ASCII)
    QString serverPubKey; // Server RSA public key (hex-encoded, AES-encrypted)
    QString appId;        // WeChat mini-program app ID (e.g. wx0123456789abcdef)
    QString mpCode;
    QString baseUrl;      // API base URL (with trailing slash)
    int mpVersion = 0;    // Mini-program version, sent in the Referer header
    QString loadError;    // Load failure reason; empty means loaded successfully

    // Loads config.json next to the executable; a missing file yields empty fields.
    static AppConfig load();
    static AppConfig loadFrom(const QString &path);
};

extern AppConfig g_config;
