#pragma once

#include <QByteArray>
#include <QString>

// Offline decrypt + unpack for PC WeChat mini-program packages (*.wxapkg).
//
// On-disk encrypted layout (BlackTrace/pc_wxapkg_decrypt algorithm):
//   "V1MMWX" (6B) | AES-256-CBC(plain[0:1023]) (1024B) | XOR(appId[-2])(plain[1023:])
//   key = PBKDF2-HMAC-SHA1(password=appId, salt="saltiest", iter=1000, dkLen=32)
//   iv  = "the iv: 16 bytes"
//
// Decrypted container layout:
//   u8 0xBE | u32be infoLen | u32be idxLen | u32be bodyLen | [u8 0xED lastMark]
//   u32be count, then per entry: u32be nameLen | name(utf8) | u32be offset | u32be size
//   (offset is absolute, from the start of the decrypted buffer)
namespace WxPkg {

// Decrypt one encrypted .wxapkg file. Returns the decrypted container, or an
// empty array with *err set (missing V1MMWX magic, CNG failure, ...).
QByteArray decryptFile(const QString &path, const QString &appId, QString *err);

// Extract a decrypted container into outDir. Returns the number of files
// written, or -1 with *err set on structural failures (bad 0xBE magic,
// truncated index, out-of-range entry offsets). Individual write failures
// are skipped and reported via *err while the count stays >= 0.
int unpackToDir(const QByteArray &data, const QString &outDir, QString *err);

}  // namespace WxPkg
