// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <devicekey.h>

#include <support/cleanse.h>
#include <util/strencodings.h>

#include <QCryptographicHash>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QSaveFile>
#include <QTimer>

#include <qt6keychain/keychain.h>

namespace {

const QString SERVICE = QStringLiteral("BPS Companion");

/** The keychain entry for one data folder. */
QString EntryName(const QString& dir)
{
    const QByteArray hash = QCryptographicHash::hash(QDir(dir).absolutePath().toUtf8(), QCryptographicHash::Sha256);
    return QStringLiteral("device-key-") + QString::fromLatin1(hash.toHex().left(16));
}

/**
 * Run a keychain job to its end. They are asynchronous; this runs before the
 * app's own loop starts. A keyring that never answers counts as none.
 */
QKeychain::Error RunJob(QKeychain::Job& job)
{
    job.setAutoDelete(false);
    bool finished = false;
    QEventLoop loop;
    QObject::connect(&job, &QKeychain::Job::finished, &loop, [&] {
        finished = true;
        loop.quit();
    });
    QTimer::singleShot(15000, &loop, &QEventLoop::quit);
    job.start();
    if (!finished) loop.exec();
    return finished ? job.error() : QKeychain::OtherError;
}

bool KeyFromHex(const QByteArray& hex, CKey& key)
{
    std::vector<unsigned char> raw = ParseHex(hex.trimmed().toStdString());
    if (raw.size() != 32) return false;
    key.Set(raw.begin(), raw.end(), true);
    memory_cleanse(raw.data(), raw.size());
    return key.IsValid();
}

QByteArray KeyToHex(const CKey& key)
{
    return QByteArray::fromStdString(HexStr(Span<const unsigned char>(key.begin(), key.size())));
}

bool WriteFile(const QString& path, const CKey& key)
{
    QSaveFile out(path);
    if (!out.open(QIODevice::WriteOnly)) return false;
    out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    out.write(KeyToHex(key) + '\n');
    return out.commit();
}

/** Overwrite before removing, so the key does not linger in the freed blocks of a simple filesystem. */
void RemoveFile(const QString& path)
{
    QFile f(path);
    if (f.open(QIODevice::ReadWrite)) {
        f.write(QByteArray(f.size(), '0'));
        f.flush();
        f.close();
    }
    QFile::remove(path);
}

} // namespace

bool LoadOrMakeDeviceKey(const QString& dir, CKey& key, bool& in_keystore, QString& error)
{
    const QString name = EntryName(dir);
    const QString file = dir + QStringLiteral("/device.key");
    in_keystore = false;

    QKeychain::ReadPasswordJob read(SERVICE);
    read.setKey(name);
    const QKeychain::Error found = RunJob(read);
    const bool keystore = found == QKeychain::NoError || found == QKeychain::EntryNotFound;
    if (found == QKeychain::NoError) {
        if (!KeyFromHex(read.binaryData(), key)) {
            error = QObject::tr("The device key in the system keystore is damaged.");
            return false;
        }
        in_keystore = true;
        // Moved in by an earlier run that could not remove the file: finish the job.
        if (QFile::exists(file)) RemoveFile(file);
        return true;
    }

    QFile in(file);
    if (in.open(QIODevice::ReadOnly)) {
        if (!KeyFromHex(in.readAll(), key)) {
            error = QObject::tr("The device key in %1 is damaged.").arg(file);
            return false;
        }
        in.close();
    } else {
        key.MakeNewKey(true);
    }

    if (keystore) {
        QKeychain::WritePasswordJob write(SERVICE);
        write.setKey(name);
        write.setBinaryData(KeyToHex(key));
        if (RunJob(write) == QKeychain::NoError) {
            in_keystore = true;
            if (QFile::exists(file)) RemoveFile(file);
            return true;
        }
    }
    if (QFile::exists(file)) return true;
    if (!WriteFile(file, key)) {
        error = QObject::tr("Could not write the device key to %1.").arg(file);
        return false;
    }
    return true;
}
