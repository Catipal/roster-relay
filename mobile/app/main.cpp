// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// BPS Companion: a phone that spends from an allowance wallet on its owner's
// home node, within limits only the home node can change. The phone holds no
// coin keys - only a device key, which can spend nothing without the PIN.

#include <backend.h>
#include <qrprovider.h>

#include <key.h>
#include <random.h>
#include <util/system.h>

#include <QCommandLineParser>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QStandardPaths>

#include <functional>
#include <string>

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

int main(int argc, char* argv[])
{
    SetupEnvironment();
    RandomInit();
    ECC_Start();
    int ret = 1;
    {
        ECCVerifyHandle verify;
        QGuiApplication app(argc, argv);
        QGuiApplication::setOrganizationName(QStringLiteral("BPS"));
        QGuiApplication::setApplicationName(QStringLiteral("BPS Companion"));
        QGuiApplication::setDesktopFileName(QStringLiteral("org.bps.companion"));

        QCommandLineParser parser;
        parser.addHelpOption();
        QCommandLineOption datadir(QStringLiteral("datadir"),
                                   QStringLiteral("Keep the device key and home node in <dir>."), QStringLiteral("dir"));
        parser.addOption(datadir);
        parser.process(app);
        const QString dir = parser.isSet(datadir) ? parser.value(datadir)
                                                  : QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);

        // One look on every platform, drawn by the app rather than borrowed.
        QQuickStyle::setStyle(QStringLiteral("Basic"));

        Backend backend(dir);
        QString error;
        const bool loaded = backend.Load(error);

        QQmlApplicationEngine engine;
        engine.addImageProvider(QStringLiteral("qr"), new QrProvider);
        engine.rootContext()->setContextProperty(QStringLiteral("backend"), &backend);
        engine.rootContext()->setContextProperty(QStringLiteral("startupError"), loaded ? QString() : error);
        QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app,
                         [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
        engine.loadFromModule("BPSCompanion", "Main");
        ret = app.exec();
    }
    ECC_Stop();
    return ret;
}
