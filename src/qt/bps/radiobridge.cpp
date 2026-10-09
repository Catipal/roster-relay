// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/radiobridge.h>

#include <qt/bps/settingspage.h>
#include <qt/guiutil.h>

#include <overlay/radio.h>
#include <util/system.h>

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QSettings>

RadioBridge::RadioBridge(QObject* parent) : QObject(parent) {}

RadioBridge::~RadioBridge()
{
    Stop();
}

QString RadioBridge::DefaultPython()
{
#ifdef Q_OS_WIN
    return QStringLiteral("python");
#else
    return QStringLiteral("python3");
#endif
}

QString RadioBridge::ScriptPath()
{
    const QString name = QStringLiteral("bps-rns-bridge.py");
    const QDir app(QCoreApplication::applicationDirPath());
    for (const QString& candidate : {app.filePath(name), app.filePath("../share/bps/" + name),
                                     app.filePath("../../contrib/reticulum/" + name)}) {
        if (QFileInfo::exists(candidate)) return QDir::cleanPath(candidate);
    }
    return QString();
}

void RadioBridge::SetStatus(const QString& status)
{
    m_status = status;
    Q_EMIT statusChanged(status);
}

void RadioBridge::StartIfWanted()
{
    if (m_process) return;
    if (!gArgs.GetBoolArg("-radio", overlay::DEFAULT_RADIO) || !gArgs.GetBoolArg("-overlay", false)) {
        SetStatus(tr("Radio is off."));
        return;
    }
    if (!SettingsPage::StartRadioBridge()) {
        SetStatus(tr("Radio is on; start the Reticulum bridge yourself (contrib/reticulum/bps-rns-bridge.py)."));
        return;
    }
    const QString script = ScriptPath();
    if (script.isEmpty()) {
        SetStatus(tr("bps-rns-bridge.py is not beside BPS Relay, so the bridge cannot be started."));
        return;
    }
    const QString datadir = GUIUtil::boostPathToQString(GetDataDir());
    QDir(datadir).mkpath("radio");

    m_process = new QProcess(this);
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    m_process->setStandardOutputFile(QDir(datadir).filePath("radio/bridge.log"), QIODevice::Append);
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) {
            SetStatus(tr("Python could not be started as \"%1\". Install Python, or set the command under "
                         "Settings, Radio.").arg(SettingsPage::PythonCommand()));
        }
    });
    connect(m_process, static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus) {
                // Exit status 2 is the bridge saying Reticulum is missing.
                SetStatus(code == 2 ? tr("Reticulum is not installed. Install it with: pip install rns")
                                    : tr("The Reticulum bridge stopped (status %1); see radio/bridge.log.").arg(code));
                m_process->deleteLater();
                m_process = nullptr;
            });
    m_process->start(SettingsPage::PythonCommand(), {script, QStringLiteral("--datadir"), datadir});
    SetStatus(tr("The Reticulum bridge is starting."));
}

void RadioBridge::Stop()
{
    if (!m_process) return;
    QProcess* process = m_process;
    m_process = nullptr;
    process->disconnect(this);
    process->terminate();
    if (!process->waitForFinished(3000)) process->kill();
    process->deleteLater();
}
