// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_RADIOBRIDGE_H
#define BITCOIN_QT_BPS_RADIOBRIDGE_H

#include <QObject>
#include <QProcess>
#include <QString>

/**
 * Runs the Reticulum bridge (contrib/reticulum/bps-rns-bridge.py) beside the
 * node, so radio links work without a terminal (overlay/radio.h).
 *
 * The bridge is Python and Reticulum is installed separately, with pip; this
 * only starts it, with the node's data directory, stops it with the client,
 * and says why when it cannot run. Its output goes to radio/bridge.log.
 */
class RadioBridge : public QObject
{
    Q_OBJECT

public:
    explicit RadioBridge(QObject* parent = nullptr);
    ~RadioBridge();

    /** Start it, if the node runs with -radio and Settings asks for the bridge. */
    void StartIfWanted();
    void Stop();

    /** One line on how it is going, for Settings and the Overlay page. */
    QString Status() const { return m_status; }

    /** Where the script is: beside the client, in share/, or in the source tree. */
    static QString ScriptPath();
    /** "python" on Windows, where the installer puts it on the path by that name; "python3" elsewhere. */
    static QString DefaultPython();

Q_SIGNALS:
    void statusChanged(const QString& status);

private:
    void SetStatus(const QString& status);

    QProcess* m_process{nullptr};
    QString m_status;
};

#endif // BITCOIN_QT_BPS_RADIOBRIDGE_H
