// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BPS_MOBILE_APP_QRSCANNER_H
#define BPS_MOBILE_APP_QRSCANNER_H

#include <QElapsedTimer>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QUrl>
#include <QVideoSink>
#include <QtQml/qqmlregistration.h>

/**
 * Reads QR codes from a camera's frames, or from a picture. Frames are
 * looked at a few times a second, each off the GUI thread, and the first
 * code read is reported once until `reset()`.
 */
class QrScanner : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(QVideoSink* videoSink READ videoSink WRITE setVideoSink NOTIFY videoSinkChanged)

public:
    explicit QrScanner(QObject* parent = nullptr);

    QVideoSink* videoSink() const { return m_sink; }
    void setVideoSink(QVideoSink* sink);

    /** The text of the QR code in the picture at `url`, or "" if there is none. */
    Q_INVOKABLE QString decodeFile(const QUrl& url) const;
    /** Look for a code again after one was found. */
    Q_INVOKABLE void reset();

Q_SIGNALS:
    void videoSinkChanged();
    void found(const QString& text);

private:
    void OnFrame(const QVideoFrame& frame);

    QPointer<QVideoSink> m_sink;
    QElapsedTimer m_since;
    bool m_working{false};
    bool m_done{false};
};

#endif // BPS_MOBILE_APP_QRSCANNER_H
