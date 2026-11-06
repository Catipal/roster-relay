// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BPS_MOBILE_APP_ANDROIDPICKER_H
#define BPS_MOBILE_APP_ANDROIDPICKER_H

#include <QObject>
#include <QUrl>
#include <QtCore/private/qandroidextras_p.h>
#include <QtQml/qqmlregistration.h>

/**
 * The phone's own picture picker. QtQuick.Dialogs would do the same, but it
 * brings every Qt Quick Controls style with it, a third of the package.
 */
class AndroidPicturePicker : public QObject, public QAndroidActivityResultReceiver
{
    Q_OBJECT
    QML_ELEMENT

public:
    explicit AndroidPicturePicker(QObject* parent = nullptr) : QObject(parent) {}

    Q_INVOKABLE void open();

    void handleActivityResult(int request, int result, const QJniObject& data) override;

Q_SIGNALS:
    /** A content:// address, which QImage and QFile open as they are. */
    void picked(const QUrl& url);
};

#endif // BPS_MOBILE_APP_ANDROIDPICKER_H
