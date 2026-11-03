// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BPS_MOBILE_APP_QRPROVIDER_H
#define BPS_MOBILE_APP_QRPROVIDER_H

#include <QQuickImageProvider>

/** "image://qr/<text>": the text as a QR code drawn by ZXing-C++, black on white, with its quiet zone. */
class QrProvider : public QQuickImageProvider
{
public:
    QrProvider() : QQuickImageProvider(QQuickImageProvider::Image) {}
    QImage requestImage(const QString& id, QSize* size, const QSize& requested) override;
};

#endif // BPS_MOBILE_APP_QRPROVIDER_H
