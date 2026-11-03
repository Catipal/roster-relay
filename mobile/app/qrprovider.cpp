// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qrprovider.h>

#include <QPainter>
#include <QUrl>

#include <qrencode.h>

QImage QrProvider::requestImage(const QString& id, QSize* size, const QSize& requested)
{
    const QByteArray text = QUrl::fromPercentEncoding(id.toUtf8()).toUtf8();
    QRcode* code = QRcode_encodeString(text.constData(), 0, QR_ECLEVEL_M, QR_MODE_8, 1);
    if (!code) return {};
    const int quiet = 4;
    const int modules = code->width + 2 * quiet;
    const int side = std::max(modules, requested.isValid() ? std::min(requested.width(), requested.height()) : 0);
    const int scale = std::max(1, side / modules);
    QImage image(modules * scale, modules * scale, QImage::Format_RGB32);
    image.fill(Qt::white);
    QPainter painter(&image);
    for (int y = 0; y < code->width; ++y) {
        for (int x = 0; x < code->width; ++x) {
            if (code->data[y * code->width + x] & 1) {
                painter.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale, Qt::black);
            }
        }
    }
    painter.end();
    QRcode_free(code);
    if (size) *size = image.size();
    return image;
}
