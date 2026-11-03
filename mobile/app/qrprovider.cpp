// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qrprovider.h>

#include <QPainter>
#include <QUrl>

#include <ZXing/BitMatrix.h>
#include <ZXing/MultiFormatWriter.h>

#include <algorithm>

QImage QrProvider::requestImage(const QString& id, QSize* size, const QSize& requested)
{
    const std::string text = QUrl::fromPercentEncoding(id.toUtf8()).toStdString();
    ZXing::BitMatrix code;
    try {
        // Width and height 0: one pixel a module, scaled up below. Error correction M, as BPS Relay's codes.
        code = ZXing::MultiFormatWriter(ZXing::BarcodeFormat::QRCode).setMargin(0).setEccLevel(4).encode(text, 0, 0);
    } catch (const std::exception&) {
        return {};
    }
    const int quiet = 4;
    const int modules = code.width() + 2 * quiet;
    const int side = std::max(modules, requested.isValid() ? std::min(requested.width(), requested.height()) : 0);
    const int scale = std::max(1, side / modules);
    QImage image(modules * scale, modules * scale, QImage::Format_RGB32);
    image.fill(Qt::white);
    QPainter painter(&image);
    for (int y = 0; y < code.height(); ++y) {
        for (int x = 0; x < code.width(); ++x) {
            if (code.get(x, y)) painter.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale, Qt::black);
        }
    }
    painter.end();
    if (size) *size = image.size();
    return image;
}
