// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qrscanner.h>

#include <QImage>
#include <QVideoFrame>
#include <QtConcurrent/QtConcurrentRun>

#include <ZXing/ReadBarcode.h>

namespace {

/** Milliseconds between frames looked at: enough to feel instant, little enough to stay cool. */
constexpr qint64 FRAME_GAP_MS = 200;
/** Frames are scaled down to this on their longer side first; a code filling a fair part of the view still reads. */
constexpr int MAX_SIDE = 1280;

QString Decode(QImage image)
{
    if (image.isNull()) return {};
    if (std::max(image.width(), image.height()) > MAX_SIDE) {
        image = image.scaled(MAX_SIDE, MAX_SIDE, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    }
    image = image.convertToFormat(QImage::Format_Grayscale8);
    const ZXing::ImageView view(image.constBits(), image.width(), image.height(), ZXing::ImageFormat::Lum,
                                int(image.bytesPerLine()));
    ZXing::ReaderOptions options;
    options.setFormats(ZXing::BarcodeFormat::QRCode);
    options.setTryHarder(true);
    options.setTryRotate(true);
    const ZXing::Barcode code = ZXing::ReadBarcode(view, options);
    if (!code.isValid()) return {};
    return QString::fromStdString(code.text());
}

} // namespace

QrScanner::QrScanner(QObject* parent) : QObject(parent) { m_since.start(); }

void QrScanner::setVideoSink(QVideoSink* sink)
{
    if (m_sink == sink) return;
    if (m_sink) disconnect(m_sink, nullptr, this, nullptr);
    m_sink = sink;
    if (m_sink) connect(m_sink, &QVideoSink::videoFrameChanged, this, &QrScanner::OnFrame);
    Q_EMIT videoSinkChanged();
}

void QrScanner::reset() { m_done = false; }

void QrScanner::OnFrame(const QVideoFrame& frame)
{
    if (m_done || m_working || !frame.isValid() || m_since.elapsed() < FRAME_GAP_MS) return;
    m_since.restart();
    m_working = true;
    // The copy to an image is the only part done here; reading it is not.
    const QImage image = frame.toImage();
    // Back on this object's thread, and not at all if it is gone by then.
    QtConcurrent::run(Decode, image).then(this, [this](const QString& text) {
        m_working = false;
        if (text.isEmpty() || m_done) return;
        m_done = true;
        Q_EMIT found(text);
    });
}

QString QrScanner::decodeFile(const QUrl& url) const
{
    return Decode(QImage(url.isLocalFile() ? url.toLocalFile() : url.toString()));
}
