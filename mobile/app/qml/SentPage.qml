import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

ColumnLayout {
    id: root
    signal done()
    spacing: 16

    Item { implicitHeight: 40 }
    Rectangle {
        implicitWidth: 64
        implicitHeight: 64
        radius: 32
        color: "#E3F4EA"
        Label { anchors.centerIn: parent; text: "✓"; font.pixelSize: 32; color: Theme.good }
    }
    PageTitle { text: qsTr("Sent"); Layout.fillWidth: true }
    Label {
        text: qsTr("%1 BPS to %2. The home node signed it and passed it on.")
                .arg(backend.sent.amount || "").arg(backend.sent.to || "")
        color: Theme.muted
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Label {
        text: backend.sent.txid || ""
        font.family: Theme.mono
        font.pixelSize: 12
        color: Theme.muted
        wrapMode: Text.WrapAnywhere
        Layout.fillWidth: true
    }
    Item { Layout.fillHeight: true }
    PrimaryButton { text: qsTr("Done"); Layout.fillWidth: true; onClicked: root.done() }
}
