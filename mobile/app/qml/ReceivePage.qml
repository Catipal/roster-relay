import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

ColumnLayout {
    id: root
    property bool copied: false
    spacing: 16

    PageTitle { text: qsTr("Receive"); Layout.fillWidth: true }
    Label {
        text: qsTr("Coins sent here go into the allowance wallet on your home node. Each time, a new address.")
        color: Theme.muted
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Rectangle {
        Layout.alignment: Qt.AlignHCenter
        implicitWidth: 236
        implicitHeight: 236
        radius: 16
        color: Theme.surface
        border.color: Theme.line
        Image {
            anchors.centerIn: parent
            width: 212
            height: 212
            visible: backend.address !== ""
            source: backend.address !== "" ? "image://qr/" + encodeURIComponent(backend.address) : ""
            sourceSize: Qt.size(212, 212)
            smooth: false
            Accessible.name: qsTr("QR code of the address")
        }
        BusyIndicator { anchors.centerIn: parent; running: backend.address === "" && backend.busy }
    }
    Label {
        text: backend.address
        font.family: Theme.mono
        font.pixelSize: 13
        color: Theme.text
        wrapMode: Text.WrapAnywhere
        horizontalAlignment: Text.AlignHCenter
        Layout.fillWidth: true
    }
    Label {
        visible: backend.error !== ""
        text: backend.error
        color: Theme.danger
        font.pixelSize: 14
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    RowLayout {
        Layout.fillWidth: true
        spacing: 12
        QuietButton {
            text: root.copied ? qsTr("Copied") : qsTr("Copy")
            enabled: backend.address !== ""
            Layout.fillWidth: true
            onClicked: { backend.copyText(backend.address); root.copied = true }
        }
        QuietButton {
            text: qsTr("New address")
            enabled: !backend.busy
            Layout.fillWidth: true
            onClicked: { root.copied = false; backend.newAddress() }
        }
    }
    Item { Layout.fillHeight: true }
}
