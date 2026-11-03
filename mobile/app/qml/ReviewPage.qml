import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// The payment as the home node prepared it, and the PIN that sends it.
ColumnLayout {
    id: root
    signal back()
    spacing: 14

    function reset() { pad.clear() }

    PageTitle { text: qsTr("Check and send"); back: true; onBackClicked: root.back(); Layout.fillWidth: true }

    Rectangle {
        Layout.fillWidth: true
        implicitHeight: summary.implicitHeight + 32
        radius: 16
        color: Theme.surface
        border.color: Theme.line
        ColumnLayout {
            id: summary
            anchors.fill: parent
            anchors.margins: 16
            spacing: 10
            RowLayout {
                Layout.fillWidth: true
                Label { text: qsTr("To"); color: Theme.muted }
                Label {
                    text: backend.prepared.to || ""
                    font.weight: Font.DemiBold
                    horizontalAlignment: Text.AlignRight
                    elide: Text.ElideMiddle
                    Layout.fillWidth: true
                }
            }
            Label {
                visible: !!backend.prepared.isName
                text: backend.prepared.address || ""
                font.family: Theme.mono
                font.pixelSize: 11
                color: Theme.muted
                wrapMode: Text.WrapAnywhere
                horizontalAlignment: Text.AlignRight
                Layout.fillWidth: true
            }
            RowLayout {
                Layout.fillWidth: true
                Label { text: qsTr("Amount"); color: Theme.muted; Layout.fillWidth: true }
                Label { text: (backend.prepared.amount || "") + " BPS" }
            }
            RowLayout {
                Layout.fillWidth: true
                Label { text: qsTr("Fee"); color: Theme.muted; Layout.fillWidth: true }
                Label { text: (backend.prepared.fee || "") + " BPS" }
            }
            Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: Theme.line }
            RowLayout {
                Layout.fillWidth: true
                Label { text: qsTr("Total"); font.weight: Font.Bold; Layout.fillWidth: true }
                Label { text: (backend.prepared.total || "") + " BPS"; font.weight: Font.Bold }
            }
        }
    }

    Label {
        text: backend.error !== "" ? backend.error : qsTr("Your PIN sends it.")
        color: backend.error !== "" ? Theme.danger : Theme.muted
        font.pixelSize: 14
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        Layout.fillWidth: true
        Layout.minimumHeight: 36
    }

    Item { Layout.fillHeight: true }
    BusyIndicator { visible: backend.busy; running: visible; Layout.alignment: Qt.AlignHCenter }
    PinPad {
        id: pad
        active: !backend.busy
        Layout.alignment: Qt.AlignHCenter
        onEntered: (pin) => { backend.send(pin); pad.clear() }
    }
}
