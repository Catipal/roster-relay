import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// Choosing a PIN while pairing: once, then again to be sure.
Item {
    id: root
    property bool confirming: false
    property string problem: ""
    property bool working: false
    signal chosen(string pin)
    signal back()

    function reset() { pad.clear() }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.gutter
        anchors.topMargin: 16
        spacing: 16

        PageTitle { back: true; onBackClicked: root.back(); Layout.fillWidth: true }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 8
            Label {
                text: root.confirming ? qsTr("The same PIN again") : qsTr("Choose a PIN")
                font.pixelSize: 22
                font.weight: Font.Bold
                color: Theme.text
                Layout.alignment: Qt.AlignHCenter
            }
            Label {
                text: qsTr("Six to twelve digits. The home node asks for it before every payment, and locks this phone after five wrong ones.")
                color: Theme.muted
                font.pixelSize: 14
                wrapMode: Text.Wrap
                horizontalAlignment: Text.AlignHCenter
                Layout.fillWidth: true
            }
        }

        Label {
            text: root.problem
            color: Theme.danger
            font.pixelSize: 14
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            Layout.fillWidth: true
            Layout.minimumHeight: 40
        }

        Item { Layout.fillHeight: true }

        BusyIndicator {
            visible: root.working
            running: visible
            Layout.alignment: Qt.AlignHCenter
        }

        PinPad {
            id: pad
            active: !root.working
            Layout.alignment: Qt.AlignHCenter
            onEntered: (pin) => root.chosen(pin)
        }
    }
}
