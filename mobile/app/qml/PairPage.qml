import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

Flickable {
    id: root
    property alias ticket: ticketArea.text
    property alias phoneName: nameField.text
    property string problem: ""
    signal next()
    contentHeight: column.implicitHeight + 72
    clip: true

    ColumnLayout {
        id: column
        x: Theme.gutter
        y: 48
        width: root.width - 2 * Theme.gutter
        spacing: 20

        ColumnLayout {
            spacing: 8
            Label {
                text: qsTr("BPS Companion").toUpperCase()
                font.pixelSize: 13
                font.weight: Font.DemiBold
                font.letterSpacing: 1
                color: Theme.accent
            }
            PageTitle { text: qsTr("Pair with your home node"); Layout.fillWidth: true }
            Label {
                text: qsTr("On your computer, open BPS Relay, Server, Phone companion, and choose Pair a phone. Copy the text under the code it shows and paste it here.")
                color: Theme.muted
                wrapMode: Text.Wrap
                lineHeight: 1.3
                Layout.fillWidth: true
            }
        }

        ColumnLayout {
            spacing: 6
            Layout.fillWidth: true
            Label {
                text: qsTr("The text from the home node")
                font.pixelSize: 13
                font.weight: Font.DemiBold
                color: Theme.label
            }
            TextArea {
                id: ticketArea
                Layout.fillWidth: true
                Layout.preferredHeight: 104
                placeholderText: "BPSC1:…"
                wrapMode: TextEdit.WrapAnywhere
                font.family: Theme.mono
                font.pixelSize: 13
                color: Theme.text
                padding: 12
                background: Rectangle {
                    radius: Theme.radius
                    color: Theme.surface
                    border.width: ticketArea.activeFocus ? 2 : 1
                    border.color: ticketArea.activeFocus ? Theme.accent : Theme.border
                }
            }
        }

        Field {
            id: nameField
            label: qsTr("Name for this phone")
            Layout.fillWidth: true
        }

        Label {
            visible: text !== ""
            text: root.problem !== "" ? root.problem : backend.error
            color: Theme.danger
            font.pixelSize: 14
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }

        PrimaryButton {
            text: qsTr("Continue")
            Layout.fillWidth: true
            Layout.topMargin: 8
            onClicked: {
                root.problem = backend.checkTicket(ticketArea.text)
                if (root.problem === "" && nameField.text.trim() === "")
                    root.problem = qsTr("Give this phone a name, so you can tell it apart on the home node.")
                if (root.problem === "") {
                    backend.clearError()
                    root.next()
                }
            }
        }
    }
}
