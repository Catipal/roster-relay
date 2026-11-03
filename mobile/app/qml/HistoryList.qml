import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// Payments in and out of the allowance wallet, newest first.
Rectangle {
    id: root
    property var items: []
    property string empty: qsTr("Nothing yet.")
    radius: 16
    color: Theme.surface
    border.color: Theme.line
    implicitHeight: list.implicitHeight + 8

    ColumnLayout {
        id: list
        anchors.fill: parent
        anchors.margins: 4
        spacing: 0

        Label {
            visible: root.items.length === 0
            text: root.empty
            color: Theme.muted
            padding: 16
        }
        Repeater {
            model: root.items
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 0
                Rectangle {
                    visible: index > 0
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                    implicitHeight: 1
                    color: Theme.line
                }
                RowLayout {
                    Layout.fillWidth: true
                    Layout.margins: 12
                    spacing: 12
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Label {
                            text: modelData.label
                            font.weight: Font.DemiBold
                            color: Theme.text
                            elide: Text.ElideMiddle
                            Layout.fillWidth: true
                        }
                        Label {
                            text: modelData.when
                            font.pixelSize: 13
                            color: Theme.muted
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                    }
                    Label {
                        text: modelData.signed
                        font.weight: Font.DemiBold
                        color: modelData.incoming ? Theme.good : Theme.text
                    }
                }
            }
        }
    }
}
