import QtQuick
import QtQuick.Controls.Basic

Button {
    id: control
    implicitHeight: 52
    font.pixelSize: 16
    font.weight: Font.DemiBold
    contentItem: Text {
        text: control.text
        font: control.font
        color: "white"
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }
    background: Rectangle {
        radius: Theme.radius
        color: !control.enabled ? Theme.border : control.down ? Theme.accentDark : Theme.accent
    }
}
