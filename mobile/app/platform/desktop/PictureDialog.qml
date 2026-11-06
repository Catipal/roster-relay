import QtQuick

// Choosing a picture of a code, on a computer: Qt's file dialog.
// Made at run time, not imported: Qt's deployment scans every QML file under
// the app's folder, the phone's build too, and QtQuick.Dialogs would bring
// every Controls style into the phone's package.
Item {
    id: root
    signal picked(url url)

    property var dialog: null

    function open() {
        if (!dialog) {
            dialog = Qt.createQmlObject(
                'import QtQuick.Dialogs\nFileDialog {}', root, "PictureDialog")
            dialog.title = qsTr("A picture of the code")
            dialog.nameFilters = [qsTr("Pictures (*.png *.jpg *.jpeg *.webp *.bmp)")]
            dialog.accepted.connect(() => root.picked(dialog.selectedFile))
        }
        dialog.open()
    }
}
