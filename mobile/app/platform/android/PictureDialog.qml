import QtQuick

// Choosing a picture of a code, on a phone: the system's own picker.
Item {
    id: root
    signal picked(url url)
    function open() { picker.open() }

    AndroidPicturePicker {
        id: picker
        onPicked: (url) => root.picked(url)
    }
}
