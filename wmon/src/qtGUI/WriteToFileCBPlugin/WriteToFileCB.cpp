#include "WriteToFileCB.h"
#include "GUIEventDispatcher.h"

WriteToFileCB::WriteToFileCB(QWidget* parent) : QCheckBox(parent) {
    fGUI = NULL;
    connect(this, SIGNAL(clicked(bool)), this, SLOT(setChecked(bool)));
    setText(tr("Write to file"));
}

WriteToFileCB::~WriteToFileCB() {
    unregisterFileGUI();
}

void WriteToFileCB::setChecked(bool state) {
    if (state) {
        fGUI = new FileGUI(path.toStdString().c_str());
        if (fGUI->fileOK()) GUIEventDispatcher::registerGUI(fGUI);
        else {
            QCheckBox::setChecked(false);
            delete fGUI;
            fGUI = NULL;
        }
    }
    else unregisterFileGUI();
}

void WriteToFileCB::setPath(const QString& path) {
    this->path = path;
    setDisabled(path.isEmpty());
}

void WriteToFileCB::unregisterFileGUI() {
    if (fGUI != NULL) {
        GUIEventDispatcher::unregisterGUI(fGUI);
        delete fGUI;
        fGUI = NULL;
    }
}
