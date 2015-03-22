#ifndef WRITETOFILECB_H
#define WRITETOFILECB_H

#include <QCheckBox>
#include <QtDesigner/QDesignerExportWidget>
#include "FileGUI.h"

class QDESIGNER_WIDGET_EXPORT WriteToFileCB : public QCheckBox {
Q_OBJECT

public:
    WriteToFileCB(QWidget *parent = 0);
    ~WriteToFileCB();

public slots:
    void setChecked(bool state);
    void setPath(const QString& path);
    
signals:

private:
    QString path;
    FileGUI* fGUI;
    
    void unregisterFileGUI();
};

#endif
