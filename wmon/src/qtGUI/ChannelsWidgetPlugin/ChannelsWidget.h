#ifndef CHANNELSWIDGET_H
#define CHANNELSWIDGET_H

#include <QAbstractListModel>

class ChannelsModel : public QAbstractListModel {
    Q_OBJECT
public:
    ChannelsModel(QObject *parent);
    int rowCount(const QModelIndex &parent = QModelIndex()) const ;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    bool addChannel(unsigned short channel);
    bool removeRows (int row, int count, const QModelIndex& parent = QModelIndex());
    
    std::list<unsigned short> getChannels() const;
    void addChannels(const std::list<unsigned short>& channels);
    
private:
    std::list<unsigned short> channels;
};

#include "ui_ChannelsWidget.h"
#include <QWidget>
#include <QtDesigner/QDesignerExportWidget>

class QDESIGNER_WIDGET_EXPORT ChannelsWidget : public QWidget {
Q_OBJECT

public:
    ChannelsWidget(QWidget *parent = 0);
    void addChannels(const std::list<unsigned short>& channels);
    
signals:
    void addChannel(uint channel);
    void removeChannel(uint channel);
    void selectChannel(uint channel);

private slots:
    void addChannel();
    void removeChannels();
    void selectChannel(const QModelIndex& index);

private:
    Ui::ChannelsWidget ui;
    ChannelsModel* model;
};

#endif
