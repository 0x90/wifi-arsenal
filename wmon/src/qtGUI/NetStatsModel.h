#ifndef NETSTATSMODEL_H
#define NETSTATSMODEL_H

#include "NetStats.h"
#include <list>
#include <QAbstractTableModel>
#include <pthread.h>

class NetStatsModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Fields {BSSID, CHANNEL, UTILIZATION, LOSS, RSSI, VALID, SECURITY, SSID};
    
    NetStatsModel(QObject *parent);
    int rowCount(const QModelIndex &parent = QModelIndex()) const ;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    bool hasChildren (const QModelIndex& parent = QModelIndex()) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

    void updateStats(const std::list<NetStats>& stats);

private:
    pthread_mutex_t dataMutex;
    std::list<NetStats> stats;
    
    void refreshRow(unsigned int row);
};

#endif
