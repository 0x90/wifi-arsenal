#include "NetStatsModel.h"
#include "Utils.h"
#include <sstream>
#include <iomanip>
#include <iostream>
using namespace std;

NetStatsModel::NetStatsModel(QObject *parent)
    :QAbstractTableModel(parent) {
}

int NetStatsModel::rowCount(const QModelIndex& /*parent*/) const {
   return stats.size();
}

int NetStatsModel::columnCount(const QModelIndex& /*parent*/) const {
    return 8;
}

bool NetStatsModel::hasChildren (const QModelIndex& parent) const {
    return not parent.isValid();
}

QVariant NetStatsModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole)
        return QVariant();

    if (orientation == Qt::Horizontal) {
        switch (section) {
            case BSSID:
                return tr("BSSID");

            case CHANNEL:
                return tr("Channel");

            case UTILIZATION:
                return tr("Utilization");

            case LOSS:
                return tr("Loss");

            case RSSI:
                return tr("RSSI");

            case VALID:
                return tr("Valid");

            case SECURITY:
                return tr("Security");

            case SSID:
                return tr("SSID");

            default:
                return QVariant();
        }
    }
    return QVariant();
}

QVariant NetStatsModel::data(const QModelIndex& index, int role) const {
    if (stats.empty()) return QVariant();
    
    std::list<NetStats>::const_iterator net = stats.begin();
    advance(net, index.row());
    
    if (role == Qt::DisplayRole or role == Qt::UserRole) {
        std::stringstream ss;
        ss.setf(std::ios::fixed);
        ss.precision(2);
        switch (index.column()) {
            case BSSID: // Return QByteArray
                if (role == Qt::UserRole) return QByteArray(reinterpret_cast<const char*>(net->bssid), sizeof(net->bssid));
                Utils::writeBytes(ss, net->bssid, sizeof(net->bssid));
                break;

            case CHANNEL: // Return QUInt
                if (role == Qt::UserRole) return static_cast<uint>(net->channel);
                ss << net->channel;
                break;

            case UTILIZATION: // Return QDouble
                if (role == Qt::UserRole) return net->weightedDelay;
                
                if (net->loss == 1) ss << "---";
                else ss << std::setw(6) << net->weightedDelay*100 << "%";
                break;

            case LOSS: // Return QDouble
                if (role == Qt::UserRole) return net->loss;
                
                if (net->loss == 1) ss << "---";
                else ss << std::setw(6) << net->loss*100 << "%";
                break;

            case RSSI: // Return QInteger
                if (role == Qt::UserRole) return net->rssi;
                
                if (net->loss == 1) ss << "---";
                else ss << std::setw(4) << net->rssi << " dBm";
                break;

            case VALID: // Return QBool
                if (role == Qt::UserRole) return net->ok;
                return QVariant();

            case SECURITY: // Return QString
                if (role == Qt::UserRole) return net->protection.c_str();
                ss << net->protection;
                break;

            case SSID: // Return QString
                if (role == Qt::UserRole) return net->ssid.c_str();
                ss << net->ssid;
                break;

            default:
                return QVariant();
        }
        return tr(ss.str().c_str());
    }
    else if (role == Qt::CheckStateRole and index.column() == VALID) {
        return net->ok ? Qt::Checked : Qt::Unchecked;
    }
    else if (role == Qt::TextAlignmentRole) {
        if (index.column() == CHANNEL or index.column() == UTILIZATION or
            index.column() == LOSS or index.column() == RSSI) 
            return Qt::AlignRight;
    }
    
    return QVariant();
}

void NetStatsModel::updateStats(const std::list<NetStats>& stats) {
    for (std::list<NetStats>::const_iterator net = stats.begin(); net != stats.end(); ++net) {
        bool tr = false;
        unsigned int numElem = 0;
        std::list<NetStats>::iterator storedNet;
        for (storedNet = this->stats.begin(); not tr and storedNet != this->stats.end();) {
            tr = Utils::sameNetwork(*storedNet, *net);
            if (not tr) {
                ++storedNet;
                ++numElem;
            }
        }
        
        if (tr) {
            *storedNet = *net;
            refreshRow(numElem);
        }
        else {
            beginInsertRows(QModelIndex(), this->stats.size(), this->stats.size());
            this->stats.push_back(*net);
            endInsertRows();
        }
    }
}

void NetStatsModel::refreshRow(unsigned int row) {
    QModelIndex modelIndex;
    unsigned int cols = columnCount(modelIndex);
    for (unsigned int col = 0; col < cols; ++col) {
        QModelIndex cellIndex = index(row, col, modelIndex);
        emit dataChanged(cellIndex, cellIndex);
    }
}

