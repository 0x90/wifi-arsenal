#ifndef NETSTATSSORTPROXYMODEL_H
#define NETSTATSSORTPROXYMODEL_H

 #include <QSortFilterProxyModel>

class NetStatsSortProxyModel : public QSortFilterProxyModel {
    Q_OBJECT

public:
    NetStatsSortProxyModel(QObject *parent = 0);
    void setDisappearedAtBottom(bool enabled);
    

protected:
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const;

private:
    bool disappearedAtBottom;

};

#endif
