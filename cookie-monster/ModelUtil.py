from PyQt4 import QtCore
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *
from PyQt4.QtWebKit import *
import os
import sys

class CookieModel(QAbstractItemModel):
    def __init__(self, parent=None):
        super(CookieModel, self).__init__(parent)
        self.parents=[]
        self.rootItem = TreeItem("Right Click on Useragent to launch attack")

    def setData(self, index, value, role):
        if index.isValid() and role == Qt.EditRole:
            prev_value = self.getValue(index)

            item = index.internalPointer()

            item.setData(unicode(value.toString()))

            return True
        else:
            return False
    def removeRows(self, position=0, count=1,  parent=QModelIndex()):

        node = self.nodeFromIndex(parent)
        self.beginRemoveRows(parent, position, position + count - 1)
        node.childItems.pop(position)
        self.endRemoveRows()

    def nodeFromIndex(self, index):
        if index.isValid():
            return index.internalPointer()
        else:
            return self.rootItem

    def getValue(self, index):
        item = index.internalPointer()
        return item.data(index.column())

    def columnCount(self, parent):
        if parent.isValid():
            return parent.internalPointer().columnCount()
        else:
            return self.rootItem.columnCount()

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        if role != Qt.DisplayRole:
            return None

        item = index.internalPointer()
        return (item.data(index.column()))

    def flags(self, index):
        if not index.isValid():
            print "not valid"
            return Qt.NoItemFlags

        return Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable

    def headerData(self, section, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return QVariant(self.rootItem.data(section))
        return None
    def index(self, row, column, parent):

        if row < 0 or column < 0 or row >= self.rowCount(parent) or column >= self.columnCount(parent):
            return QModelIndex()

        if not parent.isValid():
            parentItem = self.rootItem
        else:
            parentItem = parent.internalPointer()

        childItem = parentItem.child(row)
        if childItem:
            return self.createIndex(row, column, childItem)
        else:
            return QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()

        childItem = index.internalPointer()
        parentItem = childItem.parent()

        if parentItem == self.rootItem:
            return QModelIndex()

        return self.createIndex(parentItem.row(), 0, parentItem)

    def rowCount(self, parent):
        if parent.column() > 0:
            return 0

        if not parent.isValid():
            parentItem = self.rootItem
        else:
            parentItem = parent.internalPointer()

        return parentItem.childCount()
    
    def addCookie(self,infos,cookie,ua):
        cur = self.rootItem;
        for i in range(0,len(infos)):
            if cur.findVal(infos[i]) is None:
                cur.appendChild(TreeItem(infos[i],cur,TreeItem.INDEX_TYPE))
            cur = cur.findVal(infos[i])
        #according to policy
        if cur.childCount() >0:
            cur.child(0).setData(cookie)
        else:
            cur.appendChild(TreeItem(infos[i],cur,TreeItem.COOKIE_TYPE))  
        
        cur = cur.child(0)
        if cur.findVal(ua) is None:
            cur.appendChild(TreeItem(ua,cur,TreeItem.UA_TYPE))
#        if cur.findVal(cookie) is None:
#            cur.appendChild(CookieItem(cookie,cur))
#        else:
#            cur.findVal(cookie).setData(cookie)
           
    
        
class TreeItem(object):
    INDEX_TYPE = 0
    COOKIE_TYPE = 1
    UA_TYPE = 2

    def __init__(self, val, parent=None,type=INDEX_TYPE):
        self.parentItem = parent
        self.itemData = [val,]
        self.childItems = []
        self.type = type
        
    def isUA(self):
        return self.type == self.UA_TYPE
    def isCookie(self):
        return self.type == self.COOKIE_TYPE
    
    def appendChild(self, item):
        self.childItems.append(item)

    def child(self, row):
        return self.childItems[row]

    def childCount(self):
        return len(self.childItems)

    def columnCount(self):
        return len(self.itemData)

    def data(self, column):
        try:
            return self.itemData[column]
        except IndexError:
            return None

    def parent(self):
        return self.parentItem

    def row(self):
        if self.parentItem:
            return self.parentItem.childItems.index(self)
        return 0
    
    def setData(self, val):
        self.itemData[0] = val
        
    def equalVal(self,val):
        return self.data(0) == val
    
    def findVal(self,val):
        for item in self.childItems:
            if item.equalVal(val):
                return item
        return None
    

if __name__ == "__main__":
    app = QApplication(sys.argv)
    widget = QTreeView()
    model = CookieModel(None)
    model.addCookie(("ASUS","192.168.1.1","cc98.org"), "aaa", "firefox")
    model.addCookie(("ASUS","192.168.1.1","cc98.org"), "bbb", "firefox")
    widget.setModel(model)
    widget.show()
    app.exec_()
