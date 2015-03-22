#!/usr/bin/env python

#############################################################################
##
## Copyright (C) 2010 Hans-Peter Jansen <hpj@urpla.net>.
## Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
## All rights reserved.
##
## This file is part of the examples of PyQt.
##
## $QT_BEGIN_LICENSE:BSD$
## You may use this file under the terms of the BSD license as follows:
##
## "Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are
## met:
##   * Redistributions of source code must retain the above copyright
##     notice, this list of conditions and the following disclaimer.
##   * Redistributions in binary form must reproduce the above copyright
##     notice, this list of conditions and the following disclaimer in
##     the documentation and/or other materials provided with the
##     distribution.
##   * Neither the name of Nokia Corporation and its Subsidiary(-ies) nor
##     the names of its contributors may be used to endorse or promote
##     products derived from this software without specific prior written
##     permission.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
## "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
## LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
## A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
## OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
## SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
## LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
## DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
## THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
## (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
## OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
## $QT_END_LICENSE$
##
###########################################################################


from PyQt4 import QtCore, QtGui, QtNetwork, QtWebKit
from PyQt4.QtWebKit import *
from PyQt4.QtCore import *
class FancyBrowser(QtGui.QMainWindow):
    def __init__(self):
        super(FancyBrowser, self).__init__()

        self.progress = 0

        QtNetwork.QNetworkProxyFactory.setUseSystemConfiguration(True)

        self.view = QtWebKit.QWebView(self)
        self.view.page().setLinkDelegationPolicy(QWebPage.DelegateExternalLinks)
        self.connect(self.view, SIGNAL("linkClicked(QUrl)"), self.onLinkClicked)
        self.view.loadFinished.connect(self.adjustLocation)
        self.view.titleChanged.connect(self.adjustTitle)
        self.view.loadProgress.connect(self.setProgress)
        self.view.loadFinished.connect(self.finishLoading)

        self.locationEdit = QtGui.QLineEdit(self)
        self.locationEdit.setSizePolicy(QtGui.QSizePolicy.Expanding,
                self.locationEdit.sizePolicy().verticalPolicy())
        self.locationEdit.returnPressed.connect(self.changeLocation)

        toolBar = self.addToolBar("Navigation")
        toolBar.addAction(self.view.pageAction(QtWebKit.QWebPage.Back))
        toolBar.addAction(self.view.pageAction(QtWebKit.QWebPage.Forward))
        toolBar.addAction(self.view.pageAction(QtWebKit.QWebPage.Reload))
        toolBar.addAction(self.view.pageAction(QtWebKit.QWebPage.Stop))
        toolBar.addWidget(self.locationEdit)

        viewMenu = self.menuBar().addMenu("&View")
        viewSourceAction = QtGui.QAction("Page Source", self)
        viewSourceAction.triggered.connect(self.viewSource)
        viewMenu.addAction(viewSourceAction)

        toolsMenu = self.menuBar().addMenu("&Tools")
        self.setCentralWidget(self.view)
        self.setUnifiedTitleAndToolBarOnMac(True)

    def viewSource(self):
        accessManager = self.view.page().networkAccessManager()
        request = QtNetwork.QNetworkRequest(self.view.url())
        reply = accessManager.get(request)
        reply.finished.connect(self.slotSourceDownloaded)

    def onLinkClicked(self, url):
        self.view.load(url)

    def slotSourceDownloaded(self):
        reply = self.sender()
        self.textEdit = QtGui.QTextEdit(None)
        self.textEdit.setAttribute(QtCore.Qt.WA_DeleteOnClose)
        self.textEdit.show()
        self.textEdit.setPlainText(QtCore.QTextStream(reply).readAll())
        self.textEdit.resize(600, 400)
        reply.deleteLater()

    def adjustLocation(self):
        self.locationEdit.setText(self.view.url().toString())

    def changeLocation(self):
        url = QtCore.QUrl.fromUserInput(self.locationEdit.text())
        self.view.load(url)
        self.view.setFocus()

    def adjustTitle(self):
        if 0 < self.progress < 100:
            self.setWindowTitle("%s (%s%%)" % (self.view.title(), self.progress))
        else:
            self.setWindowTitle(self.view.title())

    def setProgress(self, p):
        self.progress = p
        self.adjustTitle()

    def finishLoading(self):
        self.progress = 100
        self.adjustTitle()

    def getView(self):
        return self.view

if __name__ == '__main__':

    import sys

    app = QtGui.QApplication(sys.argv)

    if len(sys.argv) > 1:
        url = QtCore.QUrl(sys.argv[1])
    else:
        url = QtCore.QUrl('http://www.google.com/ncr')

    browser = FancyBrowser()
    browser.show()

    sys.exit(app.exec_())
