from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *
from PyQt4.QtNetwork import *
import getopt
import sys
import re


class MyBrowser(QWebView):
    def __init__(self,father=None):
        super(MyBrowser, self).__init__(father)
        self.page().setLinkDelegationPolicy(QWebPage.DelegateExternalLinks)
        self.connect(self, SIGNAL("linkClicked(QUrl)"), self.onLinkClicked)

    def onLinkClicked(self, url):
        self.load(url)

class MonsterWindow(QWidget):
    def __init__(self, father = None):
        super(MonsterWindow, self).__init__(father)
        
class MonsterBrowser():
    urlPat = re.compile("https?://([^/]*)(.*)")

    def usage(self):
        print """
    Usage: python MonsterBrowser.py [options] url

    Options:
        -c  --cookie <Cookie>        set cookie
        -u --useragent <UserAgent>   set useragent

        """

    def parseArguments(self, argv):
        try:
            opts, args = getopt.getopt(argv, "c:u:", ["cookie=", "useragent="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)

        if len(args) < 1:
            self.usage()
            sys.exit(2)

        url = args[0]
        cookie = None
        useragent = None
        for opt, args in opts:
            if opt in ("-c", "--cookie"):
                cookie = args

            if opt in ("-u", "--useragent"):
                useragent = args
        if useragent is None:
            useragent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20120427 Firefox/15.0a1"
        print cookie, useragent, url
        self.launch(cookie, useragent, url)

    def launch(self, rawcookie, useragent, url):
        '''
        url: http://xxx.yyy.zzz/aaa/bbb?ccc/
        host: xxx.yyy.zzz
        domain: yyy.zzz
        '''
        cookies = []

        # if no http protocol header, append it
        if not url.startswith("http://"):
            url = "http://" + url

        match = self.urlPat.match(url)
        host = match.group(1)
        uri = match.group(2)
        domain = ".".join(host.split(".")[-2:])

        # adding cookies to cookiejar
        for cookie in rawcookie.split(";"):
            qnc = QNetworkCookie()
            qnc.setDomain("."+domain)
            key = cookie.split("=")[0]
            value = "=".join(cookie.split("=")[1:])
            qnc.setName(key)
            qnc.setValue(value)
            cookies.append(qnc)
        self.open_web(url, cookies, useragent)
        return

    def open_web(self, url, cookies, useragent):
        app = QApplication(sys.argv)
        wind = QMainWindow()
        view = MyBrowser()
        nam = QNetworkAccessManager()
        view.page().setNetworkAccessManager(nam)

        print " [!]  Spawning web view of " + url
        ncj = QNetworkCookieJar()
        ncj.setAllCookies(cookies)
        nam.setCookieJar(ncj)

        qnr = QNetworkRequest(QUrl(url))
        qnr.setRawHeader("User-Agent", useragent)

        view.load(qnr)
        wind.setCentralWidget(view)
        wind.show()
        app.exec_()

if __name__ == "__main__":
    browser = MonsterBrowser()
    browser.parseArguments(sys.argv[1:])
