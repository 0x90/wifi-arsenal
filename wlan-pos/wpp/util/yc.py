#!/usr/bin/python
# coding=UTF-8
 
import os
import sys
import re
import random
import time
import urllib2
import urllib
import cookielib
import pprint as pp
 
from logging import getLogger, Formatter, INFO, DEBUG
from logging.handlers import SysLogHandler
try:
    from cloghandler import ConcurrentRotatingFileHandler as loghandler_rotfile
except ImportError:
    from logging.handlers import RotatingFileHandler as loghandler_rotfile
yclog = getLogger('yc')
yclog.setLevel(INFO)
logfmt = Formatter('[%(asctime)s][%(levelname)s] %(message)s')
logdir = '%s/tmp/log/yc' % os.environ['HOME']
logfile = '%s/yc.log' % logdir #TODO: dynamic path instead of ugly static path.
if not os.path.isfile(logfile):
    if not os.path.isdir(logdir):
        try:
            os.mkdir(logdir, 0755)
        except OSError, errmsg:
            print "Failed to mkdir: %s, %s!" % (logdir, str(errmsg))
            sys.exit(99)
    open(logfile, 'w').close()
# Rotate after 20M, keep 20 old copies.
loghandler = loghandler_rotfile(logfile, "a", 20*1024*1024, 20) 
loghandler.setFormatter(logfmt)
yclog.addHandler(loghandler)

from wpp.util.net import connectRetry, sendMail


class CourseReservation(object):
    def __init__(self, user_info=None):
        self.url_root = 'http://114.251.109.215/WLYC'
        self.url_chkcode = '%s/image.aspx' % self.url_root
        self.url_login = '%s/XYYC21DR1.aspx' % self.url_root 
        self.url_cal = '%s/script/calendar.aspx' % self.url_root 

        self.restr_redirect_url = "language='javascript'>window\.open\('(.*)','SubWindow"
        self.restr_timetable = '<input type="submit" name="gv\$ctl(\d+)\$I_HOUR(\d+_\d+)" +value="(\d+ *)"'
        self.restr_dates = '\<td\>\<font color="\#\d+"\>(\d+-\d+-\d+)\((.*)\)'
        self.restr_stat = '\<span id="lblMessage".*\<font color="Red" size="3"\>(.*)\<\/font\>'
        self.restr_curphase = '\<span id="lblCurrentPhase".*\<font color="Black"\>(.*)\<\/font\>'
        self.restr_mytickets = '<input type="submit" name="gv\$ctl(\d+)\$I_HOUR(\d+_\d+)" +value="(\d+ +)"'
        self.restr_closed = 'id="gv_ctl%s_I_HOUR%s" disabled="disabled" />' # %(02, 9_13)
        self.restr_reserved = '<input type="submit" name="gv\$ctl%s\$I_HOUR%s" +value="(\d+ +)"' # %(02, 9_13)
        
        self.req = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookielib.LWPCookieJar()))
        self.req.addheaders = [('User-agent', 'Firefox/4.0b7'),
                               ('Connection', 'keep-alive'), ('Keep-Alive', 300)]
        if user_info and isinstance(user_info, dict):
            self.userid = user_info['userid'] if 'userid' in user_info else ''
            self.passwd = user_info['passwd'] if 'passwd' in user_info else ''
            self.userphase = user_info['phase'] if 'phase' in user_info else ''
        self.id_phase = {0: '模拟机', 1: '散段', 2: '综合训练'}
        self.phase_id = dict([ (self.id_phase[id],id) for id in self.id_phase ])
        # timetable: {'2011-09-19':{'13_17':0, '17_19':0, '19_21':51, '7_9':8, '9_13':0}}
        self.timetable = {}
        self.pagephase = ''

    def _getHiddenVals(self, page=None):
        self.VS = re.findall('id="__VIEWSTATE" value="(.*)"', page)[0]
        self.EV = re.findall('id="__EVENTVALIDATION" value="(.*)"', page)[0]

    def getCookie(self):
        #yclog.debug('Getting cookie & hidden vals ...')
        resp_root = self.req.open(self.url_root)
        if resp_root.getcode() == 200:
            page_root = resp_root.read()
            headers_resp = dict(resp_root.headers)
            self.cookie = headers_resp['set-cookie'].split('; ')[0]
            self.req.addheaders += [('Cookie', self.cookie)]
            self._getHiddenVals(page_root)
        else:
            yclog.error('Failed to connect: %s' % self.url_root)
            sys.exit(99)

    def getChkcode(self):
        #yclog.debug('Getting check code ...')
        resp_chkcode = self.req.open(self.url_chkcode)
        if resp_chkcode.getcode() == 200:
            headers_resp = dict(resp_chkcode.headers)
            # 'set-cookie': 'CheckCode=NNDB4; path=/, ImageV=NNDB4; path=/' 
            self.chkcode = headers_resp['set-cookie'].split('; ')[0].split('=')[1]
            self.cookie = '%s; CheckCode=%s; ImageV=%s' % (self.cookie, self.chkcode, self.chkcode)
            self.req.addheaders[-1] = ('Cookie', self.cookie)
        else:
            yclog.error('Failed to connect: %s' % self.url_chkcode)
            sys.exit(99)

    def login(self, user_info=None):
        self.getCookie()
        self.getChkcode()
        # login POST data.
        if user_info and isinstance(user_info, dict):
            self.userid = user_info['userid'] if 'userid' in user_info else ''
            self.passwd = user_info['passwd'] if 'passwd' in user_info else ''
            self.userphase = user_info['phase'] if 'phase' in user_info else ''
            #yclog.debug('Current user phase: %s' % self.userphase)
        if not self.userid or not self.passwd:
            yclog.error('Failed to login: user info error!')
            sys.exit(99)
        data_login = {'__VIEWSTATE': self.VS, '__EVENTVALIDATION': self.EV,
                   'RadioButtonList1': self.userphase,
                   'txtname': self.userid, 'txtpwd': self.passwd, 'yanzheng': self.chkcode,
                   'button.x': random.randint(0, 99), 'button.y': random.randint(0, 99)}
        data_urlencode = urllib.urlencode(data_login)
        yclog.info('Login: [UserID:%s]' % self.userid)
        resp_login = self.req.open(self.url_login, data_urlencode)
        if resp_login.getcode() == 200:
            page_login = resp_login.read()
            path_login_redirect = re.findall(self.restr_redirect_url, page_login)[0]
            if path_login_redirect:
                self.url_timetable = '%s/%s' % (self.url_root, path_login_redirect)
            else:
                self.url_timetable = '%s/%s' % (self.url_root, 'aspx/car/XYYC22.aspx')
            #yclog.debug('Redirecting to: %s' % path_login_redirect)
            self.getDataTimetable()
        else:
            yclog.error('Failed to connect: %s' % self.url_login)
            sys.exit(99)

    def getPageTimetable(self, refresh=False, save_page=False):
        """ refresh: first-time fetch or refresh a page.
                    1)True -- same page refresh with same phase refresh. 
                    2)False-- 1st-time fetching.
                    3)0-3 -- same page with different phase. 0:模拟机,1:散段,2:综合训练.
        """
        if refresh is False: 
            resp_login = self.req.open(self.url_timetable)
            yclog.info('Getting timetable: |%s|' % self.userphase)
        else:
            target_phase = self.id_phase[refresh] if refresh in self.id_phase else self.userphase
            self._getHiddenVals(self.page_timetable)
            target_btn = 'RadioButtonList1$%s'%refresh if refresh is not True else ''
            data_refresh = {'__VIEWSTATE': self.VS, '__EVENTVALIDATION': self.EV,
                            '__EVENTTARGET': target_btn, 'RadioButtonList1': target_phase,
                            '__EVENTARGUMENT': '', '__LASTFOCUS': ''}
            if refresh is True:
                data_refresh['btnRefresh'] = '刷新'
                yclog.info('Refreshing timetable |%s|' % target_phase)
            else:
                yclog.info('Switch to timetable: |%s|' % target_phase)
            data_urlencode = urllib.urlencode(data_refresh)
            #yclog.info(data_refresh)
            resp_login = self.req.open(self.url_timetable, data_urlencode)
        if resp_login.getcode() == 200:
            self.page_timetable = resp_login.read()
            if save_page and self.page_timetable:
                f = open('%s/tmp/tmp.aspx'%os.environ['HOME'], 'a')
                f.write(self.page_timetable+'\n'*2)
                f.close()
            status = re.findall(self.restr_stat, self.page_timetable)[0]
            if status:
                yclog.info('Status: %s' % status)
            if refresh is False:
                self.pagephase = re.findall(self.restr_curphase, self.page_timetable)[0]
            else:
                self.pagephase = target_phase
            #yclog.debug('Current page phase: %s' % self.pagephase)
        else:
            yclog.error('Failed to connect: %s' % self.url_timetable)
            sys.exit(99)

    def getDataTimetable(self, refresh=False):
        """ Filter out time table data from webpage.
        """
        self.getPageTimetable(refresh=refresh)
        # <input type="submit" name="gv$ctl08$I_HOUR19_21" value="94" ...
        # timetable: [(dateid, hour_win, num_tickets]
        timetable = re.findall(self.restr_timetable, self.page_timetable)
        # dates: {date(2011-09-30): day of week(chinese)}
        dates = dict(re.findall(self.restr_dates, self.page_timetable))
        dateids = list(set([ x[0] for x  in timetable ]))
        dateids.sort()
        dates_keys = dates.keys()
        dates_keys.sort()
        self.id_date = dict(zip(dateids, dates_keys))
        self.date_id = dict([ (self.id_date[id],id) for id in self.id_date ])
        for x in timetable:
            self.timetable.setdefault(self.id_date[x[0]], {})[x[1]] = int(x[2])

    def flipTicket(self, ticket=None):
        """ Flipping a ticket to reserve or abandon a course of the corresponding
        ticket(phase & date & hour-window). *flip* here means the status of a ticket
        switches between 'taken' and 'dropped' on every click.
        """
        date = ticket['date']; hour = ticket['hour']; phase = ticket['phase']
        if self.pagephase != phase:
            self.getDataTimetable(refresh=self.phase_id[phase])
        if not hour in self.timetable[date]: 
            return 'Already reserved: [%(phase)s,%(date)s|%(hour)s]' % ticket
        elif self.timetable[date][hour] == 0: 
            return 'No ticket left: [%(phase)s,%(date)s|%(hour)s]' % ticket
        else: pass
        self._getHiddenVals(self.page_timetable)
        # id_button: gv$ctl08$I_HOUR17_19
        id_button = 'gv$ctl%s$I_HOUR%s' % (self.date_id[date], hour)
        num_tickets = self.timetable[date][hour]
        data_order = {'__VIEWSTATE': self.VS, '__EVENTVALIDATION': self.EV,
                      'RadioButtonList1': phase, id_button: num_tickets}
        data_urlencode = urllib.urlencode(data_order)
        yclog.info('Flipping ticket: [%(phase)s][%(date)s|%(hour)s]' % ticket)
        resp_order = self.req.open(self.url_timetable, data_urlencode)
        if resp_order.getcode() == 200:
            self.page_timetable = resp_order.read()
            status = re.findall(self.restr_stat, self.page_timetable)
            if status: status = status[0]
            return status
        else:
            yclog.info('Failed to connect: %s' % self.url_chkcode)
            return str(resp_order.getcode())

    def getReservedTickets(self, phase=None):
        """Get reserved tickets for a certain phase.  
        Why not support traversing the tickets for all phases: the reservation
        access to the next phase is not permitted if the training of current
        phase is not finished.

        Parameter
        ---------
        phase: phase name(chinese).

        Return
        ---------
        [{'phase':p, 'date':d, 'hour':h, 'id':id}, ... ]
        """
        phase =  self.userphase if not phase else phase
        self.tickets = []
        # update self.page_timetable for a certain phase in phases.
        if phase != self.pagephase:
            self.getPageTimetable(refresh=self.phase_id[phase])
        # filter out tickets of a certain phase in phases.
        found_tickets = re.findall(self.restr_mytickets, self.page_timetable)
        for found_ticket in found_tickets:
            id_date, hour, tid = found_ticket
            date = self.id_date[id_date]
            self.tickets.append({'phase':phase, 'date':date, 'hour':hour, 'id':tid.strip()})
        return self.tickets

    def chkTicket(self, ticket=None):
        """ Query to know if a ticket is closed, reserved, or expired.
        """
        date = ticket['date']; hour = ticket['hour']; phase = ticket['phase']
        # update self.page_timetable if the phases dont match.
        if self.pagephase != phase:
            self.getDataTimetable(refresh=self.phase_id[phase])
        # query if the ticket is expired(beyond 7days).
        if date in self.date_id:
            dateid = self.date_id[date]
        else: 
            yclog.info('Ticket EXPIRED/NOT_PUB: [%(phase)s,%(date)s|%(hour)s]' % ticket)
            return 'EXP/NOTPUB' # the required ticket is already expired.
        # query if the ticket is closed(no more left).
        re_str = self.restr_closed % (dateid,hour)
        is_closed = re.findall(re_str, self.page_timetable)
        if is_closed: 
            yclog.info('Ticket CLOSED: [%(phase)s,%(date)s|%(hour)s]' % ticket)
            return 'CLOSED' # no ticket left.
        # query if the ticket is already reserved.
        re_str = self.restr_reserved % (dateid,hour)
        is_reserved = re.findall(re_str, self.page_timetable)
        if is_reserved: 
            yclog.info('Ticket RESERVED: [%(phase)s,%(date)s|%(hour)s]' % ticket)
            return 'RESERVED' # the ticket has already been reserved.
        return 'OPEN'


users_info = {'yxt': {'userid': '11041536',
                      'passwd': '05070',
                       'phase': '散段',},
              'lvj': {'userid': '11041539',
                      'passwd': '02190',
                       'phase': '散段',} }

def makeMsg(user_tickets=None):
    # ready to config & send email.
    body = ''
    for user in user_tickets:
        if not user_tickets[user]: continue
        body += 'User:[%s|%s]\r\n' % (user, users_info[user]['userid'])
        for u_ticket in user_tickets[user]:
            body += '[%(phase)s]:[id:%(id)s][time:%(date)s|%(hour)s]\r\n' % u_ticket
    return body

def sendMsg(body=None):
    subject = "[约车时间]" #% (_file, _func, ','.join(alerts['vers']))
    mail_to = ('yxtbj@139.com', '13488793935@139.com')
    mail_from = 'xiaotian.yan@gmail.com'
    credentails = ('xiaotian.yan', 'yan714257')
    yclog.info('%s\n%s' % (subject, body))

    yclog.info('Sending notice email -> %s' % '|'.join(mail_to))
    sendMail(mail_from, credentails, mail_to, subject.decode('utf8'), body.decode('utf8'))

@connectRetry(try_times=1, timeout=8)
def reserveCourse(user_tickets=None, send_notice=True, always_flip=False):
    need_notice = False
    yclog.info('')
    for user in users_info:
        yclog.info('%s Connecting %s' % ('='*5, '='*5))
        aCourse = CourseReservation()
        aCourse.login(user_info=users_info[user])
        # reserve a ticket.
        for user_ticket in user_tickets[user]:
            yclog.info('-'*25)
            if not always_flip:
                # query if a ticket is *closed* or already *reserved*.
                ticket_status = aCourse.chkTicket(ticket=user_ticket)
                if not ticket_status == 'OPEN': continue
                else: need_notice = True
            status = aCourse.flipTicket(ticket=user_ticket)
            yclog.info(status)
        yclog.info('-'*25)
        user_tickets[user] = aCourse.getReservedTickets(phase=user_tickets[user][0]['phase'])
    #yclog.debug(user_tickets)

    if send_notice and need_notice: 
        msg_body = makeMsg(user_tickets=user_tickets)
        if msg_body: 
            sendMsg(body=msg_body)


if __name__ == '__main__':
    # time format MUST be: yyyy-mm-dd.
    user_tickets = {'yxt': [
          {'phase': '散段', 'date': '2011-10-15', 'hour': '9_13'},
          {'phase': '散段', 'date': '2011-10-15', 'hour': '13_17'},
          {'phase': '散段', 'date': '2011-10-15', 'hour': '17_19'},
          {'phase': '散段', 'date': '2011-10-16', 'hour': '9_13'},
          {'phase': '散段', 'date': '2011-10-16', 'hour': '17_19'},
          {'phase': '散段', 'date': '2011-10-16', 'hour': '13_17'}, ] }
    user_tickets['lvj'] = user_tickets['yxt']

    # for tests.
    #users_info.pop('lvj')
    #user_tickets.pop('lvj')
    #user_tickets['yxt'].pop()

    reserveCourse(user_tickets=user_tickets, send_notice=True, always_flip=False)
