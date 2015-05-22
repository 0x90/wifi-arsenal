from flask import Flask, request, redirect
app = Flask(__name__)

import os
import datetime

@app.route('/say', methods=['GET', 'POST'])
def say():
  timestamp = datetime.datetime.now().strftime("%y/%m/%d %H:%M")
  if request.method == 'POST':
    lines = [request.form['line1'], request.form['line2'], request.form['line3']]
  else:
    lines = [ request.args.get('line1', ''), request.args.get('line2', ''), request.args.get('line3', '') ]

  prefix = ['-1', '-2', '-3']

  for i in range(len(lines)):
    lines[i] = lines[i].replace("'", "")
    os.system("echo [%s] %s >> history.log" % (timestamp, lines[i]))
    os.system("tail -n1 history.log")
    os.system("uci set wireless.@wifi-iface[%d].ssid='%s %s'" % (i,prefix[i],lines[i]))
  os.system("uci commit wireless")
  os.system("ifup wan")
  os.system("wifi")

  return 'success'

@app.route('/')
def home():
  return redirect("/static/index.html")

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
  return redirect("/static/index.html")

if __name__ == "__main__":
  app.run(port=80,host='0.0.0.0')
