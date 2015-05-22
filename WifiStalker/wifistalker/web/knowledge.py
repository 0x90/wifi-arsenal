# Author: Tomasz bla Fortuna
# License: GPLv2

from flask import Blueprint

from flask import Flask, request, g
from flask import jsonify

from IPython import embed

api = Blueprint('api_knowledge', __name__)

@api.route('/logs')
def get_logs():
    u"Read logs"
    logs = g.db.log_get(count=20)
    return jsonify({'logs': logs})

@api.route('/knowledge')
def get_knowledge():
    u"Read knowledge limited to recent appearances"
    time_window = request.args.get('time_window', None)
    sort = request.args.get('sort', 'last_seen')
    mac = request.args.get('mac', None)

    if time_window:
        time_window = float(time_window)

    knowledge = g.db.knowledge.sender_query(mac=mac, sort=sort, time_window=time_window)

    for_web = []
    for sender in knowledge:
        sender = sender.get_dict()
        if mac is None:
            # Limit assocs / dsts in response for the table, keep in directed questions
            sender['aggregate']['tags_dst'] = len(sender['aggregate']['tags_dst'])
        else:
            # List instead of dict + sort it in Python
            dsts = [(mac, tags)
                    for mac, tags in sender['aggregate']['tags_dst'].iteritems()]
            dsts.sort(key=lambda x: x[1]['_sum'], reverse=True)
            sender['aggregate']['tags_dst'] = dsts

        for_web.append(sender)

    if mac is not None:
        # Add additional related data
        sender = for_web[0]
        related_macs = [m for m, t in sender['aggregate']['tags_dst']]
        mapping = g.db.knowledge.alias_query(related_macs)
    else:
        mapping = None

    return jsonify({
        'knowledge': for_web,
        'related': mapping,
    })

@api.route('/snapshot', methods=['POST'])
def post_snapshot():
    u"Handle a data dump"
    data = request.get_json()
    time_window = data.get('timeWindow', None)
    name = data.get('name', 'noname')
    if not name:
        name = 'noname'
    try:
        time_window = int(time_window)
    except (ValueError, TypeError):
        return

    model.presence_snapshot(name, time_window)
    return jsonify({'OK': True})

@api.route('/userdata', methods=['POST'])
def set_alias():
    u"Handle a alias update"
    data = request.get_json()
    mac = data.get('mac', None)
    alias = data.get('alias', None)
    notes = data.get('notes', None)
    owner = data.get('owner', None)
    if mac is None:
        return
    if not alias:  # '' -> None
        alias = None
    if not owner:
        owner = None
    if not notes:
        notes = None

    for i in range(10):
        sender = g.db.knowledge.sender_query(mac=mac)
        if not sender:
            print "UNABLE TO FIND SENDER TO UPDATE"
            return jsonify({'OK': False})

        sender = sender[0]
        sender.set_userdata(alias, owner, notes)
        ret = g.db.knowledge.sender_store(sender)
        if ret is False:
            print "OPTIMISTIC LOCKING FAILED - retry", i
            continue
        return jsonify({'OK': True})
    return jsonify({'OK': False})
