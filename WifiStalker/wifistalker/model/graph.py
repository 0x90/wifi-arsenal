# Author: Tomasz bla Fortuna
# License: GPLv2

from time import time

from wifistalker import config

class Graph(object):
    "Represents a relation graph for a specific sender MAC"

    def __init__(self, db, mac):
        self.db = db
        self.graphs = self.db['graphs']
        self.graphs.ensure_index('mac')

        self.init(mac)


    def load(self, mac):
        "Load graph from DB"
        now = time()

        # Remove timeouted
        self.graphs.remove({
            'stamp': {'$lt': now - config.graph_relations['cache_time']}
        })

        res = self.graphs.find({'mac': mac})
        if res.count() < 1:
            return None
        return res[0]

    def init(self, mac):
        # Load sender object always
        sender = self.db.knowledge.sender_query(mac=mac)
        if not sender:
            raise Exception("Unable to find a sender required for graph")
        self.sender = sender[0]

        ret = self.load(mac)
        if ret:
            self.graph = ret
        else:
            self.graph = {
                'mac': mac,
                'nodes': [],
                'edges': [],
            }

    def get(self):
        "Return graph (cached or newly generated"
        if 'stamp' in self.graph:
            return self.graph
        else:
            self.generate()
            return self.graph

    def generate(self):
        s = self.sender
        # Add base node
        label = s.user['alias'] if s.user['alias'] else s.mac
        self.add_base_node(s)

        ##
        # Add ssids of base node
        ssids = []
        for ssid in s.aggregate['ssid_probe']:
            ssids.append(ssid)
            self.add_ssid(ssid)
            self.add_probes(s.mac, ssid)

        for ssid in s.aggregate['ssid_beacon']:
            ssids.append(ssid)
            self.add_ssid(ssid, color='lightblue')
            self.add_beacons(s.mac, ssid)

        ##
        # Find other nodes which somehow use this SSIDs
        query = {
            '$or': [
                {'aggregate.ssid_probe': {'$in': ssids }},
                {'aggregate.ssid_beacon': {'$in': ssids }},
            ]
        }
        senders = self.db.knowledge.sender_query(advanced=query)
        for rel in senders:
            if rel.mac == s.mac:
                continue # Ignore the same node
            self.add_related_node(rel)

            for ssid in rel.aggregate['ssid_probe']:
                if ssid not in ssids:
                    continue
                ssids.append(ssid)
                self.add_ssid(ssid)
                self.add_probes(rel.mac, ssid)

            for ssid in rel.aggregate['ssid_beacon']:
                if ssid not in ssids:
                    continue

                ssids.append(ssid)
                self.add_ssid(ssid, color='lightblue')
                self.add_beacons(rel.mac, ssid)



        # Upon finalization - add timestamp.
        self.graph['stamp'] = time()

        # Store to cache
        self.graphs.insert(self.graph)



    # Low-level functions
    def add_node(self, nid, label, fill, shape='ellipse', stroke=None, stroke_width=2):
        "Internal: Add a defined node"
        opts = {
            'label': label,
            'stroke': stroke if stroke else fill,
            'fill': fill,
            'image': None,
            'type': shape,
            'stroke-width': stroke_width,
        }
        collisions = [node for node in self.graph['nodes'] if node[0] == nid]
        if collisions:
            print "Node with ID={0} already exists - ignoring".format(nid)
            return
        self.graph['nodes'].append((nid, opts))

    def add_sender(self, sender, fill, stroke=None, stroke_width=2):
        "Internal: Add based on sender"
        label = sender.user['alias'] if sender.user['alias'] else sender.mac
        shape = 'rect' if sender.meta['ap'] else 'ellipse'
        self.add_node(sender.mac, label=label, fill=fill, shape=shape,
                      stroke=stroke, stroke_width=stroke_width)

    def add_edge(self, nid_a, nid_b, directed, label, color):
        "Internal: Add a defined edge"
        for edge in self.graph['edges']:
            node_a, node_b, opts = edge
            if node_a == nid_a and node_b == nid_b:
                # Already exists
                opts['label'] += '/' + label
                opts['directed'] &= directed
                return

        opts = {
            'directed': directed,
            'label': label,
            'color': color,
        }
        self.graph['edges'].append((nid_a, nid_b, opts))

    # High-level nodes - mostly different styling
    def add_base_node(self, sender):
        "Add base graph node (there's only one)"
        self.add_sender(sender, fill='#f00')

    def add_related_node(self, sender):
        "Add base graph node (there's only one)"
        self.add_sender(sender, fill='#f99')



    # High-level edges
    def add_ssid(self, ssid, color='blue'):
        "API: Define specific SSID"
        label = ssid
        if len(label) > 14:
            label = label[:13] + '...'
        self.add_node('ssid_' + ssid, shape='smallellipse', label=label, fill=color)

    def add_probes(self, mac, ssid):
        "Add probe of a ssid by mac"
        self.add_edge(mac, 'ssid_' + ssid, directed=True, label='probe', color='red')

    def add_beacons(self, mac, ssid):
        "Add beacon of a ssid by mac"
        self.add_edge(mac, 'ssid_' + ssid, directed=True, label='beacon', color='blue')
