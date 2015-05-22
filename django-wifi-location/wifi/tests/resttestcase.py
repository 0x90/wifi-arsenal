from django.test import TestCase, Client
from django.conf import settings
from django.utils import unittest
#from django_dynamic_fixture import G
from importlib import *
from wifi.models import *
import json

SUCCESS = 0
FAIL = -1

class RestTestCase(TestCase):
    def makeRequest(self, url, method, data={}):
            jsonFlag = False
            if data:
                body = json.dumps(data)
                jsonFlag = True
            try:
                resp = ""
                if method == "GET" and jsonFlag:
                    resp = self.client.get(url, body, content_type="application/json")
                elif method == "POST" and jsonFlag:
                    resp = self.client.post(url, body, content_type="application/json")
                elif method == "GET":
                    resp = self.client.get(url)
                elif method == "POST":
                    resp = self.client.post(url)
                else:
                    raise
                if not resp:
                    raise
                self.assertEqual(resp.status_code, 200)
                return json.loads(resp.content)
            except:
                raise

    def setUp(self):
            self.client = Client()