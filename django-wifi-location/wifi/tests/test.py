from resttestcase import *

class FingerprintTest(RestTestCase):
    def testSubmitFingerprint(self):
        data = { "test": "test123" }
        respData = self.makeRequest("/wifi/submit_fingerprint", "POST", data)
        print respData
        self.assertEquals(respData['status'], "ok")
    def testAddFingerprint(self):
        """
        fingerprint = [{"bssid": "00-00-00-00-00-00", 
                        "rssi": "-56"},
                        {"bssid": "00-00-00-00-00-01", 
                        "rssi": "-23"},
                        {"bssid": "00-00-00-00-00-02", 
                        "rssi": "-78"},
                        {"bssid": "00-00-00-00-00-03", 
                        "rssi": "-90"},
                        {"bssid": "00-00-00-00-00-04", 
                        "rssi": "-64"}]
        """
        fingerprint = [{"00-00-00-00-00-00":"-56"},
                        {"00-00-00-00-00-01":"-23"},
                        {"00-00-00-00-00-02":"-78"},
                        {"00-00-00-00-00-03":"-90"},
                        {"00-00-00-00-00-04":"-64"}]
        postedData = {"1": fingerprint}
        respData = self.makeRequest("/wifi/add_fingerprint", "POST", postedData)
        self.assertEquals(respData["status"], SUCCESS)



