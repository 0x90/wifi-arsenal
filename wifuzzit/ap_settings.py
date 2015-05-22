# Define variables
# SETTINGS is [ (AP_NUMBER, SAVE_RESULTS, SKIP) ]

TEST_SETTINGS_INDEX = 3

SETTINGS = [
            (0, 0, 0),
            ]

# Defining the fuzzing MAC address device
STA_MAC = "00:20:A6:61:2D:09"

# Defining the injection interface
IFACE   = "ath0"

##### BELOW VARIABLES SHOULD NOT BE TWEAKED BY THE USER

AP_NUMBER = SETTINGS[TEST_SETTINGS_INDEX][0]
SAVE_RESULTS = SETTINGS[TEST_SETTINGS_INDEX][1]
SKIP = SETTINGS[TEST_SETTINGS_INDEX][2]

# Defining fuzzing specific variables
AP = [
        ('kikoo', '00:11:22:33:44:55', 11, 'WPA-PSK'),
        ][AP_NUMBER]

SSID = AP[0]
AP_MAC = AP[1]
CHANNEL = chr(AP[2])
AP_CONFIG = AP[3]

# Defining the number of retries when authenticating/associating to the AP
CRASH_RETRIES = 10
DELAY = 1
STATE_WAIT_TIME = 2
DELAY_REBOOT = 10
LOG_LEVEL = 3
CRASH_THRESHOLD = 3
TRUNCATE = True

# Defining the log file
FNAME = [None, 'audits/ap-%s-%s.session' % (AP_MAC, AP_CONFIG)][SAVE_RESULTS]
