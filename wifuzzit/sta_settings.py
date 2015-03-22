# Define variables
# SETTINGS is [ (STA_NUMBER, SAVE_RESULTS, SKIP) ]

TEST_SETTINGS_INDEX = 1

SETTINGS = [
            (0, 0, 0),
            (1, 0, 0),
            ]

# Defining the fuzzing MAC address device
AP_MAC  = "00:20:A6:61:2D:09"

# Defining the injection interface
IFACE   = "ath0"

##### BELOW VARIABLES SHOULD NOT BE TWEAKED BY THE USER

STA_NUMBER = SETTINGS[TEST_SETTINGS_INDEX][0]
SAVE_RESULTS = SETTINGS[TEST_SETTINGS_INDEX][1]
SKIP = SETTINGS[TEST_SETTINGS_INDEX][2]

# Defining fuzzing specific variables
STA = [
        ("00:00:00:00:00:00", 1),   # ipw3945 Linux
        ('18:34:51:54:c5:c9', 1),
        ][STA_NUMBER]

STA_MAC = STA[0]
REPEAT_TIME = STA[1]

# Tuning listen value (fuzzing speed and false positive rates)
LISTEN_TIME = 60

# Defining the logging file
FNAME = [None, 'audits/sta-%s.session' % (STA_MAC)][SAVE_RESULTS]

# Defining the step value for IE fuzzing (should be odd to reach 255)
STEP    = [1, 3, 15, 17, 51][4]

# Defining the padding value
PADDING = "A"

# Defining truncate option
TRUNCATE = True

# Defining fuzzing specific variables
SSID    = "fuzzing"
CHANNEL = "\x01"                # Channel should be the same that real one
