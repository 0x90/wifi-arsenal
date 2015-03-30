-- timestamp for eternity = infinity
-- using postgresql 9.3.4
-- ensure postgresql service is running - sudo service postgresql start
-- version 0.0.11

-- create nidus user and nidus database  
--postgres@host:/var/lib$ createuser nidus --pwprompt --no-superuser --no-createrole --no-createdb
--  Enter password for new role: **** (nidus)
--  Enter it again: **** (nidusr)
--createdb --owner=nidus nidus

-- DEFUNCT will not be using this for now
-- add postgis extension to nidus db
-- psql -d nidus
-- CREATE EXTENSION postgis;
-- \q

-- ERRORS
-- Error in reassocreq table
-- DB Error:  ('42601', 'ERROR:  syntax error at or near ")"
-- \nLINE 7: vendors))\n
-- ^\n', 'reassocreq', 539L)

-- to login with nidus & verify postgis
psql -h localhost -U nidus -d nidus
-- SELECT postgis_full_version();

-- use btree_gist (see http://www.postgresql.org/docs/devel/static/rangetypes.html)
-- sudo su - postgres
-- postgres=# psql -d nidus
-- postgres=# CREATE EXTENSION btree_gist;

-- force timezone to UTC
SET TIME ZONE 'UTC';

-- sensor table
-- defines a sensor session. A sensor is a hostname, ip address and the period
-- during which it is used
-- TODO: should we create an index on period?
DROP TABLE IF EXISTS sensor;
CREATE TABLE sensor(
   session_id serial,             -- the session id
   hostname VARCHAR(64) NOT NULL, -- hostname of sensor
   ip inet NOT NULL,              -- ip of sensor
   period TSTZRANGE NOT NULL,     -- valid range of sensor
   PRIMARY KEY (session_id),
   EXCLUDE USING gist (hostname WITH =, period WITH &&)
);
CREATE INDEX sensor_period_idx ON sensor USING GIST (period);

-- platform table
-- defines the platform a sensor is running on to include the regulatory domain
-- the wireless nics are defined under. This should not change much over 
-- any conceivable time except for kernel upgrade, os upgrade and reg. domain. 
-- useful for debugging? performance metrics?
DROP TABLE IF EXISTS platform;
CREATE TABLE platform(
   sid integer NOT NULL UNIQUE,     -- foreign key to session
   os varchar(20) default 'Linux',  -- OS
   dist varchar(15),                -- OS distribution, allow null for non linux
   version varchar(10),             -- OS version, allow null for non linux
   name varchar(10),                -- OS name, allow null for non linux
   kernel varchar(25),              -- kernel version assumes linux allow for null if other
   machine varchar(10) NOT NULL,    -- machine architecture i.e. i386
   pyvers varchar(10) NOT NULL,     -- python interpreter version
   pycompiler varchar(10) NOT NULL, -- python interpreter compiler w/ version
   pylibcvers varchar(10) NOT NULL, -- python interpreter libc version
   pybits varchar(5) NOT NULL,      -- python interpreter bit architecture
   pylinkage varchar(10) NOT NULL,  -- python interpreter linkage
   region varchar(2) default '00',  -- regulatory domain
   CONSTRAINT ch_sid CHECK (sid > 0),
   FOREIGN KEY (sid) REFERENCES sensor(session_id)
);

-- gpsd table
-- details of a gps device
DROP TABLE IF EXISTS gpsd;
CREATE TABLE gpsd(
    id serial,                      -- primary key
    devid VARCHAR(9),               -- device id (XXXX:XXXX assumes usb)
    version VARCHAR(5) NOT NULL,    -- gpsd version
    flags SMALLINT DEFAULT 1,       -- device flags
    driver VARCHAR(50) NOT NULL,    -- driver for device
    bps SMALLINT DEFAULT 4800,      -- bauds per second
    tty VARCHAR(20) NOT NULL ,      -- the path of the device
    PRIMARY KEY (id)
);

-- using_gpsd table
DROP TABLE IF EXISTS using_gpsd;
CREATE TABLE using_gpsd(
   sid integer NOT NULL,          -- foreign key to session
   gid integer NOT NULL,          -- foreign key to gps device
   period TSTZRANGE NOT NULL,     -- timerange sensor is using gid
   CONSTRAINT ch_sid CHECK (sid > 0),
   CONSTRAINT ch_gid CHECK (gid > 0),
   FOREIGN KEY (sid) REFERENCES sensor(session_id),
   FOREIGN KEY (gid) REFERENCES gpsd(id),
   EXCLUDE USING gist (sid WITH =,gid WITH =,period WITH &&)
);

-- geo table
-- locational data of sensor NOTE: we use the sensor id over a gps device id
-- due to the fact that the geo may be staticly defined
-- how do we define a constraint such that the geo must have a sid that 
-- is in sensor and the ts falls within that sensor's current period
-- *dop values:
-- 1	 Ideal	    highest possible confidence level
-- 1-2	 Excellent	positional measurements are considered accurate enough for most apps
-- 2-5	 Good	    minimum appropriate for business decisions, could be used to make reliable in-route navigation suggestions
-- 5-10	 Moderate	can be used for calculations, but fix quality could be improved, more open view of sky is recommended.
-- 10-20 Fair	    low confidence level discard or used only to indicate rough estimate of current loc
-- >20	 Poor	    measurements are inaccurate and should be discard
DROP TABLE IF EXISTS geo;
CREATE TABLE geo(
   gid integer NOT NULL,        -- FOREIGN KEY to gpsd id
   ts TIMESTAMPTZ NOT NULL,     -- timestamp of geolocation
   coord VARCHAR(15) NOT NULL,  -- geolocation in mgrs
   alt REAL,                    -- altitude
   spd REAL,                    -- speed
   dir REAL,                    -- heading
   fix SMALLINT DEFAULT 0,      -- 'quality' of the fix, -1 = fixed
   xdop REAL DEFAULT 0,         -- cross-track dilution of precision
   ydop REAL DEFAULT 0,         -- cross-track dilution of precision
   pdop REAL DEFAULT 0,         -- position (3D) dilution of precision
   epx REAL DEFAULT 0,          -- longitude uncertainty
   epy REAL DEFAULT 0,          -- latitude uncertainty
   CONSTRAINT ch_gid CHECK (gid >= 0),
   CONSTRAINT ch_spd CHECK (spd >= 0),
   CONSTRAINT ch_dir CHECK(dir >=0 and dir <= 360),
   CONSTRAINT ch_fix CHECK (fix >= -1 and fix <= 3),
   CONSTRAINT ch_xdop CHECK (xdop > 0),
   CONSTRAINT ch_ydop CHECK (ydop > 0),
   CONSTRAINT ch_pdop CHECK (pdop > 0),
   CONSTRAINT ch_epx CHECK (epx >= 0),
   CONSTRAINT ch_epy CHECK (epy >= 0),
   FOREIGN KEY (gid) REFERENCES gpsd(id),
   PRIMARY KEY(gid,ts)
);

-- radio table
-- static properties of a radio i.e. a wireless nic
-- any changes to the below would imply a new wireless nic
DROP TABLE IF EXISTS radio;
CREATE TABLE radio(
   mac macaddr NOT NULL,                      -- mac address of nic
   driver VARCHAR(20) DEFAULT 'UNKNOWN',      -- nic driver
   chipset VARCHAR(20) DEFAULT 'UNKNOWN',     -- nic chipset
   channels SMALLINT[] NOT NULL,              -- list of channels supported by nic 
   standards VARCHAR(20) DEFAULT '802.11b/g', -- list of standards supported by nic
   PRIMARY KEY(mac)
);

-- antenna type enumeration
DROP TYPE IF EXISTS ANTENNA_TYPE;
CREATE TYPE ANTENNA_TYPE AS ENUM ('none','omni','omni array','yagi','grid','panel',
                                   'patch','sector');
-- antenna table
-- Each radio will have 1 or more antennas. Normally these would all be configured
-- the same, however with 802.11n it is beneficial to have antennas polarized
-- differently to increase throughput through spatial multiplexing
DROP TABLE IF EXISTS antenna;
CREATE TABLE antenna(
  mac macaddr NOT NULL,             -- mac address of nic (fk)
  ind smallint NOT NULL,            -- index of antenna, 0-based
  gain REAL,                        -- gain in dBi
  loss REAL,                        -- loss in dBi
  x REAL,                           -- rotation of antenna along x-axis
  y REAL,                           -- rotation of antenna along y-axis
  z REAL,                           -- rotation of antenna along y-axis
  type ANTENNA_TYPE DEFAULT 'omni', -- type of antenna
  period TSTZRANGE NOT NULL,        -- timerange the radio is using this antenna
  CONSTRAINT ch_ind CHECK (ind >= 0),
  CONSTRAINT ch_x CHECK(x >=0 and x < 360),
  CONSTRAINT ch_y CHECK(y >=0 and y < 360),
  CONSTRAINT ch_z CHECK(z >=0 and z < 360),
  CONSTRAINT ch_gain CHECK(gain >= 0),
  CONSTRAINT ch_loss CHECK(loss >= 0),
  FOREIGN KEY (mac) REFERENCES radio(mac),
  EXCLUDE USING gist (mac WITH =,ind WITH =,period WITH &&)
);

-- radio role type enumeration
DROP TYPE IF EXISTS ROLE;
CREATE TYPE ROLE AS ENUM ('recon','collection');

-- radio_epoch
-- epochal properties of a radio, these are expected to change (if at all) 
-- only after some period of time
DROP TABLE IF EXISTS radio_epoch;
CREATE TABLE radio_epoch(
   mac macaddr NOT NULL,            -- foreign key to radio mac addr
   role ROLE NOT NULL,              -- what role is radio playing now
   description VARCHAR(200),        -- brief description of radio
   period TSTZRANGE NOT NULL,       -- period during which record is true
   FOREIGN KEY (mac) REFERENCES radio(mac),
   EXCLUDE USING gist (mac WITH =, period WITH &&)
);

-- radio_period
-- periodic properties of a radio, these can change 'instantly'
DROP TABLE IF EXISTS radio_period;
CREATE TABLE radio_period(
   mac macaddr NOT NULL,       -- foreign key to radio mac addr
   spoofed VARCHAR(17),        -- virtual (spoofed) mac address
   txpwr SMALLINT DEFAULT 15,  -- transmit power in dBm
   period TSTZRANGE NOT NULL,  -- period during which record is true
   FOREIGN KEY (mac) REFERENCES radio(mac),
   EXCLUDE USING gist (mac WITH =, period WITH &&)
);

-- radio state enumerations
DROP TYPE IF EXISTS RADIOSTATE;
CREATE TYPE RADIOSTATE AS ENUM ('hold','scan','listen','fail');

-- radio_event table
DROP TABLE IF EXISTS radio_event;
CREATE TABLE radio_event(
   mac macaddr NOT NULL,            -- foreign key to radio mac addr
   state RADIOSTATE DEFAULT 'scan', -- radio event at timestamp ts 
   params TEXT DEFAULT '',          -- free-form params of event
   ts TIMESTAMPTZ NOT NULL,         -- timestamp for event
   FOREIGN KEY (mac) REFERENCES radio(mac),
   PRIMARY KEY(mac,ts)
);

-- using_radio table
DROP TABLE IF EXISTS using_radio;
CREATE TABLE using_radio(
   sid integer NOT NULL,      -- foreign key to sensor
   mac macaddr NOT NULL,      -- foreign key to radio
   phy VARCHAR(5) NOT NULL,   -- the phy of radio
   nic VARCHAR(5) NOT NULL,   -- actual nic of radio
   vnic VARCHAR(6) NOT NULL,  -- virtual nic of radio
   period TSTZRANGE NOT NULL, -- timerange sensor is using mac
   CONSTRAINT ch_sid CHECK (sid > 0),
   FOREIGN KEY (sid) REFERENCES sensor(session_id),
   FOREIGN KEY (mac) REFERENCES radio(mac),
   EXCLUDE USING gist (sid WITH =,mac WITH =,period WITH &&)
);

-- NOTE:
-- capture header and mpdu layers are defined in a set of tables. The phy layer 
-- is defined (partially) in frame, source, ampdu and signal. The mac layer 
-- is defined in traffic and wepcrypt, tkipcrypt and ccmpcrypt

-- frame table
-- each traffic is defined by its id, timestampe and src and describes basic
-- details of the signal to include the type of frame header, and type/subtype
-- of the mpdu layer
-- TODO: add location here or force separate select on geo table
DROP TABLE IF EXISTS frame;
CREATE TABLE frame(
   id bigserial NOT NULL,            -- frame primary key
   sid integer NOT NULL,             -- foreign key to session
   ts TIMESTAMPTZ NOT NULL,          -- time of collection
   bytes smallint NOT NULL,          -- ttl bytes
   bRTAP smallint,                   -- bytes in radiotap
   bMPDU smallint,                   -- bytes in mmpdu
   data smallint[2] NOT NULL,        -- left,right indexes into data portion 
   ampdu smallint not NULL,          -- ampdu is present    
   fcs smallint not NULL,            -- fcs is present (1) or not (0)
   CONSTRAINT ch_bytes CHECK (bytes > 0),
   CONSTRAINT ch_bytesRTAP CHECK (bRTAP >= 0),
   CONSTRAINT ch_bytesMPDU CHECK (bMPDU >= 0),
   CONSTRAINT ch_ampdu CHECK (ampdu >= 0 AND ampdu <= 1),
   CONSTRAINT ch_fcs CHECK (fcs >= 0 AND fcs <= 1),
   FOREIGN KEY(sid) REFERENCES sensor(session_id),
   PRIMARY KEY(id)
);

-- frame_path table
-- stores the file that this frame is save in
-- NOTE: this is the same id as frame.id but we do not make a reference in 
-- case the different threads processing thsee are out of sync
DROP TABLE IF EXISTS frame_path;
CREATE TABLE frame_path(
   fid bigint NOT NULL,      -- foreign key to frame id
   filepath TEXT NOT NULL,   -- file path of this frame
   CONSTRAINT ch_fid CHECK (fid > 0),
   FOREIGN KEY (fid) REFERENCES frame(id)
);

-- ampdu table
-- defines ampdu frames
DROP TABLE IF EXISTS ampdu;
CREATE TABLE ampdu(
   fid bigint NOT NULL,      -- foreign key to frame
   refnum bigint NOT NULL,   -- reference number
   flags integer NOT NULL,   -- flags
   CONSTRAINT ch_fid CHECK (fid > 0),
   CONSTRAINT ch_refnum CHECK (refnum > 0),
   CONSTRAINT ch_flags CHECK (flags > 0),
   FOREIGN KEY (fid) REFERENCES frame(id)
);

-- source table
-- defines the collecting source of a frame
DROP TABLE IF EXISTS source;
CREATE TABLE source(
   fid bigint NOT NULL,          -- foreign key to frame
   src macaddr NOT NULL,         -- foreign key to collecting source
   antenna smallint default '0', -- antenna of source collecting signal
   rfpwr smallint,               -- rf power in dB
   CONSTRAINT ch_fid CHECK (fid > 0),
   CONSTRAINT ch_ant CHECK (antenna >= 0 and antenna < 256),   
   CONSTRAINT ch_rfpwr CHECK (rfpwr > -150 and rfpwr < 150),
   FOREIGN KEY (src) REFERENCES radio(mac),
   FOREIGN KEY (fid) REFERENCES frame(id)
);

-- 802.11 standard enumeration
DROP TYPE IF EXISTS STANDARD;
CREATE TYPE STANDARD AS ENUM ('a','b','g','n','ac');

-- MCS BW ENUMERATION
DROP TYPE IF EXISTS MCS_BW;
CREATE TYPE MCS_BW AS ENUM ('20','40','20L','20U');

-- signal table
-- defines data as captured in the frame header
DROP TABLE IF EXISTS signal;
CREATE TABLE signal(
   fid bigint NOT NULL,        -- foreign key to frame
   std STANDARD NOT NULL,      -- what standard
   rate decimal(5,1) NOT NULL, -- rate in Mbps of signal
   channel smallint NOT NULL,  -- channel
   chflags integer NOT NULL,   -- channel flags
   rf smallint NOT NULL,       -- frequency
   ht smallint NOT NULL,       -- is this an ht signal
   mcs_bw MCS_BW,              -- bw from mcs field if present
   mcs_gi smallint,            -- mcs guard interval 0=long, 1=short
   mcs_ht smallint,            -- mcs ht format 0=mixed, 1=greenfield
   mcs_index smallint,         -- mcs index if known
   CONSTRAINT ch_fid CHECK (fid > 0),
   CONSTRAINT ch_rate CHECK (rate >= 0),
   CONSTRAINT ch_channel CHECK (channel > 0 and channel < 200),
   CONSTRAINT ch_chflags CHECK (chflags >= 0),
   CONSTRAINT ch_rf CHECK (rf > 0),
   CONSTRAINT ch_ht CHECK (ht >=0 and ht <= 1),
   CONSTRAINT ch_mcs_gi CHECK (mcs_gi >= 0 and mcs_gi <= 1),
   CONSTRAINT ch_mcs_ht CHECK (mcs_ht >= 0 and mcs_ht <= 1),
   CONSTRAINT ch_mcs_index CHECK (mcs_index >= 0 and mcs_index <= 31),
   FOREIGN KEY (fid) REFERENCES frame(id)
);

-- 802.11 type enumerations
DROP TYPE IF EXISTS FT_TYPE;
CREATE TYPE FT_TYPE AS ENUM ('mgmt','ctrl','data','rsrv');

-- 802.11 subtype enumerations
-- defines all subtypes together including one 'rsrv' enum
DROP TYPE IF EXISTS FT_SUBTYPE;
CREATE TYPE FT_SUBTYPE AS ENUM ('assoc-req','assoc-resp','reassoc-req','reassoc-resp',
                                'probe-req','probe-resp','timing-adv','beacon',
                                'atim','disassoc','auth','deauth','action',
                                'action-noack','wrapper','block-ack-req',
                                'block-ack','pspoll','rts','cts','ack','cfend',
                                'cfend-cfack','data','cfack','cfpoll','cfack-cfpoll',
                                'null','null-cfack','null-cfpoll','null-cfack-cfpoll',
                                'qos-data','qos-data-cfack','qos-data-cfpoll',
                                'qos-data-cfack-cfpoll','qos-null','qos-cfpoll',
                                'qos-cfack-cfpoll','rsrv');

DROP TYPE IF EXISTS DUR_TYPE;
CREATE TYPE DUR_TYPE AS ENUM ('vcs','cfp','aid','rsrv');

-- encryption type
DROP TYPE IF EXISTS CRYPT_TYPE;
CREATE TYPE CRYPT_TYPE AS ENUM ('none','wep','tkip','ccmp','other');

-- traffic table
-- defines portions of the mpdu layer.
-- The minimum mpdu is frame control, duration and address 1
-- NOTE: for duration value is only included if the type is of vsc or aid
DROP TABLE IF EXISTS traffic;
CREATE TABLE traffic(
   fid bigint NOT NULL,             -- foreign key to frame
   type FT_TYPE NOT NULL,           -- type of frame
   subtype FT_SUBTYPE NOT NULL,     -- subtype of frame
   td smallint default '0',         -- to ds bit 
   fd smallint default '0',         -- from ds bit
   mf smallint default '0',         -- more fragments bit
   rt smallint default '0',         -- retry bit
   pm smallint default '0',         -- power mgmt bit
   md smallint default '0',         -- more data bit
   pf smallint default '0',         -- protected frame bit
   so smallint default '0',         -- order bit
   dur_type DUR_TYPE NOT NULL,      -- duration type
   dur_val integer,                 -- duration value
   addr1 macaddr NOT NULL,          -- first address
   addr2 macaddr,                   -- second address
   addr3 macaddr,                   -- third address
   fragnum smallint,                -- seq control fragment number
   seqnum smallint,                 -- seq control sequence number
   addr4 macaddr,                   -- fourth address
   crypt CRYPT_TYPE default 'none', -- encryption type 
   CONSTRAINT ch_fid CHECK (fid > 0),
   CONSTRAINT ch_td CHECK (td >= 0 and td <= 1),
   CONSTRAINT ch_fd CHECK (fd >= 0 and fd <= 1),
   CONSTRAINT ch_mf CHECK (mf >= 0 and mf <= 1),
   CONSTRAINT ch_rt CHECK (rt >= 0 and rt <= 1),
   CONSTRAINT ch_pm CHECK (pm >= 0 and pm <= 1),
   CONSTRAINT ch_md CHECK (md >= 0 and md <= 1),
   CONSTRAINT ch_pf CHECK (pf >= 0 and pf <= 1),
   CONSTRAINT ch_so CHECK (so >= 0 and so <= 1),
   CONSTRAINT ch_dur_val CHECK (dur_val >= 0),
   CONSTRAINT ch_seqctrl CHECK (fragnum >= 0 and seqnum >= 0),
   FOREIGN KEY(fid) REFERENCES frame(id)
);

-- qos table
-- defines qos control table
DROP TABLE IF EXISTS qosctrl;
CREATE TABLE qosctrl(
   fid bigint NOT NULL,      -- foreign key to frame
   tid smallint NOT NULL,    -- tid/access class bits 0-3
   eosp smallint not NULL,   -- eosp bit 4
   ackpol smallint not NULL, -- ack policy bits 5-6
   amsdu smallint not NULL,  -- a-msdu bit 7
   txop smallint not NULL,   -- 8 bit txop limit, txip dur. req. AP PS, etc
   CONSTRAINT ch_fid CHECK (fid > 0),
   CONSTRAINT ch_tid CHECK (tid >=0 and tid < 16),
   CONSTRAINT ch_eosp CHECK (eosp >=0 and eosp <=1),
   CONSTRAINT ch_ackpol CHECK (ackpol >= 0 and ackpol <=4),
   CONSTRAINT ch_amsdu CHECK (amsdu >=0 and amsdu <= 1),
   CONSTRAINT ch_txop CHECK (txop >= 0 and txop < 256),
   FOREIGN KEY(fid) REFERENCES frame(id)
);

-- wepcrypt table
-- defines wep encryption scheme at layer 3
DROP TABLE IF EXISTS wepcrypt;
CREATE TABLE wepcrypt(
   fid bigint NOT NULL,      -- foreign key to frame
   iv bytea NOT NULL,        -- hex repr of 3 byte wep iv
   key_id smallint NOT NULL, -- index of wep key (out of 4) used
   icv bytea NOT NULL,       -- hex repr of f byte wep icv
   CONSTRAINT ch_fid CHECK (fid > 0),
   CONSTRAINT ch_key_id CHECK (key_id >= 0 and key_id < 4),
   FOREIGN KEY(fid) REFERENCES frame(id)
);

-- tkipcrypt table
-- defines tkip encryption scheme at layer 3
DROP TABLE IF EXISTS tkipcrypt;
CREATE TABLE tkipcrypt(
   fid bigint NOT NULL,      -- foreign key to frame
   tsc1 bytea NOT NULL,      -- hex repr of 1 byte iv-tsc1
   wepseed bytea NOT NULL,   -- hex repr of 1 byte iv-wep-seed
   tsc0 bytea NOT NULL,      -- hex repr of 1 byte iv-tsc0
   key_id smallint NOT NULL, -- index of tkip key value
   tsc2 bytea NOT NULL,      -- hex repr of 1 byte extiv-tsc2
   tsc3 bytea NOT NULL,      -- hex repr of 1 byte extiv-tsc3
   tsc4 bytea NOT NULL,      -- hex repr of 1 byte extiv-tsc4
   tsc5 bytea NOT NULL,      -- hex repr of 1 byte extiv-tsc5
   mic bytea NOT NULL,       -- hex repr of 8 byte mic
   icv bytea NOT NULL,       -- hex repr of 4 byte ICV
   CONSTRAINT ch_fid CHECK (fid > 0),
   CONSTRAINT ch_key_id CHECK (key_id >= 0 and key_id < 4),
   FOREIGN KEY(fid) REFERENCES frame(id)
);

-- ccmpcrypt table
-- defines ccmp encryption scheme at layer 3
DROP TABLE IF EXISTS ccmpcrypt;
CREATE TABLE ccmpcrypt(
   fid bigint NOT NULL,      -- foreign key to frame
   pn0 bytea NOT NULL,       -- hex repr of 1 byte pn0
   pn1 bytea NOT NULL,       -- hex repr of 1 byte pn1
   key_id smallint NOT NULL, -- index of ccmp key value
   pn2 bytea NOT NULL,       -- hex repr of 1 byte pn2
   pn3 bytea NOT NULL,       -- hex repr of 1 byte pn3
   pn4 bytea NOT NULL,       -- hex repr of 1 byte pn4
   pn5 bytea NOT NULL,       -- hex repr of 1 byte pn5
   mic bytea NOT NULL,       -- hex repr of 8 byte mic
   CONSTRAINT ch_fid CHECK (fid > 0),
   CONSTRAINT ch_key_id CHECK (key_id >= 0 and key_id < 4),
   FOREIGN KEY(fid) REFERENCES frame(id)
);

-- network entities
-- these are tables of inferred data, that is, the data in the below tables
-- already exists in some form in the above tables

-- host table
-- consolidates multiple stas under a single host 
DROP TABLE IF EXISTS host;
CREATE TABLE host(
  id serial NOT NULL, -- primary key
);

DROP TABLE IF EXISTS has_sta;
CREATE TABLE has_sta(
  hostid integer NOT NULL, -- fk to host
  staid integer NOT NULL,  -- fk to sta
  ts TIMESTAMPTZ NOT NULL, -- timestamp 'assumption' is made
  CONSTRAINT ch_hostid CHECK (hostid > 0),
  CONSTRAINT ch_staid CHECK (staid > 0),
  FOREIGN KEY (hostid) REFERENCES host(id),
  FOREIGN KEY (staid) REFERENCES sta(id)
);

-- sta table
-- primary entity of a network. A sta is a client or an ap of a BSS/IBSS or
-- a station attempting to enter/create a BSS/IBSS or the ap a sta is 
-- probing for 
-- the sta table exists across sessions
DROP TABLE IF EXISTS sta;
CREATE TABLE sta(
   id serial NOT NULL,                   -- primary key
   sid integer NOT NULL,                 -- fk to session sta was first seen
   fid bigint NOT NULL,                  -- fk to frame sta was first seen
   spotted TIMESTAMPTZ NOT NULL,         -- ts sta was first seen/heard
   mac macaddr UNIQUE NOT NULL,          -- mac address of sta's radio
   manuf VARCHAR(100) default 'unknown', -- manufacturer according to oui
   note TEXT,                            -- any notes on sta
   CONSTRAINT ch_fid CHECK (fid > 0),
   CONSTRAINT ch_sid CHECK (sid > 0),
   FOREIGN KEY (sid) REFERENCES sensor(session_id),
   FOREIGN KEY (fid) REFERENCES frame(id),
   PRIMARY KEY (id)
);

-- sta_activity table
-- defines activity (seen,heard) of 802.11 station during a session
--  Seen and Heard
-- define the stations activity timestamps during the giving session:
--  firstSeen - timestamp this station was first referenced in traffic i.e.
--              through a probe, traffic sent to etc
--  lastSeen - timestamp this station was last referenced in traffic
--  firstHeard - timestamp this station first transmitted
--  lastHeard - timestamp this station last transmitted
-- The sta_activity table defines a sta's activity on a per session basis 
DROP TABLE IF EXISTS sta_activity;
CREATE TABLE sta_activity(
   sid integer NOT NULL,   -- foreign key to session id
   staid integer NOT NULL, -- foreign key to sta id
   firstSeen TIMESTAMPTZ,  -- ts this station was first seen
   lastSeen TIMESTAMPTZ,   -- ts this station was las seen 
   firstHeard TIMESTAMPTZ, -- ts this station was first heard
   lastHeard TIMESTAMPTZ,  -- ts this station was last heard 
   CONSTRAINT ch_sid CHECK (sid > 0),
   CONSTRAINT ch_staid CHECK (staid > 0),
   FOREIGN KEY(sid) REFERENCES sensor(session_id),
   FOREIGN KEY(staid) REFERENCES sta(id),
   PRIMARY KEY(sid,staid)
);

-- Management Frames

-- assocreq table
-- similar to beacon table, the assocreq references the sid it was seen in, the
-- frame it is part of and the id of the AP as well as the id of the requesting 
-- sta.
DROP TABLE IF EXISTS assocreq;
CREATE TABLE assocreq(
  fid bigint NOT NULL,              -- fk to frame
  client integer NOT NULL,          -- fk to STA - this is the client
  ap integer NOT NULL,              -- fk to STA - this is the AP
  ess smallint default '0',         -- ess bit (comes from an AP) 
  ibss smallint default '0',        -- ibss bit (comes from an ibss)
  cf_pollable smallint default '0', -- set IAW Std Table 8-34/8-35  
  cf_poll_req smallint default '0', -- see above
  privacy smallint default '0',     -- indicates data is encrypted
  short_pre smallint default '0',   -- AP supports short preambles
  pbcc smallint default '0',        -- PKT binary convolutional code allowed
  ch_agility smallint default '0',  -- irrelevant field not used
  spec_mgmt smallint default '0',   -- 802.11h, if 1 implements DFS and TPC
  qos smallint default '0',         -- AP supports qos
  short_slot smallint default '0',  -- AP currently supports short time slots (i.e. no 802.11b)
  apsd smallint default '0',        -- AP supports 802.11e power management
  rdo_meas smallint default '0',    -- dot11RadioMeasurementActivated is true
  dsss_ofdm smallint default '0',   -- deprecated
  del_ba smallint default '0',      -- delayed block ack supported
  imm_ba smallint default '0',      -- immediate block ack supported
  listen_int integer NOT NULL,      -- listen interval in microseconds
  ssid VARCHAR(32),                 -- the ssid of this network (NULL for cloaked,
  sup_rates decimal(5,1)[],         -- list of supported rates
  ext_rates decimal(5,1)[],         -- list of extended rates
  vendors char(8)[],                -- list of (unique) vendor ouis found in info-elements
  CONSTRAINT ch_fid CHECK (fid > 0), 
  CONSTRAINT ch_client CHECK (client > 0),
  CONSTRAINT ch_ap CHECK (ap > 0),
  CONSTRAINT ch_listen_int CHECK (listen_int > 0),
  CONSTRAINT ch_ess CHECK (ess >=0 and ess <=1),
  CONSTRAINT ch_ibss CHECK (ibss >=0 and ibss <=1),
  CONSTRAINT ch_cf_pollable CHECK (cf_pollable >=0 and cf_pollable <=1),
  CONSTRAINT ch_cf_poll_req CHECK (cf_poll_req >=0 and cf_poll_req <=1),
  CONSTRAINT ch_privacy CHECK (privacy >=0 and privacy <=1),
  CONSTRAINT ch_short_pre CHECK (short_pre >=0 and short_pre <=1),
  CONSTRAINT ch_pbcc CHECK (pbcc >=0 and pbcc <=1),
  CONSTRAINT ch_ch_agility CHECK (ch_agility >=0 and ch_agility <=1),
  CONSTRAINT ch_spec_mgmt CHECK (spec_mgmt >=0 and spec_mgmt <=1),
  CONSTRAINT ch_qos CHECK (qos >=0 and qos <=1),
  CONSTRAINT ch_short_slot CHECK (short_slot >=0 and short_slot <=1),
  CONSTRAINT ch_apsd CHECK (apsd >=0 and apsd <=1),
  CONSTRAINT ch_rdo_meas CHECK (rdo_meas >=0 and rdo_meas <=1),
  CONSTRAINT ch_dsss_ofdm CHECK (dsss_ofdm >=0 and dsss_ofdm <=1),
  CONSTRAINT ch_del_ba CHECK (del_ba >=0 and del_ba <=1),
  CONSTRAINT ch_imm_ba CHECK (imm_ba >=0 and imm_ba <=1),
  FOREIGN KEY (fid) REFERENCES frame(id),
  FOREIGN KEY (client) REFERENCES sta(id),
  FOREIGN KEY (ap) REFERENCES sta(id)
);
 
-- association type
DROP TYPE IF EXISTS ASSOC_TYPE;
CREATE TYPE ASSOC_TYPE AS ENUM ('assoc','reassoc');

-- assocresp table 
-- The assocresp table stores response for both association and reassociation
-- response. See beacon for capability bits information 
DROP TABLE IF EXISTS assocresp;
CREATE TABLE assocresp(
  fid bigint NOT NULL,              -- fk to frame
  client integer NOT NULL,          -- fk to STA - this is the client
  ap integer NOT NULL,              -- fk to STA - this is the AP
  type ASSOC_TYPE NOT NULL,         -- one of {association|reassociation}
  ess smallint default '0',         -- ess bit (comes from an AP) 
  ibss smallint default '0',        -- ibss bit (comes from an ibss)
  cf_pollable smallint default '0', -- set IAW Std Table 8-34/8-35  
  cf_poll_req smallint default '0', -- see above
  privacy smallint default '0',     -- indicates data is encrypted
  short_pre smallint default '0',   -- AP supports short preambles
  pbcc smallint default '0',        -- PKT binary convolutional code allowed
  ch_agility smallint default '0',  -- irrelevant field not used
  spec_mgmt smallint default '0',   -- 802.11h, if 1 implements DFS and TPC
  qos smallint default '0',         -- AP supports qos
  short_slot smallint default '0',  -- AP currently supports short time slots (i.e. no 802.11b)
  apsd smallint default '0',        -- AP supports 802.11e power management
  rdo_meas smallint default '0',    -- dot11RadioMeasurementActivated is true
  dsss_ofdm smallint default '0',   -- deprecated
  del_ba smallint default '0',      -- delayed block ack supported
  imm_ba smallint default '0',      -- immediate block ack supported
  status integer NOT NULL,          -- status code - 0 means success 
  aid integer,                      -- if successful, the sta's AID
  ssid VARCHAR(32),                 -- the ssid of this network (NULL for cloaked,
  sup_rates decimal(5,1)[],         -- list of supported rates
  ext_rates decimal(5,1)[],         -- list of extended rates
  vendors char(8)[],                -- list of (unique) vendor ouis found in info-elements
  CONSTRAINT ch_fid CHECK (fid > 0), 
  CONSTRAINT ch_client CHECK (client > 0),
  CONSTRAINT ch_ap CHECK (ap > 0),
  CONSTRAINT ch_ess CHECK (ess >=0 and ess <=1),
  CONSTRAINT ch_ibss CHECK (ibss >=0 and ibss <=1),
  CONSTRAINT ch_cf_pollable CHECK (cf_pollable >=0 and cf_pollable <=1),
  CONSTRAINT ch_cf_poll_req CHECK (cf_poll_req >=0 and cf_poll_req <=1),
  CONSTRAINT ch_privacy CHECK (privacy >=0 and privacy <=1),
  CONSTRAINT ch_short_pre CHECK (short_pre >=0 and short_pre <=1),
  CONSTRAINT ch_pbcc CHECK (pbcc >=0 and pbcc <=1),
  CONSTRAINT ch_ch_agility CHECK (ch_agility >=0 and ch_agility <=1),
  CONSTRAINT ch_spec_mgmt CHECK (spec_mgmt >=0 and spec_mgmt <=1),
  CONSTRAINT ch_qos CHECK (qos >=0 and qos <=1),
  CONSTRAINT ch_short_slot CHECK (short_slot >=0 and short_slot <=1),
  CONSTRAINT ch_apsd CHECK (apsd >=0 and apsd <=1),
  CONSTRAINT ch_rdo_meas CHECK (rdo_meas >=0 and rdo_meas <=1),
  CONSTRAINT ch_dsss_ofdm CHECK (dsss_ofdm >=0 and dsss_ofdm <=1),
  CONSTRAINT ch_del_ba CHECK (del_ba >=0 and del_ba <=1),
  CONSTRAINT ch_imm_ba CHECK (imm_ba >=0 and imm_ba <=1),
  CONSTRAINT ch_status CHECK (status >= 0),
  CONSTRAINT ch_aid CHECK (aid >= 0),
  FOREIGN KEY (fid) REFERENCES frame(id),
  FOREIGN KEY (client) REFERENCES sta(id),
  FOREIGN KEY (ap) REFERENCES sta(id)
);
 
-- reassocreq table
-- near similar to assocreq table but includes the bssid/mac address of the
-- ap the sta is currently associated(or authenticated) to
DROP TABLE IF EXISTS reassocreq;
CREATE TABLE reassocreq(
  fid bigint NOT NULL,              -- fk to frame
  client integer NOT NULL,          -- fk to STA - this is the client
  ap integer NOT NULL,              -- fk to STA - this is the AP
  ess smallint default '0',         -- ess bit (comes from an AP) 
  ibss smallint default '0',        -- ibss bit (comes from an ibss)
  cf_pollable smallint default '0', -- set IAW Std Table 8-34/8-35  
  cf_poll_req smallint default '0', -- see above
  privacy smallint default '0',     -- indicates data is encrypted
  short_pre smallint default '0',   -- AP supports short preambles
  pbcc smallint default '0',        -- PKT binary convolutional code allowed
  ch_agility smallint default '0',  -- irrelevant field not used
  spec_mgmt smallint default '0',   -- 802.11h, if 1 implements DFS and TPC
  qos smallint default '0',         -- AP supports qos
  short_slot smallint default '0',  -- AP currently supports short time slots (i.e. no 802.11b)
  apsd smallint default '0',        -- AP supports 802.11e power management
  rdo_meas smallint default '0',    -- dot11RadioMeasurementActivated is true
  dsss_ofdm smallint default '0',   -- deprecated
  del_ba smallint default '0',      -- delayed block ack supported
  imm_ba smallint default '0',      -- immediate block ack supported
  listen_int integer NOT NULL,      -- listen interval in microseconds
  cur_ap integer NOT NULL,          -- id of currently associated ap
  ssid VARCHAR(32),                 -- the ssid of this network (NULL for cloaked,
  sup_rates decimal(5,1)[],         -- list of supported rates
  ext_rates decimal(5,1)[],         -- list of extended rates
  vendors char(8)[],                -- list of (unique) vendor ouis found in info-elements
  CONSTRAINT ch_fid CHECK (fid > 0), 
  CONSTRAINT ch_client CHECK (client > 0),
  CONSTRAINT ch_ap CHECK (ap > 0),
  CONSTRAINT ch_listen_int CHECK (listen_int > 0),
  CONSTRAINT ch_ess CHECK (ess >=0 and ess <=1),
  CONSTRAINT ch_ibss CHECK (ibss >=0 and ibss <=1),
  CONSTRAINT ch_cf_pollable CHECK (cf_pollable >=0 and cf_pollable <=1),
  CONSTRAINT ch_cf_poll_req CHECK (cf_poll_req >=0 and cf_poll_req <=1),
  CONSTRAINT ch_privacy CHECK (privacy >=0 and privacy <=1),
  CONSTRAINT ch_short_pre CHECK (short_pre >=0 and short_pre <=1),
  CONSTRAINT ch_pbcc CHECK (pbcc >=0 and pbcc <=1),
  CONSTRAINT ch_ch_agility CHECK (ch_agility >=0 and ch_agility <=1),
  CONSTRAINT ch_spec_mgmt CHECK (spec_mgmt >=0 and spec_mgmt <=1),
  CONSTRAINT ch_qos CHECK (qos >=0 and qos <=1),
  CONSTRAINT ch_short_slot CHECK (short_slot >=0 and short_slot <=1),
  CONSTRAINT ch_apsd CHECK (apsd >=0 and apsd <=1),
  CONSTRAINT ch_rdo_meas CHECK (rdo_meas >=0 and rdo_meas <=1),
  CONSTRAINT ch_dsss_ofdm CHECK (dsss_ofdm >=0 and dsss_ofdm <=1),
  CONSTRAINT ch_del_ba CHECK (del_ba >=0 and del_ba <=1),
  CONSTRAINT ch_imm_ba CHECK (imm_ba >=0 and imm_ba <=1),
  CONSTRAINT ch_cur_ap CHECK (cur_ap > 0),
  FOREIGN KEY (fid) REFERENCES frame(id),
  FOREIGN KEY (client) REFERENCES sta(id),
  FOREIGN KEY (ap) REFERENCES sta(id),
  FOREIGN KEY (cur_ap) REFERENCES sta(id)
); 

-- probereq table
-- A probe request coming from a client, we track only ssid, supported rates
-- extended rates and lists of vendors sought. Probe requests include the
-- ids to the frame and session it was collected in, the client mac addr id
-- and the the ap id (which is normally broadcast)
DROP TABLE IF EXISTS probereq;
CREATE TABLE probereq(
  fid bigint NOT NULL,      -- fk to frame
  client integer NOT NULL,  -- fk to STA - this is the client
  ap integer,               -- fk to STA - this is the AP
  ssid VARCHAR(32),         -- the ssid of this network (NULL for cloaked,
  sup_rates decimal(5,1)[], -- list of supported rates
  ext_rates decimal(5,1)[], -- list of extended rates
  vendors char(8)[],        -- list of (unique) vendor ouis found in info-elements
  FOREIGN KEY (fid) REFERENCES frame(id),
  FOREIGN KEY (client) REFERENCES sta(id),
  FOREIGN KEY (ap) REFERENCES sta(id)
); 

-- proberesp table
-- Very similar to the beacon table. References, the sid it was seen in, frame 
-- it is in and the  id of the STA or BSSID and the ts it was captured. It exposes 
-- the beacon ts as hex, the beacon interval, and capabilities info as 16 {0|1} 
-- smallints. It will also expose (if present) the ssid, supporated rates and 
-- extended rates. In addition, it will expose the sta id of the client, the
-- ap is responding to
DROP TABLE IF EXISTS proberesp;
CREATE TABLE proberesp(
  fid bigint NOT NULL,              -- fk to frame
  client integer NOT NULL,          -- fk to STA - this is the requesting STA
  ap integer NOT NULL,              -- fk to STA - this is the bss
  beacon_ts bytea NOT NULL,         -- beacon ts (as hex due to lack of 8-byte unsigned in postgres
  beacon_int integer NOT NULL,      -- beacon interval in microseconds
  ess smallint default '0',         -- ess bit (comes from an AP) 
  ibss smallint default '0',        -- ibss bit (comes from an ibss)
  cf_pollable smallint default '0', -- set IAW Std Table 8-34/8-35  
  cf_poll_req smallint default '0', -- see above
  privacy smallint default '0',     -- indicates data is encrypted
  short_pre smallint default '0',   -- AP supports short preambles
  pbcc smallint default '0',        -- PKT binary convolutional code allowed
  ch_agility smallint default '0',  -- irrelevant field not used
  spec_mgmt smallint default '0',   -- 802.11h, if 1 implements DFS and TPC
  qos smallint default '0',         -- AP supports qos
  short_slot smallint default '0',  -- AP currently supports short time slots (i.e. no 802.11b)
  apsd smallint default '0',        -- AP supports 802.11e power management
  rdo_meas smallint default '0',    -- dot11RadioMeasurementActivated is true
  dsss_ofdm smallint default '0',   -- deprecated
  del_ba smallint default '0',      -- delayed block ack supported
  imm_ba smallint default '0',      -- immediate block ack supported
  ssid VARCHAR(32),                 -- the ssid of this network (NULL for cloaked)
  sup_rates decimal(5,1)[],         -- list of supported rates
  ext_rates decimal(5,1)[],         -- list of extended rates
  vendors char(8)[],                -- list of (unique) vendor ouis found in info-elements
  CONSTRAINT ch_fid CHECK (fid > 0), 
  CONSTRAINT ch_client CHECK (client > 0),
  CONSTRAINT ch_ap CHECK (ap > 0),
  CONSTRAINT ch_beacon_int CHECK (beacon_int > 0),
  CONSTRAINT ch_ess CHECK (ess >=0 and ess <=1),
  CONSTRAINT ch_ibss CHECK (ibss >=0 and ibss <=1),
  CONSTRAINT ch_cf_pollable CHECK (cf_pollable >=0 and cf_pollable <=1),
  CONSTRAINT ch_cf_poll_req CHECK (cf_poll_req >=0 and cf_poll_req <=1),
  CONSTRAINT ch_privacy CHECK (privacy >=0 and privacy <=1),
  CONSTRAINT ch_short_pre CHECK (short_pre >=0 and short_pre <=1),
  CONSTRAINT ch_pbcc CHECK (pbcc >=0 and pbcc <=1),
  CONSTRAINT ch_ch_agility CHECK (ch_agility >=0 and ch_agility <=1),
  CONSTRAINT ch_spec_mgmt CHECK (spec_mgmt >=0 and spec_mgmt <=1),
  CONSTRAINT ch_qos CHECK (qos >=0 and qos <=1),
  CONSTRAINT ch_short_slot CHECK (short_slot >=0 and short_slot <=1),
  CONSTRAINT ch_apsd CHECK (apsd >=0 and apsd <=1),
  CONSTRAINT ch_rdo_meas CHECK (rdo_meas >=0 and rdo_meas <=1),
  CONSTRAINT ch_dsss_ofdm CHECK (dsss_ofdm >=0 and dsss_ofdm <=1),
  CONSTRAINT ch_del_ba CHECK (del_ba >=0 and del_ba <=1),
  CONSTRAINT ch_imm_ba CHECK (imm_ba >=0 and imm_ba <=1),
  FOREIGN KEY (fid) REFERENCES frame(id),
  FOREIGN KEY (client) REFERENCES sta(id),
  FOREIGN KEY (ap) REFERENCES sta(id)
);

-- beacon table
-- The beacon table references, the sid it was seen in, frame it is in and the 
-- id of the STA or BSSID and the ts it was captured. It exposes the beacon ts 
-- as hex, the beacon interval, and capabilities info as 16 {0|1} smallints. 
-- It will also expose (if present) the ssid, supporated rates and extended rates.
-- 
-- TODO: include TIM field
DROP TABLE IF EXISTS beacon;
CREATE TABLE beacon(
  fid bigint NOT NULL,              -- fk to frame
  ap integer NOT NULL,              -- fk to STA - this is the bss
  beacon_ts bytea NOT NULL,         -- beacon ts (as hex due to lack of 8-byte unsigned in postgres
  beacon_int integer NOT NULL,      -- beacon interval in microseconds
  ess smallint default '0',         -- ess bit (comes from an AP) 
  ibss smallint default '0',        -- ibss bit (comes from an ibss)
  cf_pollable smallint default '0', -- set IAW Std Table 8-34/8-35  
  cf_poll_req smallint default '0', -- see above
  privacy smallint default '0',     -- indicates data is encrypted
  short_pre smallint default '0',   -- AP supports short preambles
  pbcc smallint default '0',        -- PKT binary convolutional code allowed
  ch_agility smallint default '0',  -- irrelevant field not used
  spec_mgmt smallint default '0',   -- 802.11h, if 1 implements DFS and TPC
  qos smallint default '0',         -- AP supports qos
  short_slot smallint default '0',  -- AP currently supports short time slots (i.e. no 802.11b)
  apsd smallint default '0',        -- AP supports 802.11e power management
  rdo_meas smallint default '0',    -- dot11RadioMeasurementActivated is true
  dsss_ofdm smallint default '0',   -- deprecated
  del_ba smallint default '0',      -- delayed block ack supported
  imm_ba smallint default '0',      -- immediate block ack supported
  ssid VARCHAR(32),                 -- the ssid of this network (NULL for cloaked)
  sup_rates decimal(5,1)[],         -- list of supported rates
  ext_rates decimal(5,1)[],         -- list of extended rates
  vendors char(8)[],                -- list of (unique) vendor ouis found in info-elements
  CONSTRAINT ch_fid CHECK (fid > 0), 
  CONSTRAINT ch_ap CHECK (ap > 0),
  CONSTRAINT ch_beacon_int CHECK (beacon_int > 0),
  CONSTRAINT ch_ess CHECK (ess >=0 and ess <=1),
  CONSTRAINT ch_ibss CHECK (ibss >=0 and ibss <=1),
  CONSTRAINT ch_cf_pollable CHECK (cf_pollable >=0 and cf_pollable <=1),
  CONSTRAINT ch_cf_poll_req CHECK (cf_poll_req >=0 and cf_poll_req <=1),
  CONSTRAINT ch_privacy CHECK (privacy >=0 and privacy <=1),
  CONSTRAINT ch_short_pre CHECK (short_pre >=0 and short_pre <=1),
  CONSTRAINT ch_pbcc CHECK (pbcc >=0 and pbcc <=1),
  CONSTRAINT ch_ch_agility CHECK (ch_agility >=0 and ch_agility <=1),
  CONSTRAINT ch_spec_mgmt CHECK (spec_mgmt >=0 and spec_mgmt <=1),
  CONSTRAINT ch_qos CHECK (qos >=0 and qos <=1),
  CONSTRAINT ch_short_slot CHECK (short_slot >=0 and short_slot <=1),
  CONSTRAINT ch_apsd CHECK (apsd >=0 and apsd <=1),
  CONSTRAINT ch_rdo_meas CHECK (rdo_meas >=0 and rdo_meas <=1),
  CONSTRAINT ch_dsss_ofdm CHECK (dsss_ofdm >=0 and dsss_ofdm <=1),
  CONSTRAINT ch_del_ba CHECK (del_ba >=0 and del_ba <=1),
  CONSTRAINT ch_imm_ba CHECK (imm_ba >=0 and imm_ba <=1),
  FOREIGN KEY (fid) REFERENCES frame(id),
  FOREIGN KEY (ap) REFERENCES sta(id)
);

-- dissaoc table
-- disassociation table: a client notifies ap of disassociation or an ap notifies
-- a client(s) to dissocate. fromap = 0 if the client has sent the dissociation
-- or 1 if the ap has sent the dissociation
DROP TABLE IF EXISTS disassoc;
CREATE TABLE disassoc(
  fid bigint NOT NULL,      -- fk to frame
  client integer,           -- fk to STA - this is the requesting STA
  ap integer NOT NULL,      -- fk to STA - this is the bss
  fromap smallint NOT NULL, -- {0:client initiated|1:ap initiated}
  reason integer NOT NULL,  -- reason code for disassociation
  CONSTRAINT ch_fid CHECK (fid > 0),
  CONSTRAINT ch_client CHECK (client >= 0),
  CONSTRAINT ch_ap CHECK (ap >= 0),
  CONSTRAINT ch_fromap CHECK (fromap >= 0 and fromap <=1),
  CONSTRAINT ch_reason CHECK (reason >= 0),
  FOREIGN KEY (fid) REFERENCES frame(id),
  FOREIGN KEY (client) REFERENCES sta(id),
  FOREIGN KEY (ap) REFERENCES sta(id)
);

-- auth table
-- authentication - client request authentication to an ap
DROP TABLE IF EXISTS auth;
CREATE TABLE auth(
  fid bigint NOT NULL,         -- fk to frame
  client integer NOT NULL,     -- fk to STA, the client
  ap integer NOT NULL,         -- fk to STA, the ap
  fromap smallint NOT NULL,    -- {0:client initiated|1:ap initiated}
  auth_alg integer NOT NULL,   -- authentication algorithm number
  auth_trans integer NOT NULL, -- authentication transaction seq. number
  status integer NOT NULL,     -- status code
  CONSTRAINT ch_fid CHECK (fid > 0),
  CONSTRAINT ch_client CHECK (client >= 0),
  CONSTRAINT ch_ap CHECK (ap >= 0),
  CONSTRAINT ch_fromap CHECK (fromap >= 0 and fromap <=1),
  CONSTRAINT ch_auth_alg CHECK (auth_alg >= 0),
  CONSTRAINT ch_auth_trans CHECK (auth_trans >= 0),
  CONSTRAINT ch_status CHECK (status >= 0),
  FOREIGN KEY (fid) REFERENCES frame(id),
  FOREIGN KEY (client) REFERENCES sta(id),
  FOREIGN KEY (ap) REFERENCES sta(id)
);

-- deauth table
-- deauthentication table: a client notifies ap of deauthentication or an ap notifies
-- a client(s) to deauthenticate. fromap = 0 if the client has sent the deauthentication
-- or 1 if the ap has sent it
DROP TABLE IF EXISTS deauth;
CREATE TABLE deauth(
  fid bigint NOT NULL,      -- fk to frame
  client integer,           -- fk to STA - this is the requesting STA
  ap integer NOT NULL,      -- fk to STA - this is the bss
  fromap smallint NOT NULL, -- {0:client initiated|1:ap initiated}
  reason integer NOT NULL,  -- reason code for deauthentication
  CONSTRAINT ch_fid CHECK (fid > 0),
  CONSTRAINT ch_client CHECK (client >= 0),
  CONSTRAINT ch_ap CHECK (ap >= 0),
  CONSTRAINT ch_fromap CHECK (fromap >= 0 and fromap <=1),
  CONSTRAINT ch_reason CHECK (reason >= 0),
  FOREIGN KEY (fid) REFERENCES frame(id),
  FOREIGN KEY (client) REFERENCES sta(id),
  FOREIGN KEY (ap) REFERENCES sta(id)
);

DROP TABLE IF EXISTS action;
CREATE TABLE action(
  fid bigint NOT NULL,        -- fk to frame
  rx integer,                 -- fk to receiving STA if present
  tx integer,                 -- fk to transmitting STA if present
  ap integer NOT NULL,        -- fk to STA - this is the bss
  fromap smallint NOT NULL,   -- {0:client initiated|1:ap initiated|2:intrasta}
  noack smallint NOT NULL,    -- {0:False|1:True}
  category smallint NOT NULL, -- category code
  action smallint NOT NULL,   -- action code
  has_el smallint NOT NULL,   -- {0:no action elements present|1:action elements present}
  CONSTRAINT ch_fid CHECK (fid > 0),
  CONSTRAINT ch_rx CHECK (rx >= 0),
  CONSTRAINT ch_tx CHECK (tx >= 0),
  CONSTRAINT ch_ap CHECK (ap >= 0),
  CONSTRAINT ch_fromap CHECK (fromap >= 0 and fromap <=2),
  CONSTRAINT ch_noack CHECK (noack >= 0 and noack <=1),
  CONSTRAINT ch_category CHECK (category >= 0),
  CONSTRAINT ch_action CHECK (action >= 0),
  CONSTRAINT ch_has_el CHECK (has_el >= 0 and has_el <= 1),
  FOREIGN KEY (fid) REFERENCES frame(id),
  FOREIGN KEY (rx) REFERENCES sta(id),
  FOREIGN KEY (tx) REFERENCES sta(id),
  FOREIGN KEY (ap) REFERENCES sta(id)
);

DROP TYPE IF EXISTS STA_TYPE;
CREATE TYPE STA_TYPE AS ENUM ('unknown','ap','sta','wired');

-- TODO: add AID
DROP TABLE IF EXISTS sta_info;
CREATE TABLE sta_info(
   staid integer NOT NULL,            -- fk to sta
   fid bigint NOT NULL,               -- fk to frame these details were seen
   type STA_TYPE default 'unknown',   -- type of sta 
   ip inet,                           -- ip if known
   os_name VARCHAR(50),               -- name of os i.e. Windows
   os_flavor VARCHAR(50),             -- name of os flavor i.e. XP
   os_vers VARCHAR(50),               -- os vers i.e XP
   os_sp VARCHAR(50),                 -- os service pack or revision
   os_lang VARCHAR(50),               -- human language of os
   hw_name VARCHAR(50),               -- hw name i.e. Buffalo
   hw_flavor VARCHAR(50),             -- hw flavor i.e. N750
   hw_vers VARCHAR(50),               -- hw version
   hw_sp VARCHAR(50),                 -- hw service pack or revision
   hw_lang VARCHAR(50),               -- language
   fw_name VARCHAR(50),               -- fw/card name i.e. intel
   fw_flavor VARCHAR(50),             -- fw/card flavor i.e. centrino 1000
   fw_vers VARCHAR(50),               -- fw/card version
   fw_rev VARCHAR(50),                -- fw/card revision
   fw_driver VARCHAR(50),             -- driver of the card 
   fw_chipset VARCHAR(50),            -- chipset of the card
   CONSTRAINT ch_sid CHECK (sid > 0),
   CONSTRAINT ch_staid CHECK (staid > 0),
   FOREIGN KEY(sid) REFERENCES sensor(session_id),
   FOREIGN KEY(staid) REFERENCES sta(id)
);

#### STORED PROCEDURES

-- store procedure for deleting all content from all tables
DROP FUNCTIOON IF EXISTS delete_all();
CREATE FUNCTION delete_all()
    RETURNS void as $$
    BEGIN
      DELETE FROM ampdu;
      DELETE FROM ccmpcrypt;
      DELETE FROM qosctrl;
      DELETE FROM tkipcrypt;
      DELETE FROM traffic;
      DELETE FROM wepcrypt;
      DELETE FROM signal;
      DELETE FROM source;
      DELETE FROM frame_path;
      DELETE FROM assocreq;
      DELETE FROM reassocreq;
      DELETE FROM assocresp;
      DELETE FROM probereq;
      DELETE FROM proberesp;
      DELETE FROM disassoc;
      DELETE FROM deauth;
      DELETE FROM beacon;
      DELETE FROM auth;
      DELETE FROM action;
      DELETE FROM sta_activity;
      DELETE FROM sta;
      ALTER SEQUENCE sta_id_seq restart;
      DELETE FROM frame;
      ALTER SEQUENCE frame_id_seq RESTART;
      DELETE FROM platform;
      DELETE FROM using_gpsd;
      DELETE FROM geo;
      DELETE FROM gpsd;
      ALTER SEQUENCE gpsd_id_seq RESTART;
      DELETE FROM using_radio;
      DELETE FROM radio_epoch;
      DELETE FROM radio_event;
      DELETE FROM radio_period;
      DELETE FROM antenna;
      DELETE FROM radio;
      DELETE FROM sensor;
      ALTER SEQUENCE sensor_session_id_seq RESTART;
    END;
    $$ LANGUAGE plpgsql;

-- store procedure to fix any NULL-ended periods which can occur after
-- error or a forced kill Nidus (or a sensor)
DROP FUNCTIOON IF EXISTS fix_nullperiod();
CREATE OR REPLACE FUNCTION fix_nullperiod()
    RETURNS void as $$
    BEGIN
      SET TIME ZONE 'UTC';
      UPDATE sensor SET period = tstzrange(LOWER(period),now()) WHERE UPPER(period) IS NULL;
      UPDATE antenna SET period = tstzrange(LOWER(period),now()) WHERE UPPER(period) IS NULL;
      UPDATE radio_epoch SET period = tstzrange(LOWER(period),now()) WHERE UPPER(period) IS NULL;
      UPDATE radio_period SET period = tstzrange(LOWER(period),now()) WHERE UPPER(period) IS NULL;
      UPDATE using_radio SET period = tstzrange(LOWER(period),now()) WHERE UPPER(period) IS NULL;
      UPDATE using_gpsd SET period = tstzrange(LOWER(period),now()) WHERE UPPER(period) IS NULL;
    END;
    $$ LANGUAGE plpgsql;

-- delete data from all tables
-- TODO: look into truncate
DELETE FROM ampdu;
DELETE FROM ccmpcrypt;
DELETE FROM qosctrl;
DELETE FROM tkipcrypt;
DELETE FROM traffic;
DELETE FROM wepcrypt;
DELETE FROM signal;
DELETE FROM source;
DELETE FROM frame_path;
DELETE FROM assocreq;
DELETE FROM reassocreq;
DELETE FROM assocresp;
DELETE FROM probereq;
DELETE FROM proberesp;
DELETE FROM disassoc;
DELETE FROM deauth;
DELETE FROM beacon;
DELETE FROM auth;
DELETE FROM action;
DELETE FROM sta_activity;
DELETE FROM sta;
ALTER SEQUENCE sta_id_seq restart;
DELETE FROM frame;
ALTER SEQUENCE frame_id_seq RESTART;
DELETE FROM platform;
DELETE FROM using_gpsd;
DELETE FROM geo;
DELETE FROM gpsd;
ALTER SEQUENCE gpsd_id_seq RESTART;
DELETE FROM using_radio;
DELETE FROM radio_epoch;
DELETE FROM radio_event;
DELETE FROM radio_period;
DELETE FROM antenna;
DELETE FROM radio;
DELETE FROM sensor;
ALTER SEQUENCE sensor_session_id_seq RESTART;

DROP TABLE ampdu;
DROP TABLE ccmpcrypt;
DROP TABLE qosctrl;
DROP TABLE tkipcrypt;
DROP TABLE traffic;
DROP TABLE wepcrypt;
DROP TABLE signal;
DROP TABLE source;
DROP TABLE frame_path;
DROP TABLE assocreq;
DROP TABLE reassocreq;
DROP TABLE assocresp;
DROP TABLE probereq;
DROP TABLE proberesp;
DROP TABLE disassoc;
DROP TABLE deauth;
DROP TABLE beacon;
DROP TABLE auth;
DROP TABLE action;
DROP TABLE sta_activity;
DROP TABLE sta;
DROP TABLE frame;
DROP TABLE platform;
DROP TABLE using_gpsd;
DROP TABLE geo;
DROP TABLE gpsd;
DROP TABLE using_radio;
DROP TABLE radio_epoch;
DROP TABLE radio_event;
DROP TABLE radio_period;
DROP TABLE antenna;
DROP TABLE radio;
DROP TABLE sensor;

-- QUERIES

-- frame joined with traffic
select frame.ts,frame.bytes,frame.bRTAP,frame.bMPDU,frame.data,traffic.type,
       traffic.subtype,traffic.td,traffic.fd,traffic.mf,traffic.rt,traffic.pm,
       traffic.md,traffic.pf,traffic.so,traffic.dur_type,traffic.dur_val,
       traffic.addr1,traffic.addr2,traffic.addr3,traffic.fragnum,traffic.seqnum,
       traffic.addr4,traffic.crypt from frame,traffic where frame.id = traffic.fid;

-- beacons with ap.bssid
select beacon.ts,sta.mac,beacon.ssid,beacon.sup_rates,beacon.ext_rates,beacon.vendors 
from beacon,sta where sta.id = beacon.ap;

select sta.mac,probereq.ts,probereq.ssid,probereq.sup_rates,probereq.ext_rates,
probereq.vendors from probereq,sta where sta.id=probereq.client;

-- data sizes 
-- size of relations
SELECT nspname || '.' || relname AS "relation",
    pg_size_pretty(pg_relation_size(C.oid)) AS "size"
  FROM pg_class C
  LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace)
  WHERE nspname NOT IN ('pg_catalog', 'information_schema')
  ORDER BY pg_relation_size(C.oid) DESC;
  
-- total diskspace of table
SELECT nspname || '.' || relname AS "relation",
    pg_size_pretty(pg_total_relation_size(C.oid)) AS "total_size"
  FROM pg_class C
  LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace)
  WHERE nspname NOT IN ('pg_catalog', 'information_schema')
    AND C.relkind <> 'i'
    AND nspname !~ '^pg_toast'
  ORDER BY pg_total_relation_size(C.oid) DESC;
