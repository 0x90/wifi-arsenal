/**
Fake Access Points using Atheros wireless cards in Linux
Written by Evan Jones <ejones@uwaterloo.ca>

Released under a BSD Licence

How to Use:
1. Customize the array of access points below, if you want.
2. Bring up your Atheros interface on the desired channel.
3. Enable the raw device (echo "1" > /proc/sys/dev/ath0/rawdev)
4. Configure the raw device to use radiotap headers (echo "2" > /proc/sys/dev/ath0/rawdev_type)
5. Bring up the raw device (ifconfig ath0raw up)
6. Start this program (./fakeaps ath0raw [channel number for ath0])

How to Compile:
1. Get the "ieee80211.h" and "ieee80211_radiotap.h" headers from the MadWiFi
distribution:

http://cvs.sourceforge.net/viewcvs.py/madwifi/madwifi/net80211/

2. gcc --std=gnu99 -Wall -o fakeaps fakeaps.c


Thanks go out to John Bicket for his help in getting the raw device to work
correctly, and getting it included in the MadWiFi driver.

http://pdos.csail.mit.edu/~jbicket/

Thanks also to Sebastian Weitzel for his athrawsend program:

http://www.togg.de/stuff/athrawsend.c
*/

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <unistd.h>

#include <netinet/in.h>

#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <sys/time.h>
#include <time.h>

#define __packed __attribute__((__packed__))
#include  "ieee80211.h"
#include  "ieee80211_radiotap.h"

int openSocket( const char device[IFNAMSIZ] )
{
	struct ifreq ifr;
	struct sockaddr_ll ll;
	const int protocol = ETH_P_ALL;
	int sock = -1;
	
	assert( sizeof( ifr.ifr_name ) == IFNAMSIZ );

	sock = socket( PF_PACKET, SOCK_RAW, htons(protocol) );
	if ( sock < 0 )
	{
		perror( "socket failed (do you have root priviledges?)" );
		return -1;
	}
	
	memset( &ifr, 0, sizeof( ifr ) );
	strncpy( ifr.ifr_name, device, sizeof(ifr.ifr_name) );
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
	{
		perror("ioctl[SIOCGIFINDEX]");
		close(sock);
		return -1;
	}

	memset( &ll, 0, sizeof(ll) );
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(protocol);
	if ( bind( sock, (struct sockaddr *) &ll, sizeof(ll) ) < 0 ) {
		perror( "bind[AF_PACKET]" );
		close( sock );
		return -1;
	}
		
	// Enable promiscuous mode
	//~ struct packet_mreq mr;
	//~ memset( &mr, 0, sizeof( mr ) );
	
	//~ mr.mr_ifindex = ll.sll_ifindex;
	//~ mr.mr_type    = PACKET_MR_PROMISC;

	//~ if( setsockopt( sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof( mr ) ) < 0 )
	//~ {
		//~ perror( "setsockopt[PACKET_MR_PROMISC]" );
		//~ close( sock );
		//~ return -1;
	//~ }
	
	return sock;
}

void packet_hexdump(const uint8_t* data, size_t size)
{
	size_t i;

	printf("%02x:", data[0]);
	for(i=1; i<size; i++){
		printf("%02x:", data[i]);
		if ( (i & 0xf)  == 0xf )
		{
			// Add a carrage return every 16 bytes
			printf( "\n" );
		}
	}
	printf("\n\n");
}

typedef struct {
  uint32_t msgcode;
  uint32_t msglen;
#define WLAN_DEVNAMELEN_MAX 16
  uint8_t devname[WLAN_DEVNAMELEN_MAX];
  uint32_t hosttime;
  uint32_t mactime;
  uint32_t channel;
  uint32_t rssi;
  uint32_t sq;
  uint32_t signal;
  uint32_t noise;
  uint32_t rate;
  uint32_t istx;
  uint32_t frmlen;
} wlan_ng_prism2_header;

/** Get the current 802.11 64-bit timestamp from the system time. */
uint64_t getCurrentTimestamp()
{
	struct timeval t;
	
	int code = gettimeofday( &t, NULL );
	assert( code == 0 );
	if ( code != 0 )
	{
		perror( "error calling gettimeofday" );
		assert( 0 );
	}
	
	// Convert seconds to microseconds
	// For the purposes of 802.11 timestamps, we don't care about what happens
	// when this value wraps. As long as the value wraps consistently, we are
	// happy
	uint64_t timestamp = t.tv_sec * 1000000LL;
	timestamp += t.tv_usec;
	
	return timestamp;
}

/** Add increment microseconds to time, computing the overflow correctly. */
void incrementTimeval( struct timeval* time, suseconds_t increment )
{
	assert( time != NULL );
	assert( 0 <= time->tv_usec && time->tv_usec < 1000000 );
	
	if ( increment >= 1000000 )
	{
		// Add the seconds to the seconds field, and keep the remainder
		time->tv_sec += (increment/1000000);
		increment = increment % 1000000;
	}
	
	assert( increment < 1000000 );
	
	time->tv_usec += increment;
	if ( time->tv_usec >= 1000000 )
	{
		time->tv_sec += 1;
		time->tv_usec -= 1000000;
		
		assert( 0 <= time->tv_usec && time->tv_usec < 1000000 );
	}
}

/** Computes "second = first - second" including the underflow "borrow." */ 
void differenceTimeval( const struct timeval* first, struct timeval* second )
{
	assert( first != NULL );
	assert( second != NULL );
	
	second->tv_sec = first->tv_sec - second->tv_sec;
	second->tv_usec = first->tv_usec - second->tv_usec;
	
	// If underflow occured, borrow a second from the higher field
	if ( second->tv_usec < 0 )
	{
		second->tv_sec -= 1;
		second->tv_usec += 1000000;
		
		// If this assertion fails, the initial timevals had invalid values
		assert( 0 <= second->tv_usec && second->tv_usec < 1000000 );
	}
}

/** Returns a negative integer if first < second, zero if first == second, and a positive integer if first > second. */
int compareTimeval( const struct timeval* first, const struct timeval* second )
{
	int difference = first->tv_sec - second->tv_sec;
	if ( difference == 0 )
	{
		// If the seconds fields are equal, compare based on the microseconds
		difference = first->tv_usec - second->tv_usec;
	}
	
	return difference;
}

struct AccessPointDescriptor
{
	uint8_t macAddress[IEEE80211_ADDR_LEN];
	const uint8_t* ssid;
	size_t ssidLength;
	const uint8_t* dataRates;
	size_t dataRatesLength;
};

static const uint8_t IEEE80211_BROADCAST_ADDR[IEEE80211_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t IEEE80211B_DEFAULT_RATES[] = { 
	IEEE80211_RATE_BASIC | 2,
	IEEE80211_RATE_BASIC | 4,
	11,
	22,
};
//~ static const size_t IEEE80211B_DEFAULT_RATES_LENGTH = sizeof(IEEE80211B_DEFAULT_RATES);
#define IEEE80211B_DEFAULT_RATES_LENGTH sizeof(IEEE80211B_DEFAULT_RATES)

struct ieee80211_beacon {
	u_int64_t beacon_timestamp;
	u_int16_t beacon_interval;
	u_int16_t beacon_capabilities;
} __attribute__((__packed__));

struct ieee80211_info_element {
	u_int8_t info_elemid;
	u_int8_t info_length;
	u_int8_t* info[0];
} __attribute__((__packed__));

/** Converts a 16-bit integer from host byte order to little-endian byte order. Not implement yet. */
inline uint16_t htole16( uint16_t src ) { return src; }

#define BEACON_INTERVAL 102400

/** Returns a beacon packet for the specified descriptor. The packet will be allocated using malloc. */
uint8_t* constructBeaconPacket( uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* beaconLength )
{
	// Validate parameters
	assert( apDescription != NULL );
	assert( beaconLength != NULL );
	
	assert( 0 <= apDescription->ssidLength && apDescription->ssidLength <= 32 );
	assert( 1 <= apDescription->dataRatesLength && apDescription->dataRatesLength <= 8 );
	
	uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 ); 
	
	// Packet size: radiotap header + 1 byte for rate + ieee80211_frame header + beacon info + tags
	*beaconLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) +
		sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_beacon) +
	// SSID, rates, channel
		sizeof(struct ieee80211_info_element)*3 + apDescription->ssidLength +
		apDescription->dataRatesLength + sizeof(channel);
	
	uint8_t* packet = (uint8_t*) malloc( *beaconLength );
	assert( packet != NULL );
	if ( packet == NULL )
	{
		return NULL;
	}
	
	size_t remainingBytes = *beaconLength;
	
	// Add the radiotap header
	assert( remainingBytes >= sizeof(struct ieee80211_radiotap_header) );
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;
	uint8_t* packetIterator = packet + sizeof(*radiotap);
	remainingBytes -= sizeof(*radiotap);
	
	radiotap->it_version = 0;
	radiotap->it_len = sizeof(*radiotap) + sizeof(dataRate);
	radiotap->it_present = (1 << IEEE80211_RADIOTAP_RATE);
	
	// Add the data rate for the radiotap header
	assert( remainingBytes >= sizeof(dataRate) );
	*packetIterator = (dataRate & IEEE80211_RATE_VAL);
	packetIterator ++;
	remainingBytes -= sizeof(dataRate);
	
	// Build the 802.11 header
	assert( remainingBytes >= sizeof(struct ieee80211_frame) );
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) packetIterator;
	packetIterator += sizeof(*dot80211);
	remainingBytes -= sizeof(*dot80211);
	
	// Beacon packet flags
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	dot80211->i_dur[0] = 0x0;
	dot80211->i_dur[1] = 0x0;
	// Destination = broadcast (no retries)
	memcpy( dot80211->i_addr1, IEEE80211_BROADCAST_ADDR, IEEE80211_ADDR_LEN );
	// Source = our own mac address
	memcpy( dot80211->i_addr2, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// BSS = our mac address
	memcpy( dot80211->i_addr3, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// Sequence control: Automatically set by the driver
	
	// Add the beacon frame
	assert( remainingBytes >= sizeof(struct ieee80211_beacon) );
	struct ieee80211_beacon* beacon = (struct ieee80211_beacon*) packetIterator;
	packetIterator += sizeof(*beacon);
	remainingBytes -= sizeof(*beacon);
	
	beacon->beacon_timestamp = 0;
	// interval = 100 "time units" = 102.4 ms
	// Each time unit is equal to 1024 us
	beacon->beacon_interval = htole16( BEACON_INTERVAL/1024 );
	// capabilities = sent by ESS
	beacon->beacon_capabilities = htole16( 0x0001 );
	
	// Add the SSID
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + apDescription->ssidLength );
	struct ieee80211_info_element* info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	remainingBytes -= sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	
	info->info_elemid = IEEE80211_ELEMID_SSID;
	info->info_length = apDescription->ssidLength;
	memcpy( info->info, apDescription->ssid, apDescription->ssidLength );
	
	// Add the data rates
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength;
	remainingBytes -= sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength;
	
	info->info_elemid = IEEE80211_ELEMID_RATES;
	info->info_length = apDescription->dataRatesLength;
	memcpy( info->info, apDescription->dataRates, apDescription->dataRatesLength );
	
	// Add the channel
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(channel) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(channel);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(channel);
	
	info->info_elemid = IEEE80211_ELEMID_DSPARMS;
	info->info_length = sizeof(channel);
	memcpy( info->info, &channel, sizeof(channel) );
	
	assert( remainingBytes == 0 );
	return packet;
}

void transmitProbeResponse( int rawSocket, uint8_t* beaconPacket, size_t beaconLength, const uint8_t* destinationMAC )
{
	// Probe responses are identical to beacon packets, except that
	// they are directed and not broadcast, and they are
	// set to be the probe response type
	
	// Find the 802.11 frame
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) beaconPacket;
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) (beaconPacket + radiotap->it_len);
	
	dot80211->i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP;
	memcpy( dot80211->i_addr1, destinationMAC, IEEE80211_ADDR_LEN );
		
	// Send the packet
	ssize_t bytes = write( rawSocket, beaconPacket, beaconLength );
	assert( bytes == (ssize_t) beaconLength );
	
	// Set the values back to what they should be for broadcast packets
	dot80211->i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	memcpy( dot80211->i_addr1, IEEE80211_BROADCAST_ADDR, IEEE80211_ADDR_LEN );
}

// ADD MORE ACCESS POINTS HERE, IF YOU WANT
static struct AccessPointDescriptor ap0 = {
	{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc },
	(const uint8_t*) "ap0", 3,
	IEEE80211B_DEFAULT_RATES, IEEE80211B_DEFAULT_RATES_LENGTH,
};

static struct AccessPointDescriptor ap1 = {
	{ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54 },
	(const uint8_t*) "ap1", 3,
	IEEE80211B_DEFAULT_RATES, IEEE80211B_DEFAULT_RATES_LENGTH,
};

// Clients will only rarely detect this access point
// I think it takes too long to get to this probe response
static struct AccessPointDescriptor ap2 = {
	{ 0xde, 0xad, 0xbe, 0xef, 0xff, 0xff },
	(const uint8_t*) "ap2", 3,
	IEEE80211B_DEFAULT_RATES, IEEE80211B_DEFAULT_RATES_LENGTH,
};

static struct AccessPointDescriptor ap3 = {
	{ 0xca, 0xfe, 0x00, 0xba, 0xbe, 0x00 },
	(const uint8_t*) "ap3", 3,
	IEEE80211B_DEFAULT_RATES, IEEE80211B_DEFAULT_RATES_LENGTH,
};

static const struct AccessPointDescriptor* accessPoints[] = {
	&ap0, &ap1, &ap2, &ap3,
};
static const size_t numAccessPoints = sizeof(accessPoints) / sizeof(*accessPoints);

/** These offsets start from the beginning of the 802.11 frame. */
static const size_t PROBE_SSID_OFFSET = sizeof( struct ieee80211_frame );
static const size_t BEACON_TIMESTAMP_OFFSET = sizeof( struct ieee80211_frame );

void help()
{
	printf( "fakeaps [atheros raw device] [channel it is tuned to]\n" );
}

int main(int argc, char *argv[])
{
	if ( argc != 3 )
	{
		help();
		return 1;
	}
	
	long int channel = strtol( argv[2], NULL, 10 );
	if ( channel <= 0 || 255 <= channel )
	{
		printf( "The channel must be between 1 and 255.\n" );
		help();
		return 1;
	}
	
	// The 802.11b base broadcast rate
	const uint8_t dataRate = 0x4;
	const char* device = argv[1];
		
	// Construct the beacon packets
	size_t* beaconLengths = (size_t*) malloc( sizeof(size_t) * numAccessPoints );
	assert( beaconLengths != NULL );
	uint8_t** beaconPackets = (uint8_t**) malloc( sizeof(uint8_t*) * numAccessPoints );
	assert( beaconLengths != NULL );
	
	for ( size_t i = 0; i < numAccessPoints; ++ i )
	{
		beaconPackets[i] = constructBeaconPacket( dataRate, channel, accessPoints[i], &beaconLengths[i] );
		assert( beaconPackets[i] != NULL );
		assert( beaconLengths[i] > 0 );
	}

	// Open the raw device
	int rawSocket = openSocket( device );
	if ( rawSocket < 0 )
	{
		fprintf( stderr, "error opening socket\n" );
		return 1;
	}
	
	// Configure the initial timeout
	struct timeval now;
	int code = gettimeofday( &now, NULL );
	assert( code == 0 );
	
	struct timeval beaconTime = now;
	incrementTimeval( &beaconTime, BEACON_INTERVAL );
	
	// This is used to change the sequence of the probe response messages
	// In order to help clients find more of our fake access points
	size_t lastProbeStartIndex = 0;
	
	while ( 1 )
	{
		// We need to wait until one of two conditions:
		// 1. The "sockin" socket has data for us
		// 2. The beacon interval (102400 microseconds) has expired
		fd_set readfds;
		FD_ZERO( &readfds );
		FD_SET( rawSocket, &readfds );
		
		struct timeval timeout = now;
		differenceTimeval( &beaconTime, &timeout );
		int numFds = select( rawSocket+1, &readfds, NULL, NULL, &timeout );
		assert( numFds >= 0 );
		if ( numFds < 0 )
		{
			perror( "select failed" );
			return 1;
		}
		
		if ( numFds == 1 )
		{
			// We have a packet waiting: Read it
			uint8_t packetBuffer[4096];
			ssize_t bytes = read( rawSocket, packetBuffer, sizeof(packetBuffer) );
			if ( bytes < 0 )
			{
				perror( "read failed" );
				return 1;
			}
			
			// Move past the radiotap header
			assert( bytes >= (ssize_t) sizeof( struct ieee80211_radiotap_header ) );
			struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packetBuffer;
			assert( radiotap->it_version == 0 );
			assert( bytes >= radiotap->it_len );
			uint8_t* packetIterator = packetBuffer + radiotap->it_len;
			size_t remainingBytes = bytes - radiotap->it_len;
			
			// Get the 802.11 frame:
			// NOTE: This frame structure is larger than some packet types, so only read the initial bytes
			struct ieee80211_frame* frame = (struct ieee80211_frame*)( packetIterator );
			
			// Check to see if this is a PROBE_REQUEST
			assert( (frame->i_fc[0] & IEEE80211_FC0_VERSION_MASK) == IEEE80211_FC0_VERSION_0 );
			
			if ( (frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT &&
				(frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_PROBE_REQ )
			{
				//~ packet_hexdump( (const uint8_t*) frame, remainingBytes );
				
				// Locate the SSID
				assert( remainingBytes >= PROBE_SSID_OFFSET );
				packetIterator += PROBE_SSID_OFFSET;
				remainingBytes -= PROBE_SSID_OFFSET;
				struct ieee80211_info_element* info = (struct ieee80211_info_element*) packetIterator;
				assert( remainingBytes >= sizeof(*info) );
				packetIterator += sizeof(*info);
				remainingBytes -= sizeof(*info);
				assert( remainingBytes >= info->info_length );
				
				// See if it is a broadcast ssid (zero length SSID)
				if ( info->info_length == 0 )
				{
					//~ printf( "broadcast probe request!\n");
					
					// Start with the next index for the next broadcast probe
					size_t index = lastProbeStartIndex;
					lastProbeStartIndex += 1;
					if ( lastProbeStartIndex >= numAccessPoints )
					{
						lastProbeStartIndex = 0;
					}
					
					// Transmit responses for all access points
					for ( size_t i = 0; i < numAccessPoints; ++ i )
					{
						if ( index >= numAccessPoints )
						{
							index = 0;
						}
						transmitProbeResponse( rawSocket, beaconPackets[index], beaconLengths[index], frame->i_addr2 );
						index += 1;
					}
				}
				else
				{
					// Check if the SSID matches any of ours
					for ( size_t i = 0; i < numAccessPoints; ++ i )
					{
						if ( info->info_length == accessPoints[i]->ssidLength && memcmp( info->info, accessPoints[i]->ssid, info->info_length ) == 0 )
						{
							// It does!
							//~ printf( "probe for SSID '%.*s'\n", info->info_length, (char*) info->info );
							transmitProbeResponse( rawSocket, beaconPackets[i], beaconLengths[i], frame->i_addr2 );
							break;
						}
					}
				}
			}
		}
		else
		{
			// We should only have 1 or 0 fds ready
			assert( numFds == 0 );
		}
		
		// Get the current time to calculate how much longer we need to wait
		// or if we need to send a beacon now
		int code = gettimeofday( &now, NULL );
		assert( code == 0 );
		
		if ( compareTimeval( &beaconTime, &now ) <= 0 )
		{
			//~ printf( "beacon\n" );
			// The timeout has expired. Send out the beacons
			// TODO: Update the timestamp in the beacon packets
			for ( size_t i = 0; i < numAccessPoints; ++ i )
			{
				ssize_t bytes = write( rawSocket, beaconPackets[i], beaconLengths[i] );
				assert( bytes == (ssize_t) beaconLengths[i] );
				if ( bytes < (ssize_t) beaconLengths[i] )
				{
					perror( "error sending packet" );
					return 1;
				}
			}
			
			// Increment the next beacon time until it is in the future
			do {
				incrementTimeval( &beaconTime, BEACON_INTERVAL );
			} while( compareTimeval( &beaconTime, &now ) <= 0 );
		}
	}
	
	close( rawSocket );
	free( beaconPackets );
	free( beaconLengths );
}
