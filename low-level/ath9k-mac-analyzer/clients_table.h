#ifndef  CLIENT_TABLE_H_
#define  CLIENT_TABLE_H_
#define CLIENT_TABLE_ENTRIES 32
#include <zlib.h>
#define UPDATE_CLIENT_FILENAME "/tmp/bismark-uploads/mac-analyzer/%s-%" PRIu64 "-cl-%d.gz"
#define PENDING_UPDATE_CLIENT_FILENAME "/tmp/mac-analyzer/current-client-update.gz"

typedef struct {

 u_int8_t mac_address[6];
	int rx_bitrate ;
	int tx_bitrate ;

	u_int32_t tx_failed ;
	u_int32_t tx_retries;
	u_int32_t tx_pkts ;
	u_int32_t rx_pkts ;

	u_int32_t prev_tx_retries;
	u_int32_t prev_tx_pkts ;
	u_int32_t prev_rx_pkts ;
  u_int32_t prev_tx_failed; 
	
	u_int8_t dev; 
}client_entry_t ; 

typedef struct {
  /* A list of MAC mappings. A mapping ID is simply
   * that mapping's index offset into this array. */
  client_entry_t entries[CLIENT_TABLE_ENTRIES];
  /* The index of the first (i.e., oldest) mapping in the list */
  int first;
  /* The index of the last (i.e., newest) mapping in the list */
  int last;
  int length;
  /* The index of the last mapping sent to the server. */
  int added_since_last_update;
} client_address_table_t;


extern client_address_table_t client_address_table;
void address_client_table_init(client_address_table_t* table);
int address_client_table_lookup(client_address_table_t*  table, u_int32_t c_tx_failed,	
				u_int32_t c_tx_retries , u_int32_t c_tx_pkts,	
				u_int32_t c_rx_pkts, const u_int8_t * m_add ,int dev,				
				int tx_bitrate, int rx_bitrate);

int address_client_table_write_update(gzFile handle, client_address_table_t* table);

#endif 
