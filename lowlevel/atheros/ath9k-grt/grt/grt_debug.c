#include "debug.h"

/**
 * grt_debug_print_skb() - print a socket buffer
 * @param label : The label to be printed before the skb data
 * @param skb   : The socket buffer.
 */
void grt_debug_print_skb(char * label, struct sk_buff * skb)
{
  int i;
  GRT_PRINT_DEBUG("%s\n", label);
  for(i = 0; i < skb->len; i++){
    GRT_PRINT_DEBUG("%02x ", skb->data[i] & 0x0FF);
    if(((i + 1) % 16) == 0){
      GRT_PRINT_DEBUG("\n");
    }
  }
  GRT_PRINT_DEBUG("\n");
}

/**
 * grt_info_print_bf() - print a grt_buf as an info message
 * @param label : The label to be printed before the skb data
 * @param bf    : The buf to be printed
 */
void grt_info_print_bf(char * label, struct grt_buf *bf)
{
  int i;
  GRT_PRINT_INFO("%s\n", label);
  GRT_PRINT_INFO("needs ack : %s\n", ((bf->needs_ack == 0) ? "NO" : "YES"));
  GRT_PRINT_INFO("rates & tries : ");
  for(i = 0; i < IEEE80211_TX_MAX_RATES; i++){
    GRT_PRINT_INFO("(0x%x, %d) ", bf->rates[i], bf->tries[i]);
  }
  GRT_PRINT_INFO("\n");
  for(i = 0; i < bf->skb->len; i++){
    GRT_PRINT_INFO("%02x ", bf->skb->data[i] & 0x0FF);
    if(((i + 1) % 16) == 0){
      GRT_PRINT_INFO("\n");
    }
  }
  GRT_PRINT_INFO("\n");
}
