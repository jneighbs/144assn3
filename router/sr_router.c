/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define ARP 1
#define IP 2

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*------------------------------------------------------------------------
* Method: determineEthernetFrameType
* Look at the ethernet frame and return values ARP or IP to be used in 
* a switch statement
*------------------------------------------------------------------------*/
int determineEthernetFrameType(uint8_t* packet)
{
printf("--Function: determineEthernetFrameType-- \n");

printf("ethertype_arp: %us\n", ethertype_arp);
printf("ethertype_ip: %us\n", ethertype_ip);
printf("((sr_ethernet_hdr_t*)packet)->ether_type: %us\n", ntohs(((sr_ethernet_hdr_t*)packet)->ether_type);

if(ntohs(((sr_ethernet_hdr_t*)packet)->ether_type) == ethertype_arp){
	printf("Received arp packet \n");
 	return ARP;
 }
if(ntohs(((sr_ethernet_hdr_t*)packet)->ether_type) == ethertype_ip){
	printf("Received IP packet \n");
	return IP;
}
return 0;
}

/*------------------------------------------------------------------------
* Method: handleArp
* Handles logic when receiving arp packets: 
*	reply to me -> cache, send available packets in queue
*	request to me -> construct reply, send it back
*	not to me -> ignore
*------------------------------------------------------------------------*/
void handleArp(){
printf("--function: handleArp-- \n");
}

/*------------------------------------------------------------------------
* Method: handleIP
* Handles logic when receiving ip packets: 
*	to one of my interfaces -> if ICMP echo request,
* reply; else ICMP port unreachable reply
*	not to one of my interfaces -> sanity check, forward
*------------------------------------------------------------------------*/
void handleIP(struct sr_instance* sr){
printf("--function: handleIP-- \n");
sr_print_if_list(sr);
//is it destined to me, or is it not destined to me?
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  
  printf("--Function: sr_handlepacket-- \n");
  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  
  switch(determineEthernetFrameType(packet))
  {
  case ARP: 
  	handleArp(sr);
  	break;
  case IP: 
  	handleIP();
  	break;
  default: 
  	printf("!!Ethernet frame type not recognizable - author-Jacob in sr_hadlepacket!!\n");
  }

}/* end sr_ForwardPacket */














