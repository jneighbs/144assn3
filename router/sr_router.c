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

/*ethernet type*/
#define ARP 1
#define IP 2
/*ip protocols*/
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
/*icmp description*/
#define ECHO_REPLY 1
#define DESTINATION_PORT_UNREACHABLE 2

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
int determineEthernetFrameType(sr_ethernet_hdr_t* ethrheader)
{
	printf("--Function: determineEthernetFrameType-- \n");

	printf("ethertype_arp: %u\n", ethertype_arp);
	printf("ethertype_ip: %u\n", ethertype_ip);
	printf("ntohs(ethrheader->ether_type): %u\n", ntohs(ethrheader->ether_type));

	if(ntohs(ethrheader->ether_type) == ethertype_arp){
		printf("Received arp packet \n");
 		return ARP;
 }
	if(ntohs(ethrheader->ether_type) == ethertype_ip){
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
* Method: findInterfaceThatMatchesIpDest
* find the router interface that matches the packets ip, if it exists. 
* If it does, return the interface, else return NULL
*------------------------------------------------------------------------*/

struct sr_if* findInterfaceThatMatchesIpDest(struct sr_instance* sr, sr_ip_hdr_t* ipheader){

	printf("--function: findInterfaceThatMatchesIpDest-- \n");
	printf("ipheader->ip_p: %u\n", ipheader->ip_p);
	printf("ipheader->ip_dst: %u\n",ipheader->ip_dst);
	printf("ntohl(ipheader->ip_dst): %u\n",ntohl(ipheader->ip_dst));
	printf("ntohs(ipheader->ip_p): %u\n",ntohs(ipheader->ip_p));
	struct sr_if* interface = sr->if_list;
	while(interface!=NULL){
		printf("interface->ip: %u\n", interface->ip);
		printf("ntohl(interface->ip): %u\n", ntohl(interface->ip));
		if(interface->ip == ipheader->ip_dst){
			printf("We found a match!\n");
			return interface;
		}
		interface=interface->next;
	}
return NULL;
}

/*------------------------------------------------------------------------
* Method: sendICMP
* Given an ICMP description *(and probably destination?), this function sends a ICMP packet.
*-------------------------------------------------------------------------*/

void sendICMP(uint8_t description){
	printf("--function: sendICMP-- \n");
	uint8_t type;
	uint8_t code;
	
	switch(description)
	{
	case ECHO_REPLY:
		printf("creating ECHO_REPLY\n");
		type=0;
		code=0;
		break;
	case DESTINATION_PORT_UNREACHABLE:
		printf("creating DESTINATION_PORT_UNREACHABLE\n");
		type=3;
		code=3;
		break;
	default:
		printf("!!Sending unknown ICMP - auth Jacob in sendICMP!!");
	}
	/*fill this in*/
}


/*------------------------------------------------------------------------
* Method: receiveTCPorUDP
* -Returns whether or not the ip header is describing tcp or udp packet
*-------------------------------------------------------------------------*/

int receiveTCPorUDP(sr_ip_hdr_t* ipheader){
	printf("--function: receiveTCPorUDP-- \n");
	return (ipheader->ip_p==TCP_PROTOCOL || ipheader->ip_p==UDP_PROTOCOL);
}

/*------------------------------------------------------------------------
* Method: receiveEchoRequest
* -Returns whether or not the icmp header is describing an echo request
*-------------------------------------------------------------------------*/

int receiveValidEchoRequest(sr_icmp_hdr_t* icmpheader){
	printf("--function: receiveValidEchoRequest-- \n");
	printf("icmpheader->icmp_type: %u\n", icmpheader->icmp_type);
	printf("icmpheader->icmp_code: %u\n", icmpheader->icmp_code);
	/*uint16_t givenChecksum = icmpheader->icmp_sum;
	icmpheader->icmp_sum = 0;
	uint16_t calculatedChecksum = sha1(icmpheader); OH QUESTION*/
	return (icmpheader->icmp_type==8 && icmpheader->icmp_code==0);
}

/*------------------------------------------------------------------------
* Method: ipToMe
* -If the packet is an ICMP echo request and its checksum is valid, send an
* ICMP echo reply to the sending host.
* -If the packet contains a TCP or UDP payload, send an ICMP port unreachable
* to the sending host.
* -Otherwise, ignore the packet.
*-------------------------------------------------------------------------*/

void ipToMe(sr_ip_hdr_t* ipheader){
	printf("--function: ipToMe-- \n");
	if(ipheader->ip_p==ip_protocol_icmp){ /*if icmp*/
		sr_icmp_hdr_t* icmpheader = (sr_icmp_hdr_t*)(ipheader+20);/*OH QUESTION*/
		if(receiveValidEchoRequest(icmpheader)){
			sendICMP(ECHO_REPLY);
		}
	} else if(receiveTCPorUDP(ipheader)){
		sendICMP(DESTINATION_PORT_UNREACHABLE);
	}
	/*If the packet isn't caught in one of the above conditions, ignore*/
}

/*------------------------------------------------------------------------
* Method: forwardIP
* 
*-------------------------------------------------------------------------*/

void forwardIP(){
	printf("--function: forwardIP-- \n");
	/*sanity check, decrement ttl, etc*/
	/*fill this in*/
}

/*------------------------------------------------------------------------
* Method: handleIP
* Handles logic when receiving ip packets: 
*	to one of my interfaces -> if ICMP echo request,
* reply; else ICMP port unreachable reply
*	not to one of my interfaces -> sanity check, forward
*------------------------------------------------------------------------*/
void handleIP(struct sr_instance* sr, sr_ip_hdr_t* ipheader){
	printf("--function: handleIP-- \n");
	struct sr_if* interface = findInterfaceThatMatchesIpDest(sr, ipheader);
	if(interface!=NULL){
		ipToMe(ipheader);
	}else{
		forwardIP();
	}
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
  
  sr_ethernet_hdr_t* ethrheader = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* ipheader = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  sr_print_if_list(sr);
  
  switch(determineEthernetFrameType(ethrheader))
  {
  case ARP: 
  	handleArp();
  	break;
  case IP: 
  	handleIP(sr, ipheader);
  	break;
  default: 
  	printf("!!Ethernet frame type not recognizable - author-Jacob in sr_hadlepacket!!\n");
  }

}/* end sr_ForwardPacket */














