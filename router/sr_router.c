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
#include <stdlib.h>
#include <string.h>
#include <assert.h>



#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define IP_ADDR_LEN 4
/*ethernet type*/
#define ARP 1
#define IP 2
/*ip protocols*/
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
/*icmp description*/
#define ECHO_REPLY 1
#define DESTINATION_UNREACHABLE 2
#define DESTINATION_HOST_UNREACHABLE 3
#define DESTINATION_PORT_UNREACHABLE 4
#define TIME_EXCEEDED 5
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
void handleArp(struct sr_instance* sr, sr_ethernet_hdr_t* ethrheader, unsigned int len, char* interfaceName){
	printf("--function: handleArp-- \n");
	sr_arp_hdr_t* arpheader = (sr_arp_hdr_t*)(ethrheader+1);
	
	printf("---MY ARP HEADER INFO---\n");
  	print_hdr_arp((uint8_t *)arpheader);
  	printf("--------------------------\n");
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
* Method: sendTimeExceededICMP
* Sends a time exceeded icmp
*-------------------------------------------------------------------------*/
void sendTimeExceededICMP(struct sr_instance* sr, sr_ip_hdr_t* ipheader, uint8_t type, uint8_t code){
	printf("--function: sendTimeExceededICMP-- \n");
	/*

	*/
	/*int sr_send_packet(sr,(uint8_t*) ethrheader,len,iface);*/
}

/*------------------------------------------------------------------------
* Method: sendType3ICMP
* Sends a type 3 ICMP
*-------------------------------------------------------------------------*/
void sendType3ICMP(struct sr_instance* sr, sr_ip_hdr_t* ipheader, uint8_t type, uint8_t code){
	printf("--function: sendType3ICMP-- \n");
	/*

	*/
	/*int sr_send_packet(sr,(uint8_t*) ethrheader,len,iface);*/
}

/*------------------------------------------------------------------------
* Method: sendEchoReply
* Sends an echo reply
*-------------------------------------------------------------------------*/
void sendEchoReply(struct sr_instance* sr, sr_ip_hdr_t* ipheader, uint8_t type, uint8_t code){
	printf("--function: sendEchoReply-- \n");
	/*
	
	make sure to convert to network order when you place in packet
	malloc new ether of correct len
	mem copy everything in verbatim
	swithc around fields
	recompute checksum
	send
	
	malloc new ip header
	memcopy old header directly onto new header
	swap source and destination ips (carefull about endianness - could be tricky around here)
	--icmp header and data--
	malloc new icmp header - memset to 0
	after checksum field, straight up copy everything into newly malloced icmp packet
	compute checksum over headr starting at type, store in checksum
	--icmp--
	*/
	/*int sr_send_packet(sr,(uint8_t*) ethrheader,len,iface);*/
}

/*------------------------------------------------------------------------
* Method: sendICMP
* Given an ICMP description *(and probably destination?), this function sends a ICMP packet.
*** Echo reply (type 0)
* Sent in response to an echo request (ping) to one of the router's interfaces.
* (This is only for echo requests to any of the router's IPs. An echo request sent 
* elsewhere should be forwarded to the next hop address as usual.)
*** Destination unreachable (type 3, code 0)
* Sent if there is a non-existent route to the destination IP (no matching entry in routing
* table when forwarding an IP packet).
*** Destination host unreachable (type 3, code 1)
* Sent if five ARP requests were sent to the next-hop IP without a response.
*** Port unreachable (type 3, code 3)
* Sent if an IP packet containing a UDP or TCP payload is sent to one of the router's
* interfaces. This is needed for traceroute to work.
*** Time exceeded (type 11, code 0)
* Sent if an IP packet is discarded during processing because the TTL field is 0. This is
* also needed for traceroute to work.
*-------------------------------------------------------------------------*/

void sendICMP(uint8_t description, sr_ip_hdr_t* ipheader, struct sr_instance* sr){
	printf("--function: sendICMP-- \n");
	uint8_t type;
	uint8_t code;
	
	switch(description)
	{
	case ECHO_REPLY:
		printf("creating ECHO_REPLY\n");
		type=0;
		code=0;
		sendEchoReply(sr, ipheader, type, code);
		break;
	case DESTINATION_UNREACHABLE:
		printf("creating DESTINATION_UNREACHABLE\n");
		type=3;
		code=0;
		sendType3ICMP(sr, ipheader, type, code);
		break;
	case DESTINATION_HOST_UNREACHABLE:
		printf("creating DESTINATION_HOST_UNREACHABLE\n");
		type=3;
		code=1;
		break;
	case DESTINATION_PORT_UNREACHABLE:
		printf("creating DESTINATION_PORT_UNREACHABLE\n");
		type=3;
		code=3;
		break;
	case TIME_EXCEEDED:
		printf("creating TIME_EXCEEDED\n");
		type=11;
		code=0;
		sendTimeExceededICMP(sr, ipheader, type, code);
		break;
	default:
		printf("!!Sending unknown ICMP - auth Jacob in sendICMP!!");
		type=255;
		code=255;
	}

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

int receiveValidEchoRequest(sr_icmp_hdr_t* icmpheader, unsigned int len){
	printf("--function: receiveValidEchoRequest-- \n");
	printf("icmpheader->icmp_type: %u\n", icmpheader->icmp_type);
	printf("icmpheader->icmp_code: %u\n", icmpheader->icmp_code);
	
	uint16_t givenChecksum = icmpheader->icmp_sum;
	icmpheader->icmp_sum = 0;
	uint16_t calculatedChecksum= cksum(icmpheader, len);
	icmpheader->icmp_sum = givenChecksum;
	
	printf("givenChecksum: %d\n", givenChecksum);
	printf("calculatedChecksum: %d\n", calculatedChecksum);
	
	return (icmpheader->icmp_type==8 && icmpheader->icmp_code==0 && givenChecksum == calculatedChecksum);
}

/*------------------------------------------------------------------------
* Method: ipToMe
* -If the packet is an ICMP echo request and its checksum is valid, send an
* ICMP echo reply to the sending host.
* -If the packet contains a TCP or UDP payload, send an ICMP port unreachable
* to the sending host.
* -Otherwise, ignore the packet.
*-------------------------------------------------------------------------*/

void ipToMe(struct sr_instance* sr, sr_ip_hdr_t* ipheader, unsigned int len){
	printf("--function: ipToMe-- \n");
	len = len - (sizeof(*ipheader));
	printf("len: %i\n", len);
	
	if(ipheader->ip_p==ip_protocol_icmp){ /*if icmp*/
		sr_icmp_hdr_t* icmpheader = (sr_icmp_hdr_t*)(ipheader+1);
		/*
		printf("---MY ICMP HEADER INFO---\n");
  		print_hdr_icmp((uint8_t*)icmpheader);
 		printf("--------------------------\n");
 		*/
		if(receiveValidEchoRequest(icmpheader, len)){
			sendICMP(ECHO_REPLY, ipheader, sr);
		}
		
	} else if(receiveTCPorUDP(ipheader)){
		sendICMP(DESTINATION_PORT_UNREACHABLE, ipheader, sr);
	}
	/*If the packet isn't caught in one of the above conditions, ignore*/
}

/*------------------------------------------------------------------------
* Method: generateArpRequest
* generates an ARp request
* 
*-------------------------------------------------------------------------*/

void generateArpRequest(struct sr_instance* sr, char* interfaceName, uint32_t nextHopIP){
	printf("--function: generateArpRequest-- \n");
	
	struct sr_if* interface = sr_get_interface(sr, interfaceName);
	size_t packetSize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	sr_ethernet_hdr_t* ethrheader = malloc(packetSize);
	
	memset(ethrheader, 0xff, sizeof(sr_ethernet_hdr_t)+ sizeof(sr_arp_hdr_t));
	memcpy(ethrheader->ether_shost,interface->addr,ETHER_ADDR_LEN);
	ethrheader->ether_type = htons(ethertype_arp);
	
	printf("---MY generateArpRequest ETHR HEADER INFO---\n");
  	print_hdr_eth((uint8_t *)ethrheader);
 	printf("--------------------------------------------\n");
 	
 	sr_arp_hdr_t* arpheader = (sr_arp_hdr_t*)(ethrheader+1);
 	
 	arpheader->ar_hrd=htons(1);
 	arpheader->ar_pro=htons(ethertype_ip);
 	arpheader->ar_hln=ETHER_ADDR_LEN;
 	arpheader->ar_pln=IP_ADDR_LEN;
 	arpheader->ar_op=htons(1);
 	memcpy(arpheader->ar_sha,interface->addr,ETHER_ADDR_LEN);
 	arpheader->ar_sip = interface->ip;
 	arpheader->ar_tip=nextHopIP; /*NEEDS TO == NEXT HOP IP FROM TABLE*/
 	
 	printf("---MY generateArpRequest ARP HEADER INFO---\n");
  	print_hdr_arp((uint8_t *)arpheader);
 	printf("--------------------------------------------\n");
 	
 	/*
 	Needs to either send packet or return void* packet
 	Dont foget to free the packet
 	*/
}

/*------------------------------------------------------------------------
* Method: turnMaskIntoPrefixLen
* 
*-------------------------------------------------------------------------*/
uint8_t turnMaskIntoPrefixLen(uint32_t mask){
	printf("--function: turnMaskIntoPrefixLen-- \n");
	uint8_t count = 0;
	uint32_t leadingBitTurnedOn = 2^31;
	while(mask & leadingBitTurnedOn){
		print_addr_ip_int(mask);
		mask <<= mask;
		count++;
	}
	printf("mask len: %u\n", count);
	return count;
}



/*------------------------------------------------------------------------
* Method: getNextHopIPFromRouter
* 
*-------------------------------------------------------------------------*/

uint32_t getNextHopIPFromRouter(struct sr_instance* sr, uint32_t destinationIP){
	printf("--function: getNextHopIPFromRouter-- \n");
	
	struct sr_rt* tableEntry = sr->routing_table;
	uint32_t nextHopIP = 0;
	uint8_t longestPrefix = 0;
	
	
	
	
	while(tableEntry){
		char* charMask = inet_ntoa(tableEntry->mask);
		printf("charMask: %s\n", charMask);
		char* charDest = inet_ntoa(tableEntry->dest);
		printf("charDest: %s\n", charDest);
		char* charGateway = inet_ntoa(tableEntry->gw);
		printf("charGateway: %s\n", charGateway);
		
		int x = sizeof(charMask);
		printf("size of charmask: %i\n",x);
		
		uint32_t mask = (uint32_t)atoi(charMask);
		uint32_t dest = (uint32_t)atoi(charDest);
		uint32_t gateway = (uint32_t)atoi(charGateway);
		
		printf("---mask: %u---\n", mask);
		printf("---dest: %u---\n", dest);
		printf("---gateway: %u---\n", gateway);
		
		if((destinationIP & mask) == dest){
			printf("destinationIP & mask: match \n");
			uint8_t curPrefixLen = turnMaskIntoPrefixLen(mask);
			if(longestPrefix < curPrefixLen){
				longestPrefix = curPrefixLen;
			 	nextHopIP = gateway;
			 }
		}
		
		tableEntry = tableEntry->next;
	}
	printf("destinationIP: \n");
	print_addr_ip_int(destinationIP);
	printf("nextHopIP: \n");
	print_addr_ip_int(nextHopIP);
	return nextHopIP;
}

/*------------------------------------------------------------------------
* Method: forwardIP
* 
*-------------------------------------------------------------------------*/

void forwardIP(struct sr_instance* sr, sr_ip_hdr_t* ipheader){
	printf("--function: forwardIP-- \n");
	/*sanity check, decrement ttl, etc*/
	
	
	uint32_t destinationIP = ntohl(ipheader->ip_dst);
	uint32_t nextHopIP = getNextHopIPFromRouter(sr, destinationIP);
	/*check arp cache stuff*/
}

/*------------------------------------------------------------------------
* Method: handleIP
* Handles logic when receiving ip packets: 
*	to one of my interfaces -> if ICMP echo request,
* reply; else ICMP port unreachable reply
*	not to one of my interfaces -> sanity check, forward
*------------------------------------------------------------------------*/
void handleIP(struct sr_instance* sr, sr_ethernet_hdr_t* ethrheader, unsigned int len, char* interfaceName){
	sr_ip_hdr_t* ipheader = (sr_ip_hdr_t*)(ethrheader+1);
	
	printf("--function: handleIP-- \n");
	len = len - (sizeof(*ethrheader));
	printf("len: %i\n", len);
	/*
	printf("---MY IP HEADER INFO---\n");
  	print_hdr_ip((uint8_t*)ipheader);
 	printf("--------------------------\n");
 	*/
	struct sr_if* interface = findInterfaceThatMatchesIpDest(sr, ipheader);
	if(interface!=NULL){
		ipToMe(sr, ipheader, len);
	}else{
		forwardIP(sr, ipheader);
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
  sr_print_if_list(sr);
  sr_print_routing_table(sr);
  
  printf("---OFFICIAL PACKET HEADER INFO---\n");
  print_hdrs(packet, len);
  printf("---------------------------------\n");
  /*
  printf("---MY ETHR HEADER INFO---\n");
  print_hdr_eth((uint8_t *)ethrheader);
  printf("--------------------------\n");
  */
  switch(determineEthernetFrameType(ethrheader))
  {
  case ARP: 
  	generateArpRequest(sr, interface, 0);
  	handleArp(sr, ethrheader, len, interface);
  	break;
  case IP: 
  	handleIP(sr, ethrheader, len, interface);
  	break;
  default: 
  	printf("!!Ethernet frame type not recognizable - author-Jacob in sr_hadlepacket!!\n");
  }

}/* end sr_ForwardPacket */














