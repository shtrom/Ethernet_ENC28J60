/*
Ethernet_ENC28J60 is an Arduino-compatible Ethernet library
that works with Microchip's ENC28J60 Ethernet controller.

Copyright (C) 2011 Álvaro Justen <alvaro@justen.eng.br>
                                 http://twitter.com/turicas
This project is hosted at GitHub http://github.com/turicas/Ethernet_ENC28J60

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, please read the license at:
http://www.gnu.org/licenses/gpl-2.0.html
*/
#include <string.h>
#include <stdlib.h>
#include "socket.h"
#include "net.h"
#include "enc28j60.h"
#include "ip_arp_udp_tcp.h"
#define MAX_LENGHT_PACKET    150
#define BUFFER_SIZE          ETH_HEADER_LEN+IP_HEADER_LEN+TCP_HEADER_LEN_PLAIN+MAX_LENGHT_PACKET
#define MAX_ITERATIONS       1000
#define ARP_CACHE_SIZE       4
#define ARP_CACHE_TTL        1000 * 60 * 60 * 4 // 4 hours

#define NO_STATE             0
#define GOT_MAC              1
#define ARP_REQUEST_SENT     2
#define TCP_SYN_SENT         3

uint8_t myMacAddress[6], myIpAddress[4], myGatewayIpAddress[4],
        mySubnetAddress[4];
static uint8_t buffer[BUFFER_SIZE + 1];
uint16_t packetLength;

uint16_t sourcePort = 10000;

#ifdef ETHERSHIELD_DEBUG
char debugStr[80];

static void serial_write(unsigned char c) {
    while (!(UCSR0A & (1 << UDRE0))) {}
    UDR0 = c;
}

void ethershieldDebug(char *message) {
    uint8_t i;
    for (i = 0; message[i] != '\0'; i++) {
        serial_write(message[i]);
    }
}
#endif

typedef struct socketData {
    uint8_t protocol;
    uint16_t sourcePort;
	uint16_t destinationPort;
	uint8_t destinationIp[4];
    uint8_t flag;
    uint8_t state;
    uint8_t *dataBuffer;
    uint16_t bytesToRead;
    uint16_t firstByte;
    uint8_t clientState;
    uint8_t destinationMac[6];
    uint16_t sendPacketLength;
	uint32_t ackNumber;
	uint32_t sentData;
	uint8_t packets;
} SocketData;
SocketData _SOCKETS[MAX_SOCK_NUM];

typedef struct {
	uint32_t expiry;
	uint8_t macAddr[6];
	uint8_t ipAddr[4];
} arp_entry;

struct {
	arp_entry t[ARP_CACHE_SIZE];	
	uint8_t n;
} arp_table;

#ifdef ETHERSHIELD_DEBUG
void turnLEDsOn() {
    enc28j60PhyWrite(PHLCON, 0x880); //turn on
}

void turnLEDsOff() {
    enc28j60PhyWrite(PHLCON, 0x990); //turn off
}
#endif

uint8_t socket(SOCKET s, uint8_t protocol, uint16_t sourcePort, uint8_t flag) {
    _SOCKETS[s].protocol = protocol;
    _SOCKETS[s].sourcePort = sourcePort;
	memset(_SOCKETS[s].destinationIp, 0x00, 4);
	_SOCKETS[s].destinationPort = 0;
    _SOCKETS[s].flag = flag;
    _SOCKETS[s].state = SOCK_INIT;
    _SOCKETS[s].bytesToRead = 0;
    _SOCKETS[s].firstByte = 0;
	_SOCKETS[s].clientState = NO_STATE;
	return 0;
}

void clean_arpcacheentry() {
	uint8_t i = 0;
	//uint32_t time = milis();
	uint32_t time = 0;
	
	for(i=0; i<arp_table.n; i++)
		if(time < arp_table.t[i].expiry) break;
	
	if(i > 0) {
		memmove(arp_table.t, &arp_table.t[i], (arp_table.n-i) * sizeof(arp_entry));
		arp_table.n -= i;
	}		
}

void add_arpcacheentry(uint8_t *mac, uint8_t *ip) {
	uint8_t i = 0;
	
	clean_arpcacheentry();
	
	// Delete an existent entry for that IP address (if any)
	for(i=0; i<arp_table.n; i++)
		if(memcmp(arp_table.t[i].ipAddr, ip, 4) == 0) {
			if(i < ARP_CACHE_SIZE) // If the matching IP address is the last on the list, just decrease the counter
				memmove(&arp_table.t[i], &arp_table.t[i+1], (arp_table.n-i-1) * sizeof(arp_entry));
			arp_table.n--;
		}
		
	// If the arp cache is full, we need to make room for it
	if(arp_table.n == ARP_CACHE_SIZE) {
		memmove(arp_table.t, &arp_table.t[1], (arp_table.n-1) * sizeof(arp_entry));
		arp_table.n--;
	}
	
	// Fill the data
	memcpy(arp_table.t[arp_table.n].macAddr, mac, 6);
	memcpy(arp_table.t[arp_table.n].ipAddr, ip, 4);
	arp_table.t[arp_table.n].expiry = /*milis() +  ARP_CACHE_TTL*/ 100;
	arp_table.n++;
	
}

void flushSockets() {
    if (!(packetLength = enc28j60PacketReceive(BUFFER_SIZE, buffer))) { //No packet available for reading!
        return;
    }
    else if (eth_type_is_arp_and_my_ip(buffer, packetLength)) {
        if (arp_packet_is_myreply_arp(buffer)) {
#ifdef ETHERSHIELD_DEBUG
            ethershieldDebug("Received ARP reply.\r\n");
#endif
			// Add it to the arp cache list
			add_arpcacheentry(buffer+ETH_SRC_MAC_P, buffer+ETH_ARP_DST_IP_P);			
        }
        else {
            make_arp_answer_from_request(buffer);
#ifdef ETHERSHIELD_DEBUG
            ethershieldDebug("Answering ARP request.\r\n");
#endif
        }
    }
    else if (!eth_type_is_ip_and_my_ip(buffer, packetLength)) {
#ifdef ETHERSHIELD_DEBUG
        ethershieldDebug("Ignoring packet not for me.\r\n");
#endif
        return;
    }
    else if (buffer[IP_PROTO_P] == IP_PROTO_ICMP_V &&
            buffer[ICMP_TYPE_P] == ICMP_TYPE_ECHOREQUEST_V) {
        make_echo_reply_from_request(buffer, packetLength);
#ifdef ETHERSHIELD_DEBUG
        sprintf(debugStr, "Replying ICMP ECHO REQUEST from %d.%d.%d.%d.\r\n",
                buffer[IP_SRC_IP_P], buffer[IP_SRC_IP_P + 1],
                buffer[IP_SRC_IP_P + 2], buffer[IP_SRC_IP_P + 3]);
        ethershieldDebug(debugStr);
#endif
    }
    else if (buffer[IP_PROTO_P] == IP_PROTO_TCP_V) {
        //DEBUG: it's TCP and for me! Do I want it?
        uint16_t destinationPort = (buffer[TCP_DST_PORT_H_P] << 8) | buffer[TCP_DST_PORT_L_P];

#ifdef ETHERSHIELD_DEBUG
        sprintf(debugStr, "Received TCP packet from %d.%d.%d.%d:%u on port %d\r\n",
                buffer[IP_SRC_IP_P], buffer[IP_SRC_IP_P + 1],
                buffer[IP_SRC_IP_P + 2], buffer[IP_SRC_IP_P + 3],
                (buffer[TCP_SRC_PORT_H_P] << 8) | buffer[TCP_SRC_PORT_L_P],
                destinationPort);
        ethershieldDebug(debugStr);
#endif

        uint8_t i, socketSelected = MAX_SOCK_NUM;
        for (i = 0; i < MAX_SOCK_NUM; i++) {
            if (_SOCKETS[i].sourcePort == destinationPort) {
                socketSelected = i;
				if(_SOCKETS[i].state == SOCK_LISTEN) {
					_SOCKETS[i].destinationPort = (buffer[TCP_SRC_PORT_H_P] << 8) | buffer[TCP_SRC_PORT_L_P];
					memcpy(_SOCKETS[i].destinationIp, &buffer[IP_SRC_IP_P], 4);
				}
                break;
            }
        }
#ifdef ETHERSHIELD_DEBUG
        ethershieldDebug("  Socket selected: ");
        itoa(socketSelected, debugStr, 10);
        ethershieldDebug(debugStr);
        ethershieldDebug("\r\n");
#endif

        if (socketSelected == MAX_SOCK_NUM) {
            //TODO: reply and say that nobody is listening on that port
			return;
        }
        //TODO: change next 'if' to 'else if'
        //DEBUG: ok, the TCP packet is for me and I want it.
        if (buffer[TCP_FLAGS_P] == (TCP_FLAG_SYN_V | TCP_FLAG_ACK_V)) {
#ifdef ETHERSHIELD_DEBUG
            ethershieldDebug("  It is TCP SYNACK, sending ACK\r\n");
#endif
            make_tcp_ack_from_any(buffer);
            //TODO: verify if I'm waiting for this SYN+ACK
            _SOCKETS[socketSelected].clientState = SOCK_ESTABLISHED;
            return;
        }
        else if (buffer[TCP_FLAGS_P] & TCP_FLAGS_SYN_V) {
#ifdef ETHERSHIELD_DEBUG
            ethershieldDebug("  It is TCP SYN, sending SYNACK\r\n");
#endif
            _SOCKETS[socketSelected].state = SOCK_ESTABLISHED;
            make_tcp_synack_from_syn(buffer);
        }
        else if (buffer[TCP_FLAGS_P] & TCP_FLAGS_ACK_V) {
            uint16_t data;

#ifdef ETHERSHIELD_DEBUG
                ethershieldDebug("  Got an ACK...\r\n");
#endif			
			
            init_len_info(buffer);
			
			_SOCKETS[socketSelected].packets = 0;
			_SOCKETS[socketSelected].ackNumber = (uint32_t)buffer[TCP_SEQ_H_P] << 24 | (uint32_t)buffer[TCP_SEQ_H_P + 1] << 16  |  (uint32_t)buffer[TCP_SEQ_L_P] << 8 | (uint32_t)buffer[TCP_SEQ_L_P + 1];
			
            data = get_tcp_data_pointer();
            if (!data) {
#ifdef ETHERSHIELD_DEBUG
                ethershieldDebug("  It is ACK with no data\r\n");
#endif
                if (buffer[TCP_FLAGS_P] & TCP_FLAGS_FIN_V) {
#ifdef ETHERSHIELD_DEBUG
                    ethershieldDebug("    It is ACKFIN, closing socket\r\n");
#endif
                    make_tcp_ack_from_any(buffer);
                    _SOCKETS[socketSelected].state = SOCK_CLOSED;
                    _SOCKETS[socketSelected].sendPacketLength = 0;
					_SOCKETS[socketSelected].ackNumber = 0;
					_SOCKETS[socketSelected].sentData = 0;
					_SOCKETS[socketSelected].packets = 0;
                    free(_SOCKETS[socketSelected].dataBuffer);
					_SOCKETS[socketSelected].bytesToRead = 0;
                }
                return;
            }
            else {
                int dataSize;

				make_tcp_ack_from_any(buffer); //TODO-ACK

				_SOCKETS[socketSelected].ackNumber = (uint32_t)buffer[TCP_SEQACK_H_P] << 24 | (uint32_t)buffer[TCP_SEQACK_H_P + 1] << 16  |  (uint32_t)buffer[TCP_SEQACK_L_P] << 8 | (uint32_t)buffer[TCP_SEQACK_L_P + 1];

                dataSize = packetLength - (&buffer[data] - buffer);
#ifdef ETHERSHIELD_DEBUG
                itoa(dataSize, debugStr, 10);
                ethershieldDebug("  It is ACK with data, ACK sent\r\n");
                ethershieldDebug("    # bytes: ");
                ethershieldDebug(debugStr);
                ethershieldDebug("\r\n");

#endif
                _SOCKETS[socketSelected].state = SOCK_ESTABLISHED;

				if(_SOCKETS[socketSelected].bytesToRead > 0) {
					_SOCKETS[socketSelected].dataBuffer = realloc(_SOCKETS[socketSelected].dataBuffer, _SOCKETS[socketSelected].bytesToRead + (dataSize * sizeof(char))); //TODO: and about the TCP/IP/Ethernet overhead?
					memcpy(_SOCKETS[socketSelected].dataBuffer+_SOCKETS[socketSelected].bytesToRead, &buffer[data], dataSize);
				} else {
					_SOCKETS[socketSelected].dataBuffer = malloc(dataSize * sizeof(char)); //TODO: and about the TCP/IP/Ethernet overhead?
					memcpy(_SOCKETS[socketSelected].dataBuffer, &buffer[data], dataSize);
				}					
				//TODO: Add handler to malloc returning: No enough SRAM)
				
                _SOCKETS[socketSelected].bytesToRead += dataSize;
#ifdef ETHERSHIELD_DEBUG
                ethershieldDebug("    Data:\r\n");
                for (i = 0; i < dataSize; i++) {
                    serial_write(_SOCKETS[socketSelected].dataBuffer[i]);
                }
                ethershieldDebug("\r\n");
#endif
                return;
            }
        }
        else {
#ifdef ETHERSHIELD_DEBUG
            ethershieldDebug("Don't know what to do!\r\n");
#endif
            //make_tcp_ack_from_any(buffer); //TODO-ACK: send ACK using tcp_client_send_packet
        }
    }
}

uint8_t listen(SOCKET s) {
    _SOCKETS[s].state = SOCK_LISTEN;
    return 1;
}

uint8_t connect(SOCKET s, uint8_t *destinationIp, uint16_t destinationPort) {
    uint16_t i;
    char buffer[59];
	uint8_t h=0;

	memcpy(_SOCKETS[s].destinationIp, destinationIp, 4);
	_SOCKETS[s].destinationPort = destinationPort;

    make_arp_request((uint8_t*)buffer, destinationIp);
    _SOCKETS[s].clientState = ARP_REQUEST_SENT;
#ifdef ETHERSHIELD_DEBUG
    ethershieldDebug("Sent ARP request.\r\n");
#endif

    for (i = 0; _SOCKETS[s].clientState != GOT_MAC && i < MAX_ITERATIONS; i++) {
        flushSockets(); //it'll fill destinationMac on socket struct
		
		for(h=0; h<ARP_CACHE_SIZE; h++)
			if(arp_table.n > h)
				if(memcmp(destinationIp, arp_table.t[h].ipAddr, 4) == 0)
					_SOCKETS[s].clientState = GOT_MAC;
		
    }
    if (_SOCKETS[s].clientState != GOT_MAC) {
        return 0;
    }
#ifdef ETHERSHIELD_DEBUG
    ethershieldDebug("MAC received, sending TCP SYN.\r\n");
#endif

    tcp_client_send_packet((uint8_t*)buffer, destinationPort, sourcePort++, TCP_FLAG_SYN_V,
            1, 1, 0, 0, _SOCKETS[s].destinationMac,
            destinationIp);
    _SOCKETS[s].clientState = TCP_SYN_SENT;
#ifdef ETHERSHIELD_DEBUG
    ethershieldDebug("TCP SYN sent.\r\n");
#endif

    for (i = 0; _SOCKETS[s].clientState != SOCK_ESTABLISHED && i < MAX_ITERATIONS; i++) {
        flushSockets();
    }

    return _SOCKETS[s].clientState == SOCK_ESTABLISHED;
    //TODO: Maybe use a timeout instead of MAX_ITERATIONS to receive SYN+ACK
}

uint8_t head = 1;

uint16_t send(SOCKET s, const uint8_t *bufferToSend, uint16_t length) {
	uint8_t destinationPortH = 0;
    uint8_t destinationPortL = 0;
	uint32_t seq=0, ack=0;
	// Hack to wait for the ACK every 2 packets sent
	while(_SOCKETS[s].packets >= 2)
	{
		flushSockets();
		
		if(_SOCKETS[s].packets == 0)
		{
			make_eth_ip_new(buffer, _SOCKETS[s].destinationMac);
			make_ip(buffer);
			
			//TODO: Change to _SOCKETS
			destinationPortH = buffer[TCP_DST_PORT_H_P];
			destinationPortL = buffer[TCP_DST_PORT_L_P];
			buffer[TCP_DST_PORT_H_P] = buffer[TCP_SRC_PORT_H_P];
			buffer[TCP_DST_PORT_L_P] = buffer[TCP_SRC_PORT_L_P];
			buffer[TCP_SRC_PORT_H_P] = destinationPortH;
			buffer[TCP_SRC_PORT_L_P] = destinationPortL;
			
			seq = (uint32_t)buffer[TCP_SEQ_H_P] << 24 | (uint32_t)buffer[TCP_SEQ_H_P + 1] << 16  |  (uint16_t)buffer[TCP_SEQ_L_P] << 8 | (uint8_t)buffer[TCP_SEQ_L_P + 1];
			ack = (uint32_t)buffer[TCP_SEQACK_H_P] << 24 | (uint32_t)buffer[TCP_SEQACK_H_P + 1] << 16  |  (uint16_t)buffer[TCP_SEQACK_L_P] << 8 | (uint8_t)buffer[TCP_SEQACK_L_P + 1];
			
			buffer[TCP_SEQACK_H_P]   = (uint8_t)((seq >> 24) & 0xFF);
			buffer[TCP_SEQACK_H_P+1] = (uint8_t)((seq >> 16) & 0xFF);
			buffer[TCP_SEQACK_L_P]   = (uint8_t)((seq >> 8)  & 0xFF);
			buffer[TCP_SEQACK_L_P+1] = (uint8_t)(seq & 0xFF);

			buffer[TCP_SEQ_H_P]   = (uint8_t)((ack >> 24) & 0xFF);
			buffer[TCP_SEQ_H_P+1] = (uint8_t)((ack >> 16) & 0xFF);
			buffer[TCP_SEQ_L_P]   = (uint8_t)((ack >> 8)  & 0xFF);
			buffer[TCP_SEQ_L_P+1] = (uint8_t)(ack & 0xFF);
			
			make_tcphead3(buffer,0);
			head = 0;
			_SOCKETS[s].sentData = 0;
		}
	}		

	fill_tcp_data2(buffer, _SOCKETS[s].sendPacketLength, (const char *)bufferToSend, length);
	_SOCKETS[s].sendPacketLength += length;
	
	if(_SOCKETS[s].sendPacketLength >= MAX_LENGHT_PACKET) {
		make_tcp_ack_from_any_data(buffer, _SOCKETS[s].sendPacketLength, _SOCKETS[s].ackNumber, _SOCKETS[s].sentData, head);
#ifdef ETHERSHIELD_DEBUG
		if(head)
			ethershieldDebug("   HEAD!\r\n");
		else
			ethershieldDebug("   NOT HEAD!\r\n");

		ethershieldDebug("   Data packet sent!\r\n");
#endif
		_SOCKETS[s].sentData += _SOCKETS[s].sendPacketLength;
		_SOCKETS[s].sendPacketLength = 0;
		_SOCKETS[s].packets++;
		head = 1;
	}
	
	return 0;
	
	//tcp_client_send_packet(buffer, _SOCKETS[s].destinationPort, _SOCKETS[s].sourcePort, TCP_FLAG_ACK_V, 200, 0, 0, 200, _SOCKETS[s].destinationMac, _SOCKETS[s].destinationIp);		
}

uint16_t recv(SOCKET s, uint8_t *recvBuffer, uint16_t length) {
    if (_SOCKETS[s].bytesToRead == 0) {
        return 0;
    }
    else if (length == 1) {
        recvBuffer[0] = _SOCKETS[s].dataBuffer[_SOCKETS[s].firstByte];
        _SOCKETS[s].firstByte++;
        if (_SOCKETS[s].firstByte == _SOCKETS[s].bytesToRead) {
            _SOCKETS[s].bytesToRead = 0;
            _SOCKETS[s].firstByte = 0;
            free(_SOCKETS[s].dataBuffer);
        }
    }
    else {
        //TODO: what if length > 1?
    }
	return 1;
}

uint8_t disconnect(SOCKET s) {
    if (_SOCKETS[s].sendPacketLength) {
        //make_tcp_ack_from_any(buffer); //TODO-ACK
        make_tcp_ack_with_data(buffer, _SOCKETS[s].sendPacketLength);
    }
    //TODO: send FYN packet
    //TODO: wait to receive ACK?
    close(s);
	return 0;
}

uint8_t close(SOCKET s) {
    //do not call the function that does verifications
    _SOCKETS[s].state = SOCK_CLOSED;
    _SOCKETS[s].sendPacketLength = 0;
	_SOCKETS[s].ackNumber = 0;
    _SOCKETS[s].bytesToRead = 0;
	_SOCKETS[s].sentData = 0;
	_SOCKETS[s].packets = 0;
    free(_SOCKETS[s].dataBuffer); //TODO: really need this?
	return 0;
}

uint8_t getSn_SR(SOCKET s) {
    //get socket status
    //TODO: change on standard Ethernet library to do not use this

    flushSockets();
    return _SOCKETS[s].state;
}

uint16_t getSn_RX_RSR(SOCKET s) {
    //return the size of the receive buffer for that socket
    //TODO: change on standard Ethernet library to do not use this

    flushSockets();
    return _SOCKETS[s].bytesToRead;
}

void iinchip_init() {
    //TODO: change on standard Ethernet library to do not use this

    //do nothing
}

void sysinit(uint8_t txSize, uint8_t rxSize) {
    //TODO: change on standard Ethernet library to do not use this
    uint8_t i;
    for (i = 0; i < MAX_SOCK_NUM; i++) {
        _SOCKETS[i].state = SOCK_CLOSED;
        _SOCKETS[i].sendPacketLength = 0;
		_SOCKETS[i].ackNumber = 0;
		_SOCKETS[i].sentData = 0;
		_SOCKETS[i].packets = 0;
    }
#ifdef ETHERSHIELD_DEBUG
    ethershieldDebug("Init.\r\n");
#endif
}

void setSHAR(uint8_t *macAddress) {
    //TODO: change on standard Ethernet library to do not use this
    uint8_t i;
    for (i = 0; i < 6; i++) {
        myMacAddress[i] = macAddress[i];
    }
    enc28j60Init(myMacAddress);
    enc28j60clkout(2);
    enc28j60PhyWrite(PHLCON, 0x476); //LEDA = link status, LEDB = RX/TX
}

void setSIPR(uint8_t *ipAddress) {
    //TODO: change on standard Ethernet library to do not use this
    uint8_t i;
    for (i = 0; i < 4; i++) {
        myIpAddress[i] = ipAddress[i];
    }
}

void setGAR(uint8_t *gatewayIpAddress) {
    //TODO: change on standard Ethernet library to do not use this
    uint8_t i;
    for (i = 0; i < 4; i++) {
        myGatewayIpAddress[i] = gatewayIpAddress[i];
    }
}

void setSUBR(uint8_t *subnetAddress) {
    //TODO: change on standard Ethernet library to do not use this
    uint8_t i;
    for (i = 0; i < 4; i++) {
        mySubnetAddress[i] = subnetAddress[i];
    }

    init_ip_arp_udp_tcp(myMacAddress, myIpAddress);
}
