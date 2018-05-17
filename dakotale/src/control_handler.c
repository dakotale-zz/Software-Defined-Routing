/**
 * @control_handler
 * @author  Swetank Kumar Saha <swetankk@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * Handler for the control plane.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/queue.h>
#include <unistd.h>
#include <string.h>

#include "../include/global.h"
#include "../include/network_util.h"
#include "../include/control_header_lib.h"
#include "../include/author.h"
#include "../include/control_handler.h"
#include "../include/connection_manager.h"

#ifndef PACKET_USING_STRUCT
    #define CNTRL_CONTROL_CODE_OFFSET 0x04
    #define CNTRL_PAYLOAD_LEN_OFFSET 0x06
#endif

#define OFFSET_TWO 2
#define OFFSET_FOUR 4
#define OFFSET_SIX 6
#define OFFSET_EIGHT 8
#define OFFSET_TEN 10 
#define OFFSET_TWEL 12
#define OFFSET_SIXTEN 16
#define OFFSET_EIGHTEN 18   

uint16_t getcostalgo(uint16_t id);

struct routers 
{
    uint16_t router_id;
    uint16_t router_port;
    uint16_t data_port;
    uint16_t link_cost;
    uint16_t init_link_cost;
    uint32_t router_ipaddr;
    uint32_t next;
    int alive;
}nodes[5];

struct costpeer
{
    uint32_t peerip;
    uint16_t peerport;
    uint16_t peercost;
    uint16_t peerid;
    int valid;
};

/* Linked List for active control connections */
struct ControlConn
{
    int sockfd;
    LIST_ENTRY(ControlConn) next;
}*connection, *conn_temp;
LIST_HEAD(ControlConnsHead, ControlConn) control_conn_list;

int create_control_sock()
{
    int sock;
    struct sockaddr_in control_addr;
    socklen_t addrlen = sizeof(control_addr);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
        ERROR("socket() failed");

    /* Make socket re-usable */
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int)) < 0)
        ERROR("setsockopt() failed");

    bzero(&control_addr, sizeof(control_addr));

    control_addr.sin_family = AF_INET;
    control_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    control_addr.sin_port = htons(CONTROL_PORT);

    if(bind(sock, (struct sockaddr *)&control_addr, sizeof(control_addr)) < 0)
        ERROR("bind() failed");

    if(listen(sock, 5) < 0)
        ERROR("listen() failed");

    LIST_INIT(&control_conn_list);

    return sock;
}

int new_control_conn(int sock_index)
{
    int fdaccept, caddr_len;
    struct sockaddr_in remote_controller_addr;

    caddr_len = sizeof(remote_controller_addr);
    fdaccept = accept(sock_index, (struct sockaddr *)&remote_controller_addr, &caddr_len);
    if(fdaccept < 0)
        ERROR("accept() failed");

    /* Insert into list of active control connections */
    connection = malloc(sizeof(struct ControlConn));
    connection->sockfd = fdaccept;
    LIST_INSERT_HEAD(&control_conn_list, connection, next);

    return fdaccept;
}

void remove_control_conn(int sock_index)
{
    LIST_FOREACH(connection, &control_conn_list, next) {
        if(connection->sockfd == sock_index) LIST_REMOVE(connection, next); // this may be unsafe?
        free(connection);
    }

    close(sock_index);
}

bool isControl(int sock_index)
{
    LIST_FOREACH(connection, &control_conn_list, next)
        if(connection->sockfd == sock_index) return TRUE;

    return FALSE;
}

bool control_recv_hook(int sock_index)
{
    char *cntrl_header, *cntrl_payload;
    uint8_t control_code;
    uint16_t payload_len;

    /* Get control header */
    cntrl_header = (char *) malloc(sizeof(char)*CNTRL_HEADER_SIZE);
    bzero(cntrl_header, CNTRL_HEADER_SIZE);

    if(recvALL(sock_index, cntrl_header, CNTRL_HEADER_SIZE) < 0){
        remove_control_conn(sock_index);
        free(cntrl_header);
        return FALSE;
    }

    /* Get control code and payload length from the header */
    #ifdef PACKET_USING_STRUCT
        /** ASSERT(sizeof(struct CONTROL_HEADER) == 8) 
          * This is not really necessary with the __packed__ directive supplied during declaration (see control_header_lib.h).
          * If this fails, comment #define PACKET_USING_STRUCT in control_header_lib.h
          */
        BUILD_BUG_ON(sizeof(struct CONTROL_HEADER) != CNTRL_HEADER_SIZE); // This will FAIL during compilation itself; See comment above.

        struct CONTROL_HEADER *header = (struct CONTROL_HEADER *) cntrl_header;
        control_code = header->control_code;
        payload_len = ntohs(header->payload_len);
    #endif
    #ifndef PACKET_USING_STRUCT
        memcpy(&control_code, cntrl_header+CNTRL_CONTROL_CODE_OFFSET, sizeof(control_code));
        memcpy(&payload_len, cntrl_header+CNTRL_PAYLOAD_LEN_OFFSET, sizeof(payload_len));
        payload_len = ntohs(payload_len);
    #endif

    free(cntrl_header);

    /* Get control payload */
    if(payload_len != 0){
        cntrl_payload = (char *) malloc(sizeof(char)*payload_len);
        bzero(cntrl_payload, payload_len);

        if(recvALL(sock_index, cntrl_payload, payload_len) < 0){
            remove_control_conn(sock_index);
            free(cntrl_payload);
            return FALSE;
        }
    }

    /* Triage on control_code */
    switch(control_code)
    {
        case 0: author_response(sock_index);
                break;

        case 1: 
		callinit(sock_index, cntrl_payload);
		initack(sock_index);
        break;

    	case 2:
    		sendtocontroller(sock_index);
    		break;
        default:
            exit(0);
    }

    if(payload_len != 0)
	free(cntrl_payload);
    return TRUE;
}

void callinit(int sock_index, char *cntrl_payload)
{

    memcpy(&numnodes, cntrl_payload, sizeof(numnodes));
    memcpy(&periodic_interval, cntrl_payload+OFFSET_TWO, sizeof(periodic_interval));
    
    numnodes = ntohs(numnodes);   
    periodic_interval = ntohs(periodic_interval);
    timetv.tv_sec = periodic_interval;
    timetv.tv_usec = 0;    

    memset(&nodes,0,sizeof nodes);

    for(int i=0; i < numnodes; i++)
    {
        memcpy(&nodes[i].router_id, cntrl_payload+OFFSET_FOUR+(i*OFFSET_TWEL), sizeof(nodes[i].router_id));
        memcpy(&nodes[i].router_port, cntrl_payload+OFFSET_SIX+(i*OFFSET_TWEL), sizeof(nodes[i].router_port));
        memcpy(&nodes[i].data_port, cntrl_payload+OFFSET_EIGHT+(i*OFFSET_TWEL), sizeof(nodes[i].data_port));
        memcpy(&nodes[i].init_link_cost, cntrl_payload+OFFSET_TEN+(i*OFFSET_TWEL), sizeof(nodes[i].init_link_cost));
        memcpy(&nodes[i].link_cost, cntrl_payload+OFFSET_TEN+(i*OFFSET_TWEL), sizeof(nodes[i].link_cost));
        memcpy(&nodes[i].router_ipaddr, cntrl_payload+OFFSET_TWEL+(i*OFFSET_TWEL), sizeof(nodes[i].router_ipaddr));
        nodes[i].router_id=ntohs(nodes[i].router_id);
        nodes[i].router_port=ntohs(nodes[i].router_port);
        nodes[i].data_port=ntohs(nodes[i].data_port);
        nodes[i].init_link_cost=ntohs(nodes[i].init_link_cost);
        nodes[i].link_cost=ntohs(nodes[i].link_cost);
        nodes[i].router_ipaddr=ntohl(nodes[i].router_ipaddr);
        nodes[i].alive=1;
        
        if(nodes[i].init_link_cost == 0)
        {
            router_index=i;
        }

        if(nodes[i].init_link_cost == 65535)
        {
            nodes[i].next=65535;
        }
        else
        {
            nodes[i].next=nodes[i].router_id;
        }
    }
    
    router_socket=socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in raddr;
    memset(&raddr,0,sizeof raddr);
    
    raddr.sin_family = AF_INET;
    raddr.sin_port = htons(nodes[router_index].router_port);
    raddr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    bind(router_socket,(struct sockaddr*) &raddr, sizeof(raddr));
    
    FD_SET(router_socket,&master_list);
    if(router_socket > head_fd)
        head_fd = router_socket;
 
}

void initack(int sock_index)
{
    uint16_t payload_len=0, response_len;
    char *cntrl_response;

    cntrl_response = create_response_header(sock_index, 1, 0, payload_len);
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    sendALL(sock_index, cntrl_response, response_len);
    free(cntrl_response);
}

void routingupdate()
{
    uint16_t maxrouters;
    uint16_t sourceport;
    uint16_t destport;
    uint16_t destid;
    uint16_t destcost;
    uint32_t sourceip;
    uint32_t destip;

    struct sockaddr_in paddr;   
    int size=OFFSET_EIGHT+(OFFSET_TWEL * numnodes);
    
    char *routing_update_response = (char *) malloc(size);
    memset(routing_update_response, 0, size);
    
    maxrouters=htons(numnodes);
    sourceport=htons(nodes[router_index].router_port);
    sourceip=htonl(nodes[router_index].router_ipaddr);

    memcpy(routing_update_response,&maxrouters, sizeof(maxrouters));
    memcpy(routing_update_response+OFFSET_TWO,&sourceport, sizeof(sourceport));
    memcpy(routing_update_response+OFFSET_FOUR,&sourceip, sizeof(sourceip));
    
    for(int i =0; i < numnodes; i++)
    {
        destip=htonl(nodes[i].router_ipaddr);
        destport=htons(nodes[i].router_port);
        destid=htons(nodes[i].router_id);
        destcost=htons(nodes[i].link_cost);

        memcpy(routing_update_response+OFFSET_EIGHT+(i*OFFSET_TWEL),&destip, sizeof(destip));
        memcpy(routing_update_response+OFFSET_TWEL+(i*OFFSET_TWEL),&destport, sizeof(destport));
        memcpy(routing_update_response+OFFSET_SIXTEN+(i*OFFSET_TWEL),&destid, sizeof(destid));
        memcpy(routing_update_response+OFFSET_EIGHTEN+(i*OFFSET_TWEL),&destcost, sizeof(destcost));
    }
 
    for(int i=0; i < numnodes; i++)
    {
        if(nodes[i].init_link_cost != 0 && nodes[i].init_link_cost != 65535 && nodes[i].alive == 1)
        {
            uint32_t router_ip=htonl(nodes[i].router_ipaddr);
            memset(&paddr, 0 ,sizeof(paddr));

            paddr.sin_family = AF_INET;
            paddr.sin_port = htons(nodes[i].router_port);
            memcpy(&paddr.sin_addr.s_addr,&router_ip,4);

            int snt_bytes = sendto(router_socket, routing_update_response, size, 0, (struct sockaddr*)&paddr, sizeof(paddr));
        }
    }

    if(routing_update_response)
        free(routing_update_response);
}

void sendtocontroller(int sock_index)
{
    uint16_t payload_len, response_len;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;
    
    payload_len=numnodes*OFFSET_EIGHT;
    cntrl_response_payload = (char *) malloc(payload_len);
    memset(cntrl_response_payload,0,payload_len);

    cntrl_response_header = create_response_header(sock_index, 2, 0, payload_len);

    // Making the payload
    for(int i=0; i < numnodes; i++)
    {
        uint16_t temp_id,temp_next,temp_cost;
        temp_id=htons(nodes[i].router_id);
        temp_next=htons(nodes[i].next);
        temp_cost=htons(nodes[i].link_cost);

        memcpy(cntrl_response_payload+(i*OFFSET_EIGHT),&temp_id,sizeof temp_id);
        memcpy(cntrl_response_payload+OFFSET_FOUR+(i*OFFSET_EIGHT),&temp_next,sizeof temp_next);
        memcpy(cntrl_response_payload+OFFSET_SIX+(i*OFFSET_EIGHT),&temp_cost,sizeof temp_cost);
    }

    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    memset(cntrl_response,0,response_len);

    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);

    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);

    sendALL(sock_index, cntrl_response, response_len);
    
    if(cntrl_response)
        free(cntrl_response);   
}

void distancevec(char *routing_packet)
{   
    uint16_t numfields;
    uint16_t sourceport;
    uint16_t sourceid;
    uint16_t peerport;
    uint16_t peerid;
    uint16_t peercost;
    uint32_t sourceip;
    uint32_t peerip;

    struct costpeer peerinfo[5];
    memset(&peerinfo,0,sizeof peerinfo);
    
    memcpy(&numfields,routing_packet,sizeof numfields);
    memcpy(&sourceport,routing_packet+OFFSET_TWO,sizeof sourceport );
    memcpy(&sourceip,routing_packet+OFFSET_FOUR,sizeof sourceip);
    
    numfields=ntohs(numfields);
    sourceport=ntohs(sourceport);
    sourceip=ntohl(sourceip);

    for(int i=0; i < numfields; i++)
    {
        memcpy(&peerid, routing_packet+OFFSET_SIXTEN+(i*OFFSET_TWEL), sizeof(peerid));
        memcpy(&peerip, routing_packet+OFFSET_EIGHT+(i*OFFSET_TWEL), sizeof(peerip));
        memcpy(&peerport, routing_packet+OFFSET_TWEL+(i*OFFSET_TWEL),sizeof(peerport));
        memcpy(&peercost, routing_packet+OFFSET_EIGHTEN+(i*OFFSET_TWEL), sizeof(peercost));

        peerid=(int)ntohs(peerid);
        peerip=ntohl(peerip);
        peercost=ntohs(peercost);
        peerport=ntohs(peerport);
        
        peerinfo[i].peerid=peerid;
        peerinfo[i].peerip=peerip;
        peerinfo[i].peercost=peercost;
        peerinfo[i].peerport=peerport;
    }
    
    
    for(int i=0; i < numnodes; i++)
    {
        if(nodes[i].router_port == sourceport)
        {
            sourceid=nodes[i].router_id;
            break;
        }
    }

    
    for(int i=0; i < numnodes; i++)
    {
        uint16_t new_cost, next;

        if(i == router_index)
            continue;
        
        new_cost = getcostalgo(sourceid);

        if(new_cost == 65535)
            continue;

        for(int j=0; j < numfields; j++)
        {
            if(nodes[i].router_id == peerinfo[j].peerid)
            {
                if(peerinfo[j].peercost == 65535)
                    new_cost = 65535;
                else
                    new_cost = new_cost + peerinfo[j].peercost;
                break;
            }
        }

        if(new_cost < nodes[i].link_cost)
        {
            nodes[i].link_cost=new_cost;    
            nodes[i].next=sourceid;
        }           
    }
}

uint16_t getcostalgo(uint16_t id)
{
    uint16_t ans=65535;
    for(int i=0;i < numnodes; i++)
    {
        if(nodes[i].router_id == id)
        {
            ans= nodes[i].init_link_cost;
            break;
        }
    }
    return ans;
}