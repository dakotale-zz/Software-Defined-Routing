/**
 * @connection_manager
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
 * Connection Manager listens for incoming connections/messages from the
 * controller and other routers and calls the desginated handlers.
 */

#include <sys/select.h>
#include <string.h>

#include "../include/connection_manager.h"
#include "../include/global.h"
#include "../include/control_handler.h"

#define OFFSET_EIGHT 8
#define OFFSET_TWEL 12

void main_loop()
{
    int selret, sock_index, fdaccept;

    while(TRUE){

	if(router_socket>0)
    {
	   FD_SET(router_socket, &master_list);
       if(router_socket > head_fd)
            head_fd = router_socket;
	}

	
    watch_list = master_list;
    
	struct timeval tv;
	tv.tv_sec = timetv.tv_sec;
    tv.tv_usec = timetv.tv_usec;		

    selret = select(head_fd+1, &watch_list, NULL, NULL, &tv);

    if(selret < 0)
        ERROR("select failed.");

	if(selret==0)
	{
		timetv.tv_sec=periodic_interval;
		timetv.tv_usec=0;

		if (router_socket >0)
		{
			routingupdate();	
		}
		continue;
	}
	timetv.tv_sec = tv.tv_sec;
	timetv.tv_usec = tv.tv_usec;

        /* Loop through file descriptors to check which ones are ready */
        for(sock_index=0; sock_index<=head_fd; sock_index+=1){

            if(FD_ISSET(sock_index, &watch_list)){

                /* control_socket */
                if(sock_index == control_socket){
                    fdaccept = new_control_conn(sock_index);

                    /* Add to watched socket list */
                    FD_SET(fdaccept, &master_list);
                    if(fdaccept > head_fd) head_fd = fdaccept;
                }

                /* router_socket */
                else if(sock_index == router_socket){
		
                    //call handler that will call recvfrom() .....
			struct sockaddr_in rec_addr;
			memset(&rec_addr, 0 ,sizeof(rec_addr));			
			int addr_len=sizeof rec_addr;
			int size=OFFSET_EIGHT+(OFFSET_TWEL * numnodes);
                    	char *buffer=(char*) malloc(size);
			memset(buffer,0,size);
  	 		int len = recvfrom(router_socket, buffer,size, 0, (struct sockaddr *) &rec_addr, &addr_len);

			if(len>0)
			{
				distancevec(buffer);
			}		        
                 }

                /* data_socket */
                else if(sock_index == data_socket){
                    //new_data_conn(sock_index);
                }

                /* Existing connection */
                else{
                    if(isControl(sock_index)){
                        if(!control_recv_hook(sock_index)) 
				FD_CLR(sock_index, &master_list);
						
                    }
                    //else if isData(sock_index);
                    else ERROR("Unknown socket index");
                }
            }
        }
    }
}

void init()
{
    control_socket = create_control_sock();

    //router_socket and data_socket will be initialized after INIT from controller

    FD_ZERO(&master_list);
    FD_ZERO(&watch_list);

    /* Register the control socket */
    FD_SET(control_socket, &master_list);
    head_fd = control_socket;
	

    main_loop();
}
