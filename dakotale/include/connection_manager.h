#ifndef CONNECTION_MANAGER_H_
#define CONNECTION_MANAGER_H_

int control_socket, router_socket, data_socket;
fd_set master_list, watch_list;
int head_fd;
struct timeval tv_temp;
void init();

#endif
