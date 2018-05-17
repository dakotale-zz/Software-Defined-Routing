#ifndef CONTROL_HANDLER_H_
#define CONTROL_HANDLER_H_

int create_control_sock();
int new_control_conn(int sock_index);
bool isControl(int sock_index);
bool control_recv_hook(int sock_index);
void callinit(int sock_index, char *cntrl_payload);
void initack(int sock_index);
void routingupdate();
void sendtocontroller(int sock_index);
void distancevec(char *routing_packet);
#endif