#ifndef _C_GLOBALS_
#define _C_GLOBALS_
//
// contains all the component external definitions used by the lwip stack
// initialized in tcpip component.
//
#include <sys/exception.h>
#include <services/services.h>
#include <drivers/adi_dev.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct net_config_info
				{
				    int   imask;
					short rx_buffs;
					short tx_buffs;
					short rx_buff_datalen;
					short tx_buff_datalen;
					short buff_area;
					short buff_area_size;
					short use_dhcp;
					unsigned char mac_addr[6];
			        int ipaddr;
					int netmask;
					int gateway;
				}net_config_info;

extern struct net_config_info user_net_config_info[];

int init_stack(int poll_th_pri, int poll_th_period,int buffer_length,char *buffer_start);
int start_stack(void);
int stop_stack(void);

int set_pli_services(int num_services,ADI_DEV_DEVICE_HANDLE *pdd_handles);
void stack_callback_handler(void *arg1,unsigned int event,void* pack_list);

int GetSocketError();

int gethostaddr(int nwifce_no,char *host_addr);
int sethostaddr(int nwifce_no,char *host_addr);
#ifdef __cplusplus
}
#endif
#endif /* _C_GLOBALS_ */
