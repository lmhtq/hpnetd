#ifndef __CONFIG_H_
#define __CONFIG_H_

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef MAX_FILE_LEN
#define MAX_FILE_LEN 1024
#endif

#include <inttypes.h>

typedef struct config_variables config_variables_t;
#define MAX_ARPS 1024
#define MAX_ROUTES 1024
#define _DEVELOP_

/* struct of a NIC */
struct nic_info
{
    char dev_name[128];
    int ifindex;
    unsigned char haddr[ETH_ALEN];
    uint32_t netmask;
    uint32_t ip_addr;
};
typedef struct nic_info* nic_info_t;


/* struct of a arp */
struct arp_info
{
    uint32_t ip;
    int8_t prefix;
    uint32_t mask;
    uint32_t masked;
    unsigned char haddr[ETH_ALEN];
};
typedef struct arp_info* arp_info_t;

/* strcut of a route */
struct route_info
{
    uint32_t ip;
    uint32_t mask;
    uint32_t masked;
    int prefix;
    int nif;
};
typedef struct route_info* route_info_t;

/* struct of config_variables */
struct config_variables
{
    /* cpu, memory */
    int num_cores;
    int num_memory_channels;

    /* concurrency */
    int max_concurrency;

    /* buffer config */
    int max_num_buffers;
    int recv_buf_size;
    int send_buf_size;

    /* NICs */
    int num_of_dpdk_devices;
    nic_info_t nics;

    /* ARP */
    int num_of_arps;
    arp_info_t arps;

    /* ROUTE */
    int num_of_routes;
    route_info_t routes;

};

/* mmutcpd's basic config */
config_variables_t m_config;

/* functions definition */

int set_cpu_nums();

void dump_config();

int set_nics();

/* init arp table */
int init_arp_table();

/* set arp table */
int set_arp_table(char *arp_config_file);

/* add a arp to arp table */
int add_to_arp_table(char *arp_line, int arp_idx);

/* add a arp to arp table core */
inline int add_to_arp_table_core(arp_info_t arp,
    char *dest_ip, char *prefix, char *dest_mac);

/* init route table */
int init_route_table();

/* set route table */
int set_route_table(char *route_config_file);

/* add a route to route table */
int add_to_route_table(char *route_line, int route_idx);

/* add a route to route table core */
inline int add_to_route_table_core(route_info_t route,
    char *dest_ip, char *prefix, char *dev_name);

#endif /* __CONFIG_H_ */