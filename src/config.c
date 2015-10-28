#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include "config.h"

/* functions implements */

/* init rte of dpdk, default config */
int init_rte()
{
    m_config.num_cores = 1;
    m_config.num_memory_channels = 2;
    m_config.max_concurrency = 10000;
    m_config.max_num_buffers = 10000;
    m_config.recv_buf_size = 8192;
    m_config.send_buf_size = 8192;
}

/* set rte of dpdk */
int set_rte(char *rte_config_file)
{
    FILE *fp;
    fp = fopen(rte_config_file, "rt");

    char line[MAX_FILE_LEN];
    char *p;
    char *tail;

    /* read rte config from file */
    while(NULL != fgets(line, MAX_FILE_LEN, fp)) {
        /* read each line */
        p = line;

        //skip spaces in front
        while(isspace(*p))
            p++;

        //skip spaces in tail
        tail = p + strlen(p) - 1;
        if (isspace(*tail))
            *tail = 0;

        //skip comment
        if ('#' == *p)
            continue;

        //skip empty line
        if (0 == strlen(p)) 
            continue;

        //process a config line
        set_to_rte(p);
    }

    /* close file */
    fclose(fp);
    return 0;
}

/* set a rte config */
int set_to_rte(char *rte_line)
{
    char *ptr;
    char *key;
    char *value;

    key = strtok_r(rte_line, " \t=", &ptr);
    value = strtok_r(NULL, " \t=", &ptr);

    if (0 == strcmp("CPU_NUM", key)) {
        m_config.num_cores = atoi(value);
    } else if (0 == strcmp("MEM_CHAN_NUM", key)) {
        m_config.num_memory_channels = atoi(value);
    } else if (0 == strcmp("MAX_CONCURRENCY_NUM", key)) {
        m_config.max_concurrency = atoi(value);
    } else if (0 == strcmp("MAX_BUF_NUM", key)) {
        m_config.max_num_buffers = atoi(value);
    } else if (0 == strcmp("RECV_BUF_SIZE", key)) {
        m_config.recv_buf_size = atoi(value);
    } else if (0 == strcmp("SEND_BUF_SIZE", key)) {
        m_config.send_buf_size = atoi(value);
    } 
}

/* dump rte config */
void dump_rte_config()
{
    printf("CPU_NUM             =%d\n", m_config.num_cores);
    printf("MEM_CHAN_NUM        =%d\n", m_config.num_memory_channels);
    printf("MAX_CONCURRENCY_NUM =%d\n", m_config.max_concurrency);
    printf("MAX_BUF_NUM         =%d\n", m_config.max_num_buffers);
    printf("RECV_BUF_SIZE       =%d\n", m_config.recv_buf_size);
    printf("SEND_BUF_SIZE       =%d\n", m_config.send_buf_size);
}

/* init dpdk rte */
int init_dpdk_rte()
{
    int cpu = m_config.num_cores;
    uint32_t cpu_mask = 0;
    char cpu_mask_buf[10];
    char mem_chan_buf[10];
    int i;
    int argc;
    int num_of_devices;

    /* set cpu mask */
    for (i = 0; i < cpu; i++)
        cpu_mask |= 1 << i;
    sprintf(cpu_mask_buf, "%x", cpu_mask);

    /* set mem channels per socket */
    if (m_config.num_memory_channels <= 0) {
        fprintf(stderr, 
            "Error of num_memory_channels.\n");
        exit(-1);
    }
    sprintf(mem_chan_buf, "%d", m_config.num_memory_channels);

	argc = 6;
    char *argv[] = {"",
     "-c", cpu_mask_buf, "-n", mem_chan_buf,
     "--proc-type=auto", ""};

     /* init dpdk eal env */
	if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Invalid EAL args");
        fprintf(stderr, 
            "Error EAL args.\n");
        exit(-1);
     }

     /* get nic ports that support dpdk */
     num_of_devices = rte_eth_dev_count();
	 printf("DPDK devices: %d\n", num_of_devices);
     if (num_of_devices <= 0) {
        rte_exit(EXIT_FAILURE, "No DPDK nic ports\n");
        fprintf(stderr, 
            "Error DPDK nic ports.\n");
        exit(-1);
     }
     m_config.num_of_nics = num_of_devices;

     return 0;
}

/* init nic list */
int init_nics()
{
	int i;

    m_config.num_of_nics = 0;
    m_config.nics = (nic_info_t)calloc(MAX_NICS,
        sizeof(struct nic_info));

    if (NULL == m_config.nics) {
        fprintf(stderr, 
            "Error in calloc, in init_nics.\n");
        exit(-1);
    }

	for (i = 0; i < MAX_NICS; i++) {
		/* use for avoiding count twice! */
		m_config.nics[i].ifindex = -1;
	}
	return 0;
}

/* set nic list */
int set_nics()
{
    struct ifaddrs *ifaddr_head, *ifa;
    int nic_idx = 0;

    if (-1 == getifaddrs(&ifaddr_head)) {
        fprintf(stderr, 
            "Error in getifaddrs, in set_nics.\n");
        exit(-1);
    }

    for (ifa = ifaddr_head; ifa != NULL; ifa = ifa->ifa_next) {
        /* check sa_family */
        if (ifa->ifa_addr->sa_family != AF_INET || ifa->ifa_addr == NULL)
            continue;

        /* add a nic to nics */
        if (!add_to_nics(ifa, nic_idx)) {
            nic_idx++;
            m_config.num_of_nics++;
        }
    }

    free(ifaddr_head);
    return 0;
}

/* dump nic list */
void dump_nic_list()
{
	int nic_idx, i;

	printf("\n\nNIC_NUM:%d\n", m_config.num_of_nics);
	
	for (nic_idx = 0; nic_idx < m_config.num_of_nics; nic_idx++){
		printf("dev_name: %s\n", m_config.nics[nic_idx].dev_name);
		printf("ifindex:  %d\n", m_config.nics[nic_idx].ifindex);
		printf("mac_addr: ");
		for (i = 0; i < ETH_ALEN; i++) {
			printf("%x%c", m_config.nics[nic_idx].haddr[i],
					(i==ETH_ALEN-1)?'\n':':');
		}
		printf("net_mask: %08x\n", m_config.nics[nic_idx].netmask);
		printf("ip_addr:  %08x\n\n", m_config.nics[nic_idx].ip_addr);
	}
}

/* add a nic to nic list */
inline int add_to_nics(struct ifaddrs *ifa, int nic_idx)
{
    struct ifreq ifr;
    int i;
    
    static struct ether_addr nics_ports[RTE_MAX_ETHPORTS];
    /* get mac addr of all devices */
    for (i = 0; i < RTE_MAX_ETHPORTS; i++) 
        rte_eth_macaddr_get(i, &nics_ports[i]);
    
    /* setting dev_name */
    strcpy(m_config.nics[nic_idx].dev_name, ifa->ifa_name);
    strcpy(ifr.ifr_name, ifa->ifa_name);

    /* create socket */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (-1 == sock) {
        fprintf(stderr, 
            "Error in socket, add_to_nics.\n");
        exit(-1);
    }

    /* set ip address */
    if (0 == ioctl(sock, SIOCGIFADDR, &ifr)) {
        struct in_addr sin = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
        m_config.nics[nic_idx].ip_addr = *(uint32_t *)&sin;
    }

    /* set mac address */
    if (0 == ioctl(sock, SIOCGIFHWADDR, &ifr)) {
        for (i = 0; i < ETH_ALEN; i++)
            m_config.nics[nic_idx].haddr[i] = ifr.ifr_addr.sa_data[i];
    }

    /* set netmask */
    if (0 == ioctl(sock, SIOCGIFNETMASK, &ifr)) {
        struct in_addr sin = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
        m_config.nics[nic_idx].netmask = *(uint32_t *)&sin;
    }

    /* close socket */
    close(sock);

    /* set ifindex */
    /* p1p1 p1p2, now only support this format */
    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        if (!memcmp(m_config.nics[nic_idx].haddr, nics_ports + i, 
            ETH_ALEN)) {
			if (m_config.nics[nic_idx].ifindex == i) {
				/* already set it. otherwise, it will count twice! */
				return -1;
			}
            m_config.nics[nic_idx].ifindex = i;
			return 0;
		}
    }
    
    /* TODO */
    /* p1p1:0 p1p1:1 p1p1:2, this format need to be process later! */

    return -1;
}

/* init arp table */
int init_arp_table()
{
    m_config.arps = (arp_info_t)calloc(MAX_ARPS, 
        sizeof(struct arp_info));

    if (NULL == m_config.arps) {
        fprintf(stderr, 
            "Error in calloc, init_arp_table\n");
        exit(-1);
    }

    return 0;
}

/* set arps */
int set_arp_table(char *arp_config_file)
{
#define ARP_NUM "ARP_NUM" 
    FILE *fp;
    fp = fopen(arp_config_file, "rt");
    
    char line[MAX_FILE_LEN];
    char *p;
    char *tail;

    int num_of_arps = 0;
    int has_get_num = 0;
    int arp_idx = 0;
    
    /* read arps from file */
    while(NULL != fgets(line, MAX_FILE_LEN, fp)) {
        /* read each line */
        p = line;

        //skip spaces in front
        while (isspace(*p))
            p++;

        //skip spaces in tail
        tail = p + strlen(p) - 1;
        if (isspace(*tail))
            *tail = 0;

        //skip comment
        if (*p == '#')
            continue;

        //skip empty line
        if (0 == strlen(p))
            continue;
        
        //print the valid line
        //printf("%s\n", p);
        
        //process a config line
        if (!has_get_num && 
            0 == strncmp(p, ARP_NUM, strlen(ARP_NUM))) {
            /* get num of arps */
            //printf("%s\n", ARP_NUM);
            //printf("%s\n", p + strlen(ARP_NUM));
            
            sscanf(p + strlen(ARP_NUM), "%d", &num_of_arps);
            //printf("%d\n", num_of_arps);
            
            if (num_of_arps <= 0) {
                fprintf(stderr, 
                    "Error in arp.conf %s\n", p);
            }
            
            m_config.num_of_arps = num_of_arps;
            has_get_num = 1;
        } else {
            /* add a arp to arp table */
            if (num_of_arps <= 0) {
                fprintf(stderr, 
                    "Error in arp.conf, too many arps\n");
                exit(-1);
            }

            /* add to the arp table */
            if (!add_to_arp_table(p, arp_idx)) {
                num_of_arps--;
                arp_idx++;
            }
        }
    }/* end of while */

    fclose(fp);
    return 0;
}

/* dump arp table */
int dump_arp_table()
{
    int arp_idx;

    printf("\n\nARP_NUM:%d\n", m_config.num_of_arps);

    for (arp_idx = 0; arp_idx < m_config.num_of_arps; arp_idx++) {
        unsigned char *mac_addr = m_config.arps[arp_idx].haddr;    
    
        printf("ip:     %08x\n", m_config.arps[arp_idx].ip);
        printf("prefix: %d\n", m_config.arps[arp_idx].prefix);
        printf("mask:   %08x\n", m_config.arps[arp_idx].mask);
        printf("masked: %08x\n", m_config.arps[arp_idx].masked);
        printf("mac:    %x:%x:%x:%x:%x:%x\n\n", mac_addr[0], mac_addr[1],
            mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    }

    return 0;
}

/* add a arp to arp table */
int add_to_arp_table(char *arp_line, int arp_idx)
{
    char *dest_ip;
    char *prefix;
    char *dest_mac;

    char *ptr;
    dest_ip = strtok_r(arp_line, "/", &ptr);
    prefix = strtok_r(NULL, " ", &ptr);
    dest_mac = strtok_r(NULL, "\n", &ptr);

    if (NULL == dest_ip || NULL == dest_mac) {
        fprintf(stderr, 
            "Error in arp.conf. %s\n", arp_line);
        exit(-1);
    }

    //printf("%s %s %s\n", dest_ip, prefix, dest_mac);
    /* add to the arp table */
    add_to_arp_table_core(m_config.arps + arp_idx, 
        dest_ip, prefix, dest_mac);

}

/* add a arp to arp table core */
inline int add_to_arp_table_core(arp_info_t arp,
    char *dest_ip, char *prefix, char *dest_mac)
{
    uint32_t *ip_addr = &arp->ip;
    unsigned char *mac_addr = arp->haddr;
    int i, cnt = 0, len = strlen(dest_mac);
    uint32_t mask = 0;
    uint8_t *mask_t = (uint8_t *)&mask;
    int prefix_i, j;

    /* translate ip_str to ip_addr in 32bit */
    *ip_addr = inet_addr(dest_ip);
    if (INADDR_NONE == *ip_addr) {
        fprintf(stderr, 
            "Error in arp.conf, wrong ip address %s\n", dest_ip);
        exit(-1);
    }

    /* translate mac_str to mac_addr */
    for (i = 0; i < len; i++)
        if (dest_mac[i] == ':')
            cnt++;

    if (cnt != 5) {
        fprintf(stderr, 
            "Error in arp.conf, wrong mac address %s\n", dest_mac);
        exit(-1);
    }
    sscanf(dest_mac, "%x:%x:%x:%x:%x:%x", mac_addr, mac_addr+1,
        mac_addr+2, mac_addr+3, mac_addr+4, mac_addr+5);
    // printf("%x:%x:%x:%x:%x:%x\n", mac_addr[0], mac_addr[1],
    //     mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

    /* set the mask */
    if (NULL == prefix) {
        prefix_i = 32;
    } else {
        sscanf(prefix, "%d", &prefix_i);
    }
    for (j = 0; j < prefix_i; j++) {
        mask |= 1 << j;
    }
    arp->mask = mask;
    arp->masked = mask & arp->ip;
    arp->prefix = prefix_i;
    // printf("ip:%08x\nmask:%08x\nmasked:%08x\n",
    //     arp->ip, arp->mask, arp->masked);

    return 0;
}


/* init route table */
int init_route_table()
{
    m_config.routes = (route_info_t)calloc(MAX_ROUTES,
        sizeof(struct route_info));

    if (NULL == m_config.routes) {
        fprintf(stderr, 
            "Error in calloc, init_route_table\n");
    }
}

/* set route table */
int set_route_table(char *route_config_file)
{
#define ROUTE_NUM "ROUTE_NUM"
    FILE *fp;
    fp = fopen(route_config_file, "rt");

    char line[MAX_FILE_LEN];
    char *p;
    char *tail;

    int num_of_routes = 0;
    int has_get_num = 0;
    int route_idx = 0;

    /* read routes from file */
    while(NULL != fgets(line, MAX_FILE_LEN, fp)) {
        /* read each line */
        p = line;

        //skip spaces in front
        while(isspace(*p))
            p++;

        //skip spaces in tail
        tail = p + strlen(p) - 1;
        if (isspace(*tail))
            *tail = 0;

        //skip comment
        if ('#' == *p)
            continue;

        //skip empty line
        if (0 == strlen(p)) 
            continue;

        //process a config line
        if (!has_get_num && 
            0 == strncmp(p, ROUTE_NUM, strlen(ROUTE_NUM))) {
            /* get num of routes */
            sscanf(p + strlen(ROUTE_NUM), "%d", &num_of_routes);
            printf("ROUTE_NUM: %d\n", num_of_routes);

            if (num_of_routes <= 0) {
                fprintf(stderr, 
                    "Error in route.conf, %s\n", p);
            }

            m_config.num_of_routes = num_of_routes;
            has_get_num = 1;
        } else {
            /* add a route to route table */
            if (num_of_routes <= 0) {
                fprintf(stderr, 
                    "Error in route.conf, too many routes.\n");
                exit(-1);
            }

            /* add to the route table */
            if (!add_to_route_table(p, route_idx)) {
                num_of_routes--;
                route_idx++;
            }
        }
    }/* end of while */

    fclose(fp);
    return 0;
}

/* dump route table */
int dump_route_table()
{
	int route_idx;

    printf("\n\nROUTE_NUM:%d\n", m_config.num_of_routes);
    
	for (route_idx = 0; route_idx < m_config.num_of_routes; route_idx++) {
        printf("ip:     %08x\n", m_config.routes[route_idx].ip);
        printf("prefix: %d\n", m_config.routes[route_idx].prefix);
        printf("mask:   %08x\n", m_config.routes[route_idx].mask);
        printf("masked: %08x\n", m_config.routes[route_idx].masked);
        printf("ifindex:%d\n", m_config.routes[route_idx].ifindex);

    }        

    return 0;    
}

/* add a route to route table */
int add_to_route_table(char *route_line, int route_idx)
{
    char *dest_ip;
    char *prefix;
    char *dev_name;
    int ret;

    char *ptr;
    dest_ip = strtok_r(route_line, "/", &ptr);
    prefix = strtok_r(NULL, " ", &ptr);
    dev_name = strtok_r(NULL, "\n", &ptr);

    if (NULL == dest_ip || NULL == dev_name) {
        fprintf(stderr, 
            "Error in route.conf, %s\n", route_line);
        exit(-1);
    }

    /* add to the route table */
    ret = add_to_route_table_core(m_config.routes + route_idx, 
        dest_ip, prefix, dev_name);

    return ret;
}

/* add a route to route table core */
inline int add_to_route_table_core(route_info_t route,
    char *dest_ip, char *prefix, char *dev_name)
{
    printf("ip:       %s\n", dest_ip);
    printf("prefix:   %s\n", prefix);
    printf("dev_name: %s\n", dev_name);
    uint32_t *ip_addr = &route->ip;
    int prefix_i, j;
    uint32_t mask = 0;

    /* translate ip_str to ip_addr in 32bit */
    *ip_addr = inet_addr(dest_ip);
    if (INADDR_NONE == *ip_addr) {
        fprintf(stderr, 
            "Error in route.conf, wrong ip address %s\n", dest_ip);
        exit(-1);
    }

    /* set the mask */
    if (NULL == prefix) {
        prefix_i = 32;
    } else {
        sscanf(prefix, "%d", &prefix_i);
    }
    for (j = 0; j < prefix_i; j++) {
        mask |= 1 << j;
    }
    route->mask = mask;
    route->masked = mask & route->ip;
    route->prefix = prefix_i;

    for (j = 0; j < m_config.num_of_nics; j++) {
        if (strcmp(m_config.nics[j].dev_name, dev_name) == 0) {
            route->ifindex = m_config.nics[j].ifindex;
            break;
        }
    }

    return 0;
}

