#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include "config.h"

/* functions implements */
int set_cpu_nums(int cpu_nums)
{
    m_config.num_cores = cpu_nums;
}

void dump_config()
{
    printf("num_cores:%d\n", m_config.num_cores);
}

int set_nics()
{
	printf("setting nics ...");	
}

/* init arp table */
int init_arp_table()
{
    m_config.arps = (arp_info_t)calloc(MAX_ARPS, sizeof(struct arp_info));

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
            printf("%d\n", num_of_arps);
            
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

#ifdef _DEVELOP_
    for (arp_idx = 0; arp_idx < m_config.num_of_arps; arp_idx++) {
        unsigned char *mac_addr = m_config.arps[arp_idx].haddr;    
    
        printf("ip:     %08x\n", m_config.arps[arp_idx].ip);
        printf("mask:   %08x\n", m_config.arps[arp_idx].mask);
        printf("masked: %08x\n", m_config.arps[arp_idx].masked);
        printf("mac:    %x:%x:%x:%x:%x:%x\n\n", mac_addr[0], mac_addr[1],
            mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    }
#endif

    fclose(fp);
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
    add_to_arp_table_core(m_config.arps + arp_idx, dest_ip, prefix, dest_mac);

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
    // printf("ip:%08x\nmask:%08x\nmasked:%08x\n",
    //     arp->ip, arp->mask, arp->masked);

    return 0;
}

int set_routes(char *route_config_file)
{

}