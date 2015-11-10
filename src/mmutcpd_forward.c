#include <stdio.h>
#include <stdlib.h>
#include "forward.h"
#include "config.h"

int main(int argc, char* argv[])
{
    init_rte();
    set_rte("../config/etc/rte.conf");
    //dump_rte_config();
    //return 0;
    init_dpdk_rte();
    init_nics();
    set_nics();
    //dump_nic_list();
    //return 0;
    init_arp_table();
    set_arp_table("../config/etc/arp.conf");
    //dump_arp_table();
    //return 0;
    init_route_table();
    set_route_table("../config/etc/route.conf");
    //dump_route_table();
    printf("\nConfig module OK!\n");


    

    return 0;
}
