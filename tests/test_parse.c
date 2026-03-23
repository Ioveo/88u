#include "../include/parse.h"
#include <assert.h>

int main(void) {
    PortList pl = parse_ports("1080,1081-1083");
    assert(pl.count == 4);
    assert(pl.ports[0] == 1080 && pl.ports[3] == 1083);
    portlist_free(&pl);

    IpList iplist = {0};
    assert(parse_token_ipv4(&iplist, "192.168.0.1-3") == 0);
    assert(count_token_fast_ipv4(&iplist) == 3);
    iplist_free(&iplist);
    return 0;
}
