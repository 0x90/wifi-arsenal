#include <netinet/ether.h>

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/macvlan.h>

int main(int argc, char *argv[])
{
	struct rtnl_link *link;
	struct nl_cache *link_cache;
	struct nl_sock *sk;
        struct nl_addr* addr;
	int err, master_index;

	sk = nl_socket_alloc();
	if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
		nl_perror(err, "Unable to connect socket");
		return err;
	}

	if ((err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache)) < 0) {
		nl_perror(err, "Unable to allocate cache");
		return err;
	}

	if (!(master_index = rtnl_link_name2i(link_cache, "eth0"))) {
		fprintf(stderr, "Unable to lookup eth0");
		return -1;
	}

	link = rtnl_link_macvlan_alloc();

	rtnl_link_set_link(link, master_index);

        addr = nl_addr_build(AF_LLC, ether_aton("00:11:22:33:44:55"), ETH_ALEN);
        rtnl_link_set_addr(link, addr);
        nl_addr_put(addr);

	rtnl_link_macvlan_set_mode(link, rtnl_link_macvlan_str2mode("bridge"));

	if ((err = rtnl_link_add(sk, link, NLM_F_CREATE)) < 0) {
		nl_perror(err, "Unable to add link");
		return err;
	}

	rtnl_link_put(link);
	nl_close(sk);

	return 0;
}
