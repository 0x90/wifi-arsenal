#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <errno.h>
#include "acs.h"

struct dl_list offchan_ops_list = {
        (&offchan_ops_list),
        (&offchan_ops_list),
};

struct offchan_ev {
	int ifidx;
	int freq;
	__u32 duration;
	__u64 cookie;
};

struct wait_event {
	int n_cmds;
	const __u32 *cmds;
	bool completed;
	struct offchan_ev ev; /* use union later for other events */
};

struct offchan_op {
	struct offchan_ev ev;
	struct dl_list list_member;
};

static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static bool offchan_ops_match(struct offchan_op *op1, struct offchan_op *op2)
{
	/*
	 * Note we do not check for the duration, just checking for the
	 * cookie should be enough though
	 */
	if (op1->ev.ifidx != op2->ev.ifidx)
		return false;
	if (op1->ev.freq != op2->ev.freq)
		return false;
	if (op1->ev.cookie != op2->ev.cookie)
		return false;
	return true;
}

static int wait_sanity_check(struct nl_msg *msg, struct wait_event *wait)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	char ifname[100];
	struct offchan_op *op, *tmp;
	struct offchan_op op_now;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_IFINDEX] ||
	    !tb[NL80211_ATTR_WIPHY_FREQ]) {
		printf("Invalid data passed on event\n");
		return -EINVAL;
	}
	
	op_now.ev.ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
	op_now.ev.freq = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);
	op_now.ev.cookie = nla_get_u64(tb[NL80211_ATTR_COOKIE]);

	if (tb[NL80211_ATTR_DURATION])
		op_now.ev.duration = nla_get_u32(tb[NL80211_ATTR_DURATION]);
	else
		op_now.ev.duration = 0;

	if_indextoname(op_now.ev.ifidx, ifname);

	switch (gnlh->cmd) {
	/*
	 * Theory of operation:
	 *
	 * We may get events for new events from other userspace apps doing
	 * other offchannel operations. The best we can do then is to capture
	 * the cookie for the command we sent (stored in the wait.ev) and then
	 * check if the completed command matches the wait.ev's cookie. Otherwise
	 * we add the received command onto a linked list, this lets us later
	 * send the the kernel multiple offchannel op requests and just deal
	 * with the completions at whatever order the kernel wants to follow.
	 */ 
	case NL80211_CMD_REMAIN_ON_CHANNEL:
		op = (struct offchan_op *) malloc(sizeof(struct offchan_op));

		op->ev.freq = op_now.ev.freq;
		op->ev.ifidx = op_now.ev.ifidx;
		op->ev.cookie = op_now.ev.cookie;
		op->ev.duration = op_now.ev.duration;

		if (op->ev.freq == wait->ev.freq &&
		    op->ev.ifidx == wait->ev.ifidx) {
			wait->ev.duration = op->ev.duration;
			wait->ev.cookie = op->ev.cookie;

			printf("%s: remain on freq: %d MHz, duration: %dms, cookie %llx, completed: ",
			       ifname,
			       op_now.ev.freq,
			       op_now.ev.duration,
			       (unsigned long long) op_now.ev.cookie);
		}

		dl_list_add_tail(&offchan_ops_list, &op->list_member);

		break;
	case NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL:
		dl_list_for_each_safe(op, tmp, &offchan_ops_list, struct offchan_op, list_member) {
			if (!offchan_ops_match(op, &op_now))
				continue;
			if (wait->ev.cookie == op->ev.cookie) {
				wait->completed = true;
				printf("yes\n");
			}
			dl_list_del(&op->list_member);
			free(op);
		}
		break;
	default:
		printf("unknown event %d\n", gnlh->cmd);
		break;
	}

	fflush(stdout);
	return NL_SKIP;
}

static int wait_event(struct nl_msg *msg, void *arg)
{
	struct wait_event *wait = arg;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int i;

	for (i = 0; i < wait->n_cmds; i++) {
		if (gnlh->cmd == wait->cmds[i]) {
			wait_sanity_check(msg, wait);
		}
	}

	return NL_SKIP;
}

int nl80211_add_membership_mlme(struct nl80211_state *state)
{
	int mcid, ret;

	/* MLME multicast group */
	mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "mlme");
	if (mcid >= 0) {
		ret = nl_socket_add_membership(state->nl_sock, mcid);
		if (ret)
			return ret;
	}

	return 0;
}

__u32 wait_for_offchan_op(struct nl80211_state *state,
			  int devidx, int freq,
			  const int n_waits, const __u32 *waits)
{
	struct nl_cb *cb = nl_cb_alloc(nl_debug ? NL_CB_DEBUG : NL_CB_DEFAULT);
	struct wait_event wait;

	if (!cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		return -ENOMEM;
	}

	/* no sequence checking for multicast messages */
	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);

	wait.cmds = waits;
	wait.n_cmds = n_waits;
	wait.ev.ifidx = devidx;
	wait.ev.freq = freq;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, wait_event, &wait);

	wait.completed = 0;

	while (!wait.completed)
		nl_recvmsgs(state->nl_sock, cb);

	nl_cb_put(cb);

	return 0;
}

void clear_offchan_ops_list(void)
{
	struct offchan_op *op, *tmp;

	dl_list_for_each_safe(op, tmp, &offchan_ops_list, struct offchan_op, list_member) {
		dl_list_del(&op->list_member);
		free(op);
	}
}
