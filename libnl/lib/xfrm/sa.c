/*
 * Copyright (C) 2012 Texas Instruments Incorporated - http://www.ti.com/
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *    Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the
 *    distribution.
 *
 *    Neither the name of Texas Instruments Incorporated nor the names of
 *    its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * @ingroup xfrmnl
 * @defgroup sa Security Association
 * @brief
 */

#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/object.h>
#include <netlink/xfrm/selector.h>
#include <netlink/xfrm/lifetime.h>
#include <time.h>

/** @cond SKIP */
#define XFRM_SA_ATTR_SEL            0x01
#define XFRM_SA_ATTR_DADDR          0x02
#define XFRM_SA_ATTR_SPI            0x04
#define XFRM_SA_ATTR_PROTO          0x08
#define XFRM_SA_ATTR_SADDR          0x10
#define XFRM_SA_ATTR_LTIME_CFG      0x20
#define XFRM_SA_ATTR_LTIME_CUR      0x40
#define XFRM_SA_ATTR_STATS          0x80
#define XFRM_SA_ATTR_SEQ            0x100
#define XFRM_SA_ATTR_REQID          0x200
#define XFRM_SA_ATTR_FAMILY         0x400
#define XFRM_SA_ATTR_MODE           0x800
#define XFRM_SA_ATTR_REPLAY_WIN     0x1000
#define XFRM_SA_ATTR_FLAGS          0x2000
#define XFRM_SA_ATTR_ALG_AEAD       0x4000
#define XFRM_SA_ATTR_ALG_AUTH       0x8000
#define XFRM_SA_ATTR_ALG_CRYPT      0x10000
#define XFRM_SA_ATTR_ALG_COMP       0x20000
#define XFRM_SA_ATTR_ENCAP          0x40000
#define XFRM_SA_ATTR_TFCPAD         0x80000
#define XFRM_SA_ATTR_COADDR         0x100000
#define XFRM_SA_ATTR_MARK           0x200000
#define XFRM_SA_ATTR_SECCTX         0x400000
#define XFRM_SA_ATTR_REPLAY_MAXAGE  0x800000
#define XFRM_SA_ATTR_REPLAY_MAXDIFF 0x1000000
#define XFRM_SA_ATTR_REPLAY_STATE   0x2000000
#define XFRM_SA_ATTR_EXPIRE         0x4000000

static struct nl_cache_ops  xfrmnl_sa_ops;
static struct nl_object_ops xfrm_sa_obj_ops;
/** @endcond */

static void xfrm_sa_alloc_data(struct nl_object *c)
{
	struct xfrmnl_sa* sa =   nl_object_priv (c);

	if ((sa->sel = xfrmnl_sel_alloc ()) == NULL)
		return;

	if ((sa->lft = xfrmnl_ltime_cfg_alloc ()) == NULL)
		return;
}

static void xfrm_sa_free_data(struct nl_object *c)
{
	struct xfrmnl_sa* sa =   nl_object_priv (c);

	if (sa == NULL)
		return;

	xfrmnl_sel_put (sa->sel);
	xfrmnl_ltime_cfg_put (sa->lft);
	nl_addr_put (sa->id.daddr);
	nl_addr_put (sa->saddr);

	if (sa->aead)
		free (sa->aead);
	if (sa->auth)
		free (sa->auth);
	if (sa->crypt)
		free (sa->crypt);
	if (sa->comp)
		free (sa->comp);
	if (sa->encap)
		free (sa->encap);
	if (sa->coaddr)
		nl_addr_put (sa->coaddr);
	if (sa->sec_ctx)
		free (sa->sec_ctx);
	if (sa->replay_state_esn)
		free (sa->replay_state_esn);
}

static int xfrm_sa_clone(struct nl_object *_dst, struct nl_object *_src)
{
	struct xfrmnl_sa*   dst = nl_object_priv(_dst);
	struct xfrmnl_sa*   src = nl_object_priv(_src);
	uint32_t            len = 0;

	if (src->sel)
		if ((dst->sel = xfrmnl_sel_clone (src->sel)) == NULL)
			return -NLE_NOMEM;

	if (src->lft)
		if ((dst->lft = xfrmnl_ltime_cfg_clone (src->lft)) == NULL)
			return -NLE_NOMEM;

	if (src->id.daddr)
		if ((dst->id.daddr = nl_addr_clone (src->id.daddr)) == NULL)
			return -NLE_NOMEM;

	if (src->saddr)
		if ((dst->saddr = nl_addr_clone (src->saddr)) == NULL)
			return -NLE_NOMEM;

	if (src->aead)
	{
		len = sizeof (struct xfrmnl_algo_aead) + ((src->aead->alg_key_len + 7) / 8);
		if ((dst->aead = calloc (1, len)) == NULL)
			return -NLE_NOMEM;
		memcpy ((void *)dst->aead, (void *)src->aead, len);
	}

	if (src->auth)
	{
		len = sizeof (struct xfrmnl_algo_auth) + ((src->auth->alg_key_len + 7) / 8);
		if ((dst->auth = calloc (1, len)) == NULL)
			return -NLE_NOMEM;
		memcpy ((void *)dst->auth, (void *)src->auth, len);
	}

	if (src->crypt)
	{
		len = sizeof (struct xfrmnl_algo) + ((src->crypt->alg_key_len + 7) / 8);
		if ((dst->crypt = calloc (1, len)) == NULL)
			return -NLE_NOMEM;
		memcpy ((void *)dst->crypt, (void *)src->crypt, len);
	}

	if (src->comp)
	{
		len = sizeof (struct xfrmnl_algo) + ((src->comp->alg_key_len + 7) / 8);
		if ((dst->comp = calloc (1, len)) == NULL)
			return -NLE_NOMEM;
		memcpy ((void *)dst->comp, (void *)src->comp, len);
	}

	if (src->encap)
	{
		len = sizeof (struct xfrmnl_encap_tmpl);
		if ((dst->encap = calloc (1, len)) == NULL)
			return -NLE_NOMEM;
		memcpy ((void *)dst->encap, (void *)src->encap, len);
	}

	if (src->coaddr)
		if ((dst->coaddr = nl_addr_clone (src->coaddr)) == NULL)
			return -NLE_NOMEM;

	if (src->sec_ctx)
	{
		len = sizeof (struct xfrmnl_sec_ctx) + src->sec_ctx->ctx_len;
		if ((dst->sec_ctx = calloc (1, len)) == NULL)
			return -NLE_NOMEM;
		memcpy ((void *)dst->sec_ctx, (void *)src->sec_ctx, len);
	}

	if (src->replay_state_esn)
	{
		len = sizeof (struct xfrmnl_replay_state_esn) + (src->replay_state_esn->bmp_len * sizeof (uint32_t));
		if ((dst->replay_state_esn = calloc (1, len)) == NULL)
			return -NLE_NOMEM;
		memcpy ((void *)dst->replay_state_esn, (void *)src->replay_state_esn, len);
	}

	return 0;
}

static int xfrm_sa_compare(struct nl_object *_a, struct nl_object *_b, uint32_t attrs, int flags)
{
	struct xfrmnl_sa* a  =   (struct xfrmnl_sa *) _a;
	struct xfrmnl_sa* b  =   (struct xfrmnl_sa *) _b;
	int diff = 0;
	int found = 0;

#define XFRM_SA_DIFF(ATTR, EXPR) ATTR_DIFF(attrs, XFRM_SA_ATTR_##ATTR, a, b, EXPR)
	diff |= XFRM_SA_DIFF(SEL,	xfrmnl_sel_cmp(a->sel, b->sel));
	diff |= XFRM_SA_DIFF(DADDR,	nl_addr_cmp(a->id.daddr, b->id.daddr));
	diff |= XFRM_SA_DIFF(SPI,	a->id.spi != b->id.spi);
	diff |= XFRM_SA_DIFF(PROTO,	a->id.proto != b->id.proto);
	diff |= XFRM_SA_DIFF(SADDR,	nl_addr_cmp(a->saddr, b->saddr));
	diff |= XFRM_SA_DIFF(LTIME_CFG,	xfrmnl_ltime_cfg_cmp(a->lft, b->lft));
	diff |= XFRM_SA_DIFF(REQID,	a->reqid != b->reqid);
	diff |= XFRM_SA_DIFF(FAMILY,a->family != b->family);
	diff |= XFRM_SA_DIFF(MODE,a->mode != b->mode);
	diff |= XFRM_SA_DIFF(REPLAY_WIN,a->replay_window != b->replay_window);
	diff |= XFRM_SA_DIFF(FLAGS,a->flags != b->flags);
	diff |= XFRM_SA_DIFF(ALG_AEAD,(strcmp(a->aead->alg_name, b->aead->alg_name) ||
	                              (a->aead->alg_key_len != b->aead->alg_key_len) ||
	                              (a->aead->alg_icv_len != b->aead->alg_icv_len) ||
	                              memcmp(a->aead->alg_key, b->aead->alg_key,
	                              ((a->aead->alg_key_len + 7)/8))));
	diff |= XFRM_SA_DIFF(ALG_AUTH,(strcmp(a->auth->alg_name, b->auth->alg_name) ||
	                              (a->auth->alg_key_len != b->auth->alg_key_len) ||
	                              (a->auth->alg_trunc_len != b->auth->alg_trunc_len) ||
	                              memcmp(a->auth->alg_key, b->auth->alg_key,
	                              ((a->auth->alg_key_len + 7)/8))));
	diff |= XFRM_SA_DIFF(ALG_CRYPT,(strcmp(a->crypt->alg_name, b->crypt->alg_name) ||
	                              (a->crypt->alg_key_len != b->crypt->alg_key_len) ||
	                              memcmp(a->crypt->alg_key, b->crypt->alg_key,
	                              ((a->crypt->alg_key_len + 7)/8))));
	diff |= XFRM_SA_DIFF(ALG_COMP,(strcmp(a->comp->alg_name, b->comp->alg_name) ||
	                              (a->comp->alg_key_len != b->comp->alg_key_len) ||
	                              memcmp(a->comp->alg_key, b->comp->alg_key,
	                              ((a->comp->alg_key_len + 7)/8))));
	diff |= XFRM_SA_DIFF(ENCAP,((a->encap->encap_type != b->encap->encap_type) ||
	                            (a->encap->encap_sport != b->encap->encap_sport) ||
	                            (a->encap->encap_dport != b->encap->encap_dport) ||
	                            nl_addr_cmp(a->encap->encap_oa, b->encap->encap_oa)));
	diff |= XFRM_SA_DIFF(TFCPAD,a->tfcpad != b->tfcpad);
	diff |= XFRM_SA_DIFF(COADDR,nl_addr_cmp(a->coaddr, b->coaddr));
	diff |= XFRM_SA_DIFF(MARK,(a->mark.m != b->mark.m) ||
	                          (a->mark.v != b->mark.v));
	diff |= XFRM_SA_DIFF(SECCTX,((a->sec_ctx->ctx_doi != b->sec_ctx->ctx_doi) ||
	                            (a->sec_ctx->ctx_alg != b->sec_ctx->ctx_alg) ||
	                            (a->sec_ctx->ctx_len != b->sec_ctx->ctx_len) ||
	                            (a->sec_ctx->ctx_sid != b->sec_ctx->ctx_sid) ||
	                            strcmp(a->sec_ctx->ctx_str, b->sec_ctx->ctx_str)));
	diff |= XFRM_SA_DIFF(REPLAY_MAXAGE,a->replay_maxage != b->replay_maxage);
	diff |= XFRM_SA_DIFF(REPLAY_MAXDIFF,a->replay_maxdiff != b->replay_maxdiff);
	diff |= XFRM_SA_DIFF(EXPIRE,a->hard != b->hard);

	/* Compare replay states */
	found = AVAILABLE_MISMATCH (a, b, XFRM_SA_ATTR_REPLAY_STATE);
	if (found == 0) // attribute exists in both objects
	{
		if (((a->replay_state_esn != NULL) && (b->replay_state_esn == NULL)) ||
		    ((a->replay_state_esn == NULL) && (b->replay_state_esn != NULL)))
			found |= 1;

		if (found == 0) // same replay type. compare actual values
		{
			if (a->replay_state_esn)
			{
				if (a->replay_state_esn->bmp_len != b->replay_state_esn->bmp_len)
					diff |= 1;
				else
				{
					uint32_t len = sizeof (struct xfrmnl_replay_state_esn) +
					               (a->replay_state_esn->bmp_len * sizeof (uint32_t));
					diff |= memcmp (a->replay_state_esn, b->replay_state_esn, len);
				}
			}
			else
			{
				if ((a->replay_state.oseq != b->replay_state.oseq) ||
				    (a->replay_state.seq != b->replay_state.seq) ||
				    (a->replay_state.bitmap != b->replay_state.bitmap))
					diff |= 1;
			}
		}
	}
#undef XFRM_SA_DIFF

	return diff;
}

/**
 * @name XFRM SA Attribute Translations
 * @{
 */
static const struct trans_tbl sa_attrs[] = {
	__ADD(XFRM_SA_ATTR_SEL, selector),
	__ADD(XFRM_SA_ATTR_DADDR, daddr),
	__ADD(XFRM_SA_ATTR_SPI, spi),
	__ADD(XFRM_SA_ATTR_PROTO, proto),
	__ADD(XFRM_SA_ATTR_SADDR, saddr),
	__ADD(XFRM_SA_ATTR_LTIME_CFG, lifetime_cfg),
	__ADD(XFRM_SA_ATTR_LTIME_CUR, lifetime_cur),
	__ADD(XFRM_SA_ATTR_STATS, stats),
	__ADD(XFRM_SA_ATTR_SEQ, seqnum),
	__ADD(XFRM_SA_ATTR_REQID, reqid),
	__ADD(XFRM_SA_ATTR_FAMILY, family),
	__ADD(XFRM_SA_ATTR_MODE, mode),
	__ADD(XFRM_SA_ATTR_REPLAY_WIN, replay_window),
	__ADD(XFRM_SA_ATTR_FLAGS, flags),
	__ADD(XFRM_SA_ATTR_ALG_AEAD, alg_aead),
	__ADD(XFRM_SA_ATTR_ALG_AUTH, alg_auth),
	__ADD(XFRM_SA_ATTR_ALG_CRYPT, alg_crypto),
	__ADD(XFRM_SA_ATTR_ALG_COMP, alg_comp),
	__ADD(XFRM_SA_ATTR_ENCAP, encap),
	__ADD(XFRM_SA_ATTR_TFCPAD, tfcpad),
	__ADD(XFRM_SA_ATTR_COADDR, coaddr),
	__ADD(XFRM_SA_ATTR_MARK, mark),
	__ADD(XFRM_SA_ATTR_SECCTX, sec_ctx),
	__ADD(XFRM_SA_ATTR_REPLAY_MAXAGE, replay_maxage),
	__ADD(XFRM_SA_ATTR_REPLAY_MAXDIFF, replay_maxdiff),
	__ADD(XFRM_SA_ATTR_REPLAY_STATE, replay_state),
	__ADD(XFRM_SA_ATTR_EXPIRE, expire),
};

static char* xfrm_sa_attrs2str(int attrs, char *buf, size_t len)
{
	return __flags2str (attrs, buf, len, sa_attrs, ARRAY_SIZE(sa_attrs));
}
/** @} */

/**
 * @name XFRM SA Flags Translations
 * @{
 */
static const struct trans_tbl sa_flags[] = {
	__ADD(XFRM_STATE_NOECN, no ecn),
	__ADD(XFRM_STATE_DECAP_DSCP, decap dscp),
	__ADD(XFRM_STATE_NOPMTUDISC, no pmtu discovery),
	__ADD(XFRM_STATE_WILDRECV, wild receive),
	__ADD(XFRM_STATE_ICMP, icmp),
	__ADD(XFRM_STATE_AF_UNSPEC, unspecified),
	__ADD(XFRM_STATE_ALIGN4, align4),
	__ADD(XFRM_STATE_ESN, esn),
};

char* xfrmnl_sa_flags2str(int flags, char *buf, size_t len)
{
	return __flags2str (flags, buf, len, sa_flags, ARRAY_SIZE(sa_flags));
}

int xfrmnl_sa_str2flag(const char *name)
{
	return __str2flags (name, sa_flags, ARRAY_SIZE(sa_flags));
}
/** @} */

/**
 * @name XFRM SA Mode Translations
 * @{
 */
static const struct trans_tbl sa_modes[] = {
	__ADD(XFRM_MODE_TRANSPORT, transport),
	__ADD(XFRM_MODE_TUNNEL, tunnel),
	__ADD(XFRM_MODE_ROUTEOPTIMIZATION, route optimization),
	__ADD(XFRM_MODE_IN_TRIGGER, in trigger),
	__ADD(XFRM_MODE_BEET, beet),
};

char* xfrmnl_sa_mode2str(int mode, char *buf, size_t len)
{
	return __type2str (mode, buf, len, sa_modes, ARRAY_SIZE(sa_modes));
}

int xfrmnl_sa_str2mode(const char *name)
{
	return __str2type (name, sa_modes, ARRAY_SIZE(sa_modes));
}
/** @} */


static void xfrm_sa_dump_line(struct nl_object *a, struct nl_dump_params *p)
{
	char                dst[INET6_ADDRSTRLEN+5], src[INET6_ADDRSTRLEN+5];
	struct xfrmnl_sa*   sa  =   (struct xfrmnl_sa *) a;
	char                flags[128], mode[128];
	time_t              add_time, use_time;
	struct tm           *add_time_tm, *use_time_tm;

	nl_dump_line(p, "src %s dst %s family: %s\n", nl_addr2str(sa->saddr, src, sizeof(src)),
	             nl_addr2str(sa->id.daddr, dst, sizeof(dst)),
	             nl_af2str (sa->family, flags, sizeof (flags)));

	nl_dump_line(p, "\tproto %s spi 0x%x reqid %u\n",
	             nl_ip_proto2str (sa->id.proto, flags, sizeof(flags)),
	             sa->id.spi, sa->reqid);

	xfrmnl_sa_flags2str(sa->flags, flags, sizeof (flags));
	xfrmnl_sa_mode2str(sa->mode, mode, sizeof (mode));
	nl_dump_line(p, "\tmode: %s flags: %s (0x%x) seq: %u replay window: %u\n",
	             mode, flags, sa->flags, sa->seq, sa->replay_window);

	nl_dump_line(p, "\tlifetime configuration: \n");
	if (sa->lft->soft_byte_limit == XFRM_INF)
		sprintf (flags, "INF");
	else
		sprintf (flags, "%" PRIu64, sa->lft->soft_byte_limit);
	if (sa->lft->soft_packet_limit == XFRM_INF)
		sprintf (mode, "INF");
	else
		sprintf (mode, "%" PRIu64, sa->lft->soft_packet_limit);
	nl_dump_line(p, "\t\tsoft limit: %s (bytes), %s (packets)\n", flags, mode);
	if (sa->lft->hard_byte_limit == XFRM_INF)
		sprintf (flags, "INF");
	else
		sprintf (flags, "%" PRIu64, sa->lft->hard_byte_limit);
	if (sa->lft->hard_packet_limit == XFRM_INF)
		sprintf (mode, "INF");
	else
		sprintf (mode, "%" PRIu64, sa->lft->hard_packet_limit);
	nl_dump_line(p, "\t\thard limit: %s (bytes), %s (packets)\n", flags, mode);
	nl_dump_line(p, "\t\tsoft add_time: %llu (seconds), soft use_time: %llu (seconds) \n",
	             sa->lft->soft_add_expires_seconds, sa->lft->soft_use_expires_seconds);
	nl_dump_line(p, "\t\thard add_time: %llu (seconds), hard use_time: %llu (seconds) \n",
	             sa->lft->hard_add_expires_seconds, sa->lft->hard_use_expires_seconds);

	nl_dump_line(p, "\tlifetime current: \n");
	nl_dump_line(p, "\t\t%llu bytes, %llu packets\n", sa->curlft.bytes, sa->curlft.packets);
	if (sa->curlft.add_time != 0)
	{
		add_time = sa->curlft.add_time;
		add_time_tm = gmtime (&add_time);
		strftime (flags, 128, "%Y-%m-%d %H-%M-%S", add_time_tm);
	}
	else
	{
		sprintf (flags, "%s", "-");
	}

	if (sa->curlft.use_time != 0)
	{
		use_time = sa->curlft.use_time;
		use_time_tm = gmtime (&use_time);
		strftime (mode, 128, "%Y-%m-%d %H-%M-%S", use_time_tm);
	}
	else
	{
		sprintf (mode, "%s", "-");
	}
	nl_dump_line(p, "\t\tadd_time: %s, use_time: %s\n", flags, mode);

	if (sa->aead)
	{
		nl_dump_line(p, "\tAEAD Algo: \n");
		nl_dump_line(p, "\t\tName: %s Key len(bits): %u ICV Len(bits): %u\n",
		             sa->aead->alg_name, sa->aead->alg_key_len, sa->aead->alg_icv_len);
	}

	if (sa->auth)
	{
		nl_dump_line(p, "\tAuth Algo: \n");
		nl_dump_line(p, "\t\tName: %s Key len(bits): %u Trunc len(bits): %u\n",
		             sa->auth->alg_name, sa->auth->alg_key_len, sa->auth->alg_trunc_len);
	}

	if (sa->crypt)
	{
		nl_dump_line(p, "\tEncryption Algo: \n");
		nl_dump_line(p, "\t\tName: %s Key len(bits): %u\n",
		             sa->crypt->alg_name, sa->crypt->alg_key_len);
	}

	if (sa->comp)
	{
		nl_dump_line(p, "\tCompression Algo: \n");
		nl_dump_line(p, "\t\tName: %s Key len(bits): %u\n",
		             sa->comp->alg_name, sa->comp->alg_key_len);
	}

	if (sa->encap)
	{
		nl_dump_line(p, "\tEncapsulation template: \n");
		nl_dump_line(p, "\t\tType: %d Src port: %d Dst port: %d Encap addr: %s\n",
		             sa->encap->encap_type, sa->encap->encap_sport, sa->encap->encap_dport,
		             nl_addr2str (sa->encap->encap_oa, dst, sizeof (dst)));
	}

	if (sa->ce_mask & XFRM_SA_ATTR_TFCPAD)
		nl_dump_line(p, "\tTFC Pad: %u\n", sa->tfcpad);

	if (sa->ce_mask & XFRM_SA_ATTR_COADDR)
		nl_dump_line(p, "\tCO Address: %s\n", nl_addr2str (sa->coaddr, dst, sizeof (dst)));

	if (sa->ce_mask & XFRM_SA_ATTR_MARK)
		nl_dump_line(p, "\tMark mask: 0x%x Mark value: 0x%x\n", sa->mark.m, sa->mark.v);

	if (sa->ce_mask & XFRM_SA_ATTR_SECCTX)
		nl_dump_line(p, "\tDOI: %d Algo: %d Len: %u SID: %u ctx: %s\n", sa->sec_ctx->ctx_doi,
		             sa->sec_ctx->ctx_alg, sa->sec_ctx->ctx_len, sa->sec_ctx->ctx_sid, sa->sec_ctx->ctx_str);

	nl_dump_line(p, "\treplay info: \n");
	nl_dump_line(p, "\t\tmax age %u max diff %u \n", sa->replay_maxage, sa->replay_maxdiff);

	if (sa->ce_mask & XFRM_SA_ATTR_REPLAY_STATE)
	{
		nl_dump_line(p, "\treplay state info: \n");
		if (sa->replay_state_esn)
		{
			nl_dump_line(p, "\t\toseq %u seq %u oseq_hi %u seq_hi %u replay window: %u \n",
			             sa->replay_state_esn->oseq, sa->replay_state_esn->seq,
			             sa->replay_state_esn->oseq_hi, sa->replay_state_esn->seq_hi,
			             sa->replay_state_esn->replay_window);
		}
		else
		{
			nl_dump_line(p, "\t\toseq %u seq %u bitmap: %u \n", sa->replay_state.oseq,
			             sa->replay_state.seq, sa->replay_state.bitmap);
		}
	}

	nl_dump_line(p, "\tselector info: \n");
	xfrmnl_sel_dump (sa->sel, p);

	nl_dump_line(p, "\tHard: %d\n", sa->hard);

	nl_dump(p, "\n");
}

static void xfrm_sa_dump_stats(struct nl_object *a, struct nl_dump_params *p)
{
	struct xfrmnl_sa*   sa  =   (struct xfrmnl_sa*)a;

	nl_dump_line(p, "\tstats: \n");
	nl_dump_line(p, "\t\treplay window: %u replay: %u integrity failed: %u \n",
	             sa->stats.replay_window, sa->stats.replay, sa->stats.integrity_failed);

	return;
}

static void xfrm_sa_dump_details(struct nl_object *a, struct nl_dump_params *p)
{
	xfrm_sa_dump_line(a, p);
	xfrm_sa_dump_stats (a, p);
}

/**
 * @name XFRM SA Object Allocation/Freeage
 * @{
 */

struct xfrmnl_sa* xfrmnl_sa_alloc(void)
{
	return (struct xfrmnl_sa*) nl_object_alloc(&xfrm_sa_obj_ops);
}

void xfrmnl_sa_put(struct xfrmnl_sa* sa)
{
	nl_object_put((struct nl_object *) sa);
}

/** @} */

/**
 * @name SA Cache Managament
 * @{
 */

/**
 * Build a SA cache including all SAs currently configured in the kernel.
 * @arg sock		Netlink socket.
 * @arg result		Pointer to store resulting cache.
 *
 * Allocates a new SA cache, initializes it properly and updates it
 * to include all SAs currently configured in the kernel.
 *
 * @return 0 on success or a negative error code.
 */
int xfrmnl_sa_alloc_cache(struct nl_sock *sock, struct nl_cache **result)
{
	return nl_cache_alloc_and_fill(&xfrmnl_sa_ops, sock, result);
}

/**
 * Look up a SA by destination address, SPI, protocol
 * @arg cache		SA cache
 * @arg daddr		destination address of the SA
 * @arg spi         SPI
 * @arg proto       protocol
 * @return sa handle or NULL if no match was found.
 */
struct xfrmnl_sa* xfrmnl_sa_get(struct nl_cache* cache, struct nl_addr* daddr,
                                unsigned int spi, unsigned int proto)
{
	struct xfrmnl_sa *sa;

	//nl_list_for_each_entry(sa, &cache->c_items, ce_list) {
	for (sa = (struct xfrmnl_sa*)nl_cache_get_first (cache);
		 sa != NULL;
		 sa = (struct xfrmnl_sa*)nl_cache_get_next ((struct nl_object*)sa))
	{
		if (sa->id.proto == proto &&
		    sa->id.spi == spi &&
			!nl_addr_cmp(sa->id.daddr, daddr))
		{
			nl_object_get((struct nl_object *) sa);
			return sa;
		}

	}

	return NULL;
}


/** @} */


static struct nla_policy xfrm_sa_policy[XFRMA_MAX+1] = {
	[XFRMA_SA]              = { .minlen = sizeof(struct xfrm_usersa_info)},
	[XFRMA_ALG_AUTH_TRUNC]  = { .minlen = sizeof(struct xfrm_algo_auth)},
	[XFRMA_ALG_AEAD]        = { .minlen = sizeof(struct xfrm_algo_aead) },
	[XFRMA_ALG_AUTH]        = { .minlen = sizeof(struct xfrm_algo) },
	[XFRMA_ALG_CRYPT]       = { .minlen = sizeof(struct xfrm_algo) },
	[XFRMA_ALG_COMP]        = { .minlen = sizeof(struct xfrm_algo) },
	[XFRMA_ENCAP]           = { .minlen = sizeof(struct xfrm_encap_tmpl) },
	[XFRMA_TMPL]            = { .minlen = sizeof(struct xfrm_user_tmpl) },
	[XFRMA_SEC_CTX]         = { .minlen = sizeof(struct xfrm_sec_ctx) },
	[XFRMA_LTIME_VAL]       = { .minlen = sizeof(struct xfrm_lifetime_cur) },
	[XFRMA_REPLAY_VAL]      = { .minlen = sizeof(struct xfrm_replay_state) },
	[XFRMA_REPLAY_THRESH]   = { .type = NLA_U32 },
	[XFRMA_ETIMER_THRESH]   = { .type = NLA_U32 },
	[XFRMA_SRCADDR]         = { .minlen = sizeof(xfrm_address_t) },
	[XFRMA_COADDR]          = { .minlen = sizeof(xfrm_address_t) },
	[XFRMA_MARK]            = { .minlen = sizeof(struct xfrm_mark) },
	[XFRMA_TFCPAD]          = { .type = NLA_U32 },
	[XFRMA_REPLAY_ESN_VAL]  = { .minlen = sizeof(struct xfrm_replay_state_esn) },
};

static int xfrm_sa_request_update(struct nl_cache *c, struct nl_sock *h)
{
	struct xfrm_id   sa_id;

	memset ((void *)&sa_id, 0, sizeof (struct xfrm_id));
	return nl_send_simple (h, XFRM_MSG_GETSA, NLM_F_DUMP,(void*)&sa_id, sizeof (struct xfrm_id));
}

int xfrmnl_sa_parse(struct nlmsghdr *n, struct xfrmnl_sa **result)
{
	struct xfrmnl_sa*           sa;
	struct nlattr               *tb[XFRMA_MAX + 1];
	struct xfrm_usersa_info*    sa_info;
	struct xfrm_user_expire*    ue;
	int                         len, err;
	struct nl_addr*             addr;

	sa = xfrmnl_sa_alloc();
	if (!sa) {
		err = -NLE_NOMEM;
		goto errout;
	}

	sa->ce_msgtype = n->nlmsg_type;
	if (n->nlmsg_type == XFRM_MSG_EXPIRE)
	{
		ue = nlmsg_data(n);
		sa_info = &ue->state;
		sa->hard = ue->hard;
		sa->ce_mask |= XFRM_SA_ATTR_EXPIRE;
	}
	else if (n->nlmsg_type == XFRM_MSG_DELSA)
	{
		sa_info = (struct xfrm_usersa_info*)(nlmsg_data(n) + sizeof (struct xfrm_usersa_id) + NLA_HDRLEN);
	}
	else
	{
		sa_info = nlmsg_data(n);
	}

	err = nlmsg_parse(n, sizeof(struct xfrm_usersa_info), tb, XFRMA_MAX, xfrm_sa_policy);
	if (err < 0)
		goto errout;

	if (sa_info->sel.family == AF_INET)
		addr    = nl_addr_build (sa_info->sel.family, &sa_info->sel.daddr.a4, sizeof (sa_info->sel.daddr.a4));
	else
		addr    = nl_addr_build (sa_info->sel.family, &sa_info->sel.daddr.a6, sizeof (sa_info->sel.daddr.a6));
	nl_addr_set_prefixlen (addr, sa_info->sel.prefixlen_d);
	xfrmnl_sel_set_daddr (sa->sel, addr);
	xfrmnl_sel_set_prefixlen_d (sa->sel, sa_info->sel.prefixlen_d);

	if (sa_info->sel.family == AF_INET)
		addr    = nl_addr_build (sa_info->sel.family, &sa_info->sel.saddr.a4, sizeof (sa_info->sel.saddr.a4));
	else
		addr    = nl_addr_build (sa_info->sel.family, &sa_info->sel.saddr.a6, sizeof (sa_info->sel.saddr.a6));
	nl_addr_set_prefixlen (addr, sa_info->sel.prefixlen_s);
	xfrmnl_sel_set_saddr (sa->sel, addr);
	xfrmnl_sel_set_prefixlen_s (sa->sel, sa_info->sel.prefixlen_s);

	xfrmnl_sel_set_dport (sa->sel, ntohs(sa_info->sel.dport));
	xfrmnl_sel_set_dportmask (sa->sel, ntohs(sa_info->sel.dport_mask));
	xfrmnl_sel_set_sport (sa->sel, ntohs(sa_info->sel.sport));
	xfrmnl_sel_set_sportmask (sa->sel, ntohs(sa_info->sel.sport_mask));
	xfrmnl_sel_set_family (sa->sel, sa_info->sel.family);
	xfrmnl_sel_set_proto (sa->sel, sa_info->sel.proto);
	xfrmnl_sel_set_ifindex (sa->sel, sa_info->sel.ifindex);
	xfrmnl_sel_set_userid (sa->sel, sa_info->sel.user);
	sa->ce_mask             |= XFRM_SA_ATTR_SEL;

	if (sa_info->family == AF_INET)
		sa->id.daddr        = nl_addr_build (sa_info->family, &sa_info->id.daddr.a4, sizeof (sa_info->id.daddr.a4));
	else
		sa->id.daddr        = nl_addr_build (sa_info->family, &sa_info->id.daddr.a6, sizeof (sa_info->id.daddr.a6));
	sa->id.spi              = ntohl(sa_info->id.spi);
	sa->id.proto            = sa_info->id.proto;
	sa->ce_mask             |= (XFRM_SA_ATTR_DADDR | XFRM_SA_ATTR_SPI | XFRM_SA_ATTR_PROTO);

	if (sa_info->family == AF_INET)
		sa->saddr           = nl_addr_build (sa_info->family, &sa_info->saddr.a4, sizeof (sa_info->saddr.a4));
	else
		sa->saddr           = nl_addr_build (sa_info->family, &sa_info->saddr.a6, sizeof (sa_info->saddr.a6));
	sa->ce_mask             |= XFRM_SA_ATTR_SADDR;

	sa->lft->soft_byte_limit    =   sa_info->lft.soft_byte_limit;
	sa->lft->hard_byte_limit    =   sa_info->lft.hard_byte_limit;
	sa->lft->soft_packet_limit  =   sa_info->lft.soft_packet_limit;
	sa->lft->hard_packet_limit  =   sa_info->lft.hard_packet_limit;
	sa->lft->soft_add_expires_seconds   =   sa_info->lft.soft_add_expires_seconds;
	sa->lft->hard_add_expires_seconds   =   sa_info->lft.hard_add_expires_seconds;
	sa->lft->soft_use_expires_seconds   =   sa_info->lft.soft_use_expires_seconds;
	sa->lft->hard_use_expires_seconds   =   sa_info->lft.hard_use_expires_seconds;
	sa->ce_mask             |= XFRM_SA_ATTR_LTIME_CFG;

	sa->curlft.bytes        = sa_info->curlft.bytes;
	sa->curlft.packets      = sa_info->curlft.packets;
	sa->curlft.add_time     = sa_info->curlft.add_time;
	sa->curlft.use_time     = sa_info->curlft.use_time;
	sa->ce_mask             |= XFRM_SA_ATTR_LTIME_CUR;

	sa->stats.replay_window = sa_info->stats.replay_window;
	sa->stats.replay        = sa_info->stats.replay;
	sa->stats.integrity_failed = sa_info->stats.integrity_failed;
	sa->ce_mask             |= XFRM_SA_ATTR_STATS;

	sa->seq                 = sa_info->seq;
	sa->reqid               = sa_info->reqid;
	sa->family              = sa_info->family;
	sa->mode                = sa_info->mode;
	sa->replay_window       = sa_info->replay_window;
	sa->flags               = sa_info->flags;
	sa->ce_mask             |= (XFRM_SA_ATTR_SEQ | XFRM_SA_ATTR_REQID |
	                            XFRM_SA_ATTR_FAMILY | XFRM_SA_ATTR_MODE |
	                            XFRM_SA_ATTR_REPLAY_WIN | XFRM_SA_ATTR_FLAGS);

	if (tb[XFRMA_ALG_AEAD]) {
		struct xfrm_algo_aead* aead = nla_data(tb[XFRMA_ALG_AEAD]);
		len = sizeof (struct xfrmnl_algo_aead) + ((aead->alg_key_len + 7) / 8);
		if ((sa->aead = calloc (1, len)) == NULL)
		{
			err = -NLE_NOMEM;
			goto errout;
		}
		memcpy ((void *)sa->aead, (void *)aead, len);
		sa->ce_mask     |= XFRM_SA_ATTR_ALG_AEAD;
	}

	if (tb[XFRMA_ALG_AUTH_TRUNC]) {
		struct xfrm_algo_auth* auth = nla_data(tb[XFRMA_ALG_AUTH_TRUNC]);
		len = sizeof (struct xfrmnl_algo_auth) + ((auth->alg_key_len + 7) / 8);
		if ((sa->auth = calloc (1, len)) == NULL)
		{
			err = -NLE_NOMEM;
			goto errout;
		}
		memcpy ((void *)sa->auth, (void *)auth, len);
		sa->ce_mask     |= XFRM_SA_ATTR_ALG_AUTH;
	}

	if (tb[XFRMA_ALG_AUTH] && !sa->auth) {
		struct xfrm_algo* auth = nla_data(tb[XFRMA_ALG_AUTH]);
		len = sizeof (struct xfrmnl_algo_auth) + ((auth->alg_key_len + 7) / 8);
		if ((sa->auth = calloc (1, len)) == NULL)
		{
			err = -NLE_NOMEM;
			goto errout;
		}
		strcpy(sa->auth->alg_name, auth->alg_name);
		memcpy(sa->auth->alg_key, auth->alg_key, (auth->alg_key_len + 7) / 8);
		sa->auth->alg_key_len = auth->alg_key_len;
		sa->ce_mask     |=  XFRM_SA_ATTR_ALG_AUTH;
	}

	if (tb[XFRMA_ALG_CRYPT]) {
		struct xfrm_algo* crypt = nla_data(tb[XFRMA_ALG_CRYPT]);
		len = sizeof (struct xfrmnl_algo) + ((crypt->alg_key_len + 7) / 8);
		if ((sa->crypt = calloc (1, len)) == NULL)
		{
			err = -NLE_NOMEM;
			goto errout;
		}
		memcpy ((void *)sa->crypt, (void *)crypt, len);
		sa->ce_mask     |= XFRM_SA_ATTR_ALG_CRYPT;
	}

	if (tb[XFRMA_ALG_COMP]) {
		struct xfrm_algo* comp = nla_data(tb[XFRMA_ALG_COMP]);
		len = sizeof (struct xfrmnl_algo) + ((comp->alg_key_len + 7) / 8);
		if ((sa->comp = calloc (1, len)) == NULL)
		{
			err = -NLE_NOMEM;
			goto errout;
		}
		memcpy ((void *)sa->comp, (void *)comp, len);
		sa->ce_mask     |= XFRM_SA_ATTR_ALG_COMP;
	}

	if (tb[XFRMA_ENCAP]) {
		struct xfrm_encap_tmpl* encap = nla_data(tb[XFRMA_ENCAP]);
		len = sizeof (struct xfrmnl_encap_tmpl);
		if ((sa->encap = calloc (1, len)) == NULL)
		{
			err = -NLE_NOMEM;
			goto errout;
		}
		sa->encap->encap_type   =   encap->encap_type;
		sa->encap->encap_sport  =   ntohs(encap->encap_sport);
		sa->encap->encap_dport  =   ntohs(encap->encap_dport);
		if (sa_info->family == AF_INET)
			sa->encap->encap_oa =   nl_addr_build (sa_info->family, &encap->encap_oa.a4, sizeof (encap->encap_oa.a4));
		else
			sa->encap->encap_oa =   nl_addr_build (sa_info->family, &encap->encap_oa.a6, sizeof (encap->encap_oa.a6));
		sa->ce_mask     |= XFRM_SA_ATTR_ENCAP;
	}

	if (tb[XFRMA_TFCPAD]) {
		sa->tfcpad      =   *(uint32_t*)nla_data(tb[XFRMA_TFCPAD]);
		sa->ce_mask     |= XFRM_SA_ATTR_TFCPAD;
	}

	if (tb[XFRMA_COADDR]) {
		if (sa_info->family == AF_INET)
		{
			sa->coaddr  = nl_addr_build(sa_info->family, nla_data(tb[XFRMA_COADDR]),
			                            sizeof (uint32_t));
		}
		else
		{
			sa->coaddr  = nl_addr_build(sa_info->family, nla_data(tb[XFRMA_COADDR]),
			                            sizeof (uint32_t) * 4);
		}
		sa->ce_mask         |= XFRM_SA_ATTR_COADDR;
	}

	if (tb[XFRMA_MARK]) {
		struct xfrm_mark* m =   nla_data(tb[XFRMA_MARK]);
		sa->mark.m  =   m->m;
		sa->mark.v  =   m->v;
		sa->ce_mask |= XFRM_SA_ATTR_MARK;
	}

	if (tb[XFRMA_SEC_CTX]) {
		struct xfrm_sec_ctx* sec_ctx = nla_data(tb[XFRMA_SEC_CTX]);
		len = sizeof (struct xfrmnl_sec_ctx) + sec_ctx->ctx_len;
		if ((sa->sec_ctx = calloc (1, len)) == NULL)
		{
			err = -NLE_NOMEM;
			goto errout;
		}
		memcpy ((void *)sa->sec_ctx, (void *)sec_ctx, len);
		sa->ce_mask     |= XFRM_SA_ATTR_SECCTX;
	}

	if (tb[XFRMA_ETIMER_THRESH]) {
		sa->replay_maxage       =   *(uint32_t*)nla_data(tb[XFRMA_ETIMER_THRESH]);
		sa->ce_mask |= XFRM_SA_ATTR_REPLAY_MAXAGE;
	}

	if (tb[XFRMA_REPLAY_THRESH]) {
		sa->replay_maxdiff      =   *(uint32_t*)nla_data(tb[XFRMA_REPLAY_THRESH]);
		sa->ce_mask |= XFRM_SA_ATTR_REPLAY_MAXDIFF;
	}

	if (tb[XFRMA_REPLAY_ESN_VAL]) {
		struct xfrm_replay_state_esn* esn = nla_data (tb[XFRMA_REPLAY_ESN_VAL]);
		len =   sizeof (struct xfrmnl_replay_state_esn) + (sizeof (uint32_t) * esn->bmp_len);
		if ((sa->replay_state_esn = calloc (1, len)) == NULL)
		{
			err = -NLE_NOMEM;
			goto errout;
		}
		memcpy ((void *)sa->replay_state_esn, (void *)esn, len);
		sa->ce_mask |= XFRM_SA_ATTR_REPLAY_STATE;
	}
	else if (tb[XFRMA_REPLAY_VAL])
	{
		struct xfrm_replay_state* replay_state = nla_data (tb[XFRMA_REPLAY_VAL]);
		sa->replay_state.oseq       =   replay_state->oseq;
		sa->replay_state.seq        =   replay_state->seq;
		sa->replay_state.bitmap     =   replay_state->bitmap;
		sa->ce_mask |= XFRM_SA_ATTR_REPLAY_STATE;
		sa->replay_state_esn = NULL;
	}

	*result = sa;
	return 0;

errout:
	xfrmnl_sa_put(sa);
	return err;
}

static int xfrm_sa_update_cache (struct nl_cache *cache, struct nl_object *obj,
                                 change_func_t change_cb, void *data)
{
	struct nl_object*       old_sa;
	struct xfrmnl_sa*       sa = (struct xfrmnl_sa*)obj;

	if (nl_object_get_msgtype (obj) == XFRM_MSG_EXPIRE)
	{
		/* On hard expiry, the SA gets deleted too from the kernel state without any
		 * further delete event. On Expire message, we are only updating the cache with
		 * the SA object's new state. In absence of the explicit delete event, the cache will
		 * be out of sync with the kernel state. To get around this, expiry messages cache
		 * operations are handled here (installed with NL_ACT_UNSPEC action) instead of
		 * in Libnl Cache module. */

		/* Do we already have this object in the cache? */
		old_sa = nl_cache_search(cache, obj);
		if (old_sa)
		{
			/* Found corresponding SA object in cache. Delete it */
			nl_cache_remove (old_sa);
		}

		/* Handle the expiry event now */
		if (sa->hard == 0)
		{
			/* Soft expiry event: Save the new object to the
			 * cache and notify application of the expiry event. */
			nl_cache_move (cache, obj);

			if (old_sa == NULL && change_cb)
			{
				/* Application CB present, no previous instance of SA object present.
				 * Notify application CB as a NEW event */
				change_cb (cache, obj, NL_ACT_NEW, data);
			}
			else if (old_sa)
			{
				/* Application CB present, a previous instance of SA object present.
				 * Notify application CB as a CHANGE1 event */
				if (nl_object_diff (old_sa, obj) && change_cb)
					change_cb (cache, obj, NL_ACT_CHANGE, data);
				nl_object_put (old_sa);
			}
		}
		else
		{
			/* Hard expiry event: Delete the object from the
			 * cache and notify application of the expiry event. */
			if (change_cb)
				change_cb (cache, obj, NL_ACT_DEL, data);
			nl_object_put (old_sa);
		}

		/* Done handling expire message */
		return 0;
	}
	else
	{
		/* All other messages other than Expire, let the standard Libnl cache
		 * module handle it. */
		return nl_cache_include (cache, obj, change_cb, data);
	}
}

static int xfrm_sa_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
				struct nlmsghdr *n, struct nl_parser_param *pp)
{
	struct xfrmnl_sa*       sa;
	int                     err;

	if ((err = xfrmnl_sa_parse(n, &sa)) < 0)
		return err;

	err = pp->pp_cb((struct nl_object *) sa, pp);

	xfrmnl_sa_put(sa);
	return err;
}

/**
 * @name XFRM SA Get
 * @{
 */

int xfrmnl_sa_build_get_request(struct nl_addr* daddr, unsigned int spi, unsigned int protocol, unsigned int mark_v, unsigned int mark_m, struct nl_msg **result)
{
	struct nl_msg               *msg;
	struct xfrm_usersa_id       sa_id;
	struct xfrm_mark            mark;

	if (!daddr || !spi)
	{
		fprintf(stderr, "APPLICATION BUG: %s:%d:%s: A valid destination address, spi must be specified\n",
		        __FILE__, __LINE__, __PRETTY_FUNCTION__);
		assert(0);
		return -NLE_MISSING_ATTR;
	}

	memset(&sa_id, 0, sizeof(sa_id));
	memcpy (&sa_id.daddr, nl_addr_get_binary_addr (daddr), sizeof (uint8_t) * nl_addr_get_len (daddr));
	sa_id.family = nl_addr_get_family (daddr);
	sa_id.spi    = htonl(spi);
	sa_id.proto  = protocol;

	if (!(msg = nlmsg_alloc_simple(XFRM_MSG_GETSA, 0)))
		return -NLE_NOMEM;

	if (nlmsg_append(msg, &sa_id, sizeof(sa_id), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if ((mark_m & mark_v) != 0)
	{
		memset(&mark, 0, sizeof(struct xfrm_mark));
		mark.m = mark_m;
		mark.v = mark_v;

		NLA_PUT (msg, XFRMA_MARK, sizeof (struct xfrm_mark), &mark);
	}

	*result = msg;
	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return -NLE_MSGSIZE;
}

int xfrmnl_sa_get_kernel(struct nl_sock* sock, struct nl_addr* daddr, unsigned int spi, unsigned int protocol, unsigned int mark_v, unsigned int mark_m, struct xfrmnl_sa** result)
{
	struct nl_msg *msg = NULL;
	struct nl_object *obj;
	int err;

	if ((err = xfrmnl_sa_build_get_request(daddr, spi, protocol, mark_m, mark_v, &msg)) < 0)
		return err;

	err = nl_send_auto(sock, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	if ((err = nl_pickup(sock, &xfrm_sa_msg_parser, &obj)) < 0)
		return err;

	/* We have used xfrm_sa_msg_parser(), object is definitely a xfrm sa */
	*result = (struct xfrmnl_sa *) obj;

	/* If an object has been returned, we also need to wait for the ACK */
	 if (err == 0 && obj)
		 nl_wait_for_ack(sock);

	return 0;
}

/** @} */

static int build_xfrm_sa_message(struct xfrmnl_sa *tmpl, int cmd, int flags, struct nl_msg **result)
{
	struct nl_msg*          msg;
	struct xfrm_usersa_info sa_info;
	uint32_t                len;
	struct nl_addr*         addr;

	if (!(tmpl->ce_mask & XFRM_SA_ATTR_DADDR) ||
		!(tmpl->ce_mask & XFRM_SA_ATTR_SPI) ||
		!(tmpl->ce_mask & XFRM_SA_ATTR_PROTO))
		return -NLE_MISSING_ATTR;

	memset ((void*)&sa_info, 0, sizeof (sa_info));
	if (tmpl->ce_mask & XFRM_SA_ATTR_SEL)
	{
		addr = xfrmnl_sel_get_daddr (tmpl->sel);
		memcpy ((void*)&sa_info.sel.daddr, (void*)nl_addr_get_binary_addr (addr), sizeof (uint8_t) * nl_addr_get_len (addr));
		addr = xfrmnl_sel_get_saddr (tmpl->sel);
		memcpy ((void*)&sa_info.sel.saddr, (void*)nl_addr_get_binary_addr (addr), sizeof (uint8_t) * nl_addr_get_len (addr));
		sa_info.sel.dport       =   htons (xfrmnl_sel_get_dport (tmpl->sel));
		sa_info.sel.dport_mask  =   htons (xfrmnl_sel_get_dportmask (tmpl->sel));
		sa_info.sel.sport       =   htons (xfrmnl_sel_get_sport (tmpl->sel));
		sa_info.sel.sport_mask  =   htons (xfrmnl_sel_get_sportmask (tmpl->sel));
		sa_info.sel.family      =   xfrmnl_sel_get_family (tmpl->sel);
		sa_info.sel.prefixlen_d =   xfrmnl_sel_get_prefixlen_d (tmpl->sel);
		sa_info.sel.prefixlen_s =   xfrmnl_sel_get_prefixlen_s (tmpl->sel);
		sa_info.sel.proto       =   xfrmnl_sel_get_proto (tmpl->sel);
		sa_info.sel.ifindex     =   xfrmnl_sel_get_ifindex (tmpl->sel);
		sa_info.sel.user        =   xfrmnl_sel_get_userid (tmpl->sel);
	}

	memcpy (&sa_info.id.daddr, nl_addr_get_binary_addr (tmpl->id.daddr), sizeof (uint8_t) * nl_addr_get_len (tmpl->id.daddr));
	sa_info.id.spi    = htonl(tmpl->id.spi);
	sa_info.id.proto  = tmpl->id.proto;

	if (tmpl->ce_mask & XFRM_SA_ATTR_SADDR)
		memcpy (&sa_info.saddr, nl_addr_get_binary_addr (tmpl->saddr), sizeof (uint8_t) * nl_addr_get_len (tmpl->saddr));

	if (tmpl->ce_mask & XFRM_SA_ATTR_LTIME_CFG)
	{
		sa_info.lft.soft_byte_limit = xfrmnl_ltime_cfg_get_soft_bytelimit (tmpl->lft);
		sa_info.lft.hard_byte_limit = xfrmnl_ltime_cfg_get_hard_bytelimit (tmpl->lft);
		sa_info.lft.soft_packet_limit = xfrmnl_ltime_cfg_get_soft_packetlimit (tmpl->lft);
		sa_info.lft.hard_packet_limit = xfrmnl_ltime_cfg_get_hard_packetlimit (tmpl->lft);
		sa_info.lft.soft_add_expires_seconds = xfrmnl_ltime_cfg_get_soft_addexpires (tmpl->lft);
		sa_info.lft.hard_add_expires_seconds = xfrmnl_ltime_cfg_get_hard_addexpires (tmpl->lft);
		sa_info.lft.soft_use_expires_seconds = xfrmnl_ltime_cfg_get_soft_useexpires (tmpl->lft);
		sa_info.lft.hard_use_expires_seconds = xfrmnl_ltime_cfg_get_hard_useexpires (tmpl->lft);
	}

	//Skip current lifetime: cur lifetime can be updated only via AE
	//Skip stats: stats cant be updated
	//Skip seq: seq cant be updated

	if (tmpl->ce_mask & XFRM_SA_ATTR_REQID)
		sa_info.reqid           = tmpl->reqid;

	if (tmpl->ce_mask & XFRM_SA_ATTR_FAMILY)
		sa_info.family          = tmpl->family;

	if (tmpl->ce_mask & XFRM_SA_ATTR_MODE)
		sa_info.mode            = tmpl->mode;

	if (tmpl->ce_mask & XFRM_SA_ATTR_REPLAY_WIN)
		sa_info.replay_window   = tmpl->replay_window;

	if (tmpl->ce_mask & XFRM_SA_ATTR_FLAGS)
		sa_info.flags           = tmpl->flags;

	msg = nlmsg_alloc_simple(cmd, flags);
	if (!msg)
		return -NLE_NOMEM;

	if (nlmsg_append(msg, &sa_info, sizeof(sa_info), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (tmpl->ce_mask & XFRM_SA_ATTR_ALG_AEAD) {
		len = sizeof (struct xfrm_algo_aead) + ((tmpl->aead->alg_key_len + 7) / 8);
		NLA_PUT (msg, XFRMA_ALG_AEAD, len, tmpl->aead);
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_ALG_AUTH) {
		struct xfrm_algo*   auth;
		struct nlattr *     auth_attr;

		len = sizeof (struct xfrm_algo) + ((tmpl->auth->alg_key_len + 7) / 8);
		auth_attr = nla_reserve(msg, XFRMA_ALG_AUTH, len);
		if (!auth_attr)
			goto nla_put_failure;
		auth = nla_data (auth_attr);
		strcpy(auth->alg_name, tmpl->auth->alg_name);
		memcpy(auth->alg_key, tmpl->auth->alg_key, (tmpl->auth->alg_key_len + 7) / 8);
		auth->alg_key_len = tmpl->auth->alg_key_len;

		len = sizeof (struct xfrm_algo_auth) + ((tmpl->auth->alg_key_len + 7) / 8);
		NLA_PUT (msg, XFRMA_ALG_AUTH_TRUNC, len, tmpl->auth);
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_ALG_CRYPT) {
		len = sizeof (struct xfrm_algo) + ((tmpl->crypt->alg_key_len + 7) / 8);
		NLA_PUT (msg, XFRMA_ALG_CRYPT, len, tmpl->crypt);
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_ALG_COMP) {
		len = sizeof (struct xfrm_algo) + ((tmpl->comp->alg_key_len + 7) / 8);
		NLA_PUT (msg, XFRMA_ALG_COMP, len, tmpl->comp);
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_ENCAP) {
		struct xfrm_encap_tmpl* encap_tmpl;
		struct nlattr*          encap_attr;

		len = sizeof (struct xfrm_encap_tmpl);
		encap_attr = nla_reserve(msg, XFRMA_ENCAP, len);
		if (!encap_attr)
			goto nla_put_failure;
		encap_tmpl = nla_data (encap_attr);
		encap_tmpl->encap_type  =   tmpl->encap->encap_type;
		encap_tmpl->encap_sport =   htons (tmpl->encap->encap_sport);
		encap_tmpl->encap_dport =   htons (tmpl->encap->encap_dport);
		memcpy (&encap_tmpl->encap_oa, nl_addr_get_binary_addr (tmpl->encap->encap_oa), sizeof (uint8_t) * nl_addr_get_len (tmpl->encap->encap_oa));
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_TFCPAD) {
		NLA_PUT_U32 (msg, XFRMA_TFCPAD, tmpl->tfcpad);
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_COADDR) {
		NLA_PUT (msg, XFRMA_COADDR, sizeof (xfrm_address_t), tmpl->coaddr);
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_MARK) {
		NLA_PUT (msg, XFRMA_MARK, sizeof (struct xfrm_mark), &tmpl->mark);
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_SECCTX) {
		len = sizeof (struct xfrm_sec_ctx) + tmpl->sec_ctx->ctx_len;
		NLA_PUT (msg, XFRMA_SEC_CTX, len, tmpl->sec_ctx);
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_REPLAY_MAXAGE) {
		NLA_PUT_U32 (msg, XFRMA_ETIMER_THRESH, tmpl->replay_maxage);
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_REPLAY_MAXDIFF) {
		NLA_PUT_U32 (msg, XFRMA_REPLAY_THRESH, tmpl->replay_maxdiff);
	}

	if (tmpl->ce_mask & XFRM_SA_ATTR_REPLAY_STATE) {
		if (tmpl->replay_state_esn) {
			len =   sizeof (struct xfrm_replay_state_esn) + (sizeof (uint32_t) * tmpl->replay_state_esn->bmp_len);
			NLA_PUT (msg, XFRMA_REPLAY_ESN_VAL, len, tmpl->replay_state_esn);
		}
		else {
			NLA_PUT (msg, XFRMA_REPLAY_VAL, sizeof (struct xfrm_replay_state), &tmpl->replay_state);
		}
	}

	*result = msg;
	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return -NLE_MSGSIZE;
}

/**
 * @name XFRM SA Add
 * @{
 */

int xfrmnl_sa_build_add_request(struct xfrmnl_sa* tmpl, int flags, struct nl_msg **result)
{
	return build_xfrm_sa_message (tmpl, XFRM_MSG_NEWSA, flags, result);
}

int xfrmnl_sa_add(struct nl_sock* sk, struct xfrmnl_sa* tmpl, int flags)
{
	int             err;
	struct nl_msg   *msg;

	if ((err = xfrmnl_sa_build_add_request(tmpl, flags, &msg)) < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(sk);
}

/**
 * @name XFRM SA Update
 * @{
 */

int xfrmnl_sa_build_update_request(struct xfrmnl_sa* tmpl, int flags, struct nl_msg **result)
{
	return build_xfrm_sa_message (tmpl, XFRM_MSG_UPDSA, flags, result);
}

int xfrmnl_sa_update(struct nl_sock* sk, struct xfrmnl_sa* tmpl, int flags)
{
	int             err;
	struct nl_msg   *msg;

	if ((err = xfrmnl_sa_build_update_request(tmpl, flags, &msg)) < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(sk);
}

/** @} */

static int build_xfrm_sa_delete_message(struct xfrmnl_sa *tmpl, int cmd, int flags, struct nl_msg **result)
{
	struct nl_msg*          msg;
	struct xfrm_usersa_id   sa_id;

	if (!(tmpl->ce_mask & XFRM_SA_ATTR_DADDR) ||
		!(tmpl->ce_mask & XFRM_SA_ATTR_SPI) ||
		!(tmpl->ce_mask & XFRM_SA_ATTR_PROTO))
		return -NLE_MISSING_ATTR;

	memcpy (&sa_id.daddr, nl_addr_get_binary_addr (tmpl->id.daddr),
	        sizeof (uint8_t) * nl_addr_get_len (tmpl->id.daddr));
	sa_id.family = nl_addr_get_family (tmpl->id.daddr);
	sa_id.spi    = htonl(tmpl->id.spi);
	sa_id.proto  = tmpl->id.proto;

	msg = nlmsg_alloc_simple(cmd, flags);
	if (!msg)
		return -NLE_NOMEM;

	if (nlmsg_append(msg, &sa_id, sizeof(sa_id), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (tmpl->ce_mask & XFRM_SA_ATTR_MARK) {
		NLA_PUT (msg, XFRMA_MARK, sizeof (struct xfrm_mark), &tmpl->mark);
	}

	*result = msg;
	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return -NLE_MSGSIZE;
}

/**
 * @name XFRM SA Delete
 * @{
 */

int xfrmnl_sa_build_delete_request(struct xfrmnl_sa* tmpl, int flags, struct nl_msg **result)
{
	return build_xfrm_sa_delete_message (tmpl, XFRM_MSG_DELSA, flags, result);
}

int xfrmnl_sa_delete(struct nl_sock* sk, struct xfrmnl_sa* tmpl, int flags)
{
	int             err;
	struct nl_msg   *msg;

	if ((err = xfrmnl_sa_build_delete_request(tmpl, flags, &msg)) < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(sk);
}

/** @} */


/**
 * @name Attributes
 * @{
 */

struct xfrmnl_sel* xfrmnl_sa_get_sel (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_SEL)
		return sa->sel;
	else
		return NULL;
}

int xfrmnl_sa_set_sel (struct xfrmnl_sa* sa, struct xfrmnl_sel* sel)
{
	/* Release any previously held selector object from the SA */
	if (sa->sel)
		xfrmnl_sel_put (sa->sel);

	/* Increment ref count on new selector and save it in the SA */
	xfrmnl_sel_get (sel);
	sa->sel     =   sel;
	sa->ce_mask |=  XFRM_SA_ATTR_SEL;

	return 0;
}

static inline int __assign_addr(struct xfrmnl_sa* sa, struct nl_addr **pos,
					struct nl_addr *new, int flag, int nocheck)
{
	if (!nocheck)
	{
		if (sa->ce_mask & XFRM_SA_ATTR_FAMILY)
		{
			if (nl_addr_get_family (new) != sa->family)
				return -NLE_AF_MISMATCH;
		}
	}

	if (*pos)
		nl_addr_put(*pos);

	nl_addr_get(new);
	*pos = new;

	sa->ce_mask |= flag;

	return 0;
}


struct nl_addr* xfrmnl_sa_get_daddr (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_DADDR)
		return sa->id.daddr;
	else
		return NULL;
}

int xfrmnl_sa_set_daddr (struct xfrmnl_sa* sa, struct nl_addr* addr)
{
	return __assign_addr(sa, &sa->id.daddr, addr, XFRM_SA_ATTR_DADDR, 0);
}

int xfrmnl_sa_get_spi (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_SPI)
		return sa->id.spi;
	else
		return -1;
}

int xfrmnl_sa_set_spi (struct xfrmnl_sa* sa, unsigned int spi)
{
	sa->id.spi = spi;
	sa->ce_mask |= XFRM_SA_ATTR_SPI;

	return 0;
}

int xfrmnl_sa_get_proto (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_PROTO)
		return sa->id.proto;
	else
		return -1;
}

int xfrmnl_sa_set_proto (struct xfrmnl_sa* sa, unsigned int protocol)
{
	sa->id.proto = protocol;
	sa->ce_mask |= XFRM_SA_ATTR_PROTO;

	return 0;
}

struct nl_addr* xfrmnl_sa_get_saddr (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_SADDR)
		return sa->saddr;
	else
		return NULL;
}

int xfrmnl_sa_set_saddr (struct xfrmnl_sa* sa, struct nl_addr* addr)
{
	return __assign_addr(sa, &sa->saddr, addr, XFRM_SA_ATTR_SADDR, 1);
}

struct xfrmnl_ltime_cfg* xfrmnl_sa_get_lifetime_cfg (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_LTIME_CFG)
		return sa->lft;
	else
		return NULL;
}

int xfrmnl_sa_set_lifetime_cfg (struct xfrmnl_sa* sa, struct xfrmnl_ltime_cfg* ltime)
{
	/* Release any previously held lifetime cfg object from the SA */
	if (sa->lft)
		xfrmnl_ltime_cfg_put (sa->lft);

	/* Increment ref count on new lifetime object and save it in the SA */
	xfrmnl_ltime_cfg_get (ltime);
	sa->lft     =   ltime;
	sa->ce_mask |=  XFRM_SA_ATTR_LTIME_CFG;

	return 0;
}

int xfrmnl_sa_get_curlifetime (struct xfrmnl_sa* sa, unsigned long long int* curr_bytes,
                               unsigned long long int* curr_packets, unsigned long long int* curr_add_time, unsigned long long int* curr_use_time)
{
	if (sa == NULL || curr_bytes == NULL || curr_packets == NULL || curr_add_time == NULL || curr_use_time == NULL)
		return -1;

	if (sa->ce_mask & XFRM_SA_ATTR_LTIME_CUR)
	{
		*curr_bytes     =   sa->curlft.bytes;
		*curr_packets   =   sa->curlft.packets;
		*curr_add_time  =   sa->curlft.add_time;
		*curr_use_time  =   sa->curlft.use_time;
	}
	else
		return -1;

	return 0;
}

int xfrmnl_sa_get_stats (struct xfrmnl_sa* sa, unsigned long long int* replay_window,
                         unsigned long long int* replay, unsigned long long int* integrity_failed)
{
	if (sa == NULL || replay_window == NULL || replay == NULL || integrity_failed == NULL)
		return -1;

	if (sa->ce_mask & XFRM_SA_ATTR_STATS)
	{
		*replay_window      =   sa->stats.replay_window;
		*replay             =   sa->stats.replay;
		*integrity_failed   =   sa->stats.integrity_failed;
	}
	else
		return -1;

	return 0;
}

int xfrmnl_sa_get_seq (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_SEQ)
		return sa->seq;
	else
		return -1;
}

int xfrmnl_sa_get_reqid (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_REQID)
		return sa->reqid;
	else
		return -1;
}

int xfrmnl_sa_set_reqid (struct xfrmnl_sa* sa, unsigned int reqid)
{
	sa->reqid = reqid;
	sa->ce_mask |= XFRM_SA_ATTR_REQID;

	return 0;
}

int xfrmnl_sa_get_family (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_FAMILY)
		return sa->family;
	else
		return -1;
}

int xfrmnl_sa_set_family (struct xfrmnl_sa* sa, unsigned int family)
{
	sa->family = family;
	sa->ce_mask |= XFRM_SA_ATTR_FAMILY;

	return 0;
}

int xfrmnl_sa_get_mode (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_MODE)
		return sa->mode;
	else
		return -1;
}

int xfrmnl_sa_set_mode (struct xfrmnl_sa* sa, unsigned int mode)
{
	sa->mode    =   mode;
	sa->ce_mask |=  XFRM_SA_ATTR_MODE;

	return 0;
}

int xfrmnl_sa_get_replay_window (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_REPLAY_WIN)
		return sa->replay_window;
	else
		return -1;
}

int xfrmnl_sa_set_replay_window (struct xfrmnl_sa* sa, unsigned int replay_window)
{
	sa->replay_window   =   replay_window;
	sa->ce_mask         |=  XFRM_SA_ATTR_REPLAY_WIN;

	return 0;
}

int xfrmnl_sa_get_flags (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_FLAGS)
		return sa->flags;
	else
		return -1;
}

int xfrmnl_sa_set_flags (struct xfrmnl_sa* sa, unsigned int flags)
{
	sa->flags = flags;
	sa->ce_mask |= XFRM_SA_ATTR_FLAGS;

	return 0;
}

int xfrmnl_sa_get_aead_params (struct xfrmnl_sa* sa, char* alg_name, unsigned int* key_len, unsigned int* icv_len, char* key)
{
	if (sa->ce_mask & XFRM_SA_ATTR_ALG_AEAD)
	{
		strcpy (alg_name, sa->aead->alg_name);
		*key_len    =   sa->aead->alg_key_len;
		*icv_len    =   sa->aead->alg_icv_len;
		memcpy ((void *)key, (void *)sa->aead->alg_key, ((sa->aead->alg_key_len + 7)/8));
	}
	else
		return -1;

	return 0;
}

int xfrmnl_sa_set_aead_params (struct xfrmnl_sa* sa, char* alg_name, unsigned int key_len, unsigned int icv_len, char* key)
{
	uint32_t    newlen = sizeof (struct xfrmnl_algo_aead) + (sizeof (uint8_t) * ((key_len + 7)/8));

	/* Free up the old key and allocate memory to hold new key */
	if (sa->aead)
		free (sa->aead);
	if ((sa->aead = calloc (1, newlen)) == NULL)
		return -1;

	/* Save the new info */
	strcpy (sa->aead->alg_name, alg_name);
	sa->aead->alg_key_len   = key_len;
	sa->aead->alg_icv_len   = icv_len;
	memcpy ((void *)sa->aead->alg_key, (void *)key, newlen);

	sa->ce_mask |= XFRM_SA_ATTR_ALG_AEAD;

	return 0;
}

int xfrmnl_sa_get_auth_params (struct xfrmnl_sa* sa, char* alg_name, unsigned int* key_len, unsigned int* trunc_len, char* key)
{
	if (sa->ce_mask & XFRM_SA_ATTR_ALG_AUTH)
	{
		strcpy (alg_name, sa->auth->alg_name);
		*key_len    =   sa->auth->alg_key_len;
		*trunc_len  =   sa->auth->alg_trunc_len;
		memcpy ((void *)key, (void *)sa->auth->alg_key, ((sa->auth->alg_key_len + 7)/8));
	}
	else
		return -1;

	return 0;
}

int xfrmnl_sa_set_auth_params (struct xfrmnl_sa* sa, char* alg_name, unsigned int key_len, unsigned int trunc_len, char* key)
{
	uint32_t    newlen = sizeof (struct xfrmnl_algo_auth) + (sizeof (uint8_t) * ((key_len + 7)/8));

	/* Free up the old auth data and allocate new one */
	if (sa->auth)
		free (sa->auth);
	if ((sa->auth = calloc (1, newlen)) == NULL)
		return -1;

	/* Save the new info */
	strcpy (sa->auth->alg_name, alg_name);
	sa->auth->alg_key_len   = key_len;
	sa->auth->alg_trunc_len = trunc_len;
	memcpy ((void *)sa->auth->alg_key, (void *)key, newlen);

	sa->ce_mask |= XFRM_SA_ATTR_ALG_AUTH;

	return 0;
}

int xfrmnl_sa_get_crypto_params (struct xfrmnl_sa* sa, char* alg_name, unsigned int* key_len, char* key)
{
	if (sa->ce_mask & XFRM_SA_ATTR_ALG_CRYPT)
	{
		strcpy (alg_name, sa->crypt->alg_name);
		*key_len    =   sa->crypt->alg_key_len;
		memcpy ((void *)key, (void *)sa->crypt->alg_key, ((sa->crypt->alg_key_len + 7)/8));
	}
	else
		return -1;

	return 0;
}

int xfrmnl_sa_set_crypto_params (struct xfrmnl_sa* sa, char* alg_name, unsigned int key_len, char* key)
{
	uint32_t    newlen = sizeof (struct xfrmnl_algo) + (sizeof (uint8_t) * ((key_len + 7)/8));

	/* Free up the old crypto and allocate new one */
	if (sa->crypt)
		free (sa->crypt);
	if ((sa->crypt = calloc (1, newlen)) == NULL)
		return -1;

	/* Save the new info */
	strcpy (sa->crypt->alg_name, alg_name);
	sa->crypt->alg_key_len  = key_len;
	memcpy ((void *)sa->crypt->alg_key, (void *)key, newlen);

	sa->ce_mask |= XFRM_SA_ATTR_ALG_CRYPT;

	return 0;
}

int xfrmnl_sa_get_comp_params (struct xfrmnl_sa* sa, char* alg_name, unsigned int* key_len, char* key)
{
	if (sa->ce_mask & XFRM_SA_ATTR_ALG_COMP)
	{
		strcpy (alg_name, sa->comp->alg_name);
		*key_len    =   sa->comp->alg_key_len;
		memcpy ((void *)key, (void *)sa->comp->alg_key, ((sa->comp->alg_key_len + 7)/8));
	}
	else
		return -1;

	return 0;
}

int xfrmnl_sa_set_comp_params (struct xfrmnl_sa* sa, char* alg_name, unsigned int key_len, char* key)
{
	uint32_t    newlen = sizeof (struct xfrmnl_algo) + (sizeof (uint8_t) * ((key_len + 7)/8));

	/* Free up the old compression algo params and allocate new one */
	if (sa->comp)
		free (sa->comp);
	if ((sa->comp = calloc (1, newlen)) == NULL)
		return -1;

	/* Save the new info */
	strcpy (sa->comp->alg_name, alg_name);
	sa->comp->alg_key_len  = key_len;
	memcpy ((void *)sa->comp->alg_key, (void *)key, newlen);

	sa->ce_mask |= XFRM_SA_ATTR_ALG_COMP;

	return 0;
}

int xfrmnl_sa_get_encap_tmpl (struct xfrmnl_sa* sa, unsigned int* encap_type, unsigned int* encap_sport, unsigned int* encap_dport, struct nl_addr** encap_oa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_ENCAP)
	{
		*encap_type     =   sa->encap->encap_type;
		*encap_sport    =   sa->encap->encap_sport;
		*encap_dport    =   sa->encap->encap_dport;
		*encap_oa       =   nl_addr_clone (sa->encap->encap_oa);
	}
	else
		return -1;

	return 0;
}

int xfrmnl_sa_set_encap_tmpl (struct xfrmnl_sa* sa, unsigned int encap_type, unsigned int encap_sport, unsigned int encap_dport, struct nl_addr* encap_oa)
{
	/* Free up the old encap OA */
	if (sa->encap->encap_oa)
		nl_addr_put (sa->encap->encap_oa);

	/* Save the new info */
	sa->encap->encap_type   =   encap_type;
	sa->encap->encap_sport  =   encap_sport;
	sa->encap->encap_dport  =   encap_dport;
	nl_addr_get (encap_oa);
	sa->encap->encap_oa     =   encap_oa;

	sa->ce_mask |= XFRM_SA_ATTR_ENCAP;

	return 0;
}

int xfrmnl_sa_get_tfcpad (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_TFCPAD)
		return sa->tfcpad;
	else
		return -1;
}

int xfrmnl_sa_set_tfcpad (struct xfrmnl_sa* sa, unsigned int tfcpad)
{
	sa->tfcpad  =   tfcpad;
	sa->ce_mask |=  XFRM_SA_ATTR_TFCPAD;

	return 0;
}

struct nl_addr* xfrmnl_sa_get_coaddr (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_COADDR)
		return sa->coaddr;
	else
		return NULL;
}

int xfrmnl_sa_set_coaddr (struct xfrmnl_sa* sa, struct nl_addr* coaddr)
{
	/* Free up the old coaddr */
	if (sa->coaddr)
		nl_addr_put (sa->coaddr);

	/* Save the new info */
	nl_addr_get (coaddr);
	sa->coaddr  =   coaddr;

	sa->ce_mask |= XFRM_SA_ATTR_COADDR;

	return 0;
}

int xfrmnl_sa_get_mark (struct xfrmnl_sa* sa, unsigned int* mark_mask, unsigned int* mark_value)
{
	if (mark_mask == NULL || mark_value == NULL)
		return -1;

	if (sa->ce_mask & XFRM_SA_ATTR_MARK)
	{
		*mark_mask  =   sa->mark.m;
		*mark_value  =   sa->mark.v;

		return 0;
	}
	else
		return -1;
}

int xfrmnl_sa_set_mark (struct xfrmnl_sa* sa, unsigned int value, unsigned int mask)
{
	sa->mark.v  = value;
	sa->mark.m  = mask;
	sa->ce_mask |= XFRM_SA_ATTR_MARK;

	return 0;
}

int xfrmnl_sa_get_sec_ctx (struct xfrmnl_sa* sa, unsigned int* doi, unsigned int* alg, unsigned int* len, unsigned int* sid, char* ctx_str)
{
	if (sa->ce_mask & XFRM_SA_ATTR_SECCTX)
	{
		*doi    =   sa->sec_ctx->ctx_doi;
		*alg    =   sa->sec_ctx->ctx_alg;
		*len    =   sa->sec_ctx->ctx_len;
		*sid    =   sa->sec_ctx->ctx_sid;
		memcpy ((void *)ctx_str, (void *)sa->sec_ctx->ctx_str, sizeof (uint8_t) * sa->sec_ctx->ctx_len);
	}
	else
		return -1;

	return 0;
}

int xfrmnl_sa_set_sec_ctx (struct xfrmnl_sa* sa, unsigned int doi, unsigned int alg, unsigned int len, unsigned int sid, char* ctx_str)
{
	/* Free up the old context string and allocate new one */
	if (sa->sec_ctx)
		free (sa->sec_ctx);
	if ((sa->sec_ctx = calloc (1, sizeof (struct xfrmnl_sec_ctx) + (sizeof (uint8_t) * len))) == NULL)
		return -1;

	/* Save the new info */
	sa->sec_ctx->ctx_doi    =   doi;
	sa->sec_ctx->ctx_alg    =   alg;
	sa->sec_ctx->ctx_len    =   len;
	sa->sec_ctx->ctx_sid    =   sid;
	memcpy ((void *)sa->sec_ctx->ctx_str, (void *)ctx_str, sizeof (uint8_t) * len);

	sa->ce_mask |= XFRM_SA_ATTR_SECCTX;

	return 0;
}


int xfrmnl_sa_get_replay_maxage (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_REPLAY_MAXAGE)
		return sa->replay_maxage;
	else
		return -1;
}

int xfrmnl_sa_set_replay_maxage (struct xfrmnl_sa* sa, unsigned int replay_maxage)
{
	sa->replay_maxage  = replay_maxage;
	sa->ce_mask |= XFRM_SA_ATTR_REPLAY_MAXAGE;

	return 0;
}

int xfrmnl_sa_get_replay_maxdiff (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_REPLAY_MAXDIFF)
		return sa->replay_maxdiff;
	else
		return -1;
}

int xfrmnl_sa_set_replay_maxdiff (struct xfrmnl_sa* sa, unsigned int replay_maxdiff)
{
	sa->replay_maxdiff  = replay_maxdiff;
	sa->ce_mask |= XFRM_SA_ATTR_REPLAY_MAXDIFF;

	return 0;
}

int xfrmnl_sa_get_replay_state (struct xfrmnl_sa* sa, unsigned int* oseq, unsigned int* seq, unsigned int* bmp)
{
	if (sa->ce_mask & XFRM_SA_ATTR_REPLAY_STATE)
	{
		if (sa->replay_state_esn == NULL)
		{
			*oseq   =   sa->replay_state.oseq;
			*seq    =   sa->replay_state.seq;
			*bmp    =   sa->replay_state.bitmap;

			return 0;
		}
		else
		{
			return -1;
		}
	}
	else
		return -1;
}

int xfrmnl_sa_set_replay_state (struct xfrmnl_sa* sa, unsigned int oseq, unsigned int seq, unsigned int bitmap)
{
	sa->replay_state.oseq = oseq;
	sa->replay_state.seq = seq;
	sa->replay_state.bitmap = bitmap;
	sa->ce_mask |= XFRM_SA_ATTR_REPLAY_STATE;

	return 0;
}

int xfrmnl_sa_get_replay_state_esn (struct xfrmnl_sa* sa, unsigned int* oseq, unsigned int* seq, unsigned int* oseq_hi,
                                    unsigned int* seq_hi, unsigned int* replay_window, unsigned int* bmp_len, unsigned int* bmp)
{
	if (sa->ce_mask & XFRM_SA_ATTR_REPLAY_STATE)
	{
		if (sa->replay_state_esn)
		{
			*oseq   =   sa->replay_state_esn->oseq;
			*seq    =   sa->replay_state_esn->seq;
			*oseq_hi=   sa->replay_state_esn->oseq_hi;
			*seq_hi =   sa->replay_state_esn->seq_hi;
			*replay_window  =   sa->replay_state_esn->replay_window;
			*bmp_len        =   sa->replay_state_esn->bmp_len; // In number of 32 bit words
			memcpy (bmp, sa->replay_state_esn->bmp, sa->replay_state_esn->bmp_len * sizeof (uint32_t));

			return 0;
		}
		else
		{
			return -1;
		}
	}
	else
		return -1;
}

int xfrmnl_sa_set_replay_state_esn (struct xfrmnl_sa* sa, unsigned int oseq, unsigned int seq,
                                    unsigned int oseq_hi, unsigned int seq_hi, unsigned int replay_window,
                                    unsigned int bmp_len, unsigned int* bmp)
{
	/* Free the old replay state and allocate space to hold new one */
	if (sa->replay_state_esn)
		free (sa->replay_state_esn);

	if ((sa->replay_state_esn = calloc (1, sizeof (struct xfrmnl_replay_state_esn) + (sizeof (uint32_t) * bmp_len))) == NULL)
		return -1;
	sa->replay_state_esn->oseq = oseq;
	sa->replay_state_esn->seq = seq;
	sa->replay_state_esn->oseq_hi = oseq_hi;
	sa->replay_state_esn->seq_hi = seq_hi;
	sa->replay_state_esn->replay_window = replay_window;
	sa->replay_state_esn->bmp_len = bmp_len; // In number of 32 bit words
	memcpy (sa->replay_state_esn->bmp, bmp, bmp_len * sizeof (uint32_t));
	sa->ce_mask |= XFRM_SA_ATTR_REPLAY_STATE;

	return 0;
}


int xfrmnl_sa_is_hardexpiry_reached (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_EXPIRE)
		return (sa->hard > 0 ? 1: 0);
	else
		return 0;
}

int xfrmnl_sa_is_expiry_reached (struct xfrmnl_sa* sa)
{
	if (sa->ce_mask & XFRM_SA_ATTR_EXPIRE)
		return 1;
	else
		return 0;
}

/** @} */

static struct nl_object_ops xfrm_sa_obj_ops = {
	.oo_name        =   "xfrm/sa",
	.oo_size        =   sizeof(struct xfrmnl_sa),
	.oo_constructor =   xfrm_sa_alloc_data,
	.oo_free_data   =   xfrm_sa_free_data,
	.oo_clone       =   xfrm_sa_clone,
	.oo_dump        =   {
	                        [NL_DUMP_LINE]      =   xfrm_sa_dump_line,
	                        [NL_DUMP_DETAILS]   =   xfrm_sa_dump_details,
	                        [NL_DUMP_STATS]     =   xfrm_sa_dump_stats,
	                    },
	.oo_compare     =   xfrm_sa_compare,
	.oo_attrs2str   =   xfrm_sa_attrs2str,
	.oo_id_attrs    =   (XFRM_SA_ATTR_DADDR | XFRM_SA_ATTR_SPI | XFRM_SA_ATTR_PROTO),
};

static struct nl_af_group xfrm_sa_groups[] = {
	{ AF_UNSPEC, XFRMNLGRP_SA },
	{ AF_UNSPEC, XFRMNLGRP_EXPIRE },
	{ END_OF_GROUP_LIST },
};

static struct nl_cache_ops xfrmnl_sa_ops = {
	.co_name            = "xfrm/sa",
	.co_hdrsize         = sizeof(struct xfrm_usersa_info),
	.co_msgtypes        = {
	                        { XFRM_MSG_NEWSA, NL_ACT_NEW, "new" },
	                        { XFRM_MSG_DELSA, NL_ACT_DEL, "del" },
	                        { XFRM_MSG_GETSA, NL_ACT_GET, "get" },
	                        { XFRM_MSG_EXPIRE, NL_ACT_UNSPEC, "expire"},
	                        { XFRM_MSG_UPDSA, NL_ACT_NEW, "update"},
	                        END_OF_MSGTYPES_LIST,
	                      },
	.co_protocol        = NETLINK_XFRM,
	.co_groups          = xfrm_sa_groups,
	.co_request_update  = xfrm_sa_request_update,
	.co_msg_parser      = xfrm_sa_msg_parser,
	.co_obj_ops         = &xfrm_sa_obj_ops,
	.co_include_event   = &xfrm_sa_update_cache
};

/**
 * @name XFRM SA Cache Managament
 * @{
 */

static void __attribute__ ((constructor)) xfrm_sa_init(void)
{
	nl_cache_mngt_register(&xfrmnl_sa_ops);
}

static void __attribute__ ((destructor)) xfrm_sa_exit(void)
{
	nl_cache_mngt_unregister(&xfrmnl_sa_ops);
}

/** @} */
