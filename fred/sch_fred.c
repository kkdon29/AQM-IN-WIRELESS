
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include "fred.h"
#include <linux/if_ether.h>
#include<linux/tcp.h>
#include<linux/udp.h>
/*
	This algorithm is based on paper by Dong lin and Robert Morris titled "dynamics of random early detection". The implementation has been copied and modified from kernel stock implementation of red algorithm sch_red.c
*/

/*	Parameters, settable by user:
        -----------------------------

        limit		- bytes (must be > qth_max + burst)

        Hard limit on queue length, should be chosen >qth_max
        to allow packet bursts. This parameter does not
        affect the algorithms behaviour and can be chosen
        arbitrarily high (well, less than ram size)
        Really, this limit will never be reached
        if FRED works correctly.
 */


struct fred_sched_data {
    u32 limit; /* HARD maximal queue length */
    unsigned char flags;
    struct fred_parms parms;
    struct fred_vars vars;
    struct fred_stats stats;
    struct Qdisc *qdisc;
};

static inline int fred_use_ecn(struct fred_sched_data *q) {
    return q->flags & TC_FRED_ECN;
}

static inline int fred_use_harddrop(struct fred_sched_data *q) {
    return q->flags & TC_FRED_HARDDROP;
}

static int skb_belongs_to_flow(struct fred_flow_data *flow, u16 sourcePort) {
    if (sourcePort== flow->flowid) {
        return 1;
    }
    return 0;
}

static struct fred_flow_data * fred_get_flow(struct sk_buff *skb, struct fred_sched_data *q) {
    struct fred_flow_data *flow = NULL;
    struct iphdr *ip_header;
    u16 sourcePort;
    int i;
    if (skb == NULL) {
        return NULL;
    }
    ip_header = ip_hdr(skb);
    sourcePort=0;
    if(ip_header){
        if(ip_header->protocol==0x06){
            struct tcphdr *tcp_header=(struct tcphdr *)((void *)ip_header+ip_header->ihl*4);
            sourcePort=ntohs(tcp_header->source);
        }else if (ip_header->protocol==17){
            struct udphdr *udp_header=(struct udphdr *)((void *)ip_header+ip_header->ihl*4);
            sourcePort=ntohs(udp_header->source);
        }
    }
    for (i=0; i< 10; i++) {
        if ((q->vars.flows[i].allocated==1)&&(q->vars.flows[i].flowid==sourcePort)) {
            return &q->vars.flows[i];
        }
    }
    flow=NULL;
    for (i=0; i< 10; i++) {
        if (q->vars.flows[i].allocated==0) {
            	flow=&q->vars.flows[i];
		break;
        }
    }
    if(flow==NULL){
         return NULL;
    }
    memset(flow, 0, sizeof (struct fred_flow_data));
    flow->flowid=sourcePort;
    q->vars.Nactive=q->vars.Nactive+1;
    flow->allocated=1;
    return flow;
}

static inline void fred_calculate_avgcq(struct fred_sched_data *q, struct Qdisc *child, int pkt_being_received) {
    struct fred_vars *v = &q->vars;
    struct fred_parms *p = &q->parms;
    unsigned int backlog = child->qstats.backlog;
    unsigned long unscaledAvg;
        
    if (backlog > 0 || !pkt_being_received) {
        /* calculation taken from red algo.
         */
        v->qavg = v->qavg + (backlog - (v->qavg >> p->Wlog));
    } else {
        s64 delta = ktime_us_delta(ktime_get(), v->qidlestart);
        long us_idle = min_t(s64, delta, p->Scell_max);
        int shift;
        /*
         * The problem: ideally, average length queue recalcultion should
         * be done over constant clock intervals. This is too expensive, so
         * that the calculation is driven by outgoing packets.
         * When the queue is idle we have to model this clock by hand.
         *
         * SF+VJ proposed to "generate":
         *
         *	m = idletime / (average_pkt_size / bandwidth)
         *
         * dummy packets as a burst after idle time, i.e.
         *
         * 	v->qavg *= (1-W)^m
         *
         * This is an apparently overcomplicated solution (f.e. we have to
         * precompute a table to make this calculation in reasonable time)
         * I believe that a simpler model may be used here,
         * but it is field for experiments.
         */

        shift = p->Stab[(us_idle >> p->Scell_log) & FRED_STAB_MASK];

        if (shift)
            v->qavg = v->qavg >> shift;
        else {
            /* Approximate initial part of exponent with linear function:
             *
             * 	(1-W)^m ~= 1-mW + ...
             *
             * Seems, it is the best solution to
             * problem of too coarse exponent tabulation.
             */
            us_idle = (v->qavg * (u64) us_idle) >> p->Scell_log;

            if (us_idle < (v->qavg >> 1))
                v->qavg = v->qavg - us_idle;
            else
                v->qavg = v->qavg >> 1;
        }
        /*
         * This part is different than red
         */
        v->qidlestart = ktime_get();
    }
    unscaledAvg=v->qavg<<p->Wlog;
    if (v->Nactive > 0) {
        v->avgcq = unscaledAvg / v->Nactive;
    } else {
        v->avgcq = unscaledAvg;
    }
    if (v->avgcq < 1) {
        v->avgcq = 1;
    }
    if (backlog == 0 || !pkt_being_received) {
        v->qidlestart = ktime_get();
    }
}

static void checkEmptyFlow(struct fred_flow_data *flow, struct fred_vars *v) {
    if (flow == NULL) {
        return;
    }
    if (flow->qlen == 0) {
    	flow->allocated=0;
        v->Nactive=v->Nactive-1;
    }
}
static int fred_enqueue(struct sk_buff *skb, struct Qdisc *sch) {
    struct fred_sched_data *q = qdisc_priv(sch);
    struct Qdisc *child = q->qdisc;
    int ret;
    struct fred_flow_data *flow = fred_get_flow(skb, q);
    u64 maxq;
    if (flow == NULL) {
        //Flows are not working,enqueue packet directly
        goto enqueue_packet;
    }
    if (child->qstats.backlog == 0) {
        fred_calculate_avgcq(q, child, 1);
    }
    maxq = q->parms.qth_min<<q->parms.Wlog;

    if (q->vars.qavg >= q->parms.qth_max) {
        maxq = 2;
    }

    switch (fred_action_arrival(flow, &q->parms, &q->vars, maxq)) {
    case FRED_DONT_MARK:
        break;

    case FRED_PROB_MARK:
        sch->qstats.overlimits++;
        if (!fred_use_ecn(q) || !INET_ECN_set_ce(skb)) {
            q->stats.prob_drop++;
            flow->stats.prob_drop++;
            goto congestion_drop;
        }

        q->stats.prob_mark++;
        flow->stats.prob_mark++;
        break;

    case FRED_HARD_MARK:
        sch->qstats.overlimits++;
        if (fred_use_harddrop(q) || !fred_use_ecn(q) ||
                !INET_ECN_set_ce(skb)) {
            q->stats.forced_drop++;
            flow->stats.forced_drop++;
            goto congestion_drop;
        }
        q->stats.forced_mark++;
        break;
    }

enqueue_packet:
    ret = qdisc_enqueue(skb, child);
    if (likely(ret == NET_XMIT_SUCCESS)) {
        sch->q.qlen++;
        if (flow != NULL) {
            flow->qlen++;
        }
    } else if (net_xmit_drop_count(ret)) {
        q->stats.pdrop++;
        sch->qstats.drops++;
        if (flow != NULL) {
            flow->stats.pdrop++;
            checkEmptyFlow(flow,&q->vars);
        }
    }
    return ret;

congestion_drop:
    qdisc_drop(skb, sch);
    checkEmptyFlow(flow,&q->vars);
    return NET_XMIT_CN;
}

static struct sk_buff *fred_dequeue(struct Qdisc *sch) {
    struct sk_buff *skb;
    struct fred_sched_data *q = qdisc_priv(sch);
    struct Qdisc *child = q->qdisc;
    struct fred_flow_data *flow;
    skb = child->dequeue(child);
    flow = fred_get_flow(skb, q);

    if (skb) {

        qdisc_bstats_update(sch, skb);
        sch->q.qlen--;
        fred_calculate_avgcq(q, child, 0);

        if (flow != NULL) {
            flow->qlen--;
            checkEmptyFlow(flow,&q->vars);
        }
    } 
    return skb;
}

static struct sk_buff *fred_peek(struct Qdisc *sch) {
    struct fred_sched_data *q = qdisc_priv(sch);
    struct Qdisc *child = q->qdisc;

    return child->ops->peek(child);
}

static unsigned int fred_drop(struct Qdisc *sch) {
    struct fred_sched_data *q = qdisc_priv(sch);
    struct Qdisc *child = q->qdisc;
    unsigned int len;
    struct sk_buff *skb = child->ops->peek(child);
    if (child->ops->drop && (len = child->ops->drop(child)) > 0) {
        struct fred_flow_data *flow;
        q->stats.other++;
        sch->qstats.drops++;
        sch->q.qlen--;
        flow = fred_get_flow(skb, q);
        if (flow != NULL) {
            flow->qlen--;
            flow->stats.other++;
        }
        fred_calculate_avgcq(q, child, 0);
        checkEmptyFlow(flow,&q->vars);
        return len;
    }

    return 0;
}

static void fred_reset(struct Qdisc *sch) {
    struct fred_sched_data *q = qdisc_priv(sch);
    int i;
    for (i=0;i<10;i++) {
        q->vars.flows[i].allocated=0;
    }
    qdisc_reset(q->qdisc);
    sch->q.qlen = 0;
    fred_restart(&q->vars);
}

static void fred_destroy(struct Qdisc *sch) {
    struct fred_sched_data *q = qdisc_priv(sch);
    int i;
    for (i=0;i<10;i++) {
        q->vars.flows[i].allocated=0;
    }

    qdisc_destroy(q->qdisc);
}

static const struct nla_policy fred_policy[TCA_FRED_MAX + 1] = {
    [TCA_FRED_PARMS] =
    { .len = sizeof (struct tc_fred_qopt)},
    [TCA_FRED_STAB] =
    { .len = FRED_STAB_SIZE},
    [TCA_FRED_MAX_P] =
    { .type = NLA_U32},
};

static int fred_change(struct Qdisc *sch, struct nlattr *opt) {
    struct fred_sched_data *q = qdisc_priv(sch);
    struct nlattr * tb[TCA_FRED_MAX + 1];
    struct tc_fred_qopt *ctl;
    struct Qdisc *child = NULL;
    int err;
    u32 max_P;

    if (opt == NULL)
        return -EINVAL;

    err = nla_parse_nested(tb, TCA_FRED_MAX, opt, fred_policy);
    if (err < 0)
        return err;

    if (tb[TCA_FRED_PARMS] == NULL ||
            tb[TCA_FRED_STAB] == NULL)
        return -EINVAL;

    max_P = tb[TCA_FRED_MAX_P] ? nla_get_u32(tb[TCA_FRED_MAX_P]) : 0;

    ctl = nla_data(tb[TCA_FRED_PARMS]);

    if (ctl->limit > 0) {
        child = fifo_create_dflt(sch, &bfifo_qdisc_ops, ctl->limit);
        if (IS_ERR(child))
            return PTR_ERR(child);
    }

    sch_tree_lock(sch);
    q->flags = ctl->flags;
    q->limit = ctl->limit;
    if (child) {
        qdisc_tree_decrease_qlen(q->qdisc, q->qdisc->q.qlen);
        qdisc_destroy(q->qdisc);
        q->qdisc = child;
    }

    fred_set_parms(&q->parms,
            ctl->qth_min, ctl->qth_max, ctl->Wlog,
            ctl->Plog, ctl->Scell_log,
            nla_data(tb[TCA_RED_STAB]),
            max_P);
    fred_set_vars(&q->vars);
    if(!q->qdisc->q.qlen)
        q->vars.qidlestart=ktime_get();
    sch_tree_unlock(sch);
    return 0;
}

static int fred_init(struct Qdisc *sch, struct nlattr *opt) {
    struct fred_sched_data *q = qdisc_priv(sch);

    q->qdisc = &noop_qdisc;
    return fred_change(sch, opt);
}

static int fred_dump(struct Qdisc *sch, struct sk_buff *skb) {
    struct fred_sched_data *q = qdisc_priv(sch);
    struct nlattr *opts = NULL;
    struct tc_fred_qopt opt = {
        .limit = q->limit,
        .flags = q->flags,
        .qth_min = q->parms.qth_min >> q->parms.Wlog,
        .qth_max = q->parms.qth_max >> q->parms.Wlog,
        .Wlog = q->parms.Wlog,
        .Plog = q->parms.Plog,
        .Scell_log = q->parms.Scell_log,
    };

    sch->qstats.backlog = q->qdisc->qstats.backlog;
    opts = nla_nest_start(skb, TCA_OPTIONS);
    if (opts == NULL)
        goto nla_put_failure;
    if (nla_put(skb, TCA_FRED_PARMS, sizeof (opt), &opt) ||
            nla_put_u32(skb, TCA_FRED_MAX_P, q->parms.max_P))
        goto nla_put_failure;
    return nla_nest_end(skb, opts);

nla_put_failure:
    nla_nest_cancel(skb, opts);
    return -EMSGSIZE;
}

static int fred_dump_stats(struct Qdisc *sch, struct gnet_dump *d) {
    struct fred_sched_data *q = qdisc_priv(sch);
    struct tc_fred_xflowstats *flowStats;
    char *stat_buf;
    int ret,i;
    struct tc_fred_xstats st = {
        .early = q->stats.prob_drop + q->stats.forced_drop,
        .pdrop = q->stats.pdrop,
        .other = q->stats.other,
        .marked = q->stats.prob_mark + q->stats.forced_mark,
        .nactive=q->vars.Nactive,
    };
    int flowStat=0;
    for(i=0;i<10;i++){
	if(q->vars.flows[i].allocated==0)
		continue;
        
        struct fred_flow_data *flow=&q->vars.flows[i];
        st.flowStats[flowStat].flowid=flow->flowid;
        st.flowStats[flowStat].early=flow->stats.prob_drop+flow->stats.forced_drop;
	st.flowStats[flowStat].pdrop=flow->stats.pdrop;
	st.flowStats[flowStat].other=flow->stats.other;
	st.flowStats[flowStat].marked=flow->stats.prob_mark+flow->stats.forced_mark;
        flowStat++;
    }
    ret= gnet_stats_copy_app(d, &st, sizeof(st));
    return ret;
}

static int fred_dump_class(struct Qdisc *sch, unsigned long cl,
        struct sk_buff *skb, struct tcmsg *tcm) {
    struct fred_sched_data *q = qdisc_priv(sch);

    tcm->tcm_handle |= TC_H_MIN(1);
    tcm->tcm_info = q->qdisc->handle;
    return 0;
}

static int fred_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
        struct Qdisc **old) {
    struct fred_sched_data *q = qdisc_priv(sch);

    if (new == NULL)
        new = &noop_qdisc;

    sch_tree_lock(sch);
    *old = q->qdisc;
    q->qdisc = new;
    qdisc_tree_decrease_qlen(*old, (*old)->q.qlen);
    qdisc_reset(*old);
    sch_tree_unlock(sch);
    return 0;
}

static struct Qdisc *fred_leaf(struct Qdisc *sch, unsigned long arg) {
    struct fred_sched_data *q = qdisc_priv(sch);
    return q->qdisc;
}

static unsigned long fred_get(struct Qdisc *sch, u32 classid) {
    return 1;
}

static void fred_put(struct Qdisc *sch, unsigned long arg) {
}

static void fred_walk(struct Qdisc *sch, struct qdisc_walker *walker) {
    if (!walker->stop) {
        if (walker->count >= walker->skip)
            if (walker->fn(sch, 1, walker) < 0) {
                walker->stop = 1;
                return;
            }
        walker->count++;
    }
}

static const struct Qdisc_class_ops fred_class_ops = {
    .graft = fred_graft,
    .leaf = fred_leaf,
    .get = fred_get,
    .put = fred_put,
    .walk = fred_walk,
    .dump = fred_dump_class,
};

static struct Qdisc_ops fred_qdisc_ops __read_mostly = {
    .id = "fred",
    .priv_size = sizeof (struct fred_sched_data),
    .cl_ops = &fred_class_ops,
    .enqueue = fred_enqueue,
    .dequeue = fred_dequeue,
    .peek = fred_peek,
    .drop = fred_drop,
    .init = fred_init,
    .reset = fred_reset,
    .destroy = fred_destroy,
    .change = fred_change,
    .dump = fred_dump,
    .dump_stats = fred_dump_stats,
    .owner = THIS_MODULE,
};

static int __init fred_module_init(void) {
    return register_qdisc(&fred_qdisc_ops);
}

static void __exit fred_module_exit(void) {
    unregister_qdisc(&fred_qdisc_ops);
}

module_init(fred_module_init)
module_exit(fred_module_exit)

MODULE_LICENSE("GPL");
