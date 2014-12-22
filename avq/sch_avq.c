
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <net/red.h>
#include <linux/reciprocal_div.h>

/*
This code contains avq implementation based on paper written by Srishankar S. Kunniyur and R. Srisankar titled "An adaptive virtual queue algorithm for active queue management"
It is copied and modified from kernel implementation of stock red algorithm (sch_red.c)
*/
struct avq_params {
    u32 scaledDesiredLinkCapacity; //alpha*gamma * linkCapacity
    u32 alphaNumerator;
    u32 alphaDenominator;
    u32 linkCapacity;
};

struct avq_vars {
    u32 VQLinkCapacity;
    u32 VQCapacity;
    ktime_t lastPacketArrivalTime;
};

struct avq_stats {
    u32 drop; /* Early probability drops */
    u32 mark; /* Early probability marks */
    u32 other; /* Drops due to drop() calls */
};

struct avq_sched_data {
	u32			limit;		/* HARD maximal queue length */
	unsigned char		flags;
	struct timer_list	adapt_timer;
    struct avq_params parms;
    struct avq_vars vars;
    struct avq_stats stats;
	struct Qdisc		*qdisc;
};

static inline int avq_use_ecn(struct avq_sched_data *q)
{
	return q->flags & TC_AVQ_ECN;
}

static inline void avq_set_parms(struct avq_params *p,
				 u32 scaledDesiredLinkCapacity, u32 alphaNumerator,u32 alphaDenominator, u32 linkCapacity)
{
    p->alphaNumerator=alphaNumerator;
    p->alphaDenominator=alphaDenominator;
    p->scaledDesiredLinkCapacity=scaledDesiredLinkCapacity;
    p->linkCapacity=linkCapacity;
}
static inline void avq_set_vars(struct avq_vars *v,struct avq_params *p)
{
   v->VQCapacity=0;
    v->lastPacketArrivalTime=ktime_get();
    v->VQLinkCapacity=0;    
//v->VQLinkCapacity=p->scaledDesiredLinkCapacity;
}

static int avq_enqueue(struct sk_buff *skb, struct Qdisc *sch) {
    struct avq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;
	int ret;

    struct avq_vars *v = &q->vars;
    struct avq_params *p = &q->parms;
    ktime_t currentTime=ktime_get();
    
    s64 delta_ms = ktime_us_delta(currentTime, v->lastPacketArrivalTime) / 1000;
    s64 signedCapacity=v->VQCapacity;
    u32 skbLength;
    //Devide by 1000 for converting to seconds
    signedCapacity = signedCapacity - (((s64)v->VQLinkCapacity*delta_ms)/1000);
    
    v->VQCapacity=(signedCapacity<0)?0:(u32)signedCapacity;
    
    skbLength=skb->len;
    if (v->VQCapacity + skbLength > q->limit) {
        //AVQ doesn't calculate marking probability
        sch->qstats.overlimits++;
	if (!avq_use_ecn(q) || !INET_ECN_set_ce(skb)) {
            q->stats.drop++;
            qdisc_drop(skb, sch);
            ret = NET_XMIT_CN;
            printk(KERN_INFO "Dropping packet based on algo, sbk length is %u, vq is %u,vqlinkcapacity(C-) %u qdisc backlog is %u",skb->len,v->VQCapacity,v->VQLinkCapacity,child->qstats.backlog);
            goto update_vqcapacity;
        }
        q->stats.mark++;
    }
    ret = qdisc_enqueue(skb, child);
    if (likely(ret == NET_XMIT_SUCCESS)) {
        sch->q.qlen++;
    } else if (net_xmit_drop_count(ret)) {
        q->stats.drop++;
        sch->qstats.drops++;
    }
    v->VQCapacity += skbLength;

update_vqcapacity:
    //printk(KERN_INFO "vqlinkcapacity(C-) %u scaledDesired %u delta %lld",v->VQLinkCapacity,p->scaledDesiredLinkCapacity,delta_ms);
    
    signedCapacity=v->VQLinkCapacity + ((s64)p->scaledDesiredLinkCapacity*delta_ms)/1000;
    if(signedCapacity>p->linkCapacity){
        signedCapacity=p->linkCapacity;
    }
    v->lastPacketArrivalTime=currentTime;

    //printk(KERN_INFO "skblength %u",skbLength);
    s64 scaledskblength=skbLength;
    scaledskblength=skbLength* p->alphaNumerator/(p->alphaDenominator);
    //printk(KERN_INFO "scaled skblength %lld",scaledskblength);
    
    signedCapacity=signedCapacity-scaledskblength;
    v->VQLinkCapacity = (signedCapacity<0)?0:(u32)signedCapacity;
    //printk(KERN_INFO "vqlinkcapacity(C-) %u signedcapacity %lld",v->VQLinkCapacity,signedCapacity);
            
    return ret;
}

static struct sk_buff *avq_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb;
    struct avq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;

	skb = child->dequeue(child);
	if (skb) {
		qdisc_bstats_update(sch, skb);
		sch->q.qlen--;
	}
	return skb;
}

static struct sk_buff *avq_peek(struct Qdisc *sch) {
    struct avq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;

	return child->ops->peek(child);
}

static unsigned int avq_drop(struct Qdisc *sch) {
    struct avq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;
	unsigned int len;

	if (child->ops->drop && (len = child->ops->drop(child)) > 0) {
		q->stats.other++;
		sch->qstats.drops++;
		sch->q.qlen--;
		return len;
	}
	return 0;
}

static inline void avq_restart(struct avq_vars *v) {
    v->VQCapacity = 0;
    v->VQLinkCapacity = 0;
    v->lastPacketArrivalTime.tv64 = 0;
}

static void avq_reset(struct Qdisc *sch) {
    struct avq_sched_data *q = qdisc_priv(sch);

	qdisc_reset(q->qdisc);
    sch->q.qlen = 0;
    avq_restart(&q->vars);
}

static void avq_destroy(struct Qdisc *sch) {
    struct avq_sched_data *q = qdisc_priv(sch);
    qdisc_destroy(q->qdisc);
}
static const struct nla_policy avq_policy[TCA_AVQ_MAX + 1] = {
	[TCA_AVQ_PARMS]	= { .len = sizeof(struct tc_avq_qopt) },
};

static int avq_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct avq_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_AVQ_MAX + 1];
	struct tc_avq_qopt *ctl;
	struct Qdisc *child = NULL;
	int err;

	if (opt == NULL)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_AVQ_MAX, opt, avq_policy);
	if (err < 0)
		return err;

	if (tb[TCA_AVQ_PARMS] == NULL)
		return -EINVAL;

	ctl = nla_data(tb[TCA_AVQ_PARMS]);

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

	avq_set_parms(&q->parms,
		      ctl->scaledDesiredLinkCapacity,ctl->alphaNumerator,ctl->alphaDenominator,ctl->linkCapacity);
	avq_set_vars(&q->vars,&q->parms);

	sch_tree_unlock(sch);
	return 0;
}

static int avq_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct avq_sched_data *q = qdisc_priv(sch);

	q->qdisc = &noop_qdisc;
	return avq_change(sch, opt);
}

static int avq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct avq_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = NULL;
	
        struct tc_avq_qopt opt = {
	.limit		= q->limit,
	.flags		= q->flags,
        .scaledDesiredLinkCapacity=q->parms.scaledDesiredLinkCapacity,
        .alphaNumerator = q->parms.alphaNumerator,
        .alphaDenominator=q->parms.alphaDenominator,
        .linkCapacity=q->parms.linkCapacity

	};

	sch->qstats.backlog = q->qdisc->qstats.backlog;
	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;
	if (nla_put(skb, TCA_RED_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;
	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -EMSGSIZE;
}

static int avq_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct avq_sched_data *q = qdisc_priv(sch);
	struct tc_avq_xstats st = {
		.drop	= q->stats.drop,
		.other	= q->stats.other,
		.marked	= q->stats.mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int avq_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct avq_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(1);
	tcm->tcm_info = q->qdisc->handle;
	return 0;
}

static int avq_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	struct avq_sched_data *q = qdisc_priv(sch);

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

static struct Qdisc *avq_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct avq_sched_data *q = qdisc_priv(sch);
	return q->qdisc;
}

static unsigned long avq_get(struct Qdisc *sch, u32 classid)
{
	return 1;
}

static void avq_put(struct Qdisc *sch, unsigned long arg)
{
}

static void avq_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
	if (!walker->stop) {
		if (walker->count >= walker->skip)
			if (walker->fn(sch, 1, walker) < 0) {
				walker->stop = 1;
				return;
			}
		walker->count++;
	}
}

static const struct Qdisc_class_ops avq_class_ops = {
	.graft		=	avq_graft,
	.leaf		=	avq_leaf,
	.get		=	avq_get,
	.put		=	avq_put,
	.walk		=	avq_walk,
	.dump		=	avq_dump_class,
};

static struct Qdisc_ops avq_qdisc_ops __read_mostly = {
	.id		=	"avq",
	.priv_size	=	sizeof(struct avq_sched_data),
	.cl_ops		=	&avq_class_ops,
	.enqueue	=	avq_enqueue,
	.dequeue	=	avq_dequeue,
	.peek		=	avq_peek,
	.drop		=	avq_drop,
	.init		=	avq_init,
	.reset		=	avq_reset,
	.destroy	=	avq_destroy,
	.change		=	avq_change,
	.dump		=	avq_dump,
	.dump_stats	=	avq_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init avq_module_init(void)
{
	return register_qdisc(&avq_qdisc_ops);
}

static void __exit avq_module_exit(void)
{
	unregister_qdisc(&avq_qdisc_ops);
}

module_init(avq_module_init)
module_exit(avq_module_exit)

MODULE_LICENSE("GPL");
