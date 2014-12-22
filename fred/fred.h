#ifndef __NET_SCHED_RED_H
#define __NET_SCHED_RED_H

#include <linux/types.h>
#include <linux/bug.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <net/dsfield.h>
#include <linux/reciprocal_div.h>
#include <linux/ip.h>
#define FRED_ONE_PERCENT ((u32)DIV_ROUND_CLOSEST(1ULL<<32, 100))

#define MAX_P_MIN (1 * FRED_ONE_PERCENT)
#define MAX_P_MAX (50 * FRED_ONE_PERCENT)
#define MAX_P_ALPHA(val) min(MAX_P_MIN, val / 4)

#define FRED_STAB_SIZE	256
#define FRED_STAB_MASK	(FRED_STAB_SIZE - 1)

struct fred_stats {
    u32 prob_drop; /* Early probability drops */
    u32 prob_mark; /* Early probability marks */
    u32 forced_drop; /* Forced drops, qavg > max_thresh */
    u32 forced_mark; /* Forced marks, qavg > max_thresh */
    u32 pdrop; /* Drops due to queue limits */
    u32 other; /* Drops due to drop() calls */
};

struct fred_flow_stats {
    u32 prob_drop; /* Early probability drops */
    u32 prob_mark; /* Early probability marks */
    u32 forced_drop; /* Forced drops, qavg > max_thresh */
    u32 forced_mark; /* Forced marks, qavg > max_thresh */
    u32 pdrop; /* Drops due to queue limits */
    u32 other; /* Drops due to drop() calls */
};
struct fred_parms {
    /* Parameters */
    u32 qth_min; /* Min avg length threshold: Wlog scaled */
    u32 qth_max; /* Max avg length threshold: Wlog scaled */
    u32 Scell_max;
    u32 max_P; /* probability, [0 .. 1.0] 32 scaled */
    /* reciprocal_value(max_P / qth_delta) */
    struct reciprocal_value max_P_reciprocal;
    u32 qth_delta; /* max_th - min_th */
    u32 target_min; /* min_th + 0.4*(max_th - min_th) */
    u32 target_max; /* min_th + 0.6*(max_th - min_th) */
    u8 Scell_log;
    u8 Wlog; /* log(W)		*/
    u8 Plog; /* random number bits	*/
    u8 Stab[FRED_STAB_SIZE];
};

struct fred_flow_data {
    u16 flowid;
    u32 qlen;
    u32 strike;
    struct fred_flow_stats stats;
    int allocated;
};
	
struct fred_vars {
    /* Variables */
    int qcount; /* Number of packets since last random
					   number generation */
    u32 qR; /* Cached random number */

    unsigned long qavg; /* Average queue length: Wlog scaled */
    ktime_t qidlestart; /* Start of current idle period */
    struct fred_flow_data flows[10];
    u16 Nactive;
    unsigned long avgcq;
};

static inline u32 fred_maxp(u8 Plog) {
    return Plog < 32 ? (~0U >> Plog) : ~0U;
}

static inline void fred_set_vars(struct fred_vars *v) {
    /* Reset average queue length, the value is strictly bound
     * to the parameters below, reseting hurts a bit but leaving
     * it might result in an unreasonable qavg for a while. --TGR
     */
    int i;
    v->qavg = 0;

    v->qcount = -1;
    v->Nactive = 0;
    v->avgcq = 0;
    for(i=0;i<10;i++) {
	v->flows[i].allocated=0;
    }
}

static inline void fred_set_parms(struct fred_parms *p,
        u32 qth_min, u32 qth_max, u8 Wlog, u8 Plog,
        u8 Scell_log, u8 *stab, u32 max_P) {
    int delta = qth_max - qth_min;
    u32 max_p_delta;

    p->qth_min = qth_min << Wlog;
    p->qth_max = qth_max << Wlog;
    p->Wlog = Wlog;
    p->Plog = Plog;
    if (delta < 0)
        delta = 1;
    p->qth_delta = delta;
    if (!max_P) {
        max_P = fred_maxp(Plog);
        max_P *= delta; /* max_P = (qth_max - qth_min)/2^Plog */
    }
    p->max_P = max_P;
    max_p_delta = max_P / delta;
    max_p_delta = max(max_p_delta, 1U);
    p->max_P_reciprocal = reciprocal_value(max_p_delta);

    p->Scell_log = Scell_log;
    p->Scell_max = (255 << Scell_log);

    if (stab)
        memcpy(p->Stab, stab, sizeof (p->Stab));
}

static inline int fred_is_idling(const struct fred_vars *v) {
    return v->qidlestart.tv64 != 0;
}

static inline void fred_start_of_idle_period(struct fred_vars *v) {
    v->qidlestart = ktime_get();
}

static inline void fred_end_of_idle_period(struct fred_vars *v) {
    v->qidlestart.tv64 = 0;
}

static inline void fred_restart(struct fred_vars *v) {
    fred_end_of_idle_period(v);
    fred_set_vars(v);
}

static inline u32 fred_random(const struct fred_parms *p) {
    return reciprocal_divide(prandom_u32(), p->max_P_reciprocal);
}

static inline int fred_mark_probability(const struct fred_parms *p,
        const struct fred_vars *v,
        unsigned long qavg) {
    /* The formula used below causes questions.

       OK. qR is random number in the interval
            (0..1/max_P)*(qth_max-qth_min)
       i.e. 0..(2^Plog). If we used floating point
       arithmetics, it would be: (2^Plog)*rnd_num,
       where rnd_num is less 1.

       Taking into account, that qavg have fixed
       point at Wlog, two lines
       below have the following floating point equivalent:

       max_P*(qavg - qth_min)/(qth_max-qth_min) < rnd/qcount

       Any questions? --ANK (980924)
     */
    return !(((qavg - p->qth_min) >> p->Wlog) * v->qcount < v->qR);
}

enum {
    FRED_BELOW_MIN_THRESH,
    FRED_BETWEEN_TRESH,
    FRED_ABOVE_MAX_TRESH,
};

enum {
    FRED_DONT_MARK,
    FRED_PROB_MARK,
    FRED_HARD_MARK,
};

static inline int fred_action_arrival(struct fred_flow_data *flow, const struct fred_parms *p,
        struct fred_vars *v,
        u64 maxq) {
    u32 qlenf = flow->qlen;
    u32 maxth = p->qth_max;
    u32 strikef = flow->strike;
    u32 minth = p->qth_min;
    u32 qavg = v->qavg;
    //assuming large buffers
    u8 minq = 4;
    if (qlenf >= maxq ||
            (v->qavg >= maxth && qlenf >= 2 * v->avgcq) ||
            (qlenf >= v->avgcq && strikef >= 2)) {
        flow->strike++;
        return FRED_HARD_MARK; // Note: terminate algorithm !
    }

    if ((minth <= qavg)&&(qavg < maxth)) {
        // CASE 1: Random drop mode

        v->qcount++; // Count increases drop probability and
        // makes sure we drop ASAP

        /* -----------------------------------------
           Drop ONLY from Robust flows !!
           Do NOT drop packets from fragile flows !!!
           ------------------------------------------ */
        if (qlenf >= minq &&
                qlenf >= v->avgcq) {
            // Calculate Drop Probability (same as RED)
            if (fred_mark_probability(p, v, qavg)) {
                v->qcount = 0;
                v->qR = fred_random(p);
                return FRED_PROB_MARK;
            }
            
        }
        return FRED_DONT_MARK;

    } else if (qavg < minth) {
        // CASE 2: NO drop mode
        v->qcount = -1;
        return FRED_DONT_MARK;
    } else {
        // CASE 3: FULL QUEUE drop mode (always drop)
        v->qcount = 0;
        return FRED_HARD_MARK;
    }

    BUG();
    return FRED_DONT_MARK;
}

#endif
