/*
 * q_red.c		RED.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>

#include "utils.h"
#include "tc_util.h"

#include "tc_fred.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... red limit BYTES [min BYTES] [max BYTES] avpkt BYTES [burst PACKETS]\n");
	fprintf(stderr, "               [probability PROBABILITY] bandwidth KBPS\n");
	fprintf(stderr, "               [ecn] [harddrop]\n");
}

static int fred_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
	struct tc_fred_qopt opt;
	unsigned burst = 0;
	unsigned avpkt = 0;
	double probability = 0.02;
	unsigned rate = 0;
	int wlog;
	__u8 sbuf[256];
	__u32 max_P;
	struct rtattr *tail;

	memset(&opt, 0, sizeof(opt));

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_size(&opt.limit, *argv)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "min") == 0) {
			NEXT_ARG();
			if (get_size(&opt.qth_min, *argv)) {
				fprintf(stderr, "Illegal \"min\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "max") == 0) {
			NEXT_ARG();
			if (get_size(&opt.qth_max, *argv)) {
				fprintf(stderr, "Illegal \"max\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "burst") == 0) {
			NEXT_ARG();
			if (get_unsigned(&burst, *argv, 0)) {
				fprintf(stderr, "Illegal \"burst\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "avpkt") == 0) {
			NEXT_ARG();
			if (get_size(&avpkt, *argv)) {
				fprintf(stderr, "Illegal \"avpkt\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "probability") == 0) {
			NEXT_ARG();
			if (sscanf(*argv, "%lg", &probability) != 1) {
				fprintf(stderr, "Illegal \"probability\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "bandwidth") == 0) {
			NEXT_ARG();
			if (get_rate(&rate, *argv)) {
				fprintf(stderr, "Illegal \"bandwidth\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "ecn") == 0) {
			opt.flags |= TC_FRED_ECN;
		} else if (strcmp(*argv, "harddrop") == 0) {
			opt.flags |= TC_FRED_HARDDROP;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	if (rate == 0)
		get_rate(&rate, "10Mbit");

	if (!opt.limit || !avpkt) {
		fprintf(stderr, "FRED: Required parameter (limit, avpkt) is missing\n");
		return -1;
	}
	/* Compute default min/max thresholds based on
	 * Sally Floyd's recommendations:
	 * http://www.icir.org/floyd/REDparameters.txt
	 */
	if (!opt.qth_max)
		opt.qth_max = opt.qth_min ? opt.qth_min * 3 : opt.limit / 4;
	if (!opt.qth_min)
		opt.qth_min = opt.qth_max / 3;
	if (!burst)
		burst = (2 * opt.qth_min + opt.qth_max) / (3 * avpkt);
	if ((wlog = tc_fred_eval_ewma(opt.qth_min, burst, avpkt)) < 0) {
		fprintf(stderr, "FRED: failed to calculate EWMA constant.\n");
		return -1;
	}
	if (wlog >= 10)
		fprintf(stderr, "FRED: WARNING. Burst %d seems to be too large.\n", burst);
	opt.Wlog = wlog;
	if ((wlog = tc_fred_eval_P(opt.qth_min, opt.qth_max, probability)) < 0) {
		fprintf(stderr, "FRED: failed to calculate probability.\n");
		return -1;
	}
	opt.Plog = wlog;
	if ((wlog = tc_fred_eval_idle_damping(opt.Wlog, avpkt, rate, sbuf)) < 0) {
		fprintf(stderr, "FRED: failed to calculate idle damping table.\n");
		return -1;
	}
	opt.Scell_log = wlog;

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	addattr_l(n, 1024, TCA_FRED_PARMS, &opt, sizeof(opt));
	addattr_l(n, 1024, TCA_FRED_STAB, sbuf, 256);
	max_P = probability * pow(2, 32);
	addattr_l(n, 1024, TCA_FRED_MAX_P, &max_P, sizeof(max_P));
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

static int fred_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_FRED_MAX + 1];
	struct tc_fred_qopt *qopt;
	__u32 max_P = 0;
	SPRINT_BUF(b1);
	SPRINT_BUF(b2);
	SPRINT_BUF(b3);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_FRED_MAX, opt);

	if (tb[TCA_FRED_PARMS] == NULL)
		return -1;
	qopt = RTA_DATA(tb[TCA_FRED_PARMS]);
	if (RTA_PAYLOAD(tb[TCA_FRED_PARMS])  < sizeof(*qopt))
		return -1;

	if (tb[TCA_FRED_MAX_P] &&
	    RTA_PAYLOAD(tb[TCA_FRED_MAX_P]) >= sizeof(__u32))
		max_P = rta_getattr_u32(tb[TCA_FRED_MAX_P]);

	fprintf(f, "limit %s min %s max %s ",
		sprint_size(qopt->limit, b1),
		sprint_size(qopt->qth_min, b2),
		sprint_size(qopt->qth_max, b3));
	if (qopt->flags & TC_FRED_ECN)
		fprintf(f, "ecn ");
	if (qopt->flags & TC_FRED_HARDDROP)
		fprintf(f, "harddrop ");
	if (show_details) {
		fprintf(f, "ewma %u ", qopt->Wlog);
		if (max_P)
			fprintf(f, "probability %lg ", max_P / pow(2, 32));
		else
			fprintf(f, "Plog %u ", qopt->Plog);
		fprintf(f, "Scell_log %u", qopt->Scell_log);
	}
	return 0;
}

static int fred_print_xstats(struct qdisc_util *qu, FILE *f, struct rtattr *xstats)
{
#ifdef TC_FRED_ECN
	struct tc_fred_xstats *st;

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);
        if(RTA_PAYLOAD(xstats)<(sizeof(*st))){
            return -1;
        }
        fprintf(f, "  marked %u early %u pdrop %u other %u \n ",
		st->marked, st->early, st->pdrop, st->other);
	int i=st->nactive;
        struct tc_fred_xflowstats *flowStat=st->flowStats;
        printf("nactive is %d",i);
	while(i>0){
            /*
             * http://www.binarytides.com/c-program-to-get-mac-address-from-interface-name-on-linux/
             */
            fprintf(f,"flowid: %u" , flowStat[i].flowid);
            
            fprintf(f, "  marked %u early %u pdrop %u other %u",
		flowStat[i].marked, flowStat[i].early, flowStat[i].pdrop, flowStat[i].other);
            i--;
        }
        return 0;

#endif
	return 0;
}


struct qdisc_util fred_qdisc_util = {
	.id		= "fred",
	.parse_qopt	= fred_parse_opt,
	.print_qopt	= fred_print_opt,
	.print_xstats	= fred_print_xstats,
};
