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

#include "tc_red.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... AVQ limit BYTES alpha ALPHA gamma GAMMA \n");
	fprintf(stderr, "               bandwidth\n");
	fprintf(stderr, "               [ecn] [harddrop]\n");
}

static int avq_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
	struct tc_avq_qopt opt;
        float alpha=-1,gamma=-1;
	unsigned rate = 0;
	struct rtattr *tail;

	memset(&opt, 0, sizeof(opt));

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_size(&opt.limit, *argv)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
		}else if(strcmp(*argv,"alpha")==0){
                    NEXT_ARG();
                    sscanf(*argv,"%f",&alpha);
                }else if(strcmp(*argv,"gamma")==0){
                    NEXT_ARG();
                    sscanf(*argv,"%f",&gamma);
                } 
                else if (strcmp(*argv, "bandwidth") == 0) {
			NEXT_ARG();
			if (get_rate(&rate, *argv)) {
				fprintf(stderr, "Illegal \"bandwidth\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "ecn") == 0) {
			opt.flags |= TC_AVQ_ECN;
		}  else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	
	if (!opt.limit||alpha<0||gamma<0||rate==0) {
		fprintf(stderr, "AVQ: Required parameter (limit,alpha,gamma,bandwidth) is missing\n");
		return -1;
	}
        if(alpha>=1){
            fprintf(stderr,"Invalid value for alpha");
            return -1;
        }
        if(gamma>=1){
            fprintf(stderr,"Invalid value for gamma");
            return -1;
        }
        /* Compute default min/max thresholds based on
	 * Sally Floyd's recommendations:
	 * http://www.icir.org/floyd/REDparameters.txt
	 */
	opt.alphaNumerator=alpha*10000;
        opt.alphaDenominator=10000;
        opt.linkCapacity=rate;
        opt.scaledDesiredLinkCapacity=(__u32)(opt.linkCapacity*alpha*gamma);

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	addattr_l(n, 1024, TCA_AVQ_PARMS, &opt, sizeof(opt));
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

static int avq_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_AVQ_MAX + 1];
	struct tc_avq_qopt *qopt;

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_AVQ_MAX, opt);

	if (tb[TCA_AVQ_PARMS] == NULL)
		return -1;
	qopt = RTA_DATA(tb[TCA_AVQ_PARMS]);
	if (RTA_PAYLOAD(tb[TCA_AVQ_PARMS])  < sizeof(*qopt))
		return -1;
        float alpha=(float)qopt->alphaNumerator/qopt->alphaDenominator;
        float gamma=((float)qopt->alphaDenominator*qopt->scaledDesiredLinkCapacity)/(qopt->alphaNumerator*qopt->linkCapacity);
	fprintf(f, "limit %u alpha %f gamma %f bandwidth %u",
		qopt->limit,alpha,gamma,qopt->linkCapacity);
	if (qopt->flags & TC_AVQ_ECN)
		fprintf(f, "ecn ");
	return 0;
}

static int avq_print_xstats(struct qdisc_util *qu, FILE *f, struct rtattr *xstats)
{
#ifdef TC_AVQ_ECN
	struct tc_avq_xstats *st;

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);
	fprintf(f, "  marked %u  dropped %u other %u",
		st->marked, st->drop, st->other);
	return 0;

#endif
	return 0;
}


struct qdisc_util avq_qdisc_util = {
	.id		= "avq",
	.parse_qopt	= avq_parse_opt,
	.print_qopt	= avq_print_opt,
	.print_xstats	= avq_print_xstats,
};
