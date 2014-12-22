#ifndef _TC_FRED_H_
#define _TC_FRED_H_ 1

extern int tc_fred_eval_P(unsigned qmin, unsigned qmax, double prob);
extern int tc_fred_eval_ewma(unsigned qmin, unsigned burst, unsigned avpkt);
extern int tc_fred_eval_idle_damping(int wlog, unsigned avpkt, unsigned bandwidth, __u8 *sbuf);

#endif
