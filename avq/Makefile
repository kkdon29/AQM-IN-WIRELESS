obj-m += sch_avq.o
CDIR=$(PWD)
#CDIR=/home/kaustubh/git/CSC573-project/avq

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CDIR) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CDIR) clean
