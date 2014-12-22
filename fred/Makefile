obj-m += sch_fred.o
CDIR=$(PWD)
#CDIR=/home/kaustubh/git/assignments/CSC573/fred
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CDIR) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CDIR) clean
