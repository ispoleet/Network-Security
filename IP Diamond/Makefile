obj-m += ipd_krnl.o
COMPILER = gcc

all:
	$(COMPILER) -pthread -o ipd_backbone ipd_usr.c ipd_rsm.c ipd_lib.c ipd_main.c
	$(COMPILER) -pthread -o ipd_relay ipd_relay.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm ipd_backbone ipd_relay
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


