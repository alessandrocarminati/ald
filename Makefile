KDIR ?= /lib/modules/$(shell uname -r)/build
CONFIG_ALD ?= m
obj ?= ./

obj-$(CONFIG_ALD)			+= ald.o

