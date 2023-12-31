#
# Version: 1.5
#
# Copyright (C) 2009 Intel Corporation.  All Rights Reserved.
#
#     This file is part of SEP Development Kit
#
#     SEP Development Kit is free software; you can redistribute it
#     and/or modify it under the terms of the GNU General Public License
#     version 2 as published by the Free Software Foundation.
#
#     SEP Development Kit is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with SEP Development Kit; if not, write to the Free Software
#     Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
#     As a special exception, you may use this file as part of a free software
#     library without restriction.  Specifically, if other files instantiate
#     templates or use macros or inline functions from this file, or you compile
#     this file and link it with other files to produce an executable, this
#     file does not by itself cause the resulting executable to be covered by
#     the GNU General Public License.  This exception does not however
#     invalidate any other reasons why the executable file might be covered by
#     the GNU General Public License.
#

# -------------------- user configurable options ------------------------

# base name of driver
DRIVER_NAME = pax

# location to install driver
ifeq ($(INSTALL),)
INSTALL = .
endif

# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
EXTRA_CFLAGS += -I$(LDDINCDIR) -I$(LDDINCDIR1)

ifeq ($(UDEV_AVAILABLE),NO)
    EXTRA_CFLAGS += -DDRV_UDEV_UNAVAILABLE
    $(info ********************************************************************************)
    $(info WARNING: The device manager is NOT available. It create device files separately.)
    $(info ********************************************************************************)
endif

# if ARCH variable is set, unset it to avoid conflicts with kbuild
unexport ARCH

# platform details
MACH ?= $(shell uname -m)
ifeq ($(MACH),x86_64)
PLATFORM=x32_64
endif
ifeq ($(PLATFORM),)
PLATFORM=x32
endif
KERNEL_VERSION ?= $(shell uname -r)
SMP := $(shell uname -v | grep SMP)
ARITY=up
ifneq ($(SMP),)
ARITY=smp
endif

MAKE_CMD = $(MAKE) -C $(KERNEL_SRC_DIR) M=$(PWD) LDDINCDIR=$(PWD)/../../include LDDINCDIR1=$(PWD)/../inc modules PWD=$(PWD) -j4

# eventual filename of the driver
DRIVER_FILENAME=$(DRIVER_NAME)-$(PLATFORM)-$(KERNEL_VERSION)$(ARITY).ko

# build options ...
ifneq ($(KERNELRELEASE),)
	obj-m := $(DRIVER_NAME).o

# targets ...

# Otherwise, we were called directly from the command
# line; invoke the kernel build system.
else
	KERNEL_SRC_DIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

all: default

default:
ifeq ($(VERBOSE),1)
	$(MAKE_CMD)
	cp $(DRIVER_NAME).ko $(DRIVER_FILENAME)
else
	@$(MAKE_CMD) > /dev/null
	@cp $(DRIVER_NAME).ko $(DRIVER_FILENAME)
endif

endif

install:
	@cp $(DRIVER_FILENAME) $(INSTALL)/$(DRIVER_FILENAME)
	@cp insmod-pax $(INSTALL)/insmod-pax
	@cp rmmod-pax $(INSTALL)/rmmod-pax
	@cp boot-script $(INSTALL)/boot-script
	@echo "Installed $(DRIVER_NAME) driver to $(INSTALL)/$(DRIVER_FILENAME) ."

clean:
	rm -f *.o .*.o.cmd .*.o.d .*.ko.cmd .*.ko.unsigned.cmd *.gcno .cache.mk *.o.ur-safe .*.o.tmp *.mod .*.mod.cmd
	rm -f $(DRIVER_NAME).ko $(DRIVER_NAME).ko.unsigned $(DRIVER_FILENAME)
	rm -f Module.symvers Modules.symvers *.mod.c modules.order Module.markers .modules.order.cmd .Module.symvers.cmd
	rm -rf .tmp_versions

distclean: clean
	rm -f $(DRIVER_NAME)*.ko
