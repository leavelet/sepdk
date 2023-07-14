#
#     Copyright (C) 2010-2023 Intel Corporation.  All Rights Reserved.
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

# base name of the driver
DRIVER_NAME := vtsspp

# location to install driver
INSTALL ?= .

# current working directory
PWD := $(shell pwd)

# provide detailed messages
VERBOSE ?= 1

# check for external define from SEP Makefile
ifeq ($(KERNEL_VERSION),)
KVER ?= $(shell uname -r)
else
KVER ?= $(KERNEL_VERSION)
endif

# check for external define from SEP Makefile
ifeq ($(KERNEL_SRC_DIR),)
KDIR ?= /lib/modules/$(KVER)/build
else
KDIR ?= $(KERNEL_SRC_DIR)
endif

# platform details
MACH ?= $(shell uname -m)
PLATFORM := unknown
ifeq ($(MACH), x86_64)
PLATFORM := x32_64
endif

# eventual filename of the driver
DRIVER_FILENAME := $(DRIVER_NAME)-$(PLATFORM)-$(KVER)smp.ko

###############################################################################
# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)

ifneq ($(KVER),$(KERNELRELEASE))
$(warning Kernel version '$(KVER)' does not match the actual kernel version '$(KERNELRELEASE)')
$(warning Use 'build-driver --kernel-version=$(KERNELRELEASE) --kernel-src-dir=$(KDIR)')
endif

obj-m := $(DRIVER_NAME).o
$(DRIVER_NAME)-objs := \
	cmd.o          \
	ipt.o          \
	kmem.o         \
	kpti.o         \
	ksyms.o        \
	lbr.o          \
	mmap.o         \
	modcfg.o       \
	nmiwd.o        \
	pcb.o          \
	pebs.o         \
	pmi.o          \
	pmu.o          \
	probe.o        \
	procfs.o       \
	record.o       \
	sched.o        \
	stack.o        \
	target.o       \
	task.o         \
	task_map.o     \
	transport.o    \
	unwind.o

EXTRA_CFLAGS += -Wall
DEBUG_LIST := $(subst :, ,$(VTSS_DEBUG))
EXTRA_CFLAGS += $(foreach s,$(DEBUG_LIST),-Dvtss_pr_debug_$(s)=vtss_pr_info)
ifdef VTSS_DEBUG
$(warning Debug output enabled: $(VTSS_DEBUG))
endif

ifdef VTSS_DISABLE_PEBS
$(warning PEBS disabled)
EXTRA_CFLAGS += -DVTSS_DISABLE_PEBS
endif
ifdef VTSS_DISABLE_TRACEPOINTS
$(warning Tracepoints disabled)
EXTRA_CFLAGS += -DVTSS_DISABLE_TRACEPOINTS
endif
ifdef VTSS_DISABLE_KPROBES
$(warning Kprobes disabled)
EXTRA_CFLAGS += -DVTSS_DISABLE_KPROBES
endif
ifdef VTSS_DISABLE_KALLSYMS
$(warning Kallsyms disabled)
EXTRA_CFLAGS += -DVTSS_DISABLE_KALLSYMS
endif
ifdef VTSS_DISABLE_STACKS
$(warning Stack unwinding disabled)
EXTRA_CFLAGS += -DVTSS_DISABLE_STACKS
endif

ifeq ($(wildcard $(obj)/vtssrtcfg.h),)
COPY_PUBLIC_HEADERS := $(shell cp $(obj)/../include/* $(obj))
else
COPY_PUBLIC_HEADERS :=
endif
$(DRIVER_NAME)-objs: COPY_PUBLIC_HEADERS $(obj)/autoconf.h

CC_TEST := $(CC) $(KBUILD_CPPFLAGS) $(CPPFLAGS) $(LINUXINCLUDE) \
	   $(KBUILD_CFLAGS) $(CFLAGS_KERNEL) $(CFLAGS) $(EXTRA_CFLAGS) \
	   $(KBUILD_CFLAGS_MODULE) $(CFLAGS_MODULE) \
	   -DKBUILD_BASENAME=\"$(DRIVER_NAME)\" -Werror -c -o $(obj)/autoconf.o -xc >> $(obj)/autoconf.log 2>&1

autoconf-srcs := $(sort $(wildcard $(M)/autoconf/*.c))
$(addprefix $(obj)/,$($(DRIVER_NAME)-objs)): $(obj)/autoconf.h
$(obj)/autoconf.h: $(autoconf-srcs) $(M)/Makefile
	@echo "  GEN     $@"
	@echo "KBUILD_CPPFLAGS=$(KBUILD_CPPFLAGS)" >> $(obj)/autoconf.log
	@echo "KBUILD_CFLAGS=$(KBUILD_CFLAGS)" >> $(obj)/autoconf.log
	@echo "KBUILD_CFLAGS_MODULE=$(KBUILD_CFLAGS_MODULE)" >> $(obj)/autoconf.log
	@echo "LINUXINCLUDE=$(LINUXINCLUDE)" >> $(obj)/autoconf.log
	@echo "EXTRA_CFLAGS=$(EXTRA_CFLAGS)" >> $(obj)/autoconf.log
	@echo "/**" > $@
	@echo " * Automatically generated file; DO NOT EDIT." >> $@
	@echo " * Configuration for $(KERNELRELEASE) kernel." >> $@
	@echo " */" >> $@
	@echo "#ifndef _VTSS_AUTOCONF_H_" >> $@
	@echo "#define _VTSS_AUTOCONF_H_" >> $@
	@if [ -f $(obj)/version.h ]; then \
		echo "#include \"version.h\"" >> $@; \
	fi
	@for test in $(autoconf-srcs); do \
		def="VTSS_AUTOCONF_`basename $$test .c | tr 'a-z' 'A-Z'`"; \
		echo "  CC      $$test" >> $(obj)/autoconf.log; \
		if $(CC_TEST) $$test; then echo "#define $$def 1" >> $@; fi; \
	done
	@echo "#endif" >> $@

###############################################################################
# Otherwise, we were called directly from the command line;
# invoke the kernel build system.
else

.PHONY: default all clean distclean install

default: all

all:
ifeq ($(PLATFORM),unknown)
	@echo " *** Platform \"$(MACH)\" is not supported"
else
ifeq ($(VERBOSE),1)
	-$(MAKE) -C $(KDIR) M=$(PWD) modules
	-cp -f $(DRIVER_NAME).ko $(DRIVER_FILENAME)
else
	-@$(MAKE) -C $(KDIR) M=$(PWD) modules > /dev/null
	-@cp -f $(DRIVER_NAME).ko $(DRIVER_FILENAME)
endif
endif

clean:
ifeq ($(VERBOSE),1)
	@echo "  CLEAN   $(PWD)"
endif
	-@rm -rf .tmp_versions
	-@rm -f .*.o *.o .*.cmd *.cmd .*.o.d *.o.ur-safe *.gcno *.mod.c *.mod
	-@rm -f *.symvers *.order *.markers .cache.mk *.ipa-clones *.dwo
	-@rm -f autoconf.h autoconf.log
	-@rm -f $(DRIVER_NAME).ko $(DRIVER_NAME).ko.unsigned $(DRIVER_FILENAME)

distclean: clean
	-@rm -f $(DRIVER_NAME)*.ko

install:
	-@if [ "$(INSTALL)" != "." ]; then \
		cp -f $(DRIVER_NAME).ko $(INSTALL)/$(DRIVER_FILENAME); \
		cp -f insmod-vtsspp $(INSTALL)/insmod-vtsspp; \
		cp -f rmmod-vtsspp $(INSTALL)/rmmod-vtsspp; \
		echo "Installed $(DRIVER_NAME) driver to $(INSTALL)/$(DRIVER_FILENAME)"; \
	fi

endif
