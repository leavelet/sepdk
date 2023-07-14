==============================================================================
       HOW TO BUILD AND LOAD THE VTSS++ KERNEL DRIVER UNDER LINUX*
==============================================================================

version: 1.1
updated: 01/01/2023

This document describes the required software environment needed in order
to build and load the VTSS++ kernel driver on the Linux* operating system.
Use this information to build and load the driver in case that the kernel
on your Linux system is not one of the supported kernels listed in the
Release Notes.


1.  Basic Development Environment

In order to compile the driver, the target system must have the following:

    * C compiler that was used to build the kernel, and which is capable
      of compiling programs with anonymous structs/unions. For example,
      GCC 6.3.0 or later

    * Tools needed to build a C based program. For example, GNU make
      tool, native assembler, linker

    * System headers. For example, /usr/include/

In addition, the kernel must be configured with the following options enabled:

    CONFIG_SMP=y
    CONFIG_MODULES=y
    CONFIG_MODULE_UNLOAD=y
    CONFIG_KALLSYMS=y
    CONFIG_TRACEPOINTS=y
    CONFIG_KPROBES=y
    CONFIG_KRETPROBES=y
    CONFIG_PREEMPT_NOTIFIERS=y (optional)

These options can be verified by checking the kernel config file
(e.g., /boot/config, /proc/config.gz, /usr/src/linux/.config, etc.).

Normally, these tools are installed, and kernel options enabled, by default.
However, administrators may remove/disable them from deployment systems,
such as servers or embedded systems.


2.  Kernel Development Environment

In addition to the above tools, a proper kernel development environment
must be present on the target system.

    * Red Hat Enterprise Linux 7:

        yum install kernel-devel

    * Red Hat Enterprise Linux 8, 9:

        dnf install kernel-devel

    * SUSE Linux Enterprise Server 12, 15:

        zypper install kernel-devel

    * Ubuntu 20.04, 22.04, 22.10:

        apt install linux-headers


3.  Other Linux Distributions or Kernels

For kernels or Linux disributions not mentioned above, you need to set
up the kernel build environment manually. This involves configuring the
kernel sources (and hence kernel headers) to match the running kernel
on the target system.

For 3.10 and later kernels, the kernel sources can be configured as follows:

  # boot into the kernel you wish to build driver for
  # and make sure the kernel source tree is placed in
  # /usr/src/linux-$(uname -r)
  #
  cd /usr/src/linux-$(uname -r)
  vi Makefile # set EXTRAVERSION to a value corresponding to $(uname -r)
  make mrproper
  cp /boot/config-$(uname -r) .config
  make oldconfig
  make prepare
  make scripts

Once the configuration completes, make sure that UTS_RELEASE in
/usr/src/linux-$(uname -r)/include/generated/utsrelease.h matches $(uname -r).


4.  Building and (re)Loading the Driver

Once the standard development tools and proper kernel development
environment are installed, you can build and load the driver:

  # build the driver:
  cd /path/to/sepdk/src/vtsspp
  ./build-driver -ni

  # (re)load the driver into the kernel:
  cd /path/to/sepdk/src/vtsspp
  ./insmod-vtsspp -r -g $(id -ng)

If any errors occur during the building or loading of the driver, this
may indicate a mismatch between the kernel sources and the running kernel.
For load issues, check the /var/log/messages file or the output of dmesg.


------------------------------------------------------------------------------

Disclaimer and Legal Information

The information in this document is subject to change without notice and
Intel Corporation assumes no responsibility or liability for any errors
or inaccuracies that may appear in this document or any software that
may be provided in association with this document. This document and the
software described in it are furnished under license and may only be
used or copied in accordance with the terms of the license. No license,
express or implied, by estoppel or otherwise, to any intellectual
property rights is granted by this document. The information in this
document is provided in connection with Intel products and should not be
construed as a commitment by Intel Corporation.

EXCEPT AS PROVIDED IN INTEL'S TERMS AND CONDITIONS OF SALE FOR SUCH
PRODUCTS, INTEL ASSUMES NO LIABILITY WHATSOEVER, AND INTEL DISCLAIMS ANY
EXPRESS OR IMPLIED WARRANTY, RELATING TO SALE AND/OR USE OF INTEL
PRODUCTS INCLUDING LIABILITY OR WARRANTIES RELATING TO FITNESS FOR A
PARTICULAR PURPOSE, MERCHANTABILITY, OR INFRINGEMENT OF ANY PATENT,
COPYRIGHT OR OTHER INTELLECTUAL PROPERTY RIGHT. Intel products are not
intended for use in medical, life saving, life sustaining, critical
control or safety systems, or in nuclear facility applications.

Designers must not rely on the absence or characteristics of any
features or instructions marked "reserved" or "undefined." Intel
reserves these for future definition and shall have no responsibility
whatsoever for conflicts or incompatibilities arising from future
changes to them.

The software described in this document may contain software defects
which may cause the product to deviate from published specifications.
Current characterized software defects are available on request.

Intel, the Intel logo, Intel SpeedStep, Intel NetBurst, Intel
NetStructure, MMX, Intel386, Intel486, Celeron, Intel Centrino, Intel
Xeon, Intel XScale, Itanium, Pentium, Pentium II Xeon, Pentium III Xeon,
Pentium M, and VTune are trademarks or registered trademarks of Intel
Corporation or its subsidiaries in the United States and other countries.

*Other names and brands may be claimed as the property of others.

Copyright(c) 2010-2023 Intel Corporation.  All Rights Reserved.
