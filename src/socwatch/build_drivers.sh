#!/bin/bash
# Helper script to build both socwatch and socperf drivers
# and sign them in the case of Android targets. Script must
# executed in the top-level directory of SoCWatch package.
# **********************************************************************************
#  This file is provided under a dual BSD/GPLv2 license.  When using or
#  redistributing this file, you may do so under either license.

#  GPL LICENSE SUMMARY

#  Copyright(c) 2015 - 2021 Intel Corporation.

#  This program is free software; you can redistribute it and/or modify
#  it under the terms of version 2 of the GNU General Public License as
#  published by the Free Software Foundation.

#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.

#  Contact Information:
#  SoC Watch Developer Team <socwatchdevelopers@intel.com>
#  Intel Corporation,
#  1300 S Mopac Expwy,
#  Austin, TX 78746

#  BSD LICENSE

#  Copyright(c) 2015 - 2021 Intel Corporation.

#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:

#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in
#      the documentation and/or other materials provided with the
#      distribution.
#    * Neither the name of Intel Corporation nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.

#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# **********************************************************************************
DO_LINUX=0
BUILD_HYPERVISOR=0
HYPERVISOR_SUPPORTED=0
OPTIONS=""
SOCWATCH_DRIVER_SRC=socwatch_driver
SOCWATCH_DRIVER_PREFIX=socwatch2_15
DEFAULT_SOCWATCH_DRIVER=${SOCWATCH_DRIVER_PREFIX}.ko
SOCWATCH_DRIVER=${DEFAULT_SOCWATCH_DRIVER}
HYPERVISOR_DRIVER_SRC=hypervisor_driver
HYPERVISOR_DRIVER_PREFIX=socwatchhv2_0
DEFAULT_HYPERVISOR_DRIVER=${HYPERVISOR_DRIVER_PREFIX}.ko
HYPERVISOR_DRIVER=${DEFAULT_HYPERVISOR_DRIVER}
POSTFIX=""
ERROR_FILE=""
ERROR_OCCURRED=false
PRIV_SIGNING_KEY=signing_key.priv
PEM_SIGNING_KEY=signing_key.pem
X509_SIGNING_KEY=signing_key.x509
SIGN_FILE="X"
C_COMPILER="X"
DEFAULT_C_COMPILER=gcc
HYPERVISOR_NAME="X";

error()
{
    local message=$1
    echo "ERROR: $message"
    echo "ERROR: $message" >> ${ERROR_FILE}
    ERROR_OCCURRED=true
}

sign_driver()
{
    local sign_file=$1
    local unsigned_driver=$2
    local signed_driver=$3
    local priv_pem_key_path="${KERNEL_BUILD_DIR}/certs/${PEM_SIGNING_KEY}"
    local x509_key_path="${KERNEL_BUILD_DIR}/certs/${X509_SIGNING_KEY}"

    if ([ ! -r ${priv_pem_key_path} ] || [ ! -r ${x509_key_path} ]); then
        priv_pem_key_path="${KERNEL_BUILD_DIR}/${PRIV_SIGNING_KEY}"
        x509_key_path="${KERNEL_BUILD_DIR}/${X509_SIGNING_KEY}"
    fi

    if ([ ! -r ${priv_pem_key_path} ] || [ ! -r ${x509_key_path} ]); then
        error "The kernel build directory does not have signing keys ${PEM_SIGNING_KEY} (or ${PRIV_SIGNING_KEY}) and ${X509_SIGNING_KEY}. Drivers will not be signed."
        error "Please check if the target's kernel requires drivers to be signed."
    else
        ${sign_file} sha256 ${priv_pem_key_path} ${x509_key_path} ${unsigned_driver} ${signed_driver}
        if [ $? -ne 0 ]; then
            echo "Failed to sign the driver"
        fi
    fi
}

build_driver()
{
    # 1. Build driver
    # 2. Sign driver if requested
    # 3. Copy the driver to TARGET_DIR
    local default_driver_name=$1
    local driver_name=$2
    local options="${@:3}"
    echo ${options}
    echo "************ Building ${driver_name} driver ************"

    local build_Driver_script=""
    build_driver_script=build_linux_driver.sh
    ./${build_driver_script} ${options} --clean

    ./${build_driver_script} ${options}
    local retVal=$?;
    if [ $retVal -ne 0 ]; then
        error "Failed to build ${driver_name} driver"
        return
    fi

    mv "${default_driver_name}" "${driver_name}" > /dev/null 2>&1

    local signing_error=0
    if [ "${SIGN_FILE}" != "X" ]; then
        if [ -x "${SIGN_FILE}" ]; then
            echo "************ Signing ${driver_name} driver using ${SIGN_FILE} ************"
            mv "${driver_name}" "${driver_name}.unsigned"
            sign_driver ${SIGN_FILE} "${driver_name}.unsigned" "${driver_name}"
            if [ $? -ne 0 ]; then
                signing_error=1
            fi
            rm -f "${driver_name}.unsigned"
        else
            echo "Signing file ${SIGN_FILE} is invalid"
            signing_error=1
        fi

        if [ ${signing_error} -eq 1 ]; then
            local sign_file=${KERNEL_BUILD_DIR}/scripts/sign-file
            echo "Attempting to sign the drivers with kernel source sign_file: ${sign_file}"
            if [ -x "${sign_file}" ]; then
                echo "************ Signing ${driver_name} driver using ${sign_file} ************"
                mv "${driver_name}" "${driver_name}.unsigned"
                sign_driver ${sign_file} "${driver_name}.unsigned" "${driver_name}"
                if [ $? -ne 0 ]; then
                    signing_error=0
                fi
                rm -f "${driver_name}.unsigned"
            else
                echo "Signing file ${sign_file} is invalid"
                signing_error=1
            fi
        fi
    fi

    if [ ${signing_error} -eq 1 ]; then
        error "Failed to sign the driver"
    else
        if [ ! -f ./"$driver_name" ]; then
            # To identify a mismatch in generated vs script version of the driver
            echo ""
            error "Failed to find ${driver_name} driver in current directory : `pwd`"
            echo ""
        else
            mv "${driver_name}" "${TARGET_DIR}/${driver_name}"
        fi
    fi
}


do_work()
{
    TARGET_DIR=${top_dir}/drivers

    # If previously built driver exists, it will be removed.
    # If it does not exist, following rm will do nothing.
    echo "Removing previously built driver and scripts from ${TARGET_DIR}"
    rm -rf ${TARGET_DIR}/${SOCWATCH_DRIVER}
    rm -rf ${TARGET_DIR}/insmod-socwatch
    rm -rf ${TARGET_DIR}/rmmod-socwatch
    mkdir ${TARGET_DIR}

    # Build socwatch driver
    cd ${SOCWATCH_DRIVER_SRC}

    if [ "$C_COMPILER" = "X" ]; then
        OPTIONS="";
    else
        OPTIONS="-c $C_COMPILER"
    fi

    if [ $DO_LINUX -eq 1 ]; then
        OPTIONS="$OPTIONS -l"
    fi

    if [ -n "$KERNEL_BUILD_DIR" ]; then
        OPTIONS="$OPTIONS -k ${KERNEL_BUILD_DIR}"
    fi

    if [ -n "$MAKE_ARGS" ]; then
        OPTIONS="$OPTIONS --make-args \"${MAKE_ARGS}\""
    fi

    echo "$OPTIONS will be used to build the SoCWatch driver"
    build_driver "${DEFAULT_SOCWATCH_DRIVER}" "${SOCWATCH_DRIVER}" ${OPTIONS}
    cd ${top_dir}

    if [ ${BUILD_HYPERVISOR} -eq 1 ]; then
        cd ${HYPERVISOR_DRIVER_SRC}
        OPTIONS="-k ${KERNEL_BUILD_DIR} --hypervisor ${HYPERVISOR_NAME}"
        build_driver "${DEFAULT_HYPERVISOR_DRIVER}" "${HYPERVISOR_DRIVER}" ${OPTIONS}
        cd ${top_dir}
    fi

    # Move the module insertion and removal scripts to the drivers directory upon successful
    # building of the socwatch driver
    cp ${SOCWATCH_DRIVER_SRC}/insmod-socwatch ${TARGET_DIR}/
    cp ${SOCWATCH_DRIVER_SRC}/rmmod-socwatch ${TARGET_DIR}/

    # strip the .ko from string
    DEFAULT_MODULE_NAME=${DEFAULT_SOCWATCH_DRIVER%".ko"}

    # Replace tag in the scripts with actual versioned socwatch module name
    sed -i "s/<SOCWATCH_MODULE_NAME>/${DEFAULT_MODULE_NAME}/g" ${TARGET_DIR}/insmod-socwatch

    if [ ${ERROR_OCCURRED} == "true" ]; then
        echo ""
        echo "****** Errors occurred. Please check ${ERROR_FILE} for errors and the stderr/stdout for more information ******"
        echo ""
        exit 1
    fi
    # Moved this message here to make sure no errors occured
    echo "************ Built drivers are copied to ${TARGET_DIR} directory ************"
}

usage()
{
    echo "Usage: sh $(basename $0) [options]";
    echo "Where options are:"
    echo "-h: Print this help/usage message";
    echo "-c, --c-compiler [Path to c compiler]: Specify an alternate compiler; default is $DEFAULT_C_COMPILER"
    echo "-k, --kernel-build-dir [path]:"
    echo "                              Specify the path to the kernel build directory."
    echo "                              Required for Android and Chrome targets";
    echo "-l: Build drivers for Linux target";
    echo "-n: (deprecated) was used to skip socperf driver build, now socperf driver is not included and not build by default";
    echo "-s, --sign-file [path]: Specify the path to the sign-file for"
    echo "                        the target Android OS image (Optional; required for older versions of Android).";
    echo "--make-args: extra arguments to pass to make command"
    echo "--clean: remove previously built files"
    echo "--postfix change driver name to socwatch<major>_<minor>-<arg>.ko"
    if [ $HYPERVISOR_SUPPORTED -eq 1 ]; then
        echo "--hypervisor [mobilevisor|acrn]: Build drivers for the specified hypervisor";
    fi
}

get_args()
{
    while [ $# -gt 0 ]; do
        case $1 in
            -h)
                usage;
                exit 0;;
            -k | --kernel-build-dir)
                KERNEL_BUILD_DIR=$2;
                shift;
                if [ ! -d "${KERNEL_BUILD_DIR}" ]; then
                    echo "Please provide a valid kernel build directory for the target"
                    exit 1;
                fi
                echo "${KERNEL_BUILD_DIR} will be used as the kernel build directory"
                ;;
            -s | --sign-file)
                SIGN_FILE=$2;
                if [ -f "${SIGN_FILE}" ]; then
                    shift;
                    if [ ! -x "${SIGN_FILE}" ]; then
                        echo "************ The signing file provided is not valid. Signing will be attempted with the sign-file in the kernel source directory if found. ************"
                    fi
                fi
                ;;
            --clean)
                if [ ${HYPERVISOR_SUPPORTED} -eq 1 ]; then
                    cd "${top_dir}/hypervisor_driver"
                    ./build_linux_driver.sh --clean
                fi

                cd "${top_dir}/socwatch_driver"
                ./build_linux_driver.sh --clean
                rm -f "${top_dir}/socwatch_driver/src/*.o.ur-safe"
                rm -rf "${top_dir}/drivers"
                cd "${top_dir}/soc_perf_driver/src"
                make distclean
                exit 0;;
            --hypervisor)
                if [ ${HYPERVISOR_SUPPORTED} -eq 1 ]; then
                    BUILD_HYPERVISOR=1;
                else
                    echo "Hypervisor support is not available";
                    exit 1;
                fi
                HYPERVISOR_NAME=$2;
                echo "Building drivers for hypervisor '$HYPERVISOR_NAME'"
                shift;;
            -l)
                echo "Building drivers for Linux target"
                DO_LINUX=1;;
            -n)
                echo "-n switch is deprecated. Now it does not have any effect.";;
            -c | --c-compiler)
                C_COMPILER=$2; shift;;
            --make-args)
                MAKE_ARGS=$2;
                echo "Using extra make arguments $MAKE_ARGS"
                shift;;
            --postfix)
		SOCWATCH_DRIVER="${SOCWATCH_DRIVER_PREFIX}-$2.ko";
		HYPERVISOR_DRIVER="${HYPERVISOR_DRIVER_PREFIX}-$2.ko";
		POSTFIX="$2";
		shift;;
            *)
                usage; exit 1;;
        esac
        shift;
    done
}

main()
{
    if [ -d "$HYPERVISOR_DRIVER_SRC" ]; then
        HYPERVISOR_SUPPORTED=1;
    fi

    local top_dir=`pwd`
    # Record errors in a file
    ERROR_FILE=${top_dir}/driver_build_errors.txt
    rm -f ${ERROR_FILE}

    get_args $*
    do_work
}

main $*
