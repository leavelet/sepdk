#
# Copyright (C) 2020 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you ("License"). Unless
# the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or implied
# warranties, other than those that are expressly stated in the License.
#

inherit module


# == License ==================================================================
HOMEPAGE = "http://www.intel.com/software/products"

LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "${VTUNE_RECIPE_LICENSE_FILE}"

PR = "r0"

SECTION = "devel"
DEPENDS += " virtual/kernel"

PACKAGES="${PN}"
FILES_${PN} += "/opt/intel/*"
FILES_${PN} += "/etc/*"
FILES_${PN} += "${systemd_system_unitdir}"


# == Product specific variables =================================================
export PRODUCT_NAME="Intel(R) VTune(TM) Profiler 2023.1.0"


# == Shared variables for helper ==============================================
export VTUNE_DRIVERS
export SUMMARY
export VTUNE_TARGET_ARCH="${TARGET_ARCH}"

export STAGING_KERNEL_BUILDDIR
export KERNEL_CONFIG_DIR
export KBUILD_OUTPUT
export KERNEL_VERSION
export VTUNE_DRIVERS_PER_USER

export SOURCE_DIR_path="${S}"
export BUILD_DIR_path="${SOURCE_DIR_path}/build_dir"
export UNPACK_DIR_path="${SOURCE_DIR_path}/package"
export INSTALL_DIR_path="${D}/opt/intel/"


# == Helper ====================================================================
VTUNE_TARGET_BASE="vtune_profiler_target_"
SEPDK_HELPER_PATH="sepdk/vtune-layer/recipes-vtune/vtune-target/intel-vtune-build-helper.inc"
HELPER_PATH="${UNPACK_DIR_path}/intel-vtune-build-helper.inc"

HELPER_find() {
    TARGET_ARCHIVE="$1/${VTUNE_TARGET_BASE}*"

    for archive in $TARGET_ARCHIVE; do  # Directory not exists
        if [ -f "$archive" ] && [ -r "${archive}" ]; then
            tar xzOf "${archive}" --wildcards "*${SEPDK_HELPER_PATH}" > "${HELPER_PATH}"
        fi

        if [ -s "${HELPER_PATH}" ]; then
            return 0
        fi
    done

    return 1
}

HELPER_source () {
    . "${HELPER_PATH}" || bbfatal "Cannot read helper file from target package"
}


# == Directories ===============================================================
DIR_create() {
    if [ -d "$1" ]; then
        rm -rf "$1"
    fi
    mkdir -p "$1"
}

SOURCE_DIR_create() {
    DIR_create "${SOURCE_DIR_path}"
}

BUILD_DIR_create() {
    DIR_create "${BUILD_DIR_path}"
}

UNPACK_DIR_create() {
    DIR_create "${UNPACK_DIR_path}"
}

INSTALL_DIR_create() {
    DIR_create "${INSTALL_DIR_path}"
}


# == Init.d option ============================================================
INITD_add() {
    install -d "${D}${sysconfdir}"/init.d
    install -d "${D}${sysconfdir}"/rc1.d
    install -d "${D}${sysconfdir}"/rc2.d
    install -d "${D}${sysconfdir}"/rc3.d
    install -d "${D}${sysconfdir}"/rc4.d
    install -d "${D}${sysconfdir}"/rc5.d

    insmod_sep="${D}/${sysconfdir}/init.d/insmod-sep"
    echo 'case "$1" in start) /opt/intel/vtune_amplifier_drivers/insmod-sep;; esac' > "$insmod_sep"
    chmod +x "$insmod_sep"

    ln -sf "/${sysconfdir}/init.d/insmod-sep" "${D}/${sysconfdir}/rc1.d/S99insmod-sep"
    ln -sf "/${sysconfdir}/init.d/insmod-sep" "${D}/${sysconfdir}/rc2.d/S99insmod-sep"
    ln -sf "/${sysconfdir}/init.d/insmod-sep" "${D}/${sysconfdir}/rc3.d/S99insmod-sep"
    ln -sf "/${sysconfdir}/init.d/insmod-sep" "${D}/${sysconfdir}/rc4.d/S99insmod-sep"
    ln -sf "/${sysconfdir}/init.d/insmod-sep" "${D}/${sysconfdir}/rc5.d/S99insmod-sep"
}

# == Systemd option ============================================================
SYSTEMD_add() {
    install -d "${D}${systemd_system_unitdir}"
    install -d "${D}${sysconfdir}/systemd/system/multi-user.target.wants"

    cat > "${D}${systemd_system_unitdir}/insmod-sep.service" << EOF
[Unit]
Description=SEP Driver

[Service]
ExecStart=/opt/intel/vtune_amplifier_drivers/insmod-sep
StandardError=syslog

[Install]
WantedBy=multi-user.target
EOF

    ln -sf "${systemd_system_unitdir}/insmod-sep.service" "${D}/${sysconfdir}/systemd/system/multi-user.target.wants/insmod-sep.service"
}

# == Workflow =================================================================
do_compile() {
    HELPER_source
    BUILD_DIR_create

    VTUNE_CC=$(which $(echo ${KERNEL_CC} | cut -d ' ' -f 1)); export VTUNE_CC
    VTUNE_MAKE=$(which make); export VTUNE_MAKE
    DRIVER_build
}

do_install() {
    INSTALL_DIR_create

    for dir in "${BUILD_DIR_path}/"*; do
        build_name=${dir##*/}
        cp -r "$dir" "${INSTALL_DIR_path}/${build_name}_drivers"
        ln -sf "/opt/intel/${build_name}_drivers" "${INSTALL_DIR_path}/vtune_amplifier_drivers"
    done

    if [ "${ADD_TO_INITD}" = "y" ]; then
        INITD_add
    fi

    if [ "${ADD_TO_SYSTEMD}" = "y" ]; then
        SYSTEMD_add
    fi
}

do_unpack() {
    bbfatal "do_unpack() function is not overriden"
}


# == Includes ==================================================================
include conf/user.conf
include conf/vtune-user.conf
include intel-vtune-unpack.inc
include intel-iss-vtune-unpack.inc
