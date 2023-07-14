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

# == Unpack functions ==========================================================
UNPACK_SOURCES_FROM_VTUNE_DIR() {
    info_message="
VTUNE_PROFILER_2023_DIR is specified.
Continue with ${VTUNE_PROFILER_2023_DIR} as search path for ${PRODUCT_NAME} installation path."
    layout_message="
Cannot find valid target package in ${VTUNE_PROFILER_2023_DIR}
It may be caused by incorrect VTUNE_PROFILER_2023_DIR:
    Please specify correct path to ${PRODUCT_NAME} installation folder. For example: /opt/intel/oneapi/vtune_profiler_2023.1.0.625246
Or by incompatible target package which not contain yocto-layer subdir:
    Use newer version of ${PRODUCT_NAME} in this case.
"

    if [ "${VTUNE_PROFILER_2023_DIR}" ]; then
        bbplain "$info_message"

        target_package_dir="${VTUNE_PROFILER_2023_DIR}/target/linux"

        if ! HELPER_find "$target_package_dir"; then
            bbfatal "$layout_message"
            return 2
        fi

        HELPER_source
        target_package_archive="$target_package_dir"/$(PACKAGE_archive_file_name)
        if [ ! -f "${target_package_archive}" ] && [ ! -r "${target_package_archive}" ]; then
            bbfatal "${PRODUCT_NAME} target archive not found: ${target_package_archive}"
        fi
        tar xvzf "${target_package_archive}"

        return 0
    fi
    return 1
}

COPY_SOURCES_BASED_ON_VTUNE_TARGET_PACKAGE_DIR() {
    info_message="
VTUNE_TARGET_PACKAGE_DIR is specified.
Continue with ${VTUNE_TARGET_PACKAGE_DIR} as search path for unziped target package."
    layout_message="
Found target package has incorrect layout.
Please check if specified directory has sepdk subfolder."

    helper_file="${VTUNE_TARGET_PACKAGE_DIR}/${SEPDK_HELPER_PATH}"
    if [ "${VTUNE_TARGET_PACKAGE_DIR}" ]; then
        bbplain "$info_message"

        if [ ! -f "${helper_file}" ]; then
            bberror "$layout_message"
            return 2
        fi

        cp -rf "${VTUNE_TARGET_PACKAGE_DIR}" ./
        cp -f "${helper_file}" "${HELPER_PATH}"
        return 0
    fi
    return 1
}

COPY_SOURCES_BASED_ON_LAYER_LOCATION() {
    layout_message="
Default target package has incorrect layout. Please specify correct one in user.conf"

    package_dir="${@os.path.abspath(os.path.join("${VTUNE_LAYER_DIR}", os.pardir, os.pardir))}"
    helper_file="${package_dir}/${SEPDK_HELPER_PATH}"
    if [ -d "${package_dir}" ] || [ -L "${package_dir}" ]; then
        if [ ! -f "${helper_file}" ]; then
            bberror "$layout_message"
            return 2
        fi

        cp -rf "${package_dir}" ./
        cp -f "${helper_file}" "${HELPER_PATH}"
        return 0
    fi
    return 1
}

# == Actions ==================================================================
do_unpack() {
    common_fail_message="
${PRODUCT_NAME} target archive cannot be found by default path and invalid search directory set.

Please specify any of search path in ${VTUNE_LAYER_DIR}/conf/user.conf:
VTUNE_TARGET_PACKAGE_DIR - path for unziped target archive
VTUNE_PROFILER_2023_DIR - installation path of ${PRODUCT_NAME}"

    SOURCE_DIR_create
    UNPACK_DIR_create

    cd "$UNPACK_DIR_path" || bbfatal "Unpack directory wasn't created"

    exit_code=0
    COPY_SOURCES_BASED_ON_VTUNE_TARGET_PACKAGE_DIR || exit_code=$?
    if [ "$exit_code" -eq "2" ]; then
        bbfatal "$common_fail_message"
    elif [ "$exit_code" -eq "0" ]; then
        return 0
    fi

    exit_code=0
    UNPACK_SOURCES_FROM_VTUNE_DIR || exit_code=$?
    if [ "$exit_code" -eq "0" ]; then
        return 0
    fi

    exit_code=0
    COPY_SOURCES_BASED_ON_LAYER_LOCATION || exit_code=$?
    if [ "$exit_code" -eq "2" ]; then
        bbfatal "$common_fail_message"
    elif [ "$exit_code" -eq "0" ]; then
        return 0
    fi

    bbfatal "$common_fail_message"
}
