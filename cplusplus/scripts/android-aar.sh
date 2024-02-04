#!/bin/sh

set -e

AUTOGRAPH_VERSION="0.5.0"
SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROOT_DIR="${SOURCE_DIR}/.."
SOURCE_INCLUDE_DIR="${SOURCE_DIR}/include"
PREFIX="${SOURCE_DIR}/build/android"
AAR_DIR="${PREFIX}/aar"
RIMRAF_ARGS=""

NDK_VERSION=$(grep "Pkg.Revision = " < "${ANDROID_NDK_HOME}/source.properties" | cut -f 2 -d '=' | cut -f 2 -d' ' | cut -f 1 -d'.')

if [ -d "$1" ]
then
    OUTPUT_DIR="$(cd "$1" && pwd)"
else
    OUTPUT_DIR="${PREFIX}"
fi

OUTPUT_PATH="${OUTPUT_DIR}/autograph.aar"

if [ -f "${OUTPUT_PATH}" ]
then
    rm -f "${OUTPUT_PATH}"
fi

create_prefab_dirs() {
    mkdir "${AAR_DIR}"
    for dir in "META-INF" "prefab" "prefab/modules" "prefab/modules/autograph" "prefab/modules/autograph/libs"
    do
        mkdir "${AAR_DIR}/${dir}"
    done
}

write_prefab_files() {
    echo "{\"name\":\"autograph\",\"schema_version\":1,\"dependencies\":[],\"version\":\"$AUTOGRAPH_VERSION\"}" > "${AAR_DIR}/prefab/prefab.json"

    echo "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.android.ndk.thirdparty.autograph\" android:versionCode=\"1\" android:versionName=\"1.0\">
        <uses-sdk android:minSdkVersion=\"19\" android:targetSdkVersion=\"21\"/>
    </manifest>" > "${AAR_DIR}/AndroidManifest.xml"

    cp "${ROOT_DIR}/LICENSE" "${AAR_DIR}/META-INF"
}

create_prefab() {
    create_prefab_dirs
    write_prefab_files
}

build_cmake() {
    cmake -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_SYSTEM_NAME=Android \
        -DCMAKE_ANDROID_ARCH_ABI="${1}" \
        -DCMAKE_ANDROID_NDK="${ANDROID_NDK_HOME}" \
        -DAUTOGRAPH_INSTALL=0 \
        -DAUTOGRAPH_TESTS=0 \
        -UCMAKE_ANDROID_ARM_MODE \
        -B "${2}" "${ROOT_DIR}"
    (cd "${2}" && make)
}

write_module_file() {
    echo "{}" > "${1}/module.json"
}

write_abi_file() {
    local sdk_version="19"
    if [ ${1} = "arm64-v8a" ] || [ ${1} = "x86_64" ]
    then
        sdk_version="21"
    fi
    echo "{\"abi\":\"${1}\",\"api\":${sdk_version},\"ndk\":${NDK_VERSION},\"stl\":\"none\"}" > "${2}/abi.json"
}

copy_lib() {
    cp "${1}/libautograph.a" "${2}"
    cp "${SOURCE_DIR}/include/autograph.h" "${2}/include"
}

write_target_files() {
    local module_dir="${AAR_DIR}/prefab/modules/autograph"
    local target_dir="${module_dir}/libs/android.${1}"
    mkdir "${target_dir}" "${target_dir}/include"
    write_module_file "${module_dir}"
    write_abi_file ${1} "${target_dir}"
    copy_lib "${2}" ${target_dir}
}

build_target() {
    local build_dir="${PREFIX}/${1}"
    build_cmake ${1} "${build_dir}" > /dev/null
    write_target_files ${1} "${build_dir}"
    RIMRAF_ARGS="${RIMRAF_ARGS} ${build_dir}"
}

build_aar() {
    (cd "${AAR_DIR}" && zip -9 -r "$OUTPUT_PATH" "META-INF" "prefab" "AndroidManifest.xml" > /dev/null)
    RIMRAF_ARGS="${RIMRAF_ARGS} ${AAR_DIR}"
}

rm -rf "${PREFIX}"
mkdir "${PREFIX}"

echo "Creating prefab structure..."
create_prefab

echo "[  1%] Building for armeabi-v7a..."
build_target armeabi-v7a

echo "[ 26%] Building for arm64-v8a..."
build_target arm64-v8a

echo "[ 51%] Building for x86..."
build_target x86

echo "[ 76%] Building for x86_64..."
build_target x86_64

echo "[ 98%] Assembling AAR..."
build_aar

echo "[100%] Cleaning up..."
rm -rf ${RIMRAF_ARGS}

echo "Done!"
