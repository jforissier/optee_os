#!/bin/bash

cd /optee_os

export LC_ALL=C
export PATH=/usr/local/bin:$PATH  # clang
export TIMEFORMAT="Elapsed %0lR"
export CROSS_COMPILE32="ccache arm-linux-gnueabihf-"
export CROSS_COMPILE64="ccache aarch64-linux-gnu-"
export CCACHE_COMPRESS=1
export CFG_DEBUG_INFO=n
export CFG_WERROR=y
export SCP_OPT="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

function _do() { echo ">> $@"; $@; }
function _do_time() { echo ">> $@"; time $@; }
function print_and_reset_cache_stats() { ccache -s -z | egrep "cache hit rate"; }
function _make() { _do_time make -j$(getconf _NPROCESSORS_ONLN) -s O=out $* || exit 1; print_and_reset_cache_stats; }
function set_ssh_key() { echo Set SSH key; mkdir -p $HOME/.ssh; chmod 700 $HOME/.ssh; echo $ID_RSA | tr '$' '\n' >$HOME/.ssh/id_rsa; chmod 600 $HOME/.ssh/id_rsa; }
function download_cache() { set -x; scp $SCP_OPT -P 50022 codeship@w540.forissier.org:ccache.tar.gz $HOME && tar xf $HOME/ccache.tar.gz -C $HOME; set +x; }
function upload_cache() { set -x; tar czf $HOME/ccache.tar.gz -C $HOME .ccache && scp $SCP_OPT -P 50022 $HOME/ccache.tar.gz codeship@w540.forissier.org:./; set +x; }

set_ssh_key

download_cache
_do ccache -M 1G -s -z

_make
_make COMPILER=clang
_make CFG_TEE_CORE_LOG_LEVEL=4 CFG_TEE_CORE_DEBUG=y CFG_TEE_TA_LOG_LEVEL=4 CFG_CC_OPTIMIZE_FOR_SIZE=n CFG_DEBUG_INFO=y
_make CFG_TEE_CORE_LOG_LEVEL=0 CFG_TEE_CORE_DEBUG=n CFG_TEE_TA_LOG_LEVEL=0 CFG_CC_OPTIMIZE_FOR_SIZE=y CFG_DEBUG_INFO=n
_make CFG_TEE_CORE_LOG_LEVEL=0
_make CFG_TEE_CORE_MALLOC_DEBUG=y
_make CFG_CORE_SANITIZE_UNDEFINED=y
_make CFG_CORE_SANITIZE_KADDRESS=y
_make CFG_LOCKDEP=y
_make CFG_CRYPTO=n
_make CFG_CRYPTO_{AES,DES}=n
_make CFG_CRYPTO_{DSA,RSA,DH}=n
_make CFG_CRYPTO_{DSA,RSA,DH,ECC}=n
_make CFG_CRYPTO_{H,C,CBC_}MAC=n
_make CFG_CRYPTO_{G,C}CM=n
_make CFG_CRYPTO_{MD5,SHA{1,224,256,384,512,512_256}}=n
_make CFG_WITH_PAGER=y out/core/tee{,-pager,-pageable}.bin
_make CFG_WITH_PAGER=y CFG_CRYPTOLIB_NAME=mbedtls CFG_CRYPTOLIB_DIR=lib/libmbedtls
_make CFG_WITH_PAGER=y CFG_WITH_LPAE=y
_make CFG_WITH_LPAE=y CFG_CORE_ASLR=y
_make CFG_RPMB_FS=y CFG_CORE_ASLR=y
_make CFG_RPMB_FS=y CFG_RPMB_TESTKEY=y
_make CFG_REE_FS=n CFG_RPMB_FS=y
_make CFG_WITH_PAGER=y CFG_WITH_LPAE=y CFG_RPMB_FS=y CFG_DT=y CFG_TEE_CORE_LOG_LEVEL=1 CFG_TEE_CORE_DEBUG=y CFG_CC_OPTIMIZE_FOR_SIZE=n CFG_DEBUG_INFO=y
_make CFG_WITH_PAGER=y CFG_WITH_LPAE=y CFG_RPMB_FS=y CFG_DT=y CFG_TEE_CORE_LOG_LEVEL=0 CFG_TEE_CORE_DEBUG=n DEBUG=0
_make CFG_BUILT_IN_ARGS=y CFG_PAGEABLE_ADDR=0 CFG_NS_ENTRY_ADDR=0 CFG_DT_ADDR=0 CFG_DT=y
_make CFG_FTRACE_SUPPORT=y CFG_ULIBS_MCOUNT=y CFG_ULIBS_SHARED=y
_make CFG_TA_GPROF_SUPPORT=y CFG_FTRACE_SUPPORT=y CFG_SYSCALL_FTRACE=y CFG_ULIBS_MCOUNT=y
_make CFG_SECURE_DATA_PATH=y
_make CFG_REE_FS_TA_BUFFERED=y
_make PLATFORM=vexpress-qemu_armv8a CFG_ARM64_core=y CFG_CORE_ASLR=y
_make PLATFORM=vexpress-qemu_armv8a CFG_ARM64_core=y COMPILER=clang
_make PLATFORM=vexpress-qemu_armv8a CFG_ARM64_core=y CFG_WITH_PAGER=y
_make PLATFORM=vexpress-qemu_armv8a CFG_ARM64_core=y CFG_FTRACE_SUPPORT=y CFG_ULIBS_MCOUNT=y CFG_ULIBS_SHARED=y
_make PLATFORM=vexpress-qemu_armv8a CFG_ARM64_core=y CFG_TA_GPROF_SUPPORT=y CFG_FTRACE_SUPPORT=y CFG_SYSCALL_FTRACE=y CFG_ULIBS_MCOUNT=y
_make PLATFORM=vexpress-qemu_armv8a CFG_ARM64_core=y CFG_VIRTUALIZATION=y
_make PLATFORM=stm-b2260
_make PLATFORM=stm-cannes
_make PLATFORM=stm32mp1
_make PLATFORM=stm32mp1-157C_DK2
_make PLATFORM=vexpress-fvp
_make PLATFORM=vexpress-fvp CFG_ARM64_core=y
_make PLATFORM=vexpress-juno
_make PLATFORM=vexpress-juno CFG_ARM64_core=y
_make PLATFORM=hikey
_make PLATFORM=hikey CFG_ARM64_core=y
_make PLATFORM=mediatek-mt8173 CFG_ARM64_core=y
_make PLATFORM=imx-mx6ulevk
_make PLATFORM=imx-mx6ulevk CFG_NXP_CAAM=y
_make PLATFORM=imx-mx6ul9x9evk
_make PLATFORM=imx-mx6ullevk
_make PLATFORM=imx-mx6ulzevk
_make PLATFORM=imx-mx6slevk
_make PLATFORM=imx-mx6sllevk
_make PLATFORM=imx-mx6sxsabreauto
_make PLATFORM=imx-mx6sxsabresd
_make PLATFORM=imx-mx6sxsabresd CFG_NXP_CAAM=y
_make PLATFORM=imx-mx6solosabresd
_make PLATFORM=imx-mx6solosabreauto
_make PLATFORM=imx-mx6sxsabreauto
_make PLATFORM=imx-mx6qsabrelite
_make PLATFORM=imx-mx6qsabresd
_make PLATFORM=imx-mx6qsabresd CFG_RPMB_FS=y
_make PLATFORM=imx-mx6qsabreauto
_make PLATFORM=imx-mx6qsabreauto CFG_NXP_CAAM=y
_make PLATFORM=imx-mx6qpsabreauto
_make PLATFORM=imx-mx6qpsabresd
_make PLATFORM=imx-mx6dlsabresd
_make PLATFORM=imx-mx6dlsabreauto
_make PLATFORM=imx-mx6dapalis
_make PLATFORM=imx-mx6qapalis
_make PLATFORM=imx-mx7dsabresd
_make PLATFORM=imx-mx7dsabresd CFG_NXP_CAAM=y
_make PLATFORM=imx-mx7ulpevk
_make PLATFORM=imx-mx8mmevk
_make PLATFORM=imx-mx8mmevk CFG_NXP_CAAM=y
_make PLATFORM=imx-mx8mnevk
_make PLATFORM=imx-mx8mqevk
_make PLATFORM=imx-mx8qxpmek
_make PLATFORM=imx-mx8qmmek
_make PLATFORM=k3-j721e
_make PLATFORM=k3-j721e CFG_ARM64_core=y
_make PLATFORM=k3-am65x
_make PLATFORM=k3-am65x CFG_ARM64_core=y
_make PLATFORM=ti-dra7xx out/core/tee{,-pager,-pageable}.bin
_make PLATFORM=ti-am57xx
_make PLATFORM=ti-am43xx
_make PLATFORM=sprd-sc9860
_make PLATFORM=sprd-sc9860 CFG_ARM64_core=y
_make PLATFORM=ls-ls1021atwr
_make PLATFORM=ls-ls1021aqds
_make PLATFORM=ls-ls1043ardb
_make PLATFORM=ls-ls1046ardb
_make PLATFORM=ls-ls1012ardb
_make PLATFORM=ls-ls1012afrwy
_make PLATFORM=ls-ls1028ardb
_make PLATFORM=ls-ls1088ardb
_make PLATFORM=ls-ls2088ardb
_make PLATFORM=ls-lx2160ardb
_make PLATFORM=zynq7k-zc702
_make PLATFORM=zynqmp-zcu102
_make PLATFORM=zynqmp-zcu102 CFG_ARM64_core=y
_make PLATFORM=d02
_make PLATFORM=d02 CFG_ARM64_core=y
_make PLATFORM=rcar
_make PLATFORM=rcar CFG_ARM64_core=y
_make PLATFORM=rpi3
_make PLATFORM=rpi3 CFG_ARM64_core=y
_make PLATFORM=hikey-hikey960
_make PLATFORM=hikey-hikey960 COMPILER=clang
_make PLATFORM=hikey-hikey960 CFG_ARM64_core=y
_make PLATFORM=hikey-hikey960 CFG_ARM64_core=y COMPILER=clang
_make PLATFORM=hikey-hikey960 CFG_SECURE_DATA_PATH=n
_make PLATFORM=poplar
_make PLATFORM=poplar CFG_ARM64_core=y
_make PLATFORM=rockchip-rk322x
_make PLATFORM=sam
_make PLATFORM=marvell-armada7k8k
_make PLATFORM=marvell-armada3700
_make PLATFORM=synquacer
_make PLATFORM=sunxi-bpi_zero
_make PLATFORM=sunxi-sun50i_a64
_make PLATFORM=bcm-ns3 CFG_ARM64_core=y
_make PLATFORM=hisilicon-hi3519av100_demo
_make PLATFORM=amlogic

set -x
upload_cache
echo Done
