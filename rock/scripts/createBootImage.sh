#!/bin/bash

##########################################################################################################
# Paths and variables
##########################################################################################################

scriptdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd ${scriptdir}
cd ..
basedir=$(pwd)
cd ..
radxadir=$(pwd)
cd ${basedir}

# read config-file
source ${basedir}/build.cfg


##########################################################################################################
# Functions
##########################################################################################################

function patchingKernelSource {
	cd ${kerneldir}
	wget http://patches.aircrack-ng.org/mac80211.compat08082009.wl_frag+ack_v1.patch -O mac80211.patch
	patch -p1 --no-backup-if-mismatch < mac80211.patch
	touch .scmversion
}

function buildKernelAndModules {
	cd ${kerneldir}
	# Run make kernel with the maximun CPU threads available	
	make -j $(grep -c processor /proc/cpuinfo) Image modules
	mkdir modules
	make INSTALL_MOD_PATH=./modules modules modules_install
}

function generateInitramfs {
	cd ${kerneldir}/arch/arm/boot/
	git clone --depth 1 https://github.com/radxa/initrd.git
	make -C initrd
}

function buildBootImg {
	# Create boot-linux.img
	sudo apt-get -y install lib32stdc++6	
	mkbootimg --kernel ${kerneldir}/arch/arm/boot/Image --ramdisk ${kerneldir}/arch/arm/boot/initrd.img -o ${kerneldir}/boot-linux.img
}

function createModulesArchive {
	cd ${kerneldir}/modules/lib
	tar cvfz modules.tar.gz firmware/ modules/
}

function moveData {
	mkdir ${kerneldir}/currentBuild/
	cp ${kerneldir}/boot-linux.img ${basedir}/kernel/currentBuild/
	mv ${kerneldir}/modules/lib/modules.tar.gz ${basedir}/kernel/currentBuild/
}

##########################################################################################################
# program
##########################################################################################################

if [ ! -d ${kerneldir} ]; then
        echo "Kernel sources are needed to build the kernel. Run <getKernelSource.sh> and <createKernelConfig.sh>!"
        exit
fi

cd ${kerneldir}

if [ ! -f .config ]; then
        echo "No kernel config found. Run <createKernelConfig.sh> first!"
        exit
fi

if [ -f boot-linux.img ]; then
        while true; do
                read -p "Boot-image already created. [r]ecreate or [s]kip ?" rs
                case $rs in
                [Rr]* ) rm -rf modules;
			rm boot-linux.img;
			rm -rf initrd;
			rm initrd.img;
			rm arch/arm/boot/Image;
			rm arch/arm/boot/zImage;
			rm -rf ${kerneldir}/currentBuild
                        break;;
                [Ss]* ) exit;;
                * )     echo "Please answer [r] or [s].";;
                esac
        done
fi

patchingKernelSource

buildKernelAndModules

generateInitramfs

buildBootImg

createModulesArchive

moveData

exit
