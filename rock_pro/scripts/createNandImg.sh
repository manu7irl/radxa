#!/bin/bash

##########################################################################################################
# Paths and variables
##########################################################################################################

scriptdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd ${scriptdir}
cd ..
basedir=$(pwd)

# read config-file
source ${basedir}/build.cfg


##########################################################################################################
# functions
##########################################################################################################

function getPackTools {
        git clone https://github.com/frep/rockchip-pack-tools
}

function createNandImg {
	cd ${rootfsdir}
	getPackTools
	mkdir -p rockchip-pack-tools/Linux
	mv rock_rootfs-${version}.img rockchip-pack-tools/Linux/rootfs.img
	cp ${bootImgDir}/boot-linux.img rockchip-pack-tools/Linux/
	cd rockchip-pack-tools
	./mkupdate.sh
}

function cleanup {
	mv Linux/rootfs.img ../rock_rootfs-${version}.img
	mv update.img ../${nandImageName}-${version}.img
	cd ..
	rm -rf rockchip-pack-tools
	rm -rf kali-armhf
	rm -rf kali-arm-build-scripts
}


##########################################################################################################
# program
##########################################################################################################

if [ ! -d ${tooldir} ]; then
	echo "tools not found. Please run ./getTools.sh first"
	exit 0
fi

if [ ! -f ${bootImgDir}/boot-linux.img ]; then
	echo "boot-linux.img not found. Please check <bootImgDir> in build.cfg!"
	exit 0
fi

if [ ! -f ${bootImgDir}/modules.tar.gz ]; then
	echo "modules and firmware archive: modules.tar.gz not found. Please check <bootImgDir> in build.cfg!"
	exit 0
fi

if [ ! -d ${rootfsdir} ]; then
        # image directory does not exist yet. Create it!
        mkdir ${rootfsdir}
fi


# create the rootfs image
cd ${scriptdir}
./createKaliRootfs.sh

createNandImg

cleanup

echo "The kali-nand-image is located at: "${rootfsdir}"/"${nandImageName}"-"${version}".img"

exit
