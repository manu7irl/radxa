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
# program
##########################################################################################################

if [ ! -f ${bootImgDir}/modules.tar.gz ]; then
	echo "modules and firmware archive not found. Check <bootImgDir> in build.cfg!"
	exit 0
fi

cd ${basedir}
if [ ! -d ${imagedir} ]; then
	# image directory does not exist yet. Create it!
	mkdir images
fi

kalidir=${imagedir}/kali-${version}

# Package installations for various sections.
# This will build a minimal XFCE Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/new/kali-linux-metapackages/ for meta packages you can
# use. You can also install packages, using just the package name, but keep in
# mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate vboot-utils vboot-kernel-utils uboot-mkimage"
base="kali-menu kali-defaults initramfs-tools"
desktop="xfce4 network-manager network-manager-gnome xserver-xorg-video-fbdev"
tools="passing-the-hash winexe aircrack-ng hydra john sqlmap wireshark libnfc-bin mfoc"
services="openssh-server apache2"
extras="iceweasel wpasupplicant"

export packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
export architecture="armhf"

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

if [ ! -d ${kalidir} ]; then
        # image directory does not exist yet. Create it!
        mkdir -p ${kalidir}
fi

cd ${kalidir}

#Based on kali-arm-build-scripts/mini-x - updated for ubuntu 14.04 multiarch
echo "Download the kali-arm-build-scripts"
mkdir kali-deps-script
cd kali-deps-script
cat > build-deps.sh << "EOF"
#!/bin/bash
apt-get install -y git-core gnupg flex bison gperf libesd0-dev build-essential \
zip curl libncurses5-dev zlib1g-dev libncurses5-dev gcc-multilib g++-multilib \
parted kpartx debootstrap pixz qemu-user-static abootimg cgpt vboot-kernel-utils \
vboot-utils u-boot-tools bc lzma lzop automake autoconf m4 dosfstools pixz \
rsync schedtool git dosfstools e2fsprogs device-tree-compiler

MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then		
    dpkg --add-architecture i386
    apt-get update
    apt-get install -y lib32bz2-1.0 lib32z1 
    # Required for kernel cross compiles
    apt-get install -y lib32ncurses5
else
    apt-get install -y libncurses5
fi
EOF

chmod +x ./build-deps.sh

./build-deps.sh

cd ${kalidir}
# Create the kali script file inside the debootstrap scripts folder (/usr/share/debootstrap/scripts/) 
# credit to meefik from github - https://github.com/meefik/linuxdeploy/blob/master/assets/root/deploy/debootstrap/scripts/kali

cat > kali << "EOF"

default_mirror http://http.kali.org/kali
mirror_style release
download_style apt
finddebs_style from-indices
variants - buildd fakechroot minbase scratchbox
keyring /usr/share/keyrings/kali-archive-keyring.gpg

if doing_variant fakechroot; then
	test "$FAKECHROOT" = "true" || error 1 FAKECHROOTREQ "This variant requires fakechroot environment to be started"
fi

case $ARCH in
	alpha|ia64) LIBC="libc6.1" ;;
	kfreebsd-*) LIBC="libc0.1" ;;
	hurd-*)     LIBC="libc0.3" ;;
	*)          LIBC="libc6" ;;
esac

work_out_debs () {
	required="$(get_debs Priority: required)"

	if doing_variant - || doing_variant fakechroot; then
		#required="$required $(get_debs Priority: important)"
		#  ^^ should be getting debconf here somehow maybe
		base="$(get_debs Priority: important)"
	elif doing_variant buildd || doing_variant scratchbox; then
		base="apt build-essential"
	elif doing_variant minbase; then
		base="apt"
	fi

	if doing_variant fakechroot; then
		# ldd.fake needs binutils
		required="$required binutils"
	fi

	case $MIRRORS in
	    https://*)
		base="$base apt-transport-https ca-certificates"
		;;
	esac
}

first_stage_install () {
	extract $required

	mkdir -p "$TARGET/var/lib/dpkg"
	: >"$TARGET/var/lib/dpkg/status"
	: >"$TARGET/var/lib/dpkg/available"

	setup_etc
	if [ ! -e "$TARGET/etc/fstab" ]; then
		echo '# UNCONFIGURED FSTAB FOR BASE SYSTEM' > "$TARGET/etc/fstab"
		chown 0:0 "$TARGET/etc/fstab"; chmod 644 "$TARGET/etc/fstab"
	fi

	x_feign_install () {
		local pkg="$1"
		local deb="$(debfor $pkg)"
		local ver="$(extract_deb_field "$TARGET/$deb" Version)"

		mkdir -p "$TARGET/var/lib/dpkg/info"

		echo \
"Package: $pkg
Version: $ver
Maintainer: unknown
Status: install ok installed" >> "$TARGET/var/lib/dpkg/status"

		touch "$TARGET/var/lib/dpkg/info/${pkg}.list"
	}

	x_feign_install dpkg
}

second_stage_install () {
	setup_devices

	x_core_install () {
		smallyes '' | in_target dpkg --force-depends --install $(debfor "$@")
	}

	p () {
		baseprog="$(($baseprog + ${1:-1}))"
	}

	if doing_variant fakechroot; then
		setup_proc_fakechroot
	elif doing_variant scratchbox; then
		true
	else
		setup_proc
		in_target /sbin/ldconfig
	fi

	DEBIAN_FRONTEND=noninteractive
	DEBCONF_NONINTERACTIVE_SEEN=true
	export DEBIAN_FRONTEND DEBCONF_NONINTERACTIVE_SEEN

	baseprog=0
	bases=7

	p; progress $baseprog $bases INSTCORE "Installing core packages" #1
	info INSTCORE "Installing core packages..."

	p; progress $baseprog $bases INSTCORE "Installing core packages" #2
	ln -sf mawk "$TARGET/usr/bin/awk"
	x_core_install base-passwd
	x_core_install base-files
	p; progress $baseprog $bases INSTCORE "Installing core packages" #3
	x_core_install dpkg

	if [ ! -e "$TARGET/etc/localtime" ]; then
		ln -sf /usr/share/zoneinfo/UTC "$TARGET/etc/localtime"
	fi

	if doing_variant fakechroot; then
		install_fakechroot_tools
	fi

	p; progress $baseprog $bases INSTCORE "Installing core packages" #4
	x_core_install $LIBC

	p; progress $baseprog $bases INSTCORE "Installing core packages" #5
	x_core_install perl-base

	p; progress $baseprog $bases INSTCORE "Installing core packages" #6
	rm "$TARGET/usr/bin/awk"
	x_core_install mawk

	p; progress $baseprog $bases INSTCORE "Installing core packages" #7
	if doing_variant -; then
		x_core_install debconf
	fi

	baseprog=0
	bases=$(set -- $required; echo $#)

	info UNPACKREQ "Unpacking required packages..."

	exec 7>&1

	smallyes '' |
		(repeatn 5 in_target_failmsg UNPACK_REQ_FAIL_FIVE "Failure while unpacking required packages.  This will be attempted up to five times." "" \
		dpkg --status-fd 8 --force-depends --unpack $(debfor $required) 8>&1 1>&7 || echo EXITCODE $?) |
		dpkg_progress $baseprog $bases UNPACKREQ "Unpacking required packages" UNPACKING

	info CONFREQ "Configuring required packages..."

	echo \
"#!/bin/sh
exit 101" > "$TARGET/usr/sbin/policy-rc.d"
	chmod 755 "$TARGET/usr/sbin/policy-rc.d"

	mv "$TARGET/sbin/start-stop-daemon" "$TARGET/sbin/start-stop-daemon.REAL"
	echo \
"#!/bin/sh
echo
echo \"Warning: Fake start-stop-daemon called, doing nothing\"" > "$TARGET/sbin/start-stop-daemon"
	chmod 755 "$TARGET/sbin/start-stop-daemon"

	setup_dselect_method apt

	smallyes '' |
		(in_target_failmsg CONF_REQ_FAIL "Failure while configuring required packages." "" \
		dpkg --status-fd 8 --configure --pending --force-configure-any --force-depends 8>&1 1>&7 || echo EXITCODE $?) |
		dpkg_progress $baseprog $bases CONFREQ "Configuring required packages" CONFIGURING

	baseprog=0
	bases="$(set -- $base; echo $#)"

	info UNPACKBASE "Unpacking the base system..."

	setup_available $required $base
	done_predeps=
	while predep=$(get_next_predep); do
		# We have to resolve dependencies of pre-dependencies manually because
		# dpkg --predep-package doesn't handle this.
		predep=$(without "$(without "$(resolve_deps $predep)" "$required")" "$done_predeps")
		# XXX: progress is tricky due to how dpkg_progress works
		# -- cjwatson 2009-07-29
		p; smallyes '' |
		in_target dpkg --force-overwrite --force-confold --skip-same-version --install $(debfor $predep)
		base=$(without "$base" "$predep")
		done_predeps="$done_predeps $predep"
	done

	smallyes '' |
		(repeatn 5 in_target_failmsg INST_BASE_FAIL_FIVE "Failure while installing base packages.  This will be re-attempted up to five times." "" \
		dpkg --status-fd 8 --force-overwrite --force-confold --skip-same-version --unpack $(debfor $base) 8>&1 1>&7 || echo EXITCODE $?) |
		dpkg_progress $baseprog $bases UNPACKBASE "Unpacking base system" UNPACKING

	info CONFBASE "Configuring the base system..."

	smallyes '' |
		(repeatn 5 in_target_failmsg CONF_BASE_FAIL_FIVE "Failure while configuring base packages.  This will be re-attempted up to five times." "" \
		dpkg --status-fd 8 --force-confold --skip-same-version --configure -a 8>&1 1>&7 || echo EXITCODE $?) |
		dpkg_progress $baseprog $bases CONFBASE "Configuring base system" CONFIGURING

	mv "$TARGET/sbin/start-stop-daemon.REAL" "$TARGET/sbin/start-stop-daemon"
	rm -f "$TARGET/usr/sbin/policy-rc.d"

	progress $bases $bases CONFBASE "Configuring base system"
	info BASESUCCESS "Base system installed successfully."
}
EOF

mv kali /usr/share/debootstrap/scripts/

# Create the rootfs - not much to modify here, except maybe the hostname
debootstrap --foreign --arch $architecture kali kali-$architecture http://http.kali.org/kali | tee debootstrap.log

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

LANG=C chroot kali-$architecture /debootstrap/debootstrap --second-stage
cat > kali-$architecture/etc/apt/sources.list << "EOF"
deb http://http.kali.org/kali kali main contrib non-free
deb http://security.kali.org/kali-security kali/updates main contrib non-free
EOF

echo ${hostname} > kali-$architecture/etc/hostname

cat > kali-$architecture/etc/hosts << "EOF"
127.0.0.1       kali    localhost
::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

cat > kali-$architecture/etc/resolv.conf << "EOF"
nameserver 8.8.8.8
EOF

cat > kali-$architecture/etc/network/interfaces << "EOF"
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

modprobe binfmt_misc
mount -t proc proc kali-$architecture/proc
mount -o bind /dev/ kali-$architecture/dev/
mount -o bind /dev/pts kali-$architecture/dev/pts

cat > kali-$architecture/debconf.set << "EOF"
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

cat > kali-$architecture/third-stage << "EOF"
#!/bin/bash
dpkg-divert --add --local --divert /usr/sbin/invoke-rc.d.chroot --rename /usr/sbin/invoke-rc.d
cp /bin/true /usr/sbin/invoke-rc.d
echo -e "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

apt-get update
apt-get -y install locales-all

debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get update
apt-get -y install git-core binutils ca-certificates initramfs-tools uboot-mkimage
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
sed -i -e 's/KERNEL\!=\"eth\*|/KERNEL\!=\"/' /lib/udev/rules.d/75-persistent-net-generator.rules
rm -f /etc/udev/rules.d/70-persistent-net.rules
apt-get --yes --force-yes install $packages

rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

chmod +x kali-$architecture/third-stage

LANG=C chroot kali-$architecture /third-stage

cat > kali-$architecture/cleanup << "EOF"
#!/bin/bash
rm -rf /root/.bash_history
apt-get update
apt-get clean
rm -f /0
rm -f /hs_err*
rm -f cleanup
rm -f /usr/bin/qemu*
EOF

chmod +x kali-$architecture/cleanup

echo "Autostart services"
update-rc.d ssh defaults
update-rc.d bluetooth defaults
update-rc.d apache2 defaults

# mtd-by-name link the mtdblock to name
echo "mtd by name fix"

cat > kali-$architecture/usr/local/bin/mtd-by-name.sh << "EOF"
#!/bin/sh -e
# radxa.com, thanks to naobsd
rm -rf /dev/block/mtd/by-name/
mkdir -p /dev/block/mtd/by-name
for i in `ls -d /sys/class/mtd/mtd*[0-9]`; do
name=`cat $i/name`
tmp="`echo $i | sed -e 's/mtd/mtdblock/g'`"
dev="`echo $tmp |sed -e 's/\/sys\/class\/mtdblock/\/dev/g'`"
ln -s $dev /dev/block/mtd/by-name/$name
done
EOF

chmod +x kali-$architecture/usr/local/bin/mtd-by-name.sh

cat > kali-$architecture/etc/rc.local << "EOF"
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

writeStartup()
{
        cat /etc/rc.local | sed 's@^startup=.*$@startup=\"'$1'\"@' > tmpFile
        mv tmpFile /etc/rc.local
        chmod +x /etc/rc.local
}

fixSshService()
{
	cat /etc/init.d/ssh | sed 's@^.*# Default-Stop:.*$@# Default-Stop:         0 1 6@' > tmpFile
	mv tmpFile /etc/init.d/ssh
	chmod +x /etc/init.d/ssh
	update-rc.d -f ssh remove
	update-rc.d ssh defaults
}

startup="firstBoot"
imagetype="nand"
autoStartX="false"
if [ ${imagetype} = "nand" ]; then
    /usr/local/bin/mtd-by-name.sh
fi

if [ ${startup} = "firstBoot" ]; then
	fixSshService
        if [ ${imagetype} = "nand" ]; then
                resize2fs /dev/block/mtd/by-name/linuxroot;
                writeStartup "startupDone"
        else
                set +e
        	echo  "d\nn\np\n1\n49152\n\nw" | fdisk /dev/mmcblk0
		set -e
                writeStartup "secondBoot"
		shutdown -r now
        fi
        # log the first boot
        dmesg > /root/firstBoot.log
fi

if [ ${startup} = "secondBoot" ]; then
        resize2fs /dev/mmcblk0p1
        writeStartup "startupDone"
fi

if [ ${autoStartX} = "true" ]; then
# start X at boot
su -l root -c startx
fi

exit 0
EOF

chmod +x kali-$architecture/etc/rc.local

# add some repositories
echo "deb http://ftp.us.debian.org/debian testing main contrib non-free" >> kali-$architecture/etc/apt/sources.list
echo "deb-src http://ftp.us.debian.org/debian testing main contrib non-free" >> kali-$architecture/etc/apt/sources.list
echo "deb http://ftp.debian.org/debian/ jessie-updates main contrib non-free" >> kali-$architecture/etc/apt/sources.list
echo "deb-src http://ftp.debian.org/debian/ jessie-updates main contrib non-free" >> kali-$architecture/etc/apt/sources.list
echo "deb http://security.debian.org/ jessie/updates main contrib non-free" >> kali-$architecture/etc/apt/sources.list
echo "deb-src http://security.debian.org/ jessie/updates main contrib non-free" >> kali-$architecture/etc/apt/sources.list

cat > kali-$architecture/etc/apt/preferences.d/main.pref << "EOF"
Package: *
Pin: release n=kali
Pin-Priority: 350

Package: *
Pin: release n=kali-bleeding-edge
Pin-Priority: 300

Package: *
Pin: release n=jessie
Pin-Priority: 10
EOF

LANG=C chroot kali-$architecture /cleanup

#umount kali-$architecture/proc/sys/fs/binfmt_misc
umount kali-$architecture/dev/pts
umount kali-$architecture/dev/
umount kali-$architecture/proc

# Create the disk and partition it
echo "Creating rock_rootfs-${version}.img"
cd ${kalidir}
dd if=/dev/zero of=rock_rootfs-${version}.img bs=1M count=${nandImageSize}

#kernel use the label linuxroot to mount the rootfs as /
echo "Formatting rock_rootfs-${version}.img to ext4"
mkfs.ext4 -F -L linuxroot rock_rootfs-${version}.img
rootfs="rock_rootfs-${version}.img"

# Create the dirs for the partitions and mount them
echo "Mounting rootfs"
rootimg="${basedir}/root"
mkdir -p ${rootimg}
mount -o loop ${rootfs} ${rootimg}

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${kalidir}/kali-$architecture/ ${rootimg}

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

cd ${bootImgDir}
tar xvfz modules.tar.gz -C ${rootimg}/lib

if [ ${autoLogin} == "true" ]; then
# enable autologin
cd ${rootimg}/etc
cat inittab | sed 's@1:2345:respawn:/sbin/getty 38400 tty1@1:2345:respawn:/bin/login -f root tty1 </dev/tty1 >/dev/tty1 2>\&1@' > tempFile
mv tempFile inittab
fi

# Unmount partitions
cd ${basedir}
umount ${rootimg}
