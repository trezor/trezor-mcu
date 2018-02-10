#/bin/bash

export EMULATOR=1
export TRANSPORT=PIPE
export PKG_CONFIG_PATH=/usr/lib/i386-linux-gnu/pkgconfig
export PYTHON=python3

case "$1" in
  "-clean")
    make clean
    make -C firmware clean
    make -C emulator clean
    exit
    ;;
  "-pizero")
    export PATH=/opt/poky/2.4.1/sysroots/x86_64-pokysdk-linux/usr/bin/arm-poky-linux-gnueabi:$PATH
    export PKG_CONFIG_SYSROOT_DIR=/opt/poky/2.4.1/sysroots/arm1176jzfshf-vfp-poky-linux-gnueabi
    export PKG_CONFIG_PATH=/opt/poky/2.4.1/sysroots/arm1176jzfshf-vfp-poky-linux-gnueabi/usr/lib/pkgconfig
    export CC=arm-poky-linux-gnueabi-gcc
    export CPUFLAGS="-march=armv6 -mfpu=vfp -mfloat-abi=hard -mtune=arm1176jzf-s -mfpu=vfp --sysroot=/opt/poky/2.4.1/sysroots/arm1176jzfshf-vfp-poky-linux-gnueabi"
    export TRANSPORT=USBG
    export PIZERO=1
    export USE_RANDOM=1
    ;;
  *)
    ;;
esac

make -C emulator
make -C vendor/nanopb/generator/proto
make -C firmware/protob
make
make -C firmware trezor.elf
