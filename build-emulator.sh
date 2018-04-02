#!/bin/bash
set -e

IMAGE=trezor-mcu-build-emulator64
TAG=${1:-grs}
ELFFILE=build/trezor-emulator64-$TAG

docker build -f Dockerfile.emulator -t $IMAGE .
docker run -t -v $(pwd)/build:/build:z $IMAGE /bin/sh -c "\
	git clone http://192.168.1.9:4000/trezor-mcu.git && \
	cd trezor-mcu && \
	git checkout $TAG && \
	git submodule update --init && \
	make -C vendor/nanopb/generator/proto && \
	make -C firmware/protob && \
	EMULATOR=1 make && \
	EMULATOR=1 make -C emulator && \
	EMULATOR=1 make -C firmware && \
	cp firmware/trezor.elf /$ELFFILE"
