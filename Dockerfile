# initialize from the image

FROM ubuntu:16.04

RUN apt-get update \
 && apt-get install -yqq \
        build-essential \
        git \
        gcc-arm-none-eabi \
        python \
        python-ecdsa

ENTRYPOINT ["make", "-C", "/build"]
