FROM ubuntu:focal

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y git python3-pip curl
RUN apt-get install -y binutils-arm-linux-gnueabi binutils-aarch64-linux-gnu binutils-mips-linux-gnu binutils-mips64-linux-gnuabi64 binutils-mips64-linux-gnuabin32

RUN pip install pwn