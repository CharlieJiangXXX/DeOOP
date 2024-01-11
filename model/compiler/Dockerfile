FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -yqq update \
    && apt-get -y --quiet --no-install-recommends lsb-release software-properties-common debootstrap \
    && add-apt-repository ppa:ubuntu-toolchain-r/test \
    && apt-get -yqq update \
    && apt-get -y autoremove \
    && apt-get clean autoclean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \

COPY chroot.sh /chroot.sh
RUN chmod +x /chroot.sh
ENTRYPOINT ["/chroot.sh"]

RUN apt-get install $gcc_versions -y