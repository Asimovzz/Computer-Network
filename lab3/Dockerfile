FROM ubuntu:22.04

RUN sed -i 's/archive.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --fix-missing tzdata sudo vim iproute2 traceroute autoconf make gcc libpcap-dev openssh-server openssh-client ssh iputils-ping net-tools tcpdump && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

CMD ["tail", "-f", "/dev/null"]