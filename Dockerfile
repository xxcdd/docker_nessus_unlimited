FROM python:2.7-stretch
LABEL maintainer="https://github.com/xxcdd/docker_nessus_unlimited" \
    name="nessus" \
    description="nessus login xxcdd/xxcdd1996" \
    docker.run.cmd="docker run -d -p 8834:8834 nessus"

# --build-arg NESSUS_DEB=Nessus-8.13.1-debian6_amd64.deb
ARG NESSUS_DEB

ENV DEBIAN_FRONTEND noninteractive
COPY $NESSUS_DEB /opt
COPY install.py /opt
WORKDIR /opt
RUN set -xe;\
    sed -i 's|security.debian.org/debian-security|mirrors.ustc.edu.cn/debian-security|g' /etc/apt/sources.list;\
    sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list;\
    apt-get update --fix-missing;\
    apt-get install -y vim ;\
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime;\
    dpkg -i $NESSUS_DEB;\
    echo 'bs4' >> requirements.txt;\
    echo 'requests' >> requirements.txt;\
    pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple;\
    { \
       echo '#!/bin/bash'; \
       echo 'service nessusd start'; \
       echo 'while true; do'; \
       echo '    tail -f /opt/nessus/var/nessus/logs/*.log'; \
       echo '    sleep 5'; \
       echo 'done'; \
   } > run.sh;\
   chmod +x run.sh;\
   python install.py install

CMD [ "sh", "run.sh" ]
EXPOSE 8834