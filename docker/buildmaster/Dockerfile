FROM        debian:10
MAINTAINER  OpenWrt Maintainers

ARG         DEBIAN_FRONTEND=noninteractive

ENV         BUILDMASTER_CONFIG config.ini
ENV         BUILDMASTER_PHASE  1

USER root

RUN apt-get update && \
	apt-get install -y \
		build-essential \
		gawk \
		git-core \
		gosu \
		libncurses5-dev \
		locales \
		pv \
		pwgen \
		python3-pip \
		signify-openbsd \
		unzip \
		wget && \
	apt-get clean && \
	localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

RUN pip3 install \
	"buildbot[bundle]==2.7.0" \
	"buildbot-www==2.7.0" \
	"buildbot-waterfall-view==2.7.0" \
	"buildbot-console-view==2.7.0" \
	"buildbot-grid-view==2.7.0" \
	"pyOpenSSL" \
	"service_identity" \
	"psycopg2-binary"

ENV LANG=en_US.utf8

COPY docker/buildmaster/files/entry.sh /entry.sh
COPY docker/buildmaster/files/start.sh /start.sh
COPY phase1 /phase1
COPY phase2 /phase2
COPY scripts /scripts

RUN mkdir /master && \
    useradd -c "buildbot" -m -d /master -s /bin/bash buildbot && \
    chown buildbot:buildbot /master && \
    usermod --home /master buildbot && \
    chmod 0755 /entry.sh /start.sh

VOLUME [ "/master" ]
ENTRYPOINT [ "/entry.sh" ]
CMD [ "start" ]
