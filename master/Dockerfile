FROM debian:latest

MAINTAINER OpenWrt Maintainers

ARG DEBIAN_FRONTEND=noninteractive

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN apt-get update && \
	apt-get install -y \
		build-essential \
		gawk \
		git-core \
		libncurses5-dev \
		locales \
		pv \
		pwgen \
		python2 \
		python3-pip \
		signify-openbsd \
		unzip \
		wget \
	&& apt-get clean \
	&& localedef -i en_US -c -f UTF-8 \
		-A /usr/share/locale/locale.alias en_US.UTF-8

RUN pip3 install buildbot[bundle]

ENV BUILDMASTER_CONFIG config.ini
ENV BUILDMASTER_PHASE 1

COPY master/entry.sh /entry.sh
COPY phase1 /phase1
COPY phase2 /phase2
COPY scripts /scripts

RUN useradd -c "OpenWrt buildbot" -m -d /master -s /bin/bash buildbot
RUN chown -R buildbot:buildbot /master
RUN chmod +x /entry.sh

USER buildbot

VOLUME [ "/master" ]
WORKDIR "/master"
ENTRYPOINT [ "/entry.sh" ]
CMD [ "start" ]
