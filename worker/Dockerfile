FROM debian:latest

MAINTAINER OpenWrt Maintainers

ARG DEBIAN_FRONTEND=noninteractive

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN apt-get update && \
    apt-get install -y \
	build-essential \
	ccache \
	curl \
	gawk \
	git-core \
	gosu \
	libncurses5-dev \
	locales \
	pv \
	pwgen \
	python3 \
	python3-pip \
	rsync \
	signify-openbsd \
	unzip \
	wget \
	&& apt-get clean \
	&& localedef -i en_US -c -f UTF-8 \
		-A /usr/share/locale/locale.alias en_US.UTF-8

RUN pip3 install buildbot-worker twisted[tls]

ENV BUILDWORKER_ADMIN contact@openwrt.org
ENV BUILDWORKER_DESCRIPTION Buildworker Docker Instance

COPY ./worker/entry.sh /entry.sh

RUN useradd -c "OpenWrt buildbot" -m -d /builder -s /bin/bash buildbot
RUN chmod +x /entry.sh


USER buildbot

VOLUME [ "/builder" ]
WORKDIR "/builder"
ENTRYPOINT [ "/entry.sh" ]
