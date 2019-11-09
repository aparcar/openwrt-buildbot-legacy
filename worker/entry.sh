#!/usr/bin/env bash

[ -n "$BUILDWORKER_NAME" ] || {
	echo "Please supply a name via --env BUILDWORKER_NAME=XXX" >&2
	exit 1
}

[ -n "$BUILDWORKER_PASSWORD" ] || {
	echo "Please supply a password via --env BUILDWORKER_PASSWORD=XXX" >&2
	exit 2
}

[ -n "$BUILDWORKER_MASTER" ] || {
	echo "Please supply a buildmaster via --env BUILDWORKER_MASTER=XXX" >&2
	exit 2
}

rm -f /builder/buildbot.tac

buildbot-worker create-worker --force --umask=0o22 /builder \
    "$BUILDWORKER_MASTER" "$BUILDWORKER_NAME" "$BUILDWORKER_PASSWORD"

mkdir -p /builder/info
echo "$BUILDWORKER_ADMIN" > /builder/info/admin
echo "$BUILDWORKER_DESCRIPTION" > /builder/info/host

unset \
	BUILDWORKER_ADMIN \
	BUILDWORKER_DESCRIPTION \
	BUILDWORKER_MASTER \
	BUILDWORKER_NAME \
	BUILDWORKER_PASSWORD

rm -f /builder/twistd.pid
exec buildbot-worker start --nodaemon /builder
