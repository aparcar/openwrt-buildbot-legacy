#!/usr/bin/env bash

case "${1:-start}" in
	reconfig)
		exec buildbot reconfig /master
	;;
	start)
		case "${BUILDMASTER_PHASE:-1}" in
			1|2)
				cp /phase${BUILDMASTER_PHASE:-1}/config.ini.example /master/
			;;
			*)
				echo "Invalid BUILDMASTER_PHASE given. Must be either '1' or '2'" >&2
				exit 1
			;;
		esac

		buildbot create-master --config=/phase1/master.py /master

		unset BUILDMASTER_PHASE

		rm -f /master/twistd.pid
		exec buildbot start --nodaemon /master
	;;
	/*)
		exec "$@"
	;;
	*)
		echo "Unknown command given. Must be either 'start' or 'reconfig'" >&2
		exit 1
	;;
esac
