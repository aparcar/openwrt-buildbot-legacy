# OpenWrt buildbot

Setup notes for using the OpenWrt buildbot.

## Nginx proxy

Neither info interface nor worker connection should be handled directly via the
Buildbot but behind a Nginx proxy. The web interface is a regular proxy with
special cases for websockets, an example is found in `misc/buildmaster.conf`.

For encrypted connection between master and worker, the Nginx feature `stream`
is used to proxy non HTTP traffic. This needs to be added in the `stream`
paragraph rather than the `http` one. An example below:

```
stream {
	server {
		listen 9989 ssl;
		proxy_pass 127.0.0.1:19989;
		ssl_certificate /etc/letsencrypt/live/buildmaster.aparcar.org/fullchain.pem;
    		ssl_certificate_key /etc/letsencrypt/live/buildmaster.aparcar.org/privkey.pem;
	}
}
```

The certificates are from Let's Encrypt and managed via `certbot` and the
`python3-certbot-nginx` plugin.

## `config.ini` and `master.cfg`

The configuration `config.ini` is used for both *Phase 1* (building of images
and SDK) and *Phase 2* (building of packages via SDKs). The `master.cfg` is used
for either phase 1 or phase 2, as it contains the performed build steps.


## Docker setup

It's possible to run all services within a containers. The three main services
are Buildmaster, Buildworker and one or multiple `rsync` instances.

* The master is based on the official Buildbot docker image which uses Alpine
  Linux.
* The worker is based on the official Buildbot docker image which uses Ubuntu
  20.04.
* The rsync container is based on Alpine Linux.
