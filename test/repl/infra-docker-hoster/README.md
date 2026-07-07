
# Infra docker-hoster

This is a special infra providing container DNS resolution to the host.

## Details:
https://github.com/dvddarias/docker-hoster

## Important:
This needs to be started manually ONCE!
the container auto-starts on reboot.

## Start:
- use `cd infra-docker-hoster && docker compose up -d`
- or `./infra-docker-hoster/docker-compose-init.bash`


## Issues:
- container locks up when unable to update /etc/hosts - e.g. full filesystem
  - remove and start container mannualy

