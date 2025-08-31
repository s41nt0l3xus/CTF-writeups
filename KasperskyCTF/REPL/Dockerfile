FROM ubuntu:devel@sha256:1041699615b625b6bb6fbcdb7876bb1379f52b954374ab457360d9444a05cd7d AS ubuntu

FROM pwn.red/jail

COPY --from=ubuntu / /srv

RUN mkdir -p /srv/app
COPY --chmod=555 chall /srv/app/run
COPY --chmod=444 flag.txt /srv/app/flag.txt
