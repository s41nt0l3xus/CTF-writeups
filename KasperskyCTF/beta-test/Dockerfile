FROM ubuntu:24.04@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9 AS ubuntu

FROM pwn.red/jail

COPY --from=ubuntu / /srv

RUN mkdir -p /srv/app
COPY --chmod=555 chall /srv/app/run
COPY --chmod=444 flag.txt /srv/app/flag.txt
