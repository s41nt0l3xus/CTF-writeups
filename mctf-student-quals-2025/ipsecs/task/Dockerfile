FROM ubuntu:25.04@sha256:008b026f11c0b5653d564d0c9877a116770f06dfbdb36ca75c46fd593d863cbc AS chroot

RUN mkdir /app

RUN apt update -y && apt install socat gdbserver -y
RUN useradd ctf
COPY ./ipsecs  /app
COPY ./run.sh /app

RUN chmod +x /app/run.sh
RUN chmod +x /app/ipsecs

ADD catflag /catflag
ADD flag.txt /flag

RUN chown root:root /flag && chmod 400 /flag
RUN chown root:root /catflag && chmod 755 /catflag && chmod u+s /catflag

USER ctf
WORKDIR /app

CMD ["./run.sh"]
