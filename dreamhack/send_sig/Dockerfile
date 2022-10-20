FROM ubuntu:20.04

RUN echo 'APT{Install-Recommends "0";Install-Suggests "0";};' > /etc/apt/apt.conf.d/zzzuser
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get upgrade -qyy && apt-get autoremove -qyy --purge
RUN DEBIAN_FRONTEND=noninteractive apt-get install -qyy socat
RUN apt install libc6-dev-i386 -y
RUN adduser --no-create-home --disabled-login --gecos '' -- "send_sig" && mkdir -p "/home/send_sig"

COPY --chown=root:send_sig ./private/flag.txt /home/send_sig/
COPY --chown=root:send_sig ./public/send_sig /home/send_sig/

RUN chmod 0440 "/home/send_sig/flag.txt" && \
    chmod 0755 "/home/send_sig/send_sig"

WORKDIR /home/send_sig
EXPOSE 1898/tcp
CMD ["socat", "TCP-LISTEN:1898,reuseaddr,fork", "EXEC:/home/send_sig/send_sig"]

