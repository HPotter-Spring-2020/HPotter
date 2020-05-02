FROM debian:latest
EXPOSE 4444
RUN apt update && apt -y install socat
CMD ["/usr/bin/socat","TCP4-LISTEN:4444,reuseaddr","exec:/bin/bash,pty,stderr,setsid,sigint,sane,echo=0"]