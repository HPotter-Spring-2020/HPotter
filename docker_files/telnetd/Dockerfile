FROM debian:latest
EXPOSE 23
RUN apt update && apt -y install inetutils-telnetd
RUN echo 'telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/telnetd --authmode=none --exec-login=/bin/bash' >> /etc/inetd.conf
CMD ["/usr/sbin/inetutils-inetd","-d"]
RUN echo 'read -p "fb67f5056f5d login: "' >> ~/.bashrc
RUN echo 'read -s -p "Password: "' >> ~/.bashrc
RUN echo 'echo "\nLinux 4c9768971fde 5.3.0-40-generic #32~18.04.1-Ubuntu SMP Mon Feb 3 14:05:59 UTC 2020 x86_64 \n\nThe programs included with the Debian GNU/Linux system are free software;\nthe exact distribution terms for each program are described in the\nindividual files in /usr/share/doc/*/copyright.\n\nDebian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\npermitted by applicable law.\nNo directory, logging in with HOME=/"' >> ~/.bashrc

