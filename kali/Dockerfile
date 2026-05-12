FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y kali-linux-headless --no-install-recommends

COPY tools.txt /tmp/tools.txt
RUN apt-get install -y $(grep -v "^#" /tmp/tools.txt | tr "\n" " ")

RUN useradd -m -s /bin/bash kali && echo "kali:kali" | chpasswd && usermod -aG sudo kali

RUN apt-get install -y openssh-server && mkdir /var/run/sshd && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

EXPOSE 22

COPY entrypoint.sh /entrypoint.sh && chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]