FROM kalilinux/kali-rolling

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        nmap \
        nikto \
        nuclei \
        sqlmap \
        dnsrecon \
        sublist3r \
        amass \
        masscan \
        wpscan \
        ffuf \
        commix \
        testssl.sh \
        whatweb \
        exploitdb \
        curl wget \
        python3 python3-pip \
        && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd && \
    echo "root:optimus" | chpasswd && \
    sed -i "s/#PermitRootLogin prohibit-password/PermitRootLogin yes/" /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
