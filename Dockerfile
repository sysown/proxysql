
FROM debian:11
LABEL maintainer="Peter Lyoo <peter.lyoo@sendbird.com>"

RUN apt-get update && \
    apt-get install -y default-mysql-client wget lsb-release gnupg apt-transport-https ca-certificates jq zlib1g-dev
RUN wget -nv -O - 'https://repo.proxysql.com/ProxySQL/proxysql-2.7.x/repo_pub_key' | gpg --dearmor > /etc/apt/trusted.gpg.d/proxysql-2.7.x-keyring.gpg # buildkit
RUN echo deb https://repo.proxysql.com/ProxySQL/proxysql-2.7.x/$(lsb_release -sc)/ ./ | tee /etc/apt/sources.list.d/proxysql.list
RUN apt-get update && apt-get install -y proxysql=2.4.4 && rm -rf /var/lib/apt/lists/*

ADD ./src/proxysql /usr/bin/proxysql

CMD ["proxysql", "-f", "--idle-threads", "-D", "/var/lib/proxysql"]
