FROM docker.io/python:3-alpine

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONUNBUFFERED=1 VIRTUAL_ENV=/usr/local/venv \
    PATH="/usr/local/venv:$PATH"
ARG POWERDNS_CLI_VERSION
RUN set -e \
    && apk add --no-cache --no-interactive bash\
    && python3 -m venv /usr/local/venv \
    && pip install --no-cache-dir powerdns-cli==$POWERDNS_CLI_VERSION \
    && adduser -S -u 1001 -g 1001 -s /bin/bash powerdns

WORKDIR /home/powerdns
USER powerdns

RUN _POWERDNS_CLI_COMPLETE=bash_source powerdns-cli > ~/.powerdns-cli-complete.bash &&  \
    echo 'source ~/.powerdns-cli-complete.bash' >> ~/.bashrc && \
    echo -e 'set show-all-if-ambiguous on\nset show-all-if-unmodified on\nset menu-complete-display-prefix on\n"\t": menu-complete' > ~/.inputrc

CMD ["/bin/bash"]
