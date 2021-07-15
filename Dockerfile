FROM elasticsearch:7.4.2

ENV discovery.type=single-node

COPY bin/elastic-schema bin/

COPY bin/data-import bin/

COPY bin/replay bin/

COPY bin/docker-entrypoint.sh /usr/local/bin

RUN yum -y install epel-release \
    && yum -y install python-pip \
    && pip install --upgrade pip \
    && pip install elasticsearch

COPY batch-replay-sample/ batch-replay-sample

COPY raw-data-sample/ raw-data-sample

COPY customized-blocks/  customized-blocks

COPY py-scripts/ py-scripts

COPY tracer-scripts/ tracer-scripts
