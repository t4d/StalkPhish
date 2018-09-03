FROM alpine:latest

LABEL maintainer "o0tad0o@gmail.com"

ENV INITSYSTEM=on

# install packages
RUN apk --no-cache add --update \
py-lxml \
git \
python3 \
openrc \
sqlite \
supervisor \
tor

# clone StalkPhish from GitHub
RUN git clone https://github.com/t4d/StalkPhish.git /opt/StalkPhish

# upgrade pip
RUN pip3 install --upgrade pip

# install requirements' file
RUN pip3 install -r /opt/StalkPhish/requirements.txt

# create directories to share
RUN mkdir /opt/StalkPhish/stalkphish/log
RUN mkdir /opt/StalkPhish/stalkphish/dl
RUN mkdir /opt/StalkPhish/stalkphish/db

# Add custom supervisor config
COPY supervisord.conf /etc/supervisor/conf.d/
CMD ["/usr/bin/supervisord"; "-c"; "/etc/supervisor/conf.d/supervisord.conf"]

# Make some clean
RUN rm -rf /var/cache/apk/*
