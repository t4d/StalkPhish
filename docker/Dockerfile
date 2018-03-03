FROM phusion/baseimage:0.10.0

LABEL maintainer "o0tad0o@gmail.com"

CMD ["/sbin/my_init"]

# install packages
RUN apt-get update && apt-get -fy upgrade
RUN apt-get install -fy \
supervisor \
git \
python3 \
python3-pip \
tor

# clone StalkPhish from GitHub
RUN git clone https://github.com/t4d/StalkPhish.git /opt/StalkPhish

# install requirements' file
RUN pip3 install -r /opt/StalkPhish/requirements.txt

# create directories to share
RUN mkdir /opt/StalkPhish/stalkphish/log
RUN mkdir /opt/StalkPhish/stalkphish/dl
RUN mkdir /opt/StalkPhish/stalkphish/db

# Add custom supervisor config
ADD supervisord.conf /etc/supervisor/conf.d/supervisord.conf
CMD ["/usr/bin/supervisord"]
