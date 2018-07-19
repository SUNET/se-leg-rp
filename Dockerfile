FROM debian

MAINTAINER se-leg developers <se-leg@lists.sunet.se>

ENV DEBIAN_FRONTEND=noninteractive \
    SE_LEG_RP_SETTINGS=/rp/etc/app_config.py

WORKDIR /
EXPOSE 5000
VOLUME ["/rp/etc"]

RUN apt-get update && apt-get -yu dist-upgrade
# for troubleshooting in the container
RUN apt-get -y install \
    vim \
    net-tools \
    netcat \
    telnet \
    traceroute
RUN apt-get -y install \
    python-virtualenv \
    git-core \
    gcc \
    python3-dev \
    libffi-dev \
    libtiff5-dev \
    libjpeg62-turbo-dev \
    zlib1g-dev \
    libfreetype6-dev \
    libssl-dev
# insert additional apt-get installs here
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

RUN adduser --system --group se-leg

# Add Dockerfile to the container as documentation
ADD Dockerfile /Dockerfile

# revision.txt is dynamically updated by the CI for every build,
# to ensure the statements below this point are executed every time
ADD docker/revision.txt /revision.txt

RUN mkdir -p /rp && virtualenv -p python3 /rp/env
ADD . /rp/src
RUN cd /rp/src && \
    /rp/env/bin/pip install -U pip && \
    /rp/env/bin/pip install -r requirements.txt && \
    /rp/env/bin/pip install gunicorn

CMD ["start-stop-daemon", "--start", "-c", "se-leg:se-leg", "--exec", \
     "/rp/env/bin/gunicorn", "--pidfile", "/var/run/se-leg-rp.pid", \
     "--", \
     "--bind", "0.0.0.0:5000", "--chdir", "/tmp", \
     "-w", "3", \
     "se_leg_rp.run:app" \
     ]
