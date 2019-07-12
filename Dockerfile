FROM python:3.7-stretch

RUN apt update && apt install -y lsb-release apt-transport-https

RUN curl -sL https://repos.influxdata.com/influxdb.key | apt-key add - \
    && echo "deb https://repos.influxdata.com/debian `lsb_release --codename --short` stable" | tee /etc/apt/sources.list.d/influxdb.list \
    && apt update && apt install -y \
        dnsutils \
        mysql-client \
        postgresql-client \
        redis-tools \
        influxdb \
    && true

COPY requirements.txt /app/
RUN pip install -r /app/requirements.txt

WORKDIR /app
COPY . /app
RUN pip install .
ENTRYPOINT ["medusa"]

# run with
# docker run -it --mount type=bind,source=$HOME/.medusarc,target=/etc/medusarc,readonly --mount type=bind,source=$HOME/.aws/,target=/root/.aws/,readonly medusa
