FROM python:3.7.1-slim-stretch
LABEL maintainer="frederic.t.chan@gmail.com"
ENV REFRESHED_AT 20181129
ENV MODE PRODUCTION
ENV FLASK_ENV production
ENV PIPENV_VENV_IN_PROJECT 1
ENV DATADOG_SERVICE_NAME=everyclass-identity DD_TRACE_ANALYTICS_ENABLED=true DD_LOGS_INJECTION=true

WORKDIR /var/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends procps wget gcc libpcre3-dev git libffi-dev libssl-dev vim \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip install uwsgi

COPY . /var/app

# install Python dependencies, make entrypoint executable
RUN pip3 install --upgrade pip \
    && pip3 install pipenv \
    && pipenv sync \
    && pip3 install uwsgitop \
    && rm -r /root/.cache \
    && chmod +x ./deploy/docker-cmd.sh

ENV UWSGI_HTTP_SOCKET ":80"

CMD ["deploy/docker-cmd.sh"]