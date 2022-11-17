FROM tiangolo/uwsgi-nginx-flask:python3.6

RUN pip3 install redis
RUN pip3 install flask-session

RUN apt update
RUN apt -y install redis-server

COPY ./redis.conf /usr/local/etc/redis/redis.conf
COPY ./client.py /usr/local/lib/python3.6/http/client.py