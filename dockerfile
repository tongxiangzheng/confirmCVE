FROM ubuntu:22.04

WORKDIR /app

COPY requirements.txt /app

RUN apt update
RUN apt install -y python3 python3-pip
RUN apt install -y libarchive-dev
RUN ln -s /usr/lib/x86_64-linux-gnu/libarchive.a /usr/lib/x86_64-linux-gnu/liblibarchive.a
RUN pip3 install -r requirements.txt


#COPY data /app/data
VOLUME /app/data
COPY src/ /app/src/

CMD  ["python3","/app/src/frontEnd/server.py"]