FROM golang

COPY . /app
WORKDIR /app/cmd/runprog
RUN apt update && apt install -y gcc libstdc++6 libseccomp-dev

RUN go build 
