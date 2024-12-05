FROM golang

COPY . /app
WORKDIR /app/cmd/runprog

RUN go build 
