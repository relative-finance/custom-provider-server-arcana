# Bulid environment
FROM golang:1.23-alpine

WORKDIR /app

RUN apk update && apk add gcc

RUN apk add --no-cache build-base git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o app .

CMD ["go", "run", "."]