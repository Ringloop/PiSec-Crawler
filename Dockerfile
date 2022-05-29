#build
FROM golang:1.16-alpine as builder
COPY ./ /pisec
WORKDIR /pisec
RUN CGO_ENABLED=0 GOOS=linux go build -a -o crawler .

#end user image
FROM alpine:3.11.3
COPY --from=builder pisec/crawler .
COPY --from=builder pisec/pisec-crawler.sh .
CMD ["sh", "./pisec-crawler.sh"]
