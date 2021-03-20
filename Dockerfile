FROM gcr.io/distroless/cc

WORKDIR /app

COPY build/bin/opa-envoy-amqp /app

ENTRYPOINT ["./opa-envoy-amqp"]

CMD ["run"]
