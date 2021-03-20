# opa-envoy-amqp-plugin

* opa-envoy-amqp extends OPA with a gRPC server that implements the Envoy External Authorization API and AMQP consumer to receive new policy to self-updated.
* the implementation of opa-envoy reference [opa-envoy-plugin](https://github.com/open-policy-agent/opa-envoy-plugin)

## how to run
### local
1. `make build`
2. cd build/bin && ./opa-envoy-amqp run --server --config-file config.yaml --addr=localhost:8181

### docker
first change $IMAGE_NAME and $REPOSITORY variable to yours
1. `make image`
