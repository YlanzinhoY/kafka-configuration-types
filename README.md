# Kafka Config Keys for Go (confluent-kafka-go helper)

A tiny helper library that centralizes **all configuration keys** for Apache Kafka producers and consumers when using the official [confluent-kafka-go](https://github.com/confluentinc/confluent-kafka-go) SDK.

The goal is simple:

> Stop remembering and re-typing raw strings like `"bootstrap.servers"` or `"enable.idempotence"` everywhere, and use **type-safe, discoverable constants** instead.

---


install 

```bash
go get github.com/ylanzinhoy/kafka-configuration-types/kafkatypes
```

## Why?

By default, configuring Kafka with `confluent-kafka-go` looks like this:


before
```go

import(
    "github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

config := &kafka.ConfigMap{
    "bootstrap.servers": "localhost:9092",
    "client.id":         "my-app",
    "enable.idempotence": true,
}
```

after 

```go
import(
    "github.com/confluentinc/confluent-kafka-go/v2/kafka"
    "github.com/ylanzinhoy/kafka-configuration-types/kafkatypes"
)

config := &kafka.ConfigMap{
    kafkatypes.BootstrapServers: "localhost:9092",
    kafkatypes.ClientId:         "my-app",
    kafkatypes.EnableIdempotence: true,
}
```

## Maintenance

It's perfectly ready for production use; I'll just improve the documentation of what each command does for people who don't have experience with Kafka to use.

The repository will remain active until the Confluence team, which manages the SDK, approves my PR, which already adds what this library does natively within the SDK.