package kafkatypes

// General Configuration (Client, Network, Metadata)
const (
	// BootstrapServers: Initial list of brokers as a CSV list of broker host or host:port.
	// The application may also use rd_kafka_brokers_add() to add brokers during runtime.
	BootstrapServers = "bootstrap.servers"

	// ClientId: Client identifier.
	ClientId = "client.id"

	// MessageMaxBytes: Maximum Kafka protocol request message size.
	MessageMaxBytes = "message.max.bytes"

	// ReceiveMessageMaxBytes: Maximum Kafka protocol response message size.
	// This serves as a safety precaution to avoid memory exhaustion in case of protocol hickups.
	ReceiveMessageMaxBytes = "receive.message.max.bytes"

	// MetadataBrokerList: Alias for bootstrap.servers.
	MetadataBrokerList = "metadata.broker.list"

	// Debug: A comma-separated list of debug contexts to enable.
	// Detailed Producer debugging: broker,topic,msg. Consumer: consumer,cgrp,topic,fetch.
	Debug = "debug"

	// SocketTimeoutMs: Default timeout for network requests.
	SocketTimeoutMs = "socket.timeout.ms"

	// SocketKeepaliveEnable: Enable TCP keep-alives (SO_KEEPALIVE) on broker sockets.
	SocketKeepaliveEnable = "socket.keepalive.enable"

	// LogConnectionClose: Log broker disconnects.
	LogConnectionClose = "log.connection.close"

	// BuiltinFeatures: Indicates the builtin features for this build of librdkafka.
	BuiltinFeatures = "builtin.features"

	// MetadataMaxAgeMs: Metadata cache max age. Defaults to topic.metadata.refresh.interval.ms * 3.
	MetadataMaxAgeMs = "metadata.max.age.ms"

	// StatisticsIntervalMs: librdkafka statistics emit interval.
	// The application also needs to register a stats callback using rd_kafka_conf_set_stats_cb().
	StatisticsIntervalMs = "statistics.interval.ms"
)

// Security Configuration (SSL & SASL)
const (
	// SecurityProtocol: Protocol used to communicate with brokers.
	// Values: plaintext, ssl, sasl_plaintext, sasl_ssl.
	SecurityProtocol = "security.protocol"

	// SslCipherSuites: A cipher suite is a named combination of authentication, encryption,
	// MAC and key exchange algorithm used to negotiate the security settings.
	SslCipherSuites = "ssl.cipher.suites"

	// SslKeyLocation: Path to client's private key (PEM) used for authentication.
	SslKeyLocation = "ssl.key.location"

	// SslKeyPassword: Private key passphrase (for use with ssl.key.location and set_ssl_cert()).
	SslKeyPassword = "ssl.key.password"

	// SslCertificateLocation: Path to client's public key (PEM) used for authentication.
	SslCertificateLocation = "ssl.certificate.location"

	// SslCaLocation: File or directory path to CA certificate(s) for verifying the broker's key.
	SslCaLocation = "ssl.ca.location"

	// EnableSslCertificateVerification: Enable OpenSSL's builtin broker (server) certificate verification.
	EnableSslCertificateVerification = "enable.ssl.certificate.verification"

	// SslEndpointIdentificationAlgorithm: Endpoint identification algorithm to validate broker hostname using broker certificate.
	// Values: https (RFC2818) or none.
	SslEndpointIdentificationAlgorithm = "ssl.endpoint.identification.algorithm"

	// SaslMechanisms: SASL mechanism to use for authentication.
	// Supported: GSSAPI, PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, OAUTHBEARER.
	SaslMechanisms = "sasl.mechanisms"

	// SaslMechanism: Alias for sasl.mechanisms.
	SaslMechanism = "sasl.mechanism"

	// SaslUsername: SASL username for use with the PLAIN and SASL-SCRAM-.. mechanisms.
	SaslUsername = "sasl.username"

	// SaslPassword: SASL password for use with the PLAIN and SASL-SCRAM-.. mechanism.
	SaslPassword = "sasl.password"

	// SaslKerberosServiceName: Kerberos principal name that Kafka runs as, not including /hostname@REALM.
	SaslKerberosServiceName = "sasl.kerberos.service.name"

	// SaslKerberosPrincipal: This client's Kerberos principal name.
	SaslKerberosPrincipal = "sasl.kerberos.principal"

	// SaslKerberosKeytab: Path to Kerberos keytab file.
	SaslKerberosKeytab = "sasl.kerberos.keytab"

	// SaslOauthbearerConfig: SASL/OAUTHBEARER configuration.
	SaslOauthbearerConfig = "sasl.oauthbearer.config"

	// SaslOauthbearerMethod: Set to "default" or "oidc" to control which login method to be used.
	SaslOauthbearerMethod = "sasl.oauthbearer.method"

	// SaslOauthbearerClientId: Public identifier for the application. Only used when method is "oidc".
	SaslOauthbearerClientId = "sasl.oauthbearer.client.id"

	// SaslOauthbearerClientSecret: Client secret only known to the application and the authorization server.
	SaslOauthbearerClientSecret = "sasl.oauthbearer.client.secret"

	// SaslOauthbearerTokenEndpointUrl: OAuth/OIDC issuer token endpoint HTTP(S) URI used to retrieve token.
	SaslOauthbearerTokenEndpointUrl = "sasl.oauthbearer.token.endpoint.url"
)

// Consumer Configuration
const (
	// GroupId: Client group id string. All clients sharing the same group.id belong to the same group.
	GroupId = "group.id"

	// GroupInstanceId: Enable static group membership.
	// Static group members are able to leave and rejoin a group within the configured session.timeout.ms without prompting a group rebalance.
	GroupInstanceId = "group.instance.id"

	// PartitionAssignmentStrategy: The name of one or more partition assignment strategies.
	// Available strategies: range, roundrobin, cooperative-sticky.
	PartitionAssignmentStrategy = "partition.assignment.strategy"

	// SessionTimeoutMs: Client group session and failure detection timeout.
	SessionTimeoutMs = "session.timeout.ms"

	// HeartbeatIntervalMs: Group session keepalive heartbeat interval.
	HeartbeatIntervalMs = "heartbeat.interval.ms"

	// GroupProtocol: Group protocol to use. Use "classic" or "consumer".
	GroupProtocol = "group.protocol"

	// MaxPollIntervalMs: Maximum allowed time between calls to consume messages (e.g., rd_kafka_consumer_poll()).
	// If this interval is exceeded the consumer is considered failed and the group will rebalance.
	MaxPollIntervalMs = "max.poll.interval.ms"

	// EnableAutoCommit: Automatically and periodically commit offsets in the background.
	EnableAutoCommit = "enable.auto.commit"

	// AutoCommitIntervalMs: The frequency in milliseconds that the consumer offsets are committed (written) to offset storage.
	AutoCommitIntervalMs = "auto.commit.interval.ms"

	// EnableAutoOffsetStore: Automatically store offset of last message provided to application.
	EnableAutoOffsetStore = "enable.auto.offset.store"

	// QueuedMinMessages: Minimum number of messages per topic+partition librdkafka tries to maintain in the local consumer queue.
	QueuedMinMessages = "queued.min.messages"

	// QueuedMaxMessagesKbytes: Maximum number of kilobytes of queued pre-fetched messages in the local consumer queue.
	QueuedMaxMessagesKbytes = "queued.max.messages.kbytes"

	// FetchWaitMaxMs: Maximum time the broker may wait to fill the Fetch response with fetch.min.bytes of messages.
	FetchWaitMaxMs = "fetch.wait.max.ms"

	// FetchMinBytes: Minimum number of bytes the broker responds with.
	FetchMinBytes = "fetch.min.bytes"

	// FetchMaxBytes: Maximum amount of data the broker shall return for a Fetch request.
	FetchMaxBytes = "fetch.max.bytes"

	// IsolationLevel: Controls how to read messages written transactionally.
	// Values: read_committed, read_uncommitted.
	IsolationLevel = "isolation.level"

	// CheckCrcs: Verify CRC32 of consumed messages, ensuring no on-the-wire or on-disk corruption to the messages occurred.
	CheckCrcs = "check.crcs"

	// AutoOffsetReset: Action to take when there is no initial offset in offset store or the desired offset is out of range.
	// Values: smallest, earliest, beginning, largest, latest, end, error.
	AutoOffsetReset = "auto.offset.reset"
)

// Producer Configuration
const (
	// TransactionalId: Enables the transactional producer. Identifies the same transactional producer instance across process restarts.
	TransactionalId = "transactional.id"

	// TransactionTimeoutMs: The maximum amount of time in milliseconds that the transaction coordinator will wait for a transaction status update.
	TransactionTimeoutMs = "transaction.timeout.ms"

	// EnableIdempotence: When set to true, the producer will ensure that messages are successfully produced exactly once and in the original produce order.
	EnableIdempotence = "enable.idempotence"

	// QueueBufferingMaxMessages: Maximum number of messages allowed on the producer queue.
	QueueBufferingMaxMessages = "queue.buffering.max.messages"

	// QueueBufferingMaxKbytes: Maximum total message size sum allowed on the producer queue.
	QueueBufferingMaxKbytes = "queue.buffering.max.kbytes"

	// QueueBufferingMaxMs: Delay in milliseconds to wait for messages in the producer queue to accumulate before constructing message batches.
	QueueBufferingMaxMs = "queue.buffering.max.ms"

	// LingerMs: Alias for queue.buffering.max.ms.
	LingerMs = "linger.ms"

	// MessageSendMaxRetries: How many times to retry sending a failing Message.
	MessageSendMaxRetries = "message.send.max.retries"

	// Retries: Alias for message.send.max.retries.
	Retries = "retries"

	// RetryBackoffMs: The backoff time in milliseconds before retrying a protocol request.
	RetryBackoffMs = "retry.backoff.ms"

	// CompressionCodec: Compression codec to use for compressing message sets.
	// Values: none, gzip, snappy, lz4, zstd.
	CompressionCodec = "compression.codec"

	// CompressionType: Alias for compression.codec.
	CompressionType = "compression.type"

	// BatchNumMessages: Maximum number of messages batched in one MessageSet.
	BatchNumMessages = "batch.num.messages"

	// BatchSize: Maximum size (in bytes) of all messages batched in one MessageSet, including protocol framing overhead.
	BatchSize = "batch.size"

	// StickyPartitioningLingerMs: Delay in milliseconds to wait to assign new sticky partitions for each topic.
	StickyPartitioningLingerMs = "sticky.partitioning.linger.ms"

	// DeliveryTimeoutMs: Local message timeout. This value is only enforced locally and limits the time a produced message waits for successful delivery.
	DeliveryTimeoutMs = "delivery.timeout.ms"

	// RequestRequiredAcks: This field indicates the number of acknowledgements the leader broker must receive from ISR brokers before responding to the request.
	// Values: 0 (no ack), -1 or all (wait for all ISRs), 1 (wait for leader only).
	RequestRequiredAcks = "request.required.acks"

	// Acks: Alias for request.required.acks.
	Acks = "acks"

	// Partitioner: Partitioner strategy.
	// Values: random, consistent, consistent_random, murmur2, murmur2_random, fnv1a, fnv1a_random.
	Partitioner = "partitioner"
)
