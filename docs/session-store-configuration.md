# Session Store Configuration

Oathkeeper supports configurable session storage backends to store user session data. By default, it uses an in-memory store, but you can configure it to use Redis for persistent, distributed session storage.

## Configuration Options

### In-Memory Store (Default)

If no `session_store` configuration is provided, Oathkeeper will use the default in-memory session store:

```yaml
# No session_store configuration needed - defaults to memory
```

Or explicitly configure it:

```yaml
session_store:
  type: memory
```

### Redis Store

To use Redis as the session store backend:

```yaml
session_store:
  type: redis
  redis:
    addr: "127.0.0.1:6379"           # Redis server address
    password: "your-password"         # Optional: Redis password
    db: 0                            # Redis database number (0-15)
    session_prefix: "session:"       # Prefix for session keys
    state_prefix: "state:"           # Prefix for state keys (CSRF)
    ttl: "24h"                       # Time to live for session data
```

## Configuration Parameters

### `session_store.type`
- **Type**: `string`
- **Values**: `memory`, `redis`
- **Default**: `memory`
- **Description**: The type of session store to use.

### `session_store.redis.addr`
- **Type**: `string`
- **Required**: Yes (when using Redis)
- **Example**: `"127.0.0.1:6379"`, `"redis.example.com:6379"`
- **Description**: Redis server address in the format `host:port`.

### `session_store.redis.password`
- **Type**: `string`
- **Required**: No
- **Description**: Password for Redis authentication. Leave empty if no authentication is required.

### `session_store.redis.db`
- **Type**: `integer`
- **Default**: `0`
- **Range**: `0-15`
- **Description**: Redis database number to use.

### `session_store.redis.session_prefix`
- **Type**: `string`
- **Default**: `"session:"`
- **Description**: Prefix for session keys in Redis.

### `session_store.redis.state_prefix`
- **Type**: `string`
- **Default**: `"state:"`
- **Description**: Prefix for state keys in Redis (used for CSRF protection).

### `session_store.redis.ttl`
- **Type**: `string`
- **Default**: `"24h"`
- **Pattern**: `^[0-9]+(ns|us|ms|s|m|h)$`
- **Examples**: `"1h"`, `"30m"`, `"7d"`
- **Description**: Default TTL for session data in Redis.

## Examples

### Basic Redis Configuration

```yaml
session_store:
  type: redis
  redis:
    addr: "localhost:6379"
    ttl: "1h"
```

### Redis with Authentication

```yaml
session_store:
  type: redis
  redis:
    addr: "redis.example.com:6379"
    password: "secure-password"
    db: 1
    session_prefix: "myapp:session:"
    state_prefix: "myapp:state:"
    ttl: "8h"
```

### Production Redis Configuration

```yaml
session_store:
  type: redis
  redis:
    addr: "redis-cluster.internal:6379"
    password: "${REDIS_PASSWORD}"  # Use environment variable
    db: 0
    session_prefix: "oathkeeper:prod:session:"
    state_prefix: "oathkeeper:prod:state:"
    ttl: "24h"
```

## Benefits of Redis Session Store

1. **Persistence**: Sessions survive application restarts
2. **Scalability**: Multiple Oathkeeper instances can share session data
3. **Performance**: Redis provides fast access to session data
4. **Automatic Cleanup**: Redis handles TTL-based expiration automatically
5. **Monitoring**: Redis provides built-in monitoring and metrics

## Migration from In-Memory to Redis

To migrate from in-memory to Redis session storage:

1. Set up a Redis instance
2. Update your Oathkeeper configuration to include the `session_store` section
3. Restart Oathkeeper
4. Existing in-memory sessions will be lost (users will need to re-authenticate)

## Troubleshooting

### Connection Issues
- Verify Redis server is running and accessible
- Check network connectivity and firewall rules
- Validate Redis address and port

### Authentication Issues
- Ensure the password is correct
- Check if Redis requires authentication

### Performance Issues
- Monitor Redis memory usage
- Consider adjusting TTL values
- Use Redis monitoring tools to identify bottlenecks
