# GenAI Module Prototype

Standalone prototype demonstrating the GenAI module architecture for ProxySQL.

## Architecture Overview

This prototype demonstrates a thread-pool based GenAI module that:

1. **Receives requests** from multiple clients (MySQL/PgSQL threads) via socket pairs
2. **Queues requests** internally with a fixed-size worker thread pool
3. **Processes requests asynchronously** without blocking the clients
4. **Returns responses** to clients via the same socket connections

### Components

```
┌─────────────────────────────────────────────────────────┐
│                   GenAI Module                          │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  Listener Thread (epoll-based)                 │    │
│  │  - Monitors all client file descriptors        │    │
│  │  - Reads incoming requests                     │    │
│  │  - Pushes to request queue                     │    │
│  └──────────────────┬─────────────────────────────┘    │
│                     │                                  │
│                     ▼                                  │
│  ┌────────────────────────────────────────────────┐    │
│  │  Request Queue                                 │    │
│  │  - Thread-safe queue                           │    │
│  │  - Condition variable for worker notification  │    │
│  └──────────────────┬─────────────────────────────┘    │
│                     │                                  │
│                     ▼                                  │
│  ┌────────────────────────────────────────────────┐    │
│  │  Thread Pool (configurable number of workers)  │    │
│  │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐      │    │
│  │  │Worker│  │Worker│  │Worker│  │Worker│  ...  │    │
│  │  └───┬──┘  └───┬──┘  └───┬──┘  └───┬──┘        │    │
│  │      └──────────┴──────────┴──────────┘         │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
         ▲                    │                    ▲
         │                    │                    │
    socketpair()         Responses           socketpair()
    from clients          to clients          from clients
```

### Communication Protocol

**Client → GenAI (Request)**:
```cpp
struct RequestHeader {
    uint64_t request_id;     // Client's correlation ID
    uint32_t operation;      // 0=embedding, 1=completion, 2=rag
    uint32_t input_size;     // Size of following data
    uint32_t flags;          // Reserved
};
// Followed by input_size bytes of input data
```

**GenAI → Client (Response)**:
```cpp
struct ResponseHeader {
    uint64_t request_id;     // Echo client's ID
    uint32_t status_code;    // 0=success, >0=error
    uint32_t output_size;    // Size of following data
    uint32_t processing_time_ms;  // Time taken to process
};
// Followed by output_size bytes of output data
```

## Building and Running

```bash
# Build
make

# Run
make run

# Clean
make clean

# Debug build
make debug

# Show help
make help
```

## Current Status

**Implemented:**
- ✅ Thread pool with configurable workers
- ✅ epoll-based listener thread
- ✅ Thread-safe request queue
- ✅ socketpair communication
- ✅ Multiple concurrent clients
- ✅ Non-blocking async operation
- ✅ Simulated processing (random sleep)

**TODO (Enhancement Phase):**
- ⬜ Real LLM API integration (OpenAI, local models)
- ⬜ Request batching for efficiency
- ⬜ Priority queue for urgent requests
- ⬜ Timeout and cancellation
- ⬜ Backpressure handling (queue limits)
- ⬜ Metrics and monitoring
- ⬜ Error handling and retry logic
- ⬜ Configuration file support
- ⬜ Unit tests
- ⬜ Performance benchmarking

## Integration Plan

Phase 1: **Prototype Enhancement** (Current)
- Complete TODO items above
- Test with real LLM APIs
- Performance testing

Phase 2: **ProxySQL Integration**
- Integrate into ProxySQL build system
- Add to existing MySQL/PgSQL thread logic
- Implement GenAI variable system

Phase 3: **Production Features**
- Connection pooling
- Request multiplexing
- Caching layer
- Fallback strategies

## Design Principles

1. **Zero Coupling**: GenAI module doesn't know about client types
2. **Non-Blocking**: Clients never wait on GenAI responses
3. **Scalable**: Fixed resource usage (bounded thread pool)
4. **Observable**: Easy to monitor and debug
5. **Testable**: Standalone, independent testing
