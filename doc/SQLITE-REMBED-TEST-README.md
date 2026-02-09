# sqlite-rembed Integration Test Suite

## Overview

This test suite comprehensively validates the integration of `sqlite-rembed` (Rust SQLite extension for text embedding generation) into ProxySQL. The tests verify the complete AI pipeline from client registration to embedding generation and vector similarity search.

## Prerequisites

### System Requirements
- **ProxySQL** compiled with `sqlite-rembed` and `sqlite-vec` extensions
- **MySQL client** (`mysql` command line tool)
- **Bash** shell environment
- **Network access** to embedding API endpoint (or local Ollama/OpenAI API)

### ProxySQL Configuration
Ensure ProxySQL is running with SQLite3 server enabled:
```bash
cd /home/rene/proxysql-vec/src
./proxysql --sqlite3-server
```

### Test Configuration
The test script uses default connection parameters:
- Host: `127.0.0.1`
- Port: `6030` (default SQLite3 server port)
- User: `root`
- Password: `root`

Modify these in the script if your configuration differs.

## Test Suite Structure

The test suite is organized into 9 phases, each testing specific components:

### Phase 1: Basic Connectivity and Function Verification
- ✅ ProxySQL connection
- ✅ Database listing
- ✅ `sqlite-vec` function availability
- ✅ `sqlite-rembed` function registration
- ✅ `temp.rembed_clients` virtual table existence

### Phase 2: Client Configuration
- ✅ Create embedding API client with `rembed_client_options()`
- ✅ Verify client registration in `temp.rembed_clients`
- ✅ Test `rembed_client_options` function

### Phase 3: Embedding Generation Tests
- ✅ Generate embeddings for short and long text
- ✅ Verify embedding data type (BLOB) and size (768 dimensions × 4 bytes)
- ✅ Error handling for non-existent clients

### Phase 4: Table Creation and Data Storage
- ✅ Create regular table for document storage
- ✅ Create virtual vector table using `vec0`
- ✅ Insert test documents with diverse content

### Phase 5: Embedding Generation and Storage
- ✅ Generate embeddings for all documents
- ✅ Store embeddings in vector table
- ✅ Verify embedding count matches document count
- ✅ Check embedding storage format

### Phase 6: Similarity Search Tests
- ✅ Exact self-match (document with itself, distance = 0.0)
- ✅ Similarity search with query text
- ✅ Verify result ordering by ascending distance

### Phase 7: Edge Cases and Error Handling
- ✅ Empty text input
- ✅ Very long text input
- ✅ SQL injection attempt safety

### Phase 8: Performance and Concurrency
- ✅ Sequential embedding generation timing
- ✅ Basic performance validation (< 10 seconds for 3 embeddings)

### Phase 9: Cleanup and Final Verification
- ✅ Clean up test tables
- ✅ Verify no test artifacts remain

## Usage

### Running the Full Test Suite
```bash
cd /home/rene/proxysql-vec/doc
./sqlite-rembed-test.sh
```

### Expected Output
The script provides color-coded output:
- 🟢 **Green**: Test passed
- 🔴 **Red**: Test failed
- 🔵 **Blue**: Information and headers
- 🟡 **Yellow**: Test being executed

### Exit Codes
- `0`: All tests passed
- `1`: One or more tests failed
- `2`: Connection issues or missing dependencies

## Configuration

### Modifying Connection Parameters
Edit the following variables in `sqlite-rembed-test.sh`:
```bash
PROXYSQL_HOST="127.0.0.1"
PROXYSQL_PORT="6030"
MYSQL_USER="root"
MYSQL_PASS="root"
```

### API Configuration
The test uses a synthetic OpenAI endpoint by default. Set `API_KEY` environment variable or modify the variable below to use your own API:
```bash
API_CLIENT_NAME="test-client-$(date +%s)"
API_FORMAT="openai"
API_URL="https://api.synthetic.new/openai/v1/embeddings"
API_KEY="${API_KEY:-YOUR_API_KEY}"  # Uses environment variable or placeholder
API_MODEL="hf:nomic-ai/nomic-embed-text-v1.5"
VECTOR_DIMENSIONS=768
```

For other providers (Ollama, Cohere, Nomic), adjust the format and URL accordingly.

## Test Data

### Sample Documents
The test creates 4 sample documents:
1. **Machine Learning** - "Machine learning algorithms improve with more training data..."
2. **Database Systems** - "Database management systems efficiently store, retrieve..."
3. **Artificial Intelligence** - "AI enables computers to perform tasks typically..."
4. **Vector Databases** - "Vector databases enable similarity search for embeddings..."

### Query Texts
Test searches use:
- Self-match: Document 1 with itself
- Query: "data science and algorithms"

## Troubleshooting

### Common Issues

#### 1. Connection Failed
```
Error: Cannot connect to ProxySQL at 127.0.0.1:6030
```
**Solution**: Ensure ProxySQL is running with `--sqlite3-server` flag.

#### 2. Missing Functions
```
ERROR 1045 (28000): no such function: rembed
```
**Solution**: Verify `sqlite-rembed` was compiled and linked into ProxySQL binary.

#### 3. API Errors
```
Error from embedding API
```
**Solution**: Check network connectivity and API credentials.

#### 4. Vector Table Errors
```
ERROR 1045 (28000): A LIMIT or 'k = ?' constraint is required on vec0 knn queries.
```
**Solution**: All `sqlite-vec` similarity queries require `LIMIT` clause.

### Debug Mode
For detailed debugging, run with trace:
```bash
bash -x ./sqlite-rembed-test.sh
```

## Integration with CI/CD

The test script can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
name: sqlite-rembed Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build ProxySQL with sqlite-rembed
        run: |
          cd deps && make cleanpart && make sqlite3
          cd ../lib && make
          cd ../src && make
      - name: Start ProxySQL
        run: |
          cd src && ./proxysql --sqlite3-server &
          sleep 5
      - name: Run Integration Tests
        run: |
          cd doc && ./sqlite-rembed-test.sh
```

## Extending the Test Suite

### Adding New Tests
1. Add new test function following existing pattern
2. Update phase header and test count
3. Add to appropriate phase section

### Testing Different Providers
Modify the API configuration block to test:
- **Ollama**: Use `format='ollama'` and local URL
- **Cohere**: Use `format='cohere'` and appropriate model
- **Nomic**: Use `format='nomic'` and Nomic API endpoint

### Performance Testing
Extend Phase 8 for:
- Concurrent embedding generation
- Batch processing tests
- Memory usage monitoring

## Results Interpretation

### Success Criteria
- All connectivity tests pass
- Embeddings generated with correct dimensions
- Vector search returns ordered results
- No test artifacts remain after cleanup

### Performance Benchmarks
- Embedding generation: < 3 seconds per request (network-dependent)
- Similarity search: < 100ms for small datasets
- Memory: Stable during sequential operations

## References

- [sqlite-rembed GitHub](https://github.com/asg017/sqlite-rembed)
- [sqlite-vec Documentation](./SQLite3-Server.md)
- [ProxySQL SQLite3 Server](./SQLite3-Server.md)
- [Integration Documentation](./sqlite-rembed-integration.md)

## License

This test suite is part of the ProxySQL project and follows the same licensing terms.

---
*Last Updated: $(date)*
*Test Suite Version: 1.0*