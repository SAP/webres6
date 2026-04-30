# Testing Webres6 API

This directory contains unit tests for the webres6-api server.

## Test Files

- `test_webres6_api.py` - Tests for API endpoints and main functionality
- `test_webres6_storage.py` - Tests for storage manager implementations

## Setup

Install test dependencies:

```bash
pip install -r requirements-test.txt
```

Or if you want to install just the testing packages:

```bash
pip install pytest pytest-cov pytest-mock responses freezegun
```

## Running Tests

### Run all tests with unittest

```bash
cd api
python test_webres6_api.py
python test_webres6_storage.py
```

### Run all tests with pytest

```bash
cd api
pytest -v
```

### Run with coverage

```bash
cd api
pytest --cov=webres6_api --cov=webres6_storage --cov-report=html
```

This will generate a coverage report in `htmlcov/index.html`.

### Run specific test class or method

```bash
# Run specific test file
pytest test_webres6_api.py -v

# Run specific test class
pytest test_webres6_api.py::TestWebres6APIEndpoints -v

# Run specific test method
pytest test_webres6_api.py::TestWebres6APIEndpoints::test_ping_endpoint -v
```

## Test Coverage

The tests cover:

### API Endpoints (`test_webres6_api.py`)
- ✅ `/ping` and `/res6/ping` - Liveness probes
- ✅ `/healthz` - Readiness probe with backend health checks
- ✅ `/res6/serverconfig` - Server configuration endpoint
- ✅ `/res6/$metadata` - OData metadata
- ✅ `/res6/url(URL)` - URL analysis endpoint validation
- ✅ `/res6/report/ID` - Report retrieval validation
- ✅ `/metrics` - Prometheus metrics with authorization

### Health Check Functions
- ✅ Component health checking (storage, DNS, Selenium)
- ✅ Error handling for degraded services
- ✅ Extension health check integration

### Report Generation
- ✅ Report ID generation (deterministic and unique)
- ✅ JSON report structure
- ✅ Error report generation
- ✅ IPv6-only scoring logic
  - Empty hosts
  - IPv6-only hosts
  - Mixed IPv4/IPv6 hosts
  - NAT64 address handling

### Authorization
- ✅ API key validation
- ✅ No key configured (open access)
- ✅ Invalid key rejection

### Helper Functions
- ✅ Hostname splitting (subdomain extraction)

### Storage Managers (`test_webres6_storage.py`)
- ✅ `LocalStorageManager`
  - Health checks
  - WHOIS cache operations and expiry
  - Result cache operations and expiry
  - Report archiving and retrieval
  - Scoreboard operations
  - Persistence and loading
  - Cache expiry cleanup

- ✅ `ValkeyStorageManager`
  - Health checks (ping validation)
  - WHOIS cache operations
  - Report archiving

- ✅ `ValkeyFileHybridStorageManager`
  - Combined health checks for both backends
  - Failure scenarios

- ✅ `ValkeyS3HybridStorageManager`
  - S3 bucket accessibility checks
  - S3 archiving operations
  - Combined health validation

- ✅ `Scoreboard`
  - Entry creation
  - Error report filtering
  - Entry retrieval

## Mocking Strategy

The tests use mocks for external dependencies:

1. **Selenium WebDriver** - Mocked to avoid requiring a running Selenium Grid
2. **DNSProbe API** - Mocked HTTP requests
3. **Valkey/Redis** - Mocked client connections
4. **S3/Boto3** - Mocked S3 client operations

This allows tests to run quickly without external service dependencies.

## Notes

- Tests assume dnsprobe and selenium services would be available in production
- Storage tests use temporary directories that are cleaned up automatically
- Valkey and S3 tests use mocked clients to avoid requiring actual services
- Tests can be run in CI/CD pipelines without external dependencies

## CI/CD Integration

Add to your CI pipeline:

```yaml
# Example GitHub Actions
- name: Install dependencies
  run: pip install -r api/requirements-test.txt

- name: Run tests
  run: |
    cd api
    pytest --cov --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
```

## Future Improvements

Potential areas to expand test coverage:

- [ ] Integration tests with real Selenium Grid
- [ ] Integration tests with real DNSProbe service
- [ ] Integration tests with real Valkey/Redis instance
- [ ] Performance/load testing
- [ ] End-to-end tests for complete URL analysis workflow
- [ ] Extension module testing
- [ ] WHOIS lookup testing
