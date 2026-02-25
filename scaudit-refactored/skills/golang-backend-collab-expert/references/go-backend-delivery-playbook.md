# Go Backend Delivery Playbook

## Table of Contents

1. Architecture Baseline
2. Framework and Transport Selection
3. Data Access and Persistence
4. Reliability and Performance
5. Security and Compliance Baseline
6. Delivery Checklist

## 1. Architecture Baseline

- Use layered boundaries: handler -> service -> repository -> external clients.
- Keep domain rules in service layer; avoid embedding business logic in transport handlers.
- Keep DTOs and persistence models separate when contract evolution risk is high.
- Pass `context.Context` through every IO boundary.

## 2. Framework and Transport Selection

- Choose `net/http` + `chi` for lightweight REST services and explicit routing.
- Choose `gin` when delivery speed and middleware ecosystem matter more than minimalism.
- Choose `grpc` for internal service-to-service contracts with strong schema governance.
- Choose async events (Kafka/RabbitMQ/Redis Streams) for decoupled workflows and eventual consistency.

## 3. Data Access and Persistence

- Prefer `sqlc` for type-safe SQL and predictable performance on relational workloads.
- Use `gorm` when schema churn is high and query complexity is moderate.
- Add repository interfaces only when multiple implementations or high test isolation are needed.
- Define migration strategy before coding: forward migration, rollback path, and data backfill plan.

## 4. Reliability and Performance

- Define timeout budget per dependency and enforce with context deadlines.
- Apply idempotency keys on write APIs that can be retried.
- Add circuit breaker and retry policy for flaky downstreams; avoid unbounded retries.
- Use connection pooling and prepared statements for high-QPS database paths.
- Add cache only after identifying hot paths and invalidation strategy.

## 5. Security and Compliance Baseline

- Enforce authn/authz on every protected route; never trust frontend claims directly.
- Validate and sanitize all external input; reject overlong payloads early.
- Protect secrets via environment or secret manager; never hardcode credentials.
- Implement structured audit logs for sensitive operations.
- Apply rate limiting and abuse controls on public endpoints.

## 6. Delivery Checklist

- Freeze API contract with request/response examples and error codes.
- Cover unit tests for domain rules and integration tests for persistence and transport.
- Expose metrics and tracing for latency, error rate, and saturation.
- Define rollout plan: canary/batch release, SLO watch window, rollback trigger.
- Publish release notes with known limitations and follow-up actions.
