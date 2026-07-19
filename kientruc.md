# LOGICLAB

> **Trạng thái tài liệu:** đây là blueprint đích, không phải danh sách tính năng đã
> triển khai. Kiến trúc đang chạy của Universal static v1 được mô tả tại
> [`ARCHITECTURE.md`](ARCHITECTURE.md); các runner/microVM và semantic agents trong
> tài liệu này vẫn là roadmap trừ khi được ghi rõ khác.

## Nền tảng đa tác tử tự động săn và kiểm chứng lỗi logic bảo mật trong mã nguồn

**Phiên bản tài liệu:** 1.0
**Loại tài liệu:** Product Proposal & Technical Blueprint
**Định hướng ban đầu:** Java/Spring Boot
**Mô hình triển khai:** Local-first, open-source stack, managed research trước, enterprise platform sau

---

# 1. Tóm tắt điều hành

LogicLab là một nền tảng nghiên cứu lỗ hổng bảo mật tự động, nhận đầu vào là một repository mã nguồn và thực hiện toàn bộ quy trình:

1. Phân tích cấu trúc dự án.
2. Dựng môi trường chạy có thể tái lập.
3. Tạo người dùng, vai trò, tenant và dữ liệu nghiệp vụ thử nghiệm.
4. Mô hình hóa entry point, resource, business operation và state transition.
5. Suy luận các invariant bảo mật từ source code, test, tài liệu và lịch sử Git.
6. Tạo giả thuyết về các lỗi logic.
7. Sinh và chạy các thí nghiệm nhiều actor trong sandbox.
8. Quan sát HTTP, database, event, log và các side effect.
9. Kiểm chứng finding bằng một agent độc lập.
10. Sinh regression test và đánh giá tính đầy đủ của bản vá.

LogicLab không chỉ đưa ra cảnh báo dựa trên suy đoán của mô hình ngôn ngữ. Một finding chỉ được xác nhận khi có:

* Đường vào thực tế.
* Điều kiện tiền đề rõ ràng.
* Chuỗi thao tác có thể chạy lại.
* Bằng chứng runtime.
* Trạng thái hệ thống trước và sau.
* Invariant bị vi phạm.
* Kết quả kiểm chứng độc lập.
* Regression test có thể tích hợp vào repository.

Tầm nhìn dài hạn của LogicLab là:

> Biến mỗi codebase nghiệp vụ thành một phòng lab bảo mật tự động, trong đó các quy tắc bảo mật ngầm được chuyển thành thí nghiệm có thể thực thi và chạy lại sau mỗi thay đổi mã nguồn.

---

# 2. Vấn đề cần giải quyết

Các công cụ SAST truyền thống thường phát hiện tốt:

* SQL injection.
* Command injection.
* Unsafe deserialization.
* Secret bị hard-code.
* API nguy hiểm.
* Data flow từ source tới sink.

Tuy nhiên, chúng thường gặp khó khăn với các lỗi chỉ xuất hiện khi kết hợp nhiều yếu tố:

```text
Actor
+ Role
+ Tenant
+ Resource ownership
+ Business operation
+ Entry point
+ Current state
+ Previous actions
+ Runtime side effects
```

Ví dụ:

* Người dùng B sửa được tài nguyên thuộc người dùng A.
* Tenant B truy cập được dữ liệu của tenant A.
* REST endpoint kiểm tra quyền nhưng bulk endpoint không kiểm tra.
* Controller có guard nhưng background worker gọi thẳng service.
* Một bản vá sửa endpoint chính nhưng bỏ sót GraphQL hoặc import handler.
* Một đối tượng đã bị hủy vẫn có thể được phê duyệt.
* Cùng một idempotency key tạo ra hai giao dịch.
* Side effect xảy ra trước khi điều kiện bảo mật được kiểm tra.
* Refactor làm mất một guard đã tồn tại trong lịch sử.

Các lỗi này thường không thể xác nhận chỉ bằng cách đọc một function hoặc gửi một HTTP request đơn lẻ.

---

# 3. Định vị sản phẩm

## 3.1. Tuyên bố định vị

> LogicLab là nền tảng tự động kiểm chứng logic bảo mật trong mã nguồn. Hệ thống dựng một lab nghiệp vụ có trạng thái, mô hình hóa actor, resource, operation và invariant, sau đó tạo các thí nghiệm động để phát hiện những vi phạm mà scanner và code-review agent thông thường không thể tái hiện.

## 3.2. Thông điệp ngắn

> From source code to verified logic vulnerabilities.

Hoặc:

> Find the business-rule violations that scanners cannot reproduce.

## 3.3. LogicLab không phải là gì?

LogicLab không phải:

* Một wrapper cho CodeQL hoặc Semgrep.
* Một chatbot đọc source rồi tạo báo cáo.
* Một DAST scanner gửi payload hàng loạt.
* Một công cụ tra cứu dependency có CVE.
* Một nền tảng pentest web tổng quát.
* Một hệ thống tự động công bố CVE.
* Một framework nhiều agent trò chuyện tự do.
* Một công cụ sinh exploit có tính vũ khí hóa.

Multi-agent chỉ là kiến trúc vận hành. Sản phẩm được đánh giá bằng finding có thể kiểm chứng, không phải số lượng agent.

---

# 4. Phạm vi sản phẩm ban đầu

## 4.1. Hệ sinh thái

Phiên bản đầu chỉ hỗ trợ:

* Java 17 trở lên.
* Spring Boot.
* Spring MVC.
* REST API.
* Spring Security.
* Spring Data JPA.
* Maven.
* PostgreSQL.
* JUnit 5.
* Docker hoặc Podman.
* Testcontainers.

Các thành phần được bổ sung sau:

* Gradle.
* MySQL.
* GraphQL.
* Kafka hoặc RabbitMQ.
* Scheduler và background worker.
* gRPC.
* Kotlin/Spring.
* Django.
* Rails.
* Node.js.

## 4.2. Nhóm lỗi ưu tiên

### Giai đoạn 1

* Authorization inconsistency.
* Ownership violation.
* Cross-user access.
* Cross-tenant access.
* Bulk-operation authorization bypass.
* Validation inconsistency giữa các REST endpoint.

### Giai đoạn 2

* Workflow bypass.
* Invalid state transition.
* Approval-chain bypass.
* Idempotency failure.
* Duplicate side effect.
* Retry logic error.
* Incomplete security fix.
* Security regression sau refactor.

### Giai đoạn 3

* Financial invariant.
* Quota và resource-accounting violation.
* Delegation và impersonation.
* Cache-policy inconsistency.
* Event-driven authorization error.
* Cross-service trust violation.

---

# 5. Đầu vào và đầu ra

## 5.1. Đầu vào

Người dùng cung cấp:

```yaml
engagement:
  repository: https://example.com/organization/project
  commit: abc123
  branch: main

  target_stack:
    language: java
    framework: spring-boot
    build_system: maven
    database: postgres

  focus:
    - authorization
    - ownership
    - tenant-isolation

  limits:
    max_runtime_hours: 8
    max_model_tokens: 200000
    max_parallel_labs: 2
    network_mode: restricted

  optional_inputs:
    documentation_path: docs/
    seed_script: scripts/seed.sh
    test_accounts: null
```

## 5.2. Đầu ra

Mỗi finding bao gồm:

```yaml
finding:
  id: FIND-0021
  title: Unauthorized project update through bulk endpoint

  invariant:
    actor_must_be_owner_or_admin: true

  affected_operation:
    name: update_project
    entry_point: PUT /api/projects/bulk

  actors:
    owner: user_a
    attacker: user_b

  preconditions:
    - project belongs to user_a
    - user_b is authenticated
    - both users belong to the same tenant

  observed_behavior:
    http_status: 200
    database_mutated: true
    emitted_event: ProjectUpdated

  expected_behavior:
    allowed_status:
      - 403
      - 404
    database_mutated: false
    emitted_event: null

  evidence:
    - HTTP request and response
    - database before/after diff
    - application logs
    - relevant source path
    - replayable experiment

  verification:
    reproducible_runs: 3
    verifier_status: security-confirmed

  remediation:
    root_cause: missing service-level ownership enforcement
    regression_test: LogicLabFinding0021Test.java
    patch_status: proposed
```

---

# 6. Kiến trúc tổng thể

```text
┌────────────────────────────────────────────────────────────┐
│                       CONTROL PLANE                        │
│ Engagement · Policy · Budget · Approval · Audit            │
└────────────────────────────┬───────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│                   RESEARCH DIRECTOR                        │
│ Task planning · Department routing · Priority scheduling   │
└────────────────────────────┬───────────────────────────────┘
                             │
         ┌───────────────────┼─────────────────────┐
         ▼                   ▼                     ▼
┌────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ LAB ENGINEERING│  │ PROGRAM INTEL.   │  │ SECURITY SPEC.   │
│ Build & runtime│  │ Understand source│  │ Infer invariants │
└────────┬───────┘  └────────┬─────────┘  └─────────┬────────┘
         │                   │                      │
         └───────────────────┼──────────────────────┘
                             ▼
┌────────────────────────────────────────────────────────────┐
│                    INVESTIGATION                           │
│ Candidate discovery · Hypothesis · Scenario design         │
└────────────────────────────┬───────────────────────────────┘
                             ▼
┌────────────────────────────────────────────────────────────┐
│                 EXPERIMENT OPERATIONS                      │
│ Test generation · Sandbox execution · Runtime observation  │
└────────────────────────────┬───────────────────────────────┘
                             ▼
┌────────────────────────────────────────────────────────────┐
│                INDEPENDENT VERIFICATION                    │
│ Replay · Contradiction analysis · Finding confirmation      │
└────────────────────────────┬───────────────────────────────┘
                             ▼
┌────────────────────────────────────────────────────────────┐
│                REMEDIATION & DISCLOSURE                    │
│ Regression test · Patch validation · Human review           │
└────────────────────────────────────────────────────────────┘
```

Mọi phòng ban đọc và ghi vào một Shared Blackboard.

---

# 7. Kiến trúc phòng ban agent

## 7.1. Ban điều hành nghiên cứu

### Research Director

Trách nhiệm:

* Nhận mục tiêu của engagement.
* Chia mục tiêu thành task.
* Theo dõi dependency giữa task.
* Chọn phòng ban xử lý.
* Phân bổ ngân sách model và compute.
* Dừng các nhánh không còn giá trị.
* Chuyển finding sang verifier.
* Yêu cầu con người can thiệp khi cần.

Research Director không:

* Chạy shell trực tiếp.
* Phân tích toàn bộ source.
* Tự xác nhận finding.
* Tự sửa policy.

### Experiment Scheduler

Trách nhiệm:

* Xếp hạng hypothesis.
* Ước lượng chi phí kiểm chứng.
* Chọn thí nghiệm tiếp theo.
* Tránh chạy lại task trùng.
* Ưu tiên coverage mới.
* Giới hạn số vòng sửa test.

Điểm ưu tiên ban đầu:

```text
Priority =
  invariant_confidence
× exploitability_estimate
× evidence_novelty
× entry_point_reachability
÷ verification_cost
```

---

## 7.2. Phòng Governance

### Scope Gate

Kiểm tra:

* Repository có nằm trong engagement không.
* Commit và branch có hợp lệ không.
* Workspace nào được phép đọc.
* Environment nào được phép chạy.

### Command Gate

Mọi thao tác phải được ánh xạ tới command template:

```json
{
  "tool": "run_maven_test",
  "workspace": "project-123",
  "test_class": "LogicLabFinding21Test",
  "timeout_seconds": 300
}
```

LLM không được tạo shell command tùy ý.

### Budget Gate

Theo dõi:

* Token.
* GPU time.
* CPU time.
* Số lần build.
* Số lần khởi động lab.
* Số lần chạy experiment.
* Dung lượng artifact.

Phòng Governance hoàn toàn deterministic, không dùng LLM.

---

## 7.3. Phòng Lab Engineering

### Build Analyst

Nhiệm vụ:

* Nhận diện JDK.
* Nhận diện Maven module.
* Xác định build command.
* Phân tích lỗi build.
* Chọn hành động sửa từ danh sách được phép.

### Dependency Resolver

Nhiệm vụ:

* Xác định database.
* Xác định queue hoặc object storage.
* Phân tích Docker Compose.
* Phân tích CI workflow.
* Đề xuất dependency cần dựng.

### Fixture Engineer

Nhiệm vụ:

* Tìm test fixture hiện có.
* Xác định cách tạo user.
* Xác định cách tạo tenant.
* Xác định cách tạo resource.
* Tạo seed script hoặc fixture adapter.

### Lab Validator

Lab chỉ đạt trạng thái `READY` khi:

* Build thành công.
* Application khởi động.
* Health check thành công.
* Database migration hoàn tất.
* Tạo được ít nhất hai actor.
* Đăng nhập được.
* Tạo được resource mẫu.
* Reset snapshot thành công.
* Cùng scenario chạy lại cho kết quả ổn định.

Đầu ra của phòng:

```yaml
lab_blueprint:
  java_version: 21
  build_command: ./mvnw package
  start_command: java -jar target/app.jar

  services:
    application:
      port: 8080
    postgres:
      version: 16

  identity:
    mechanism: jwt
    login_endpoint: /api/auth/login

  fixtures:
    actor_factory: test-user-factory
    resource_factory: project-fixture

  reset:
    strategy: database_snapshot
```

---

## 7.4. Phòng Program Intelligence

### Architecture Mapper

Tạo mô hình:

* Module.
* Package.
* Controller.
* Service.
* Repository.
* Entity.
* External dependency.
* Test module.

### Entry-Point Mapper

Nhận diện:

* REST endpoint.
* HTTP method.
* Request DTO.
* Authentication requirement.
* Security annotation.
* Controller method.
* Service method.
* Repository operation.

### Data Model Analyst

Nhận diện:

* Entity.
* Primary key.
* Owner field.
* Tenant field.
* State field.
* Quan hệ parent-child.
* Trường nhạy cảm.
* Unique constraint.

### History Analyst

Phân tích:

* Commit thay đổi guard.
* Security annotation bị xóa.
* Repository query thay đổi.
* Test authorization được thêm hoặc xóa.
* Patch cũ.
* Refactor security-relevant.

Đầu ra là Project Security Twin.

---

# 8. Project Security Twin

## 8.1. Actor Graph

```yaml
actor:
  type: authenticated_user
  roles:
    - USER
    - ADMIN
  attributes:
    - user_id
    - tenant_id
    - organization_id
  authentication:
    mechanism: jwt
```

## 8.2. Resource Graph

```yaml
resource:
  type: Project
  id_field: id
  owner_field: ownerId
  tenant_field: tenantId
  state_field: status

  relationships:
    - members
    - organization
```

## 8.3. Business Operation Graph

```yaml
operation:
  name: update_project

  resource: Project

  entry_points:
    - PUT /api/projects/{id}
    - PUT /api/projects/bulk
    - POST /api/projects/import

  state_effects:
    - update Project.name
    - update Project.settings

  events:
    - ProjectUpdated
```

## 8.4. Entry-Point Equivalence Graph

Các entry point được nhóm khi có một hoặc nhiều tín hiệu:

* Gọi cùng service method.
* Ghi cùng entity.
* Thay đổi cùng field.
* Phát cùng event.
* Có test mô tả cùng nghiệp vụ.
* Có semantic operation tương đương.

Điểm tương đương:

```text
EquivalenceScore =
  shared_service_call
+ shared_entity_mutation
+ shared_event
+ semantic_similarity
+ shared_fixture
```

## 8.5. State Machine

```text
DRAFT
  ↓ submit
SUBMITTED
  ↓ approve
APPROVED
  ↓ execute
COMPLETED
```

Transition bị cấm:

```text
COMPLETED → DRAFT
CANCELLED → APPROVED
REJECTED → COMPLETED
```

---

# 9. Phòng Security Specification

## 9.1. Actor–Resource Analyst

Xác định:

* Ai thao tác.
* Tài nguyên thuộc ai.
* Tenant nào sở hữu.
* Vai trò nào được phép.
* Quan hệ chia sẻ nào tồn tại.

## 9.2. Invariant Miner

Suy luận invariant từ:

1. Security annotation.
2. Guard trong service.
3. Test hiện có.
4. Database constraint.
5. Tài liệu.
6. Error message.
7. Sibling endpoint.
8. Git history.
9. Runtime trace hợp lệ.
10. Framework pattern.

Ví dụ:

```yaml
invariant:
  id: INV-0104
  operation: update_project

  preconditions:
    - actor.authenticated
    - project.exists

  constraint:
    expression: actor.is_admin OR actor.id == project.owner_id

  unauthorized_outcome:
    state_changed: false
    event_emitted: false

  evidence_refs:
    - CODE-0091
    - TEST-0027
    - HISTORY-0012

  confidence: 0.86
```

## 9.3. Temporal Invariant Analyst

Theo dõi invariant qua commit:

```yaml
temporal_invariant:
  invariant_id: INV-0104
  first_observed_commit: a10
  last_verified_commit: b72

  changes:
    - commit: b20
      change: guard moved from service to controller

    - commit: b72
      change: bulk endpoint added without equivalent guard
```

---

# 10. Context Broker và RAG

LogicLab không sử dụng một vector database chung cho toàn bộ hệ thống.

Context Broker điều phối năm loại retrieval.

## 10.1. Symbolic Retrieval

Dùng cho:

* Definition.
* Reference.
* Caller.
* Callee.
* Annotation.
* Type.
* Interface implementation.

## 10.2. Graph Retrieval

Dùng cho:

* Call path.
* Data flow.
* Entry-point equivalence.
* Entity mutation.
* Event emission.
* Actor-resource relation.

## 10.3. Semantic Retrieval

Dùng cho:

* Documentation.
* Test intent.
* Operation similarity.
* Error message.
* Comment.
* Build log.

## 10.4. Temporal Retrieval

Dùng cho:

* Git history.
* Patch comparison.
* Guard history.
* Regression.
* Incomplete fix.
* Fork drift.

## 10.5. Evidence Retrieval

Dùng cho:

* HTTP trace.
* Database diff.
* Runtime log.
* Event.
* Previous experiment.
* Maintainer feedback.

Context request:

```json
{
  "task": "infer_ownership_invariant",
  "operation": "update_project",
  "retrieve": [
    "implementation",
    "security_guards",
    "related_tests",
    "sibling_entry_points",
    "recent_guard_changes"
  ],
  "max_context_tokens": 12000
}
```

Context Broker trả về:

```json
{
  "context_refs": [
    "CODE-122",
    "TEST-018",
    "GIT-041"
  ],
  "missing_information": [
    "bulk update authorization test"
  ]
}
```

---

# 11. Phòng Investigation

## 11.1. Hypothesis Generator

Các mẫu hypothesis chính:

### Authorization inconsistency

```text
Endpoint A kiểm tra ownership.
Endpoint B thực hiện cùng operation nhưng không có guard tương đương.
```

### Cross-tenant inconsistency

```text
Single-item query lọc tenant.
Bulk query chỉ lọc theo ID.
```

### Service-layer bypass

```text
Controller kiểm tra role.
Background handler gọi trực tiếp service không có policy.
```

### State bypass

```text
UI chỉ cho phép operation ở trạng thái PENDING.
Service method không kiểm tra trạng thái.
```

### Temporal regression

```text
Guard được chuyển khỏi service trong commit mới.
Entry point cũ vẫn gọi service trực tiếp.
```

### Incomplete fix

```text
Patch chặn REST endpoint.
Bulk endpoint vẫn thực hiện cùng operation.
```

Hypothesis object:

```yaml
hypothesis:
  id: HYP-0229
  invariant_id: INV-0104

  candidate:
    entry_point: PUT /api/projects/bulk

  reason:
    - same entity mutation
    - sibling endpoint performs ownership check
    - candidate path lacks equivalent guard

  estimated_cost: 12
  priority: 0.81
```

## 11.2. Static Analysis Agent

Dùng:

* JavaParser hoặc Spoon.
* Symbol resolver.
* Semgrep.
* CodeQL khi giấy phép và môi trường phù hợp.
* Custom Spring analyzer.
* Git diff analyzer.

Static evidence không tự động trở thành finding.

## 11.3. Scenario Designer

Chuyển hypothesis thành Logic Experiment DSL.

---

# 12. Logic Experiment DSL

## 12.1. Ví dụ ownership

```yaml
experiment:
  id: EXP-0317
  invariant: INV-0104

actors:
  owner:
    role: USER
    tenant: TENANT_A

  attacker:
    role: USER
    tenant: TENANT_A

setup:
  - login:
      actor: owner

  - create:
      operation: create_project
      as: owner
      save_as: target_project

baseline:
  - execute:
      operation: update_project
      entry_point: standard_update
      as: owner
      resource: target_project
      input:
        name: baseline-name

variant:
  - execute:
      operation: update_project
      entry_point: bulk_update
      as: attacker
      resource: target_project
      input:
        name: unauthorized-name

oracle:
  http:
    variant_status:
      allowed:
        - 401
        - 403
        - 404

  database:
    target_project.name:
      remains: baseline-name

  events:
    must_not_emit:
      - ProjectUpdated
```

## 12.2. Ví dụ cross-tenant

```yaml
actors:
  user_a:
    tenant: TENANT_A

  user_b:
    tenant: TENANT_B

setup:
  - create:
      operation: create_document
      as: user_a
      save_as: document_a

variant:
  - execute:
      operation: read_document
      as: user_b
      resource: document_a

oracle:
  response:
    must_not_contain:
      - document_a.content

  database:
    no_write: true

  audit:
    success_event: false
```

DSL phải:

* Có version.
* Có schema validation.
* Có thể replay.
* Có thể chuyển thành JUnit.
* Có thể lưu vào Git.
* Không chứa shell command.
* Không chứa target bên ngoài lab.

---

# 13. Phòng Experiment Operations

## 13.1. Test Generator

Ưu tiên truy xuất:

1. Test cùng controller.
2. Test cùng entity.
3. Existing authentication helper.
4. Fixture factory.
5. MockMvc hoặc WebTestClient setup.
6. Database cleanup utility.
7. Framework template.

Test Generator sinh:

* JUnit test.
* Integration test.
* Fixture adapter.
* HTTP scenario.
* Database assertion.

## 13.2. Lab Runner

Lifecycle:

```text
Load clean snapshot
→ prepare actors
→ prepare resources
→ run baseline
→ collect observations
→ restore snapshot
→ run variant
→ collect observations
→ evaluate deterministic oracle
→ repeat for stability
→ store evidence
```

## 13.3. Runtime Observer

Quan sát:

### HTTP

* Request.
* Response.
* Header.
* Cookie.
* Token claims.
* Status.
* Body.

### Database

* Row diff.
* Ownership.
* Tenant.
* State.
* Created record.
* Deleted record.
* Transaction result.

### Application

* Log.
* Exception.
* Security decision.
* Method trace.

### Event system

* Domain event.
* Queue message.
* Retry count.
* Dead-letter message.

### External side effect

* File creation.
* Outbound HTTP.
* Email.
* Object storage.
* Cache update.

---

# 14. Phòng Independent Verification

Verifier hoạt động độc lập với Hunter.

Verifier không nhận:

* Kết luận tự tin của Hunter.
* Severity do Hunter đề xuất.
* Câu khẳng định “đây chắc chắn là lỗ hổng”.

Verifier nhận:

* Invariant.
* Evidence gốc.
* Source path.
* Experiment DSL.
* Replay artifact.
* Bằng chứng ủng hộ.
* Bằng chứng phản bác.

## 14.1. Các câu hỏi bắt buộc

1. Invariant có đủ bằng chứng không?
2. Actor có quyền hợp lệ nào bị bỏ sót không?
3. Resource có được chia sẻ hợp lệ không?
4. Scenario có dùng API đúng cách không?
5. Hành vi có được mô tả là expected behavior không?
6. Side effect có thực sự xảy ra không?
7. Kết quả có tái hiện trên snapshot sạch không?
8. Entry point có reachable trong cấu hình thực tế không?
9. Có alternate explanation hợp lý không?
10. Một patch tối thiểu có làm hành vi biến mất không?

## 14.2. Finding state machine

```text
HYPOTHESIS
    ↓
OBSERVED_ANOMALY
    ↓
REPRODUCIBLE_ANOMALY
    ↓
SUPPORTED_POLICY_VIOLATION
    ↓
SECURITY_CONFIRMED
    ↓
HUMAN_REVIEWED
    ↓
MAINTAINER_CONFIRMED
    ↓
PATCHED
```

Nhánh khác:

```text
REJECTED
INCONCLUSIVE
EXPECTED_BEHAVIOR
CONFIGURATION_DEPENDENT
NEEDS_MAINTAINER_CLARIFICATION
```

## 14.3. Confidence breakdown

Không dùng một confidence do LLM tự tạo.

```yaml
confidence:
  invariant: 0.82
  reproducibility: 1.00
  runtime_evidence: 0.95
  reachability: 0.88
  exploitability: 0.74
  overall: 0.86
```

---

# 15. Patch Completeness Verification

Khi có patch:

```text
Original finding
→ derive violated invariant
→ inspect patch
→ locate enforcement point
→ find equivalent entry points
→ generate bypass hypotheses
→ run original experiment
→ run cross-entry-point suite
→ run valid workflows
→ assess completeness
```

Các kết quả:

* `COMPLETE`
* `LOCALLY_COMPLETE`
* `INCOMPLETE`
* `REGRESSION_INDUCING`
* `UNVERIFIABLE`

Ví dụ:

```yaml
patch_assessment:
  original_entry_point:
    status: fixed

  equivalent_entry_points:
    rest_single:
      status: fixed
    rest_bulk:
      status: vulnerable
    import_handler:
      status: untested

  final_status: INCOMPLETE
```

---

# 16. Evidence Ledger

Mọi evidence là immutable artifact.

```json
{
  "evidence_id": "EVD-0778",
  "type": "database_diff",
  "experiment_id": "EXP-0317",
  "repository_commit": "abc123",
  "lab_blueprint_version": "12",
  "actor": "attacker",
  "resource": "project-41",
  "before": {
    "name": "baseline-name"
  },
  "after": {
    "name": "unauthorized-name"
  },
  "supports": [
    "unauthorized state mutation"
  ],
  "artifact_hash": "sha256:..."
}
```

Provenance:

```text
Repository
→ Project Twin
→ Invariant
→ Hypothesis
→ Experiment
→ Evidence
→ Verification
→ Finding
→ Patch
→ Regression Result
```

Finding phải có thao tác:

```text
Replay in clean lab
```

---

# 17. Model strategy

## 17.1. Không dùng một model riêng cho mỗi agent

Kiến trúc:

```text
Logical Agents
      │
      ▼
Model Gateway
      │
      ├── General Coding Reasoner
      ├── Utility Model
      └── Independent Judge
```

## 17.2. General Coding Reasoner

Dùng cho:

* Architecture reasoning.
* Invariant inference.
* Hypothesis generation.
* Scenario design.
* Patch analysis.
* Root-cause analysis.

Cấu hình tham chiếu:

* Open-weight coder model khoảng 20B–35B.
* Quantization 4-bit khi chạy local.
* Context thực tế 16K–32K.
* Một model server dùng chung.

## 17.3. Utility Model

Model nhỏ khoảng 3B–9B dùng cho:

* Structured extraction.
* Build-error classification.
* Routing.
* Log summarization.
* Entry-point pair classification.
* Schema normalization.

Đây là model đầu tiên nên được fine-tune bằng LoRA hoặc QLoRA khi có dữ liệu.

## 17.4. Independent Judge

Dùng cho verifier:

* Context riêng.
* Không sử dụng cùng adapter với Hunter.
* Nhận evidence hỗ trợ và phản bác.
* Không có quyền trực tiếp thực thi ngoài replay workflow.

## 17.5. Deterministic components

Không dùng LLM cho:

* Scope.
* Policy.
* Command validation.
* Budget.
* State comparison.
* Oracle evaluation.
* Finding transition.
* Artifact hashing.
* Network restriction.

---

# 18. Fine-tuning strategy

## 18.1. Giai đoạn đầu

Không fine-tune.

Dùng:

```text
Base coding model
+ hybrid RAG
+ structured output
+ deterministic tools
+ verifier độc lập
```

## 18.2. Model đầu tiên cần fine-tune

Utility Model cho:

* Actor/resource extraction.
* Build-error classification.
* Entry-point matching.
* Task routing.
* Structured JSON.

## 18.3. Chỉ fine-tune khi có dữ liệu đủ chất lượng

Tập dữ liệu cần lưu:

```json
{
  "task_type": "entry_point_equivalence",
  "input_refs": [
    "CODE-18",
    "GRAPH-20"
  ],
  "model_output": {},
  "tool_results": {},
  "human_decision": "accepted",
  "maintainer_decision": null,
  "failure_reason": null,
  "model_version": "...",
  "prompt_version": "...",
  "repository_commit": "..."
}
```

Không đưa output tự sinh chưa xác minh vào tập gold.

## 18.4. Nguyên tắc

```text
Kiến thức thay đổi theo repository
→ RAG

Hành vi lặp lại và có nhãn
→ Fine-tuning

Quyết định an toàn và kiểm tra state
→ Deterministic code
```

---

# 19. Ngôn ngữ và công nghệ

## 19.1. Ngôn ngữ

### Python

Dùng cho:

* Control plane.
* Agent orchestration.
* Context Broker.
* RAG.
* Model Gateway.
* Scheduler.
* Evidence processing.
* API.
* Reporting.

### Java

Dùng cho:

* Java/Spring source analyzer.
* AST và symbol resolution.
* Runtime instrumentation.
* JUnit test.
* Spring-specific analysis.
* JDBC observer.

### SQL

Dùng cho:

* Shared Blackboard.
* Evidence Ledger.
* Task state.
* Finding state.

### YAML

Dùng cho:

* Lab Blueprint.
* Experiment DSL.
* Deployment configuration.

### TypeScript

Dùng cho dashboard ở giai đoạn sau.

## 19.2. Stack đề xuất

```text
Control API:
Python + FastAPI

Workflow:
Python state machine hoặc LangGraph subgraph

Schema:
Pydantic + JSON Schema

Database:
PostgreSQL

Vector retrieval:
pgvector hoặc vector store tương đương

Queue:
Redis + Python worker

Model serving:
vLLM hoặc runtime local tương đương

Source analysis:
JavaParser/Spoon
+ custom Spring analyzer
+ Semgrep
+ optional CodeQL

Testing:
JUnit 5
+ Spring Boot Test
+ Testcontainers

Lab:
Docker/Podman
+ Docker Compose

Observability:
OpenTelemetry
+ custom Java agent
+ JDBC observer

Artifacts:
Local filesystem hoặc MinIO
```

---

# 20. Cấu trúc mã nguồn

```text
logiclab/
├── control-plane/                 # Python
│   ├── api/
│   ├── engagements/
│   ├── policy/
│   ├── budgets/
│   └── approvals/
│
├── orchestrator/                  # Python
│   ├── director/
│   ├── scheduler/
│   ├── departments/
│   └── state-machine/
│
├── context-broker/                # Python
│   ├── symbolic-retrieval/
│   ├── graph-retrieval/
│   ├── semantic-retrieval/
│   ├── temporal-retrieval/
│   └── evidence-retrieval/
│
├── model-gateway/                 # Python
│   ├── routing/
│   ├── structured-output/
│   ├── model-policies/
│   └── adapters/
│
├── lab-manager/                   # Python
│   ├── blueprint/
│   ├── container-runtime/
│   ├── fixture-manager/
│   ├── snapshots/
│   └── health-checks/
│
├── java-intelligence/             # Java
│   ├── ast/
│   ├── symbol-resolution/
│   ├── spring-mapper/
│   ├── jpa-model/
│   └── history-analysis/
│
├── java-instrumentation/          # Java
│   ├── method-tracing/
│   ├── security-events/
│   ├── jdbc-observer/
│   └── domain-events/
│
├── experiment-runtime/            # Python + Java
│   ├── dsl/
│   ├── test-generator/
│   ├── runner/
│   ├── oracle/
│   └── replay/
│
├── evidence/                      # Python
│   ├── ledger/
│   ├── artifacts/
│   ├── redaction/
│   └── provenance/
│
├── schemas/
│   ├── lab-blueprint.schema.json
│   ├── project-twin.schema.json
│   ├── invariant.schema.json
│   ├── hypothesis.schema.json
│   ├── experiment.schema.json
│   ├── evidence.schema.json
│   └── finding.schema.json
│
├── web-ui/                        # TypeScript, làm sau
└── deployment/
    ├── docker/
    ├── compose/
    └── local/
```

---

# 21. Triển khai local không mất phí API

## 21.1. Cấu hình tham chiếu

```text
GPU:
24 GB VRAM

CPU:
12–16 core trở lên

RAM:
64–128 GB

Storage:
1–2 TB NVMe

Model:
Open-weight coding model 20B–35B
quantized 4-bit

Context:
16K–32K

Concurrent LLM jobs:
1–3

Concurrent labs:
1–4 tùy tài nguyên
```

## 21.2. Phân bổ tài nguyên

```text
GPU:
chỉ phục vụ model inference

CPU:
Maven build
static analysis
test execution
AST parsing

RAM:
lab containers
database snapshots
build cache

NVMe:
repository
Maven cache
container layers
evidence artifacts
```

## 21.3. Tối ưu hiệu năng

* Không đưa toàn repository vào prompt.
* Retrieval theo operation và call path.
* Cache AST và dependency.
* Cache Docker layer.
* Cache database snapshot.
* Prefix caching cho prompt chung.
* Giới hạn output model bằng JSON schema.
* Parallelize tool worker, không gọi model song song không kiểm soát.
* Chỉ chạy experiment động khi hypothesis đủ mạnh.
* Dùng model nhỏ cho extraction và routing.
* Cho phép hệ thống `abstain`.

---

# 22. Safety architecture

## 22.1. Phạm vi

Chỉ hoạt động trên:

* Repository mã nguồn mở.
* Repository thuộc khách hàng.
* Codebase được cho phép rõ ràng.
* Sandbox do LogicLab quản lý.

Không tự động kiểm thử deployment Internet.

## 22.2. Network

* Default-deny egress.
* Allowlist package registry.
* Chặn metadata endpoint.
* Chặn private network không liên quan.
* Mock external services.
* Network namespace riêng cho mỗi experiment.

## 22.3. Secret

* Không dùng production secret.
* Tự sinh credential giả.
* Redact token.
* Không gửi secret vào model.
* Scan secret trước khi lưu artifact.

## 22.4. Disclosure

```text
Security-confirmed finding
→ human review
→ maintainer contact
→ private reproduction
→ remediation coordination
→ embargo
→ CVE/CNA process khi phù hợp
→ controlled publication
```

Hệ thống không tự động xin hoặc công bố CVE.

---

# 23. MVP khả thi

## 23.1. Mục tiêu

> Tự dựng một ứng dụng Spring Boot REST, tạo hai actor, phát hiện một lỗi ownership inconsistency, kiểm chứng bằng HTTP và database diff, sau đó sinh JUnit regression test.

## 23.2. Phạm vi MVP

* Một repository cố định.
* Maven.
* PostgreSQL.
* JWT hoặc session đơn giản.
* Hai user.
* Một resource.
* REST API.
* Ownership invariant.
* Blueprint viết tay.
* Experiment DSL.
* HTTP observer.
* Database diff.
* Replay.
* JUnit generation.

## 23.3. Luồng MVP

```text
Repository cố định
→ blueprint viết tay
→ build và start
→ tạo Alice và Bob
→ Alice tạo resource
→ Bob thử sửa resource
→ quan sát HTTP
→ so sánh database
→ xác nhận anomaly
→ sinh regression test
```

## 23.4. Tiêu chí hoàn thành MVP

* Lab dựng được từ đầu bằng một lệnh.
* Reset state thành công.
* Hai actor đăng nhập được.
* Resource được tạo tự động.
* Experiment chạy lại ít nhất ba lần.
* Evidence có hash.
* Finding có trạng thái rõ ràng.
* JUnit test compile và chạy được.

---

# 24. Roadmap

## Phase 0 — Core experiment engine

* Một repository.
* Blueprint viết tay.
* Actor setup.
* Resource setup.
* HTTP runner.
* Database observer.
* Experiment DSL.
* Replay.

## Phase 1 — Authorization MVP

* Endpoint extraction.
* Spring Security annotation.
* Ownership-field detection.
* Cross-user experiment.
* JUnit generation.
* Evidence Ledger.

## Phase 2 — Curated repository automation

* 5–10 repository.
* Assisted Lab Builder.
* Build repair memory.
* Authentication inference.
* Existing-test retrieval.
* Fixture reuse.

## Phase 3 — Program Security Twin

* Actor Graph.
* Resource Graph.
* Business Operation Graph.
* Entry-point equivalence.
* State model.
* Side-effect model.

## Phase 4 — Hybrid RAG

* Symbol retrieval.
* Graph retrieval.
* Test retrieval.
* Lab repair memory.
* Invariant evidence retrieval.
* Temporal Git retrieval.

## Phase 5 — Multi-agent departments

* Research Director.
* Lab Engineering.
* Program Intelligence.
* Security Specification.
* Investigation.
* Independent Verification.

## Phase 6 — Cross-entry-point

* Bulk REST.
* Admin REST.
* Import handler.
* Service-level entry.
* GraphQL về sau.
* Queue và scheduler về sau.

## Phase 7 — Temporal security

* Guard history.
* Commit regression.
* Incomplete fix.
* Patch completeness.
* Pull-request integration.

## Phase 8 — Enterprise platform

* Multi-project.
* SSO.
* RBAC.
* Audit.
* On-premise.
* Private model.
* GitHub/GitLab integration.
* Continuous invariant testing.

---

# 25. KPI

## 25.1. Lab KPI

* Build success rate.
* Startup success rate.
* Login bootstrap rate.
* Fixture success rate.
* Snapshot reset success rate.
* Median repository-to-lab time.
* Replay stability rate.

## 25.2. Modeling KPI

* Endpoint extraction precision.
* Actor extraction precision.
* Resource identification precision.
* Ownership-field precision.
* Operation-grouping precision.
* Entry-point coverage.
* Invariant acceptance rate.

## 25.3. Security KPI

* Hypothesis precision.
* Confirmed findings trên mỗi repository.
* False-positive rate sau verifier.
* Time to first confirmed finding.
* Reproduction success rate.
* JUnit compile rate.
* Patch completeness detection rate.

## 25.4. Efficiency KPI

* Model tokens trên mỗi finding.
* CPU/GPU hours trên mỗi finding.
* Số lần build trên mỗi finding.
* Số experiment bị loại sớm.
* Tỷ lệ task giải quyết không cần model mạnh.
* Analyst minutes trên mỗi finding.

## 25.5. North-star metric

> Số security-policy violation được xác minh và chuyển thành regression test trên mỗi analyst-hour.

---

# 26. Mô hình kinh doanh

## 26.1. Managed Security Research

Giai đoạn đầu bán theo engagement:

* Một repository.
* Một nhóm lỗi.
* Một ngân sách compute.
* Chuyên gia giám sát.
* Finding được xác minh.
* Regression test.
* Patch assessment.

## 26.2. Continuous Assurance

Subscription cho:

* Commit Guard.
* Pull-request invariant regression.
* Patch verification.
* Dependency assurance.
* Fork comparison.

## 26.3. Enterprise On-Premise

* Local model.
* Source code không rời khỏi mạng.
* SSO và RBAC.
* Audit log.
* Custom invariant.
* Internal Git integration.
* Air-gapped deployment.
* Private blueprint corpus.

## 26.4. Khách hàng ưu tiên

* Công ty có sản phẩm Java/Spring.
* Product Security team.
* AppSec team.
* Doanh nghiệp có fork OSS nội bộ.
* Vendor cần audit trước release.
* Công ty tài chính có workflow phức tạp.
* Security research lab.
* Tổ chức tài trợ bảo mật OSS.

---

# 27. Moat

LogicLab không tạo moat bằng model.

Moat được hình thành từ:

## 27.1. Lab Blueprint Corpus

* Build recipe.
* Runtime.
* Database setup.
* Fixture.
* Login flow.
* Snapshot.
* External-service mock.
* Build repair.

## 27.2. Business Operation Dataset

```text
Entry point
→ operation
→ actor
→ resource
→ policy
→ state
→ side effect
```

## 27.3. Invariant Library

Thư viện theo:

* Spring Security.
* JPA.
* Multi-tenancy.
* Project management.
* File sharing.
* E-commerce.
* Identity.
* Approval workflow.
* Payment.

## 27.4. Verified Experiment Traces

```text
Invariant
→ Hypothesis
→ Experiment
→ Evidence
→ Human decision
→ Maintainer decision
→ Patch
```

## 27.5. Temporal Security Memory

* Guard được thêm khi nào.
* Guard bị xóa khi nào.
* Entry point nào lệch policy.
* Patch nào chưa đầy đủ.
* Regression nào từng xảy ra.

## 27.6. Maintainer feedback

Dữ liệu về finding:

* Được chấp nhận.
* Bị từ chối.
* Là expected behavior.
* Bị giảm severity.
* Được sửa theo cách khác.

---

# 28. Rủi ro và phương án xử lý

## Rủi ro 1 — Không dựng được repository

Biện pháp:

* Bắt đầu bằng curated repository.
* Blueprint viết tay.
* Chỉ hỗ trợ một stack.
* Build Repair Memory.
* Assisted onboarding.

## Rủi ro 2 — Không tạo được fixture

Biện pháp:

* Tái sử dụng existing test.
* Tìm fixture factory.
* Cho phép seed hook.
* Import database snapshot.
* Tạo adapter theo repository.

## Rủi ro 3 — Invariant sai

Biện pháp:

* Multi-source evidence.
* Không dùng template chung làm sự thật.
* Comparative validation.
* Independent verifier.
* Trạng thái `INCONCLUSIVE`.

## Rủi ro 4 — False positive cao

Biện pháp:

* Dynamic evidence.
* Database oracle.
* Replay nhiều lần.
* Evidence phản bác.
* Human review trước disclosure.

## Rủi ro 5 — Model local yếu

Biện pháp:

* Context Broker.
* Hybrid RAG.
* Retrieval theo symbol và graph.
* Dùng model nhỏ cho task đơn giản.
* Tool deterministic.
* Human escalation.

## Rủi ro 6 — Compute quá lớn

Biện pháp:

* Hypothesis ranking.
* Early stopping.
* Static filtering.
* Cache.
* Snapshot.
* Không rebuild toàn bộ cho mỗi experiment.
* Budget Gate.

## Rủi ro 7 — Đối thủ lớn mở rộng

Biện pháp:

* Chuyên sâu Java/Spring.
* Stateful actor/resource lab.
* Cross-entry-point testing.
* Temporal invariant.
* Blueprint corpus.
* Verified trace dataset.

---

# 29. Tiêu chí thành công theo mốc

## Milestone 1

Tái hiện một lỗi ownership đã biết bằng experiment tự động.

## Milestone 2

Sinh được JUnit regression test chạy thành công.

## Milestone 3

Tự nhận diện actor, resource và owner field.

## Milestone 4

Tự nhóm được hai endpoint cùng business operation.

## Milestone 5

Phát hiện cùng invariant bị vi phạm ở entry point thứ hai.

## Milestone 6

Phát hiện một incomplete fix.

## Milestone 7

Tìm được một finding mới được chuyên gia xác nhận.

## Milestone 8

Finding được maintainer xác nhận.

## Milestone 9

Một khách hàng trả tiền cho audit.

## Milestone 10

Chạy continuous invariant regression trên một codebase thực tế.

---

# 30. Kết luận

LogicLab không được xây dựng như một tập hợp agent tự do gọi tool.

Kiến trúc phù hợp là:

```text
Hierarchical Departments
+ Shared Blackboard
+ Context Broker
+ Hybrid RAG
+ Deterministic Tool Workers
+ Stateful Application Lab
+ Independent Verifier
+ Evidence Ledger
```

Giá trị cốt lõi không nằm ở:

* Số agent.
* Số model.
* Context dài.
* Số scanner được tích hợp.

Giá trị cốt lõi nằm ở khả năng:

```text
Hiểu một business operation
→ xác định invariant bảo mật
→ tìm mọi entry point liên quan
→ tạo actor và state phù hợp
→ chạy thí nghiệm
→ quan sát side effect
→ kiểm chứng độc lập
→ sinh regression test
```

Phiên bản đầu nên được giới hạn ở:

```text
Java/Spring Boot
+ REST
+ Maven
+ PostgreSQL
+ authorization
+ ownership
+ two-actor experiments
+ HTTP and database evidence
```

Tầm nhìn dài hạn:

> Mỗi invariant bảo mật quan trọng của codebase đều được lưu thành một thí nghiệm có thể thực thi và tự động chạy lại sau mỗi commit.
