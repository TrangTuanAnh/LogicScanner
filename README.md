# LogicLab Universal

LogicLab là một workbench pháp chứng chạy cục bộ, dùng để **hiểu** một Git
repository lạ trước khi cho phép bất kỳ dòng code nào của nó được chạy. Một
commit được ghim sẽ được tải về dưới dạng Git object bất biến, materialize mà
không qua checkout hook hay symlink, chuẩn hoá thành IR của repository, rồi được
xử lý bởi một đồ thị phân tích tám vai trò. Giao diện React hiển thị điểm năng
lực, thành phần, chẩn đoán, tác vụ, claim và nguồn gốc mã nguồn.

## Hiện đã chạy được

- Tiếp nhận tĩnh cho repository HTTPS không kèm credential trên GitHub, GitLab,
  Bitbucket và Codeberg, ghim theo đúng commit SHA 40 ký tự.
- Nhận diện stack và hệ thống build cho Python, Java/JVM, JavaScript/TypeScript,
  Go, Rust, .NET, Ruby, PHP, Elixir, Dart, Bazel, CMake, Make và Nix.
- Trích xuất AST cho Python, cộng với việc phát hiện thận trọng theo nhiều ngôn
  ngữ các symbol, import, endpoint, manifest, component và đường dẫn test.
- Một DAG vai trò tất định: research director, repo surveyor, architecture
  mapper, build/runtime scout, test-path analyst, security/domain mapper,
  Project Twin synthesizer và independent skeptic. Mỗi vai trò sản xuất đều phát
  ra claim có trích dẫn dưới provenance của chính nó, hoặc **abstain** kèm lý do
  có kiểu khi bằng chứng không tồn tại.
- Budget được thực thi (`StopRules` trên `BudgetUsage` tích luỹ), `max_parallelism`
  theo vai trò được thực thi, và phân xử xung đột tất định — từ chối bẻ một thế
  hoà mà bằng chứng không bẻ được.
- Mọi kết quả không thành công đều kèm bước tiếp theo: abstain, trần năng lực,
  role crash, và task bị scheduler chặn đều nói rõ điều gì sẽ gỡ được bế tắc.
- Recovery khép kín: một role crash trở thành `ERROR` có kiểu kèm recovery
  contract thay vì giết cả phiên phân tích; `TaskDAG.retry_task` đưa nó về hàng
  đợi, và `StopRules` cho nó fail khi hết ngân sách retry. Các vai trò còn lại
  vẫn tiếp tục đóng góp claim.
- Một proposer dùng model cục bộ, **mặc định tắt**, cho các claim ngữ nghĩa mà
  phân tích tĩnh không thể xác lập. Mọi đề xuất bắt buộc phải trích dẫn một
  đường dẫn nằm trong allow-list đã được materialize, và chỉ được nhận với trạng
  thái `INFERRED`.
- Claim có kiểu, kèm commit bất biến, tree digest, blob SHA-256, khoảng dòng,
  bên sản xuất và provenance của công cụ.
- Giao diện React same-origin với phiên trao đổi qua cookie HttpOnly, route
  responsive, form accessible, lỗi API đọc được và cơ chế poll job.
- Alembic migration có phiên bản, và một wheel đóng gói cả UI asset lẫn migration.

Mức độ hiểu (`U0`–`U4`) và mức độ sẵn sàng runtime (`R0`–`R4`) là hai trục **cố ý
tách rời**. Phân tích universal hiện vẫn hoàn toàn tĩnh (`R0`/`R1`). Đồ thị vai
trò mặc định là tất định và không tuyên bố có kiểm chứng runtime độc lập. Đánh
giá ngữ nghĩa chỉ tồn tại qua proposer tuỳ chọn, và đầu ra của nó luôn được đánh
dấu `INFERRED`, không bao giờ được coi là quan sát thực tế.

## Ranh giới an toàn

Việc nộp repository theo luồng universal **không bao giờ chạy code của
repository đó**. Quá trình truyền Git diễn ra trong một subprocess không prompt,
với forge nằm trong allowlist, kiểm tra DNS công khai, từ chối redirect, fetch
nông theo commit ghim, giới hạn thời gian, hạn ngạch dung lượng đĩa, và dọn dẹp
snapshot dở dang. Bước materialize bỏ qua symlink, file không phải file thường,
đường dẫn nhạy cảm, file nhị phân, file quá lớn, đường dẫn không an toàn và các
trường hợp trùng tên do phân biệt hoa thường. **Mọi phần bị bỏ qua đều làm giảm
coverage và đẩy trạng thái về `needs_review`, thay vì báo 100% giả.**

Engine thí nghiệm TLS trước đây vẫn còn trong codebase để tương thích ngược,
nhưng các thao tác ghi qua API và worker nền của nó bị tắt mặc định. Bật
`LOGICLAB_LEGACY_RUNTIME_ENABLED=true` là một lựa chọn tường minh và **không**
thuộc quy trình tĩnh universal.

## Khởi động nhanh trên Windows

Yêu cầu: Python 3.12, Git và Node.js 20+.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
npm --prefix ui ci
npm --prefix ui run build
Copy-Item .env.logiclab.example .env.logiclab
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
```

Đặt giá trị vừa sinh vào `LOGICLAB_API_TOKEN` trong `.env.logiclab`, sau đó:

```powershell
.\.venv\Scripts\logiclab.exe serve
```

Mở `http://127.0.0.1:8088`, chọn **Unlock API**, rồi nộp một URL Git công khai
kèm đúng commit SHA của nó. Ứng dụng tự áp dụng Alembic migration. File ví dụ
cấu hình sẵn SQLite; nếu muốn dùng PostgreSQL, hãy thay `LOGICLAB_DATABASE_URL`
hoặc khởi động control database đi kèm:

```powershell
docker compose -f docker-compose.logiclab.yml up -d
```

Phiên phân tích repository được lưu bền vững trước khi công việc bắt đầu, và
endpoint HTTP trả về `202`. Server sẽ chạy job có giới hạn ở nền. Nếu tiến trình
dừng trước khi một job trong hàng đợi kịp chạy, hãy tiếp tục nó bằng:

```powershell
.\.venv\Scripts\logiclab.exe analysis-worker
```

## Kiểm chứng

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests migrations
.\.venv\Scripts\python.exe -m pytest --cov=logiclab
npm --prefix ui test -- --run
npm --prefix ui run build
```

Các route API chính nằm dưới `/v1/repository-analyses`; `/health` là public, còn
mọi route dữ liệu `/v1` đều yêu cầu bearer token đã cấu hình hoặc cookie phiên
HttpOnly đã trao đổi.

## Giới hạn hiện tại

“Universal” nghĩa là **độc lập với repository và stack**, chứ không phải không
giới hạn hay không an toàn. Những điều sau đây cố ý chưa được hỗ trợ trong bản
này:

- Repository riêng tư và các forge host tuỳ ý.
- Repository vượt quá ngân sách truyền tải hoặc snapshot đã cấu hình.
- Phân giải ngữ nghĩa đầy đủ cho mọi ngôn ngữ.
- Thực thi động các file build tuỳ ý.

Quan trọng hơn, cần nói rõ hệ thống này **hiện chưa làm** ba việc mà tên gọi dễ
gây hiểu nhầm:

1. **Chưa tự dựng lab cho repository tuỳ ý.** Docker lab và orchestrator chỉ
   phục vụ một mục tiêu TLS đã được biên soạn sẵn, và nằm sau cờ legacy đang
   tắt. Luồng universal không dựng môi trường chạy cho repository bạn nộp vào.
2. **Chưa phát hiện lỗ hổng.** Nó sinh ra *claim mô tả* — thành phần, symbol,
   endpoint, hệ thống build, đường dẫn test, mức năng lực — chứ không phải
   *phát hiện bảo mật*. Vai trò `security_domain_mapper` lập bản đồ các entry
   point; nó không phán xét entry point đó có lỗ hổng hay không.
3. **Các "vai trò" không phải agent theo nghĩa LLM.** Chúng là hàm Python tất
   định. Thành phần LLM duy nhất là proposer tuỳ chọn, mặc định tắt.

Những vùng chưa hỗ trợ luôn hiện diện trong diagnostics và coverage, thay vì bị
đoán bừa.
