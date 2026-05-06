# Project Overview

Tài liệu này giải thích cách project hiện tại hoạt động, file nào làm gì, hàm nào nằm ở đâu, và chạy hệ thống như thế nào.

Mục tiêu của project là mô phỏng một hệ thống Proof-of-Space-Time theo hướng:
- Ai cũng có thể là storage provider.
- Provider phải chứng minh đã lưu dữ liệu trong một khoảng thời gian.
- Proof nên dùng folding scheme + Poseidon2 để kiểm tra tính khả thi.
- Output cần đủ ngắn gọn để hướng tới lưu trên Bitcoin.

---

## 1. Tổng Quan Về Các Thành Phần Trong Project

Project được chia thành 4 lớp chính:

### 1.1 Lớp Rust prover

Thư mục: `prover-rust/`

Đây là nơi làm phần nặng nhất:
- Nhận dữ liệu shard đầu vào.
- Dựng Merkle tree bằng Poseidon2.
- Tạo các bước PoSt để chạy Nova folding.
- Nén proof bằng Spartan.
- Xuất `input.json` cho Circom.
- Xuất committee attestation Ed25519 để chứng minh Spartan proof đã được verify ở phía Rust.

### 1.2 Lớp Circom wrapper

Thư mục: `circuits-circom/`

Đây là lớp bọc Groth16 trên BN254:
- Nhận `input.json` do Rust sinh ra.
- Kiểm tra binding giữa các giá trị public/witness.
- Sinh Groth16 proof.
- Verify Groth16 proof bằng `snarkjs`.

### 1.3 Lớp orchestration scripts

Thư mục: `scripts/`

Đây là lớp ghép pipeline:
- Chạy Rust prover.
- Kiểm tra attestation.
- Chạy Circom + snarkjs.
- Xuất benchmark.

### 1.4 Lớp tài liệu và cấu hình

Các file gốc như `README.md`, `ARCHITECTURE.md`, `requirements.txt`, `.gitignore`, `run_pipeline.sh` giúp:
- Giải thích cách chạy.
- Ghi lại kiến trúc.
- Quản lý dependency.
- Loại trừ artifact sinh ra.

---

## 2. Tổng Quan Về Luồng Chạy Của Hệ Thống

Luồng hiện tại đi theo 2 stage chính:

### Stage A: Spartan + committee attestation

1. Người dùng nhập danh sách shard.
2. Rust prover dựng cây Merkle từ shard.
3. Rust tạo các step circuit cho các shard được chọn.
4. Nova folding gộp các step lại.
5. Spartan compression nén proof.
6. Proof được verify native trong Rust.
7. Rust hash proof và ký committee attestation Ed25519.
8. Rust xuất `circuits-circom/input.json`.

### Stage B: Groth16 wrapper

1. Script verify attestation trong `input.json`.
2. Nếu chữ ký hợp lệ, Circom witness được tạo.
3. Groth16 proof được sinh bằng `snarkjs`.
4. Groth16 proof được verify lại.
5. Số đo kích thước proof và thời gian được in ra.

### Orchestrator

File `run_pipeline.sh` nối 2 stage trên lại thành một pipeline hoàn chỉnh.

---

## 3. Tổng Quan Về Mục Đích Của Các File

### 3.1 File gốc và tài liệu

- `README.md`: tài liệu chính cho người dùng.
- `ARCHITECTURE.md`: giải thích trust boundary và kiến trúc sản xuất giả lập.
- `PROJECT_OVERVIEW.md`: tài liệu bạn đang đọc.
- `requirements.txt`: dependency Python, chủ yếu để verify attestation.
- `.gitignore`: loại bỏ artifact build/proof.

### 3.2 File điều phối chạy

- `run_pipeline.sh`: pipeline tổng.
- `scripts/stage_spartan.sh`: chạy stage Rust và chuẩn bị input cho wrapper.
- `scripts/stage_wrapper_groth16.sh`: verify attestation rồi chạy Groth16.
- `scripts/verify_attestation.py`: verify toàn bộ chữ ký Ed25519 của committee.
- `scripts/build_bridge.sh`: helper cho Circom bridge.

### 3.3 File Rust prover

- `prover-rust/Cargo.toml`: dependency Rust.
- `prover-rust/src/main.rs`: CLI entrypoint.
- `prover-rust/src/core/circuit.rs`: dữ liệu sector + circuit PoSt.
- `prover-rust/src/core/poseidon2.rs`: gadget Poseidon2 trong circuit.
- `prover-rust/src/core/proof_engine.rs`: folding + Spartan + export JSON + attestation.

### 3.4 File Circom

- `circuits-circom/spartan_wrapper.circom`: wrapper circuit.
- `circuits-circom/input.json`: input/witness JSON do Rust sinh.
- `circuits-circom/proof.json`: Groth16 proof output.
- `circuits-circom/public.json`: public signals cho verifier.

---

## 4. Tổng Quan Về Các Hàm Trong Các File

Mình chỉ liệt kê các hàm quan trọng và hàm mà hệ thống thật sự dùng.

### 4.1 `prover-rust/src/main.rs`

#### `main()`

Mục đích:
- Là entrypoint của Rust prover.
- Nhận input shard từ user.
- Tạo `DataSector`.
- Tạo `PoStStepCircuit` khởi tạo.
- Khởi tạo `PostProofEngine`.
- Sinh danh sách challenge.
- Gọi `engine.run_pipeline(...)`.

Cách chạy:
- Chạy gián tiếp thông qua `cargo run --release` hoặc binary build ra.
- Script `scripts/stage_spartan.sh` gọi binary này tự động; binary cũng đọc `ENGRAM_SHARDS` hoặc tham số CLI đầu tiên.

### 4.2 `prover-rust/src/core/circuit.rs`

#### `sbox(x: Fr) -> Fr`

Mục đích:
- Tính S-box của Poseidon2 ở native field.
- Dùng công thức `x^5`.

Cách chạy:
- Không gọi trực tiếp từ CLI.
- Được `native_poseidon2()` dùng bên trong.

#### `native_poseidon2(left: Fr, right: Fr) -> Fr`

Mục đích:
- Hash native bằng Poseidon2 để dựng Merkle tree.

Cách chạy:
- Được `DataSector::new()` gọi khi dựng leaf và node.

#### `DataSector::new(raw_shards: Vec<&str>) -> Self`

Mục đích:
- Chuyển shard text thành field elements.
- Pad lên 8 shard.
- Dựng cây Merkle.
- Tính commitment root.

Cách chạy:
- Được `main()` gọi ngay sau khi user nhập input.

#### `DataSector::get_proof(index: usize) -> (Fr, Vec<Fr>, Vec<Fr>)`

Mục đích:
- Trả về dữ liệu shard, Merkle path, và path indices cho một leaf.

Cách chạy:
- Được `main()` gọi để tạo step circuit cho các shard được challenge.

#### `PoStStepCircuit::synthesize(...)`

Mục đích:
- Định nghĩa constraint của một bước PoSt.
- Kiểm tra leaf hash, từng Merkle layer, challenge index, và root.
- Xuất state tiếp theo cho Nova folding.

Cách chạy:
- Không gọi trực tiếp.
- Nova/Spartan framework gọi khi tạo proof.

### 4.3 `prover-rust/src/core/poseidon2.rs`

#### `Poseidon2Gadget::new(...)`

Mục đích:
- Khởi tạo gadget Poseidon2 trong circuit với state đầu vào.

Cách chạy:
- Được `PoStStepCircuit::synthesize()` gọi khi cần hash leaf hoặc node.

#### `Poseidon2Gadget::hash(...)`

Mục đích:
- Thực hiện toàn bộ vòng Poseidon2 trong constraint system.

Cách chạy:
- Gọi qua `Poseidon2Gadget::new(...).hash()`.

### 4.4 `prover-rust/src/core/proof_engine.rs`

#### `PostProofEngine::new(primary_circuit: &C1) -> Self`

Mục đích:
- Tạo public parameters cho Nova/Spartan.

Cách chạy:
- Được `main()` gọi qua `PostProofEngine::new(&init_circuit)`.

#### `PostProofEngine::run_pipeline(&self, steps: Vec<C1>, z0: Vec<Fr>)`

Mục đích:
- Chạy toàn bộ pipeline proof.
- Khởi tạo recursive SNARK.
- Folding từng step.
- Nén proof bằng Spartan.
- Verify compressed proof.
- Gọi export ra JSON.

Cách chạy:
- Được `main()` gọi trực tiếp.
- Đây là hàm trung tâm nhất của Rust prover.

#### `PostProofEngine::export_for_wrapper(...)`

Mục đích:
- Chuyển proof sang JSON phù hợp cho Circom.
- Hash proof bằng SHA-256.
- Tạo attestation message.
- Ký Ed25519.
- Ghi `circuits-circom/input.json`.

Cách chạy:
- Chỉ được gọi nội bộ từ `run_pipeline()` sau khi Spartan verify xong.

### 4.5 `scripts/verify_attestation.py`

#### `verify_attestation(input_json_path, strict=True)`

Mục đích:
- Đọc `input.json`.
- Lấy `expected_z0`, `spartan_proof_hash`, `epoch`, `domain_sep`, `pubkey`, `signature`.
- Rebuild message.
- Verify Ed25519 signature.

Cách chạy:
- Chạy trực tiếp bằng:
  `python3 scripts/verify_attestation.py circuits-circom/input.json`

#### `__main__`

Mục đích:
- Cho phép file này chạy như CLI tool.

Cách chạy:
- Script exit `0` nếu signature hợp lệ.
- Exit `1` nếu sai.

### 4.6 `scripts/stage_spartan.sh`

#### `get_time_ms()`

Mục đích:
- Lấy thời gian ms để benchmark.

Cách chạy:
- Chỉ là helper nội bộ.

#### Luồng chính của script

Mục đích:
- Build Rust binary.
- Chạy prover với input shards.
- In ra `SPARTAN_BUILD_MS` và `SPARTAN_RUNTIME_MS`.

Cách chạy:
- `./scripts/stage_spartan.sh 9 ./prover-rust/sample_shards 7`

### 4.7 `scripts/stage_wrapper_groth16.sh`

#### `get_time_ms()`

Mục đích:
- Benchmark cho setup/prove/verify.

#### Luồng chính của script

Mục đích:
- Tạo Circom WASM/R1CS/zkey nếu thiếu.
- Verify attestation trước.
- Tạo witness.
- Groth16 prove.
- Groth16 verify.
- In `WRAPPER_SETUP_MS`, `WRAPPER_PROVE_MS`, `WRAPPER_VERIFY_MS`, `WRAPPER_PROOF_BYTES`.

Cách chạy:
- `./scripts/stage_wrapper_groth16.sh`

### 4.8 `run_pipeline.sh`

#### `get_time_ms()`

Mục đích:
- Đo wall-clock của toàn pipeline.

#### `parse_metric(key, payload)`

Mục đích:
- Tách `KEY=value` từ output của stage scripts.

Cách chạy:
- Dùng nội bộ để đọc benchmark metrics.

#### Luồng chính của script

Mục đích:
- Hỏi user nhập shard.
- Chạy stage Spartan.
- Chạy stage wrapper.
- Tính tổng thời gian.
- In báo cáo cuối cùng.

Cách chạy:
- `./run_pipeline.sh`

### 4.9 `scripts/build_bridge.sh`

#### Luồng chính của script

Mục đích:
- Đây là script giao diện đơn giản kiểu legacy để build Circom bridge và sinh proof.
- Nó interactive hơn pipeline mới.

Cách chạy:
- Chạy trực tiếp bằng bash nếu muốn thử luồng cũ.

---

## 5. Mục Đích Và Cách Chạy Từng Hàm / Luồng

### 5.1 Nếu bạn muốn chạy toàn bộ hệ thống

Chạy:

```bash
./run_pipeline.sh
```

Nó sẽ:
- Hỏi bạn nhập shard count, challenge count, và shard directory.
- Gọi stage Spartan.
- Gọi stage wrapper.
- In benchmark và proof size.

Lưu ý về chế độ non-interactive:

- Bạn có thể chạy không cần tương tác bằng cách đặt biến môi trường `ENGRAM_SHARDS` hoặc truyền tham số CLI cho binary Rust. Ví dụ:

```bash
# dùng run_pipeline (interactive script) nhưng chuyển biến môi trường trước
ENGRAM_SHARDS="shard1,shard2,shard3" ./run_pipeline.sh

# hoặc gọi trực tiếp Rust binary (không cần prompt)
ENGRAM_SHARDS="shardA,shardB" ./prover-rust/target/release/engram-prover

# hoặc truyền tham số CLI vào binary (thứ tự ưu tiên: ENGRAM_SHARDS > CLI arg > prompt)
./prover-rust/target/release/engram-prover "shard1,shard2,shard3"
```

Vì `main.rs` giờ chấp nhận `ENGRAM_SHARDS` hoặc tham số CLI đầu tiên, script `stage_spartan.sh` và `run_pipeline.sh` sẽ không kích hoạt prompt lặp lại.

### 5.2 Nếu bạn chỉ muốn chạy phần Rust prover

Chạy:

```bash
cd prover-rust
cargo run --release
```

Hoặc qua script:

```bash
./scripts/stage_spartan.sh 9 ./prover-rust/sample_shards 7
```

Kết quả:
- Sinh `circuits-circom/input.json`.
- Có committee attestation signature.

### 5.3 Nếu bạn chỉ muốn verify attestation

Chạy:

```bash
python3 scripts/verify_attestation.py circuits-circom/input.json
```

Kết quả:
- `0` nếu hợp lệ.
- `1` nếu thất bại.

### 5.4 Nếu bạn muốn chạy riêng wrapper Groth16

Chạy:

```bash
./scripts/stage_wrapper_groth16.sh
```

Kết quả:
- Verify committee attestation.
- Generate witness.
- Prove Groth16.
- Verify Groth16.

### 5.5 Nếu bạn muốn hiểu hàm nào được gọi bởi hàm nào

Luồng gọi chính là:

```text
run_pipeline.sh
  ├─ stage_spartan.sh
  │    └─ prover-rust/target/release/engram-prover
  │         └─ main()
  │              ├─ DataSector::new()
  │              ├─ DataSector::get_proof()
  │              ├─ PostProofEngine::new()
  │              └─ PostProofEngine::run_pipeline()
  │                    └─ export_for_wrapper()
  └─ stage_wrapper_groth16.sh
       ├─ verify_attestation.py
       ├─ generate_witness.js
       ├─ snarkjs groth16 prove
       └─ snarkjs groth16 verify
```

---

## 6. Ghi Chú Quan Trọng Về Trạng Thái Hiện Tại

- Project hiện đã là một mô phỏng rất gần production về mặt kiến trúc.
- Tuy nhiên, pipeline vẫn còn dạng batch / interactive ở lớp vận hành.
- Proof JSON hiện tại có thể chưa luôn nằm dưới ngưỡng 800 bytes nếu tính đúng artifact JSON text.
- Attestation hiện có, nhưng keypair vẫn chưa nằm trong HSM/KMS.
- Nếu dùng để làm product thật, bạn vẫn cần hardening thêm ở key management, replay protection, audit log, và CI/CD.

---

## 7. Cách Đọc Nhanh Nếu Bạn Mới Bắt Đầu

Nếu bạn muốn hiểu nhanh nhất, hãy đọc theo thứ tự này:

1. `README.md`
2. `run_pipeline.sh`
3. `scripts/stage_spartan.sh`
4. `prover-rust/src/main.rs`
5. `prover-rust/src/core/circuit.rs`
6. `prover-rust/src/core/proof_engine.rs`
7. `scripts/stage_wrapper_groth16.sh`
8. `scripts/verify_attestation.py`

---

## 8. Tóm Tắt Một Câu

Project này đang mô phỏng một PoST pipeline gồm Rust Nova/Spartan, attestation Ed25519, và wrapper Groth16; logic kiến trúc là đúng hướng, còn mức production thật thì vẫn cần hardening vận hành và bảo mật.
