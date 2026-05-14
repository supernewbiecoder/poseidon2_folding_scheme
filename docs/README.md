# Giao thức chứng minh lưu trữ trong Engram
***Mục tiêu: Chuyển đổi cơ chế chứng minh lưu trữ hiện tại để phù hợp với những máy tính có cấu hình thấp hơn.***

## Tổng quan hệ thống
Hệ thống được chia thành 6 layers:
```
1. Prover (Storage node): Thực hiện thuật toán VDF (chứng minh thời gian lưu trữ) + tạo bằng chứng chứng minh lưu trữ dựa vào (folding scheme + Spartan) và sử dụng poseidon2 để tối ưu hóa cho RAM của máy tính
2. DVN (Delegated Verification Network): Mạng xác minh được ủy quyền với cơ chế đồng thuận ủy ban t-of-n
3. FROST (Threshold Schnorr Signatures): Chữ ký Schnorr ngưỡng chịu lỗi Byzantine
4. DA (Data Availability Layer): Khả dụng dữ liệu với lưu trữ tạm thời và thời gian giải quyết tranh chấp
5. FISHERMEN (Watcher Nodes): Mạng lưới phát hiện gian lận ngoài chuỗi độc lập
6. Lớp 6 (Bitcoin L1): Lớp thanh toán với xác thực OP_CHECKSIG
```

Note: A separate genesis setup (Layer 0) lives under `Layers_of_PoSt/Layer_0_genesis_setup` and simulates generation and distribution of public parameters (verifier keys / public params). Layers 1 and 2 read those parameters produced by Layer 0.

---
## 1. Lớp 1: Prover
**Mục tiêu**: Tạo bằng chứng chứng minh lưu trữ dữ liệu trong khoảng thời gian cố định
**Yêu cầu về cơ chế**: Cơ chế phải được tinh chỉnh sao cho yêu cầu về phần cứng của Prover không quá lớn.
**Đơn dữ liệu**: Dữ liệu được tổ chức với đơn vị nhỏ nhất là shard
## 💻 Yêu cầu Phần cứng (Hardware Requirements)

Kiến trúc Engram được thiết kế để hoạt động tối ưu trên các thiết bị cá nhân phổ thông bằng cách tách rời dung lượng dữ liệu khỏi yêu cầu bộ nhớ (RAM) và vô hiệu hóa lợi thế của xử lý song song.

| Linh kiện | Thông số Khuyến nghị | Chi tiết Kỹ thuật |
|:---|:---|:---|
| **RAM** | **8 GB** (Tiêu thụ thực tế ~2 GB) | Sử dụng hằng số bộ nhớ thấp nhờ Folding Scheme (Nova). |
| **CPU** | **Intel i5+ / Ryzen 5+ / Apple M1+** | Ưu tiên hiệu năng đơn luồng (Single-thread) cho VDF tuần tự. |
| **GPU** | **Không yêu cầu** (Integrated GPU) | Cơ chế chống song song hóa vô hiệu hóa lợi thế của GPU. |
| **Ổ cứng (Storage)** | **512 GB SSD** (Chuẩn NVMe) | Tối ưu hóa I/O cho việc đọc Shard dữ liệu thô. |
| **Mạng (Network)** | **Băng thông > 50 Mbps** | Chỉ cần truyền tải Proof gọn nhẹ (vài chục KB). |

> **💡 Đặc điểm cốt lõi:** Hệ thống ưu tiên sự công bằng phần cứng (Hardware Fairness).

### 1.1 Xây dựng merkle tree
**Tổng quan**: Prover phải xây dựng cây merkle tree để chứng minh lưu trữ trong thời gian cố định, và các node kiểm chứng sẽ so sánh bằng chứng ấy với merkle root mà prover đã commit trước đó để xác minh bằng chứng hợp lệ
**Mục tiêu**: Cây merkle tree được xây dựng ***đúng 1 lần mỗi khi Prover tiếp nhận yêu cầu lưu trữ từ khách hàng***. Và phải đảm bảo cây merkle tree ***không thể bị xóa đi trong quá trình Prover lưu trữ dữ liệu***.
Để đảm bảo 2 yêu cầu trên, cây merkle tree phải được thiết kế sao cho:
- Thời gian tạo merkle tree là đủ lâu với bất kì phần cứng nào, lâu tới mức Prover gian lận sẽ ***không thể nộp bằng chứng đúng hạn***. 
- Các Prover với cấu hình tối thiểu (như đã được đề xuất) có thể tạo merkle tree.
#### 1.1.1 Poseidon2 - CBC sealing
Để đảm bảo cây merkle tree được xây dựng với 2 yêu cầu trên, em đề xuất thuật toán băm Poseion2 - CBC sealing.
```
S[1] = Poseidon2(Data[1], Prover_ID, IV)
S[n]= Poseidon2(S[n-1],Data[n], Prover_ID)
```
Trong đó:
```IV```: Initial Vector: (giá tị IV nên là epoch hiện tại) với mục đích là nếu một Prover được yêu cầu phải lưu trữ 2 bản copy thì Merkle tree sinh ra từ 2 yêu cầu đó phải khác nhau (tránh việc Prover chỉ lưu trữ 1 bản)

> Lưu ý: Thuật toán băm này sẽ được áp dụng cho tầng lá của cây merkle tree, còn đối với tầng cao hơn, thì cây merkle tree sẽ được xây dựng như bình thường

#### 1.1.2 Merkle forest (rừng merkle)
**Mục tiêu**: mỗi một prover sẽ nên và chỉ nên commit một cam kết duy nhất lên trên chuỗi để tiết kiệm bộ nhớ onchain.
![ảnh minh họa](./img/merkle_forsest_gan_hoan_chinh.png)
### 1.2 Challange (thử thách của chuỗi)
**Mục tiêu**: Thử thách này có thể hoàn thành được khi và chỉ khi node đấy không gian lận và node đấy đạt đủ yêu cầu cấu hình tối thiểu.
#### 1.2.1 Nguồn sinh thử thách (challange seed)
**Yêu cầu**: Nguồn sinh thử thách phải là ngẫu nhiên để tránh prover gian lận.
- **Sử dụng Bitcoin L1 làm Beacon**: Cứ mỗi đầu Epoch (ví dụ: mỗi 1 giờ), hệ thống sẽ lấy Mã băm của Block Bitcoin mới nhất (Block Hash) kết hợp với ID của Prover để làm Hạt giống ngẫu nhiên (Seed).
- **Ánh xạ Shard**: Hạt giống này sẽ được đưa vào một Hàm giả ngẫu nhiên (PRNG). Đầu ra của hàm này sẽ chỉ định chính xác $N$ chỉ số ngẫu nhiên (Ví dụ: Shard số 15, Shard số 9.023, Shard số 45.112) mà Prover bắt buộc phải chứng minh trong Epoch này.
#### 1.2.2 Cơ chế Lấy mẫu Xác suất (Probabilistic Sampling)
**Yêu cầu**: Cơ chế sinh thử thách phải tránh việc kiểm tra toàn bộ prover để tiết kiệm chi phí tính toán nhưng cũng phải đảm bảo prover sẽ không thể gian lận.

- Thay vì kiểm tra 100%, Thử thách chỉ yêu cầu Prover lấy ra một số lượng nhỏ (ví dụ $N = 100$ Shards) để kiểm tra.
- Logic bảo mật: Nếu Prover lén xóa đi 10% dữ liệu để tiết kiệm ổ cứng, xác suất để Prover "vượt qua" bài kiểm tra ngẫu nhiên 100 Shards mà không trúng vào phần đã xóa là: $(1 - 0.1)^{100} \approx 0.0026\%$. 
Nghĩa là, chỉ cần Prover xóa một phần rất nhỏ dữ liệu, họ gần như chắc chắn 99.99% sẽ bị bắt quả tang và bị phạt (Slash).

#### 1.2.3 Luồng Chứng minh Lưu trữ Liên tục (PoSt Flow)
Khi nhận được Thử thách yêu cầu kiểm tra Shard thứ $i$, Prover sẽ thực hiện các bước sau (và đưa vào mạch ZK để gập):

- **Truy xuất dữ liệu**: Prover truy xuất từ ổ cứng các mảnh dữ liệu cần thiết cho bước $i$ bao gồm: Dữ liệu gốc ($D_i$), mã băm của khối liền trước ($S_{i-1}$), lá Merkle hiện tại ($S_i$) và Đường dẫn Merkle (Merkle Path) của lá thứ $i$.
- **Giải quyết Ràng buộc Mạch (Circuit Constraints)**: Tại mỗi bước gập (Fold), mạch $m_{aug}$ sẽ đánh giá đồng thời 2 điều kiện bắt buộc (Constraints) sau:
    - **Ràng buộc Tri thức (Chứng minh tính toàn vẹn của $D_i$)**: Mạch kiểm tra tính hợp lệ của phương trình niêm phong:
$\text{Poseidon2}(S_{i-1}, D_i, \text{Prover\_ID}) == S_i$ (với $i > 1$)
hoặc $\text{Poseidon2}(IV, D_1, \text{Prover\_ID}) == S_1$ (với $i = 1$).
(Điều này ép buộc Prover phải cung cấp đúng $D_i$ làm Private Input, chứng minh họ không xóa dữ liệu gốc).
    - **Ràng buộc Vị trí (Chứng minh sự tồn tại của $S_i$)**: Mạch sử dụng $S_i$ kết hợp với Merkle Path để băm tuần tự lên trên. Kết quả cuối cùng phải khớp hoàn toàn với Master Merkle Root mà Prover đã cam kết (commit) trên chuỗi từ trước.
- Tổng hợp Bằng chứng: Thay vì tạo ra $N$ bằng chứng rời rạc, quá trình tổng hợp được chia làm 2 giai đoạn để tối ưu hóa hiệu năng:
    - **Giai đoạn Gập (Nova Folding)**: Prover sử dụng thuật toán Nova để gập (fold) liên tiếp $N$ bước kiểm tra trạng thái lại với nhau. Kết quả của quá trình này tạo ra một Trạng thái Gập cuối cùng (Final Folded Instance) duy nhất đại diện cho toàn bộ $N$ bước kiểm tra.
    - **Giai đoạn Nén (Spartan Wrapper)**: Sau khi xác minh việc gập nội bộ thành công, Prover sử dụng thuật toán chứng minh ZK-SNARK (cụ thể là Spartan) làm lớp bọc ngoài (Wrapper). Spartan sẽ biên dịch Trạng thái Gập cuối cùng thành một bằng chứng siêu nén (chỉ vài chục KB) với thời gian kiểm chứng hằng số $O(1)$.
    - **Đệ trình (Submission)**: Bằng chứng Spartan tối hậu này sau đó được gửi lên mạng lưới xác minh (Layer 2 / DVN) để các node kiểm duyệt, từ đó hoàn thành thử thách Epoch.
### 1.3 Chi tiết luồng
1. Khi prover tham gia hệ thống: prover tải public parameter từ trên mạng lưới chung. Để xác định mạng public parameter là đúng, prover phải tự đối chiếu với hệ thống gốc.
2. Prover nhận dữ liệu yêu cầu từ thư mục shard của Layer 1, hiện được tổ chức theo cấu trúc `Layers_of_PoSt/Layer_1/prover-rust/sample_shards/`.
3. Prover niêm phong dữ liệu và cam kết dữ liệu (Poseidon2-CBC) và gửi bản cam kết của prover lên chain.
4. Prover lấy seed thử thách dựa vào head của chain.
5. Prover tự tính challange, sau đó dùng giao thức nova để gập các proof và instance.
6. Prover bọc kết quả giao thức nova ở bước cuối cùng, ghi metadata đầu ra vào `Layers_of_PoSt/Layer_1/output/prover_<id>/input.json`, rồi gửi kết quả lên Layer2.

#### 1.3.1 Thông tin meta data prover gửi lên Layer2
1. Thông tin định danh (Engram meta data)
    - prover_id: Định danh duy nhất của node thực hiện lưu trữ
    - epoch: Chu kỳ thời gian hiện tại (tính theo giờ) mà bằng chứng này có hiệu lực.
    - bitcoin_hash_used: Mã băm của block Bitcoin được dùng làm hạt giống (seed) để tạo thử thách ngẫu nhiên.
    - shards_proven: Danh sách các chỉ số Shard cụ thể đã được chọn để chứng minh trong bước này.
2. Tham số đối soát toán học:
    - expected_z0: Giá trị Merkle Root ban đầu (trước khi thực hiện $N$ bước thử thách).
    - expected_zi: Giá trị Merkle Root cuối cùng sau khi đã gập đủ $N$ bước qua mạch Nova.
3. Tính toàn vẹn của bằng chứng:
    - spartan_proof_hash: Mã băm SHA-256 của file compressed_proof.bin. Điều này ngăn chặn việc tráo đổi bằng chứng nhị phân sau khi đã xuất metadata.
    - proof_artifact: Đường dẫn trỏ tới file nhị phân chứa bằng chứng thực tế.
### 1.4 Chi phí tính toán của Prover
#### 1.4.1 Chi phí niêm phong ban đầu
Chi phí này tốn CPU nhất nhưng chỉ thực hiện một lần duy nhất cho mỗi Shard dữ liệu.
Công thức tổng quát cho thời gian niêm phong $T_{seal}$:$$T_{seal} = N \times (s \times t_{hash} + K \times t_{vdf})$$
$N$: Tổng số lượng Shard.
$s$: Kích thước mỗi Shard (tính theo số lượng Field Elements).
$t_{hash}$: Thời gian thực hiện một hàm băm Poseidon2 trên một phần tử.
$K$: Hệ số lặp (VDF delay) để tạo độ trễ vật lý.
$t_{vdf}$: Thời gian thực hiện một vòng lặp VDF.

Đặc điểm: Do tính chất CBC, $T_{seal}$ là hàm tuyến tính theo $N$. Việc tăng số nhân CPU (Multi-core) không giúp giảm $T_{seal}$ cho một bản sao dữ liệu duy nhất.
#### 1.4.2 Chi phí Chứng minh định kỳ (PoSt Proving Cost)
Đây là chi phí Prover phải trả mỗi Epoch để duy trì quyền lợi. Chi phí này được tối ưu hóa để cực thấp.
Công thức tổng quát cho thời gian tạo bằng chứng $T_{prove}$:$$T_{prove} = \underbrace{n \times (t_{fold} + t_{hash\_jit})}_{\text{Folding Phase}} + \underbrace{t_{spartan}}_{\text{Snark Phase}}$$
$n$: Số lượng Shard bị thử thách (ví dụ $n=100$).
$t_{fold}$: Thời gian gập một bước Nova (phụ thuộc vào số lượng Constraints $m_{aug} \approx 3,300$).
$t_{hash\_jit}$: Thời gian tính toán lại đường dẫn Merkle (Just-in-Time).
$t_{spartan}$: Thời gian Spartan nén trạng thái gập cuối cùng thành SNARK.
#### 1.4.3 Chi phí Bộ nhớ (Memory/RAM Cost)
Đây là ưu điểm lớn nhất của Engram. Nhờ kiến trúc Folding, bộ nhớ RAM không phụ thuộc vào tổng dung lượng dữ liệu lưu trữ $D_{total}$.
$$Memory_{prover} \approx Memory_{OS} + Memory_{Nova}(m_{aug})$$
$Memory_{prover} \approx Constant$: Với $m_{aug} \approx 3,300$, lượng RAM tiêu thụ thực tế cho tiến trình mật mã luôn duy trì dưới 2 GB, bất kể Prover đang lưu trữ 100 GB hay 10 TB dữ liệu.

## Lớp 2: Mạng lưới Xác minh Phi tập trung / DVN - Decentralized Verifier Network
### 1. Tổng quan
1. Vai trò: Mạng lưới Bitcoin cực kỳ bảo mật nhưng lại rất chậm (10 phút/block) và chi phí lưu trữ dữ liệu On-chain đắt đỏ. Nếu hàng nghìn Prover cứ mỗi giờ lại gửi thẳng một file bằng chứng lên Bitcoin, mạng lưới sẽ tắc nghẽn và phí giao dịch sẽ "đốt sạch" lợi nhuận của thợ đào.
Vì vậy, Layer 2 (DVN) ra đời như một lớp trung gian (Middleware) đóng vai trò:
    - Chấm bài siêu tốc: Xác minh toán học của hàng nghìn bằng chứng ZK-SNARK chỉ trong vài phần nghìn giây.
    - Gom cụm (Aggregation): Gom hàng nghìn kết quả kiểm chứng thành một xác nhận duy nhất.
    - Chốt sổ (Settlement): Gửi kết quả cuối cùng lên L1 (Bitcoin) một cách cực kỳ rẻ mẻ và an toàn.
2. Đầu vào của Layer2: Layer 2 sẽ ngồi chờ và tiếp nhận kết quả từ Layer 1 nộp lên. Các dữ liệu này bao gồm:
    - File bằng chứng: compressed_proof.bin (kết quả nén của thuật toán Spartan).
    - Metadata: File input.json (chứa Prover ID, Epoch, Bitcoin Seed, Root cũ $z_0$, Root mới $z_i$).
3. Quy trình vận hành cốt lõi: Khi nhận được kết quả từ prover, các Node thuộc Layer 2 sẽ thực hiện các bước sau:
    - Kiểm tra metadata: node DVN sẽ kiểm tra logic cơ bản
        - Bằng chứng này nộp có đúng hạn (Epoch) không?
        - Hạt giống (Bitcoin Hash) Prover dùng có đúng với Hash L1 hiện tại không?
        - Prover có tự ý kiểm tra sai Shard so với yêu cầu của Seed không?
    - Kiểm chứng Toán học Không Cần Tin Cậy (Trustless Verification)
        - DVN nạp bộ Tham số Công khai (Public Parameters - PP) chuẩn mà mạng lưới đã thống nhất từ trước.
        - Chạy hàm verify() của Spartan lên file compressed_proof.bin.
    - Đồng thuận và Ký đa chữ ký (Consensus & Threshold Signature)

## Chứng thực (Attestation) và Chữ kí(Signatures)

**Chứng thực** là cam kết có chữ ký ràng buộc bằng chứng đã được xác minh với siêu dữ liệu của nó.

- **Attestation** = signed proof metadata, typically `z0`, `zi`, `spartan_proof_hash`, and `epoch`
- **FROST signature** = threshold Schnorr signature used in the full 6-layer stack under `layers/orchestrator.py`

The full stack signing layer is **FROST**.

## 🚀 Quick Start

### Prerequisites

- **Rust** 1.70+ with Cargo
- **Circom** 2.1.5
- **SnarkJS** 0.6.0+
- **Node.js** 14+
- **Python** 3.8+
- **WSL** (Windows) or Linux (macOS/Linux)

### Installation

```bash
# Clone and setup
git clone <repo>
cd poseidon2_folding_scheme

# Install Python dependencies
pip install -r requirements.txt

# Pre-check Rust compilation
cd prover-rust && cargo check && cd ..

# Pre-compile Circom circuits (optional, auto-compiled on first run)
cd circuits-circom && circom spartan_wrapper.circom --r1cs && cd ..
```

### Run Full Pipeline

```bash
# Start orchestrated pipeline (interactive)
./run_pipeline.sh
# (alias of ./run_full_protocol_pipeline.sh)

# Enter shard count, challenge count, and optional directory when prompted:
# > 4
# > 4
# > C:\path\to\shards
```

**Output Sample:**
```
[LAYER 1] PROVER: Spartan Compression (Nova + Poseidon2)
[LAYERS 2-6] FULL STACK: DVN -> FROST -> DA -> Fishermen -> L1
LAYER 3: FROST -> Threshold Schnorr Signature
✅ FROST aggregated signature: 64 bytes

LAYER 6: Bitcoin L1 -> On-Chain Settlement
✅ Full stack pipeline finished successfully

⚡ ENERGY REPORT
==========================================
Nova Init                       0.42 J
Nova Folding                    5.18 J
Spartan Setup                   1.90 J
Spartan Prove                   9.95 J
Spartan Verify                  0.63 J
Export + Attestation            0.12 J
DVN Consensus + FROST           0.31 J
Fishermen + DA + L1             0.44 J

📊 BENCHMARK RESULTS
==========================================
BUILD RUST                      4.2 sec
RUNTIME ONLY (Prove + Verify)  14.5 sec
FULL STACK (L1 SETTLED)        16.1 sec
FROST SIGN                      0.02 sec
SETTLEMENT CONFIRM              0.7 sec
```

---

## 🔐 Trust Model

| Attack | Blocked By | Mechanism |
|--------|-----------|-----------|
| **False Proof** | Layer 1 Spartan verification | Invalid proof won't pass native field check |
| **Fake Attestation (Full Stack)** | Layer 3 FROST threshold signing | Attacker must control threshold committee shares |
| **Proof Tampering** | Layer 2 hash binding | Altered proof breaks signature |
| **Commitment Swapping** | Layer 4 Circom constraints | Commitment hardcoded in circuit |
| **Replay** | Epoch + Domain separation | Each proof tied to specific epoch/domain |

---

## 📊 Performance Metrics

Full-stack benchmark (DVN + FROST + DA + Fishermen + L1) on Ubuntu 22.04, Ryzen 5950X:

```
Stage                          Time        Proof Size
───────────────────────────────────────────────────────
Spartan Prove (cold)          7.3 sec     128 KB (compressed)
Spartan Verify (native)       0.1 sec     —
DVN Consensus                 0.1 sec     —
FROST Threshold Sign          0.02 sec    64 bytes
DA + Fishermen + L1           0.7 sec     —
───────────────────────────────────────────────────────
TOTAL (cold)                 ~16 sec      128 KB (compressed)
TOTAL (warm)                 ~8 sec       128 KB (compressed)
```

---

## 📂 Project Structure

```
poseidon2_folding_scheme/
├── prover-rust/                    # Nova + Spartan prover
│   ├── Cargo.toml                  # Dependencies (nova-snark, sha2)
│   ├── src/
│   │   ├── main.rs                 # CLI entry point
│   │   └── core/
│   │       ├── circuit.rs          # R1CS circuit (Merkle proof)
│   │       ├── proof_engine.rs     # Nova + Spartan + attestation export
│   │       ├── poseidon2.rs        # Poseidon2 gadget
│   │       └── constants.rs        # Poseidon2 matrices
│   └── target/release/engram-prover
│
├── layers/                         # Full-stack protocol layers (DVN/FROST/DA/Fishermen/L1)
├── scripts/                        # Helper scripts
│
├── run_pipeline.sh                 # Default entrypoint (aliases full FROST pipeline)
├── run_full_protocol_pipeline.sh   # Full-stack orchestrator (DVN + FROST + DA + Fishermen + L1)
├── ARCHITECTURE.md                 # Full technical details
├── requirements.txt                # Python deps
└── README.md                       # This file
```

---

## 🧪 Testing

```bash
# Full pipeline test
./run_pipeline.sh

# Unit tests
cd prover-rust && cargo test --release
```

New input mode:

```bash
# Binary now reads shard_0.txt ... shard_{n-1}.txt
ENGRAM_SHARD_COUNT=4 ENGRAM_SHARD_DIR=./data ./prover-rust/target/release/engram-prover
```

---

## 🚨 Troubleshooting

**Cargo build fails:**
```bash
cd prover-rust && cargo clean && cargo build --release
```

**Circom compilation errors:**
```bash
cd circuits-circom && circom spartan_wrapper.circom --r1cs --wasm
```

---

## 📚 References

- [Nova Folding Scheme](https://eprint.iacr.org/2021/370.pdf)
- [Poseidon Hash](https://eprint.iacr.org/2023/350.pdf)
- [Circom Documentation](https://docs.circom.io/)
- [SnarkJS](https://github.com/iden3/snarkjs)
- [Nova-Snark](https://github.com/microsoft/nova)

---

**Status:** Production-Like PoC (not yet audited)
