# Mô phỏng Giao thức Engram: Proof of Space-Time với Nova Folding Scheme & Poseidon2

Dự án này là bản mô phỏng (Simulation) cho phần 3.4 của giao thức lưu trữ phân tán Engram. Nó giải quyết bài toán "bùng nổ ràng buộc" (Constraint Blowup) trong các hệ thống Zero-Knowledge Proof truyền thống bằng cách kết hợp **Poseidon2 Hash** và **Nova Folding Scheme**.

Thay vì tạo một mạch ZK khổng lồ để kiểm tra nhiều phân mảnh (Batching), kiến trúc này "gấp" (fold) từng bước kiểm tra lại với nhau, giúp kích thước mạch (Constraints) và kích thước bằng chứng luôn giữ ở mức hằng số `O(1)`.

---

## 📋 Cấu trúc Dự án

Dự án được viết bằng **Rust** để tối ưu hóa hiệu năng và tương thích với thư viện `nova-snark`.

```text
poseidon2_folding_scheme/
├── Cargo.toml                 # Quản lý thư viện và dependencies
└── src/
    ├── main.rs                # Logic chính: CLI, Merkle Tree, Folding Loop, Verify
    ├── constants.rs           # Chứa ma trận số học và hằng số vòng của Poseidon2 (GF(p))
    └── poseidon2_gadget.rs    # Định nghĩa mạch R1CS cho Poseidon2
```

---

## ⚙️ Yêu cầu Hệ thống & Cài đặt

### 1. Môi trường yêu cầu
- **Hệ điều hành**: Linux, macOS, hoặc Windows (qua **WSL2** - Khuyến nghị Ubuntu 22.04+).
- **RAM**: Tối thiểu 8GB (Khuyến nghị 16GB để build Rust mượt mà).
- **Rust Toolchain**: Phiên bản 1.70 trở lên.

### 2. Cài đặt Rust (Nếu chưa có)
Chạy lệnh sau trên terminal (hoặc WSL):
```bash
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
source $HOME/.cargo/env
```

### 3. Cài đặt Dependencies cho WSL/Linux
Để thư viện mật mã biên dịch thành công, bạn cần cài đặt các gói cơ bản:
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev clang
```

---

## Hướng dẫn Chạy Mô phỏng

**Bước 1:** Clone hoặc tải mã nguồn về máy, mở terminal tại thư mục gốc của dự án.

**Bước 2:** Chạy lệnh sau để biên dịch và thực thi (BẮT BUỘC dùng cờ `--release` để tối ưu hóa thời gian chạy của ZKP):
```bash
cargo run --release
```

**Bước 3:** Làm theo hướng dẫn trên màn hình CLI:
1. Nhập danh sách các phân mảnh dữ liệu (ví dụ: `shard1, shard2, image.png, config.json`).
2. Nhập số lượng vòng kiểm tra (Epochs) mong muốn (ví dụ: `3`).

---

## 📊 Tham số Thiết lập & Lý do (Rationale)

Mô phỏng này được thiết kế dựa trên các tham số có chủ đích nhằm phản ánh đúng môi trường lưu trữ Web3:

### 1. Độ sâu cây Merkle (Depth `d = 3`)
- **Thiết lập:** Hệ thống tự động đệm (padding) dữ liệu đầu vào lên thành 8 phân mảnh (shards).
- **Lý do:** Giữ độ sâu cây ở mức `d = 3` giúp người dùng dễ dàng theo dõi luồng dữ liệu (traceability) qua CLI mà không làm màn hình bị ngập trong hàng ngàn dòng log. Trong thực tế, hàm băm sẽ chạy với `d = 20` (chứa ~1 triệu shard) mà thời gian tăng thêm không đáng kể (tăng theo Logarit).

### 2. Kích thước tập thử thách (Batch Size `k = 4`)
- **Thiết lập:** Tại mỗi Epoch, mạng lưới sinh ngẫu nhiên 4 vị trí để kiểm tra.
- **Lý do:** Đây là chỉ số Accountability. Với tổng 8 shard mà kiểm tra ngẫu nhiên 4 shard, nếu Provider xóa chỉ 1 shard, mạng lưới có 50% xác suất bắt quả tang ngay trong 1 Epoch. Qua nhiều Epoch, xác suất gian lận thành công tiệm cận 0%.

### 3. Hàm băm Poseidon2 (`T = 3`)
- **Thiết lập:** Sử dụng thuật toán Poseidon2 thay cho SHA-256 hay Blake3 bên trong mạch R1CS.
- **Lý do:** SHA-256 tiêu tốn khoảng ~30,000 constraints/hash vì sử dụng phép toán thao tác bit. Poseidon2 là hàm băm thân thiện với ZK (ZK-friendly), chỉ tiêu tốn **~240 constraints** cho mỗi lần băm, giảm thời gian chứng minh (Prover Time) xuống hàng chục lần.

### 4. Thuật toán Folding (Nova: Pallas-Vesta Cycle)
- **Thiết lập:** Sử dụng `nova-snark` để "gấp" 4 bước kiểm tra Merkle Path lại với nhau.
- **Lý do:** Nếu dùng cách gộp mạch (Batching) truyền thống, số lượng constraints sẽ là `k * ~260 = ~1,040`. Nếu `k = 1000`, mạch sẽ tràn RAM. Nova Folding Scheme cho phép **kích thước mạch giữ nguyên ở mức ~260 Constraints**, không phụ thuộc vào số lượng thử thách `k`.

---

## 🖥️ Kết quả Dự kiến (Expected Output)

Khi chạy thành công, giao diện CLI sẽ hiển thị tiến trình mạch lạc như sau:

```text
======================================================================
      MÔ PHỎNG GIAO THỨC ENGRAM (POSEIDON2 + NOVA FOLDING)
======================================================================

[Hệ thống] Nhập các dữ liệu phân mảnh cần lưu trữ (cách nhau bằng dấu phẩy, tối đa 8 mục):
> shardA, shardB, shardC

[Provider] Đang băm dữ liệu và dựng cây Merkle...

[ BÁO CÁO CAM KẾT - PHASE 1 ]
- Số lượng phân mảnh     : 8 shards (Padding lên 8)
- Mã cam kết (c_stor_i)  : Fr(0x1a2b3c...)
- Kích thước mạch ZK     : ~260 Constraints (Cố định nhờ Folding!)

[Network] Đang thiết lập Nova Public Params (Lần đầu tiên sẽ tốn vài giây)... ✅ Xong (1.23s)

[Hệ thống] Bạn muốn chạy bao nhiêu vòng kiểm tra (Epochs)?
> 2

================ BÁO CÁO XÁC THỰC LƯU TRỮ (EPOCHS) ================

---------------- EPOCH 1 ----------------
[Network]  Sinh tập thử thách (J_ipt) gồm 4 shard: [0, 2, 5, 7]
[Provider] Bắt đầu quá trình Folding Scheme (Gấp 4 shards vào 1 Bằng chứng)...
   > Fold #1 thành công (Shard 0)
   > Fold #2 thành công (Shard 2)
   > Fold #3 thành công (Shard 5)
   > Fold #4 thành công (Shard 7)
   [✓] BẰNG CHỨNG TỔNG HỢP ĐÃ HOÀN TẤT
   - Tổng thời gian Prove : 45.2ms
   - Kích thước Proof     : ~840 Bytes (O(1) Succinctness)
   - Tổng Constraints     : Giữ nguyên ở mức ~260 (Đỉnh cao của Folding!)
[Network]  Xác minh bằng chứng toán học (Verify)... ✅ HỢP LỆ (2.1ms)

---------------- EPOCH 2 ----------------
...
```