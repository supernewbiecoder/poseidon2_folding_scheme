Dưới đây là README dành riêng cho **WSL (Windows Subsystem for Linux)**:

```markdown
# Proof of Space-Time (PoSt) với Nova Folding Scheme
## Hướng dẫn cài đặt và chạy trên WSL

> **Lưu ý**: Hướng dẫn này dành cho WSL2 (Windows Subsystem for Linux 2)

## 📋 Yêu cầu hệ thống

### Windows Host:
- **Windows 10/11** (bản 2004 trở lên hoặc Build 19041+)
- **WSL2** đã được cài đặt
- **RAM**: 16GB+ (khuyến nghị 32GB)
- **CPU**: Hỗ trợ virtualization (Intel VT-x hoặc AMD-V)

### WSL2 Environment:
- **Ubuntu 22.04 LTS** hoặc **24.04 LTS**
- **Rust** 1.70+
- **Cargo**
- **8GB+ RAM available** (cấu hình trong `.wslconfig`)

## 🚀 Cài đặt WSL2 (nếu chưa có)

### 1. Cài đặt WSL2 trên Windows:

**Mở PowerShell với quyền Administrator** và chạy:

```powershell
# Cài đặt WSL
wsl --install

# Set WSL2 làm mặc định
wsl --set-default-version 2

# Khởi động lại Windows nếu được yêu cầu
```

### 2. Cấu hình WSL2 (tối ưu cho Nova):

Tạo file `.wslconfig` trong thư mục user của Windows (`%UserProfile%\.wslconfig`):

```ini
[wsl2]
memory=16GB
processors=4
swap=8GB
localhostForwarding=true
```

Sau đó restart WSL:
```powershell
wsl --shutdown
wsl
```

### 3. Cài đặt Ubuntu trên WSL:

```powershell
# Liệt kê các bản phân phối có sẵn
wsl --list --online

# Cài Ubuntu 22.04
wsl --install -d Ubuntu-22.04
```

## 🐧 Cài đặt môi trường trong WSL

### 1. Mở WSL và cập nhật hệ thống:

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Cài đặt dependencies:

```bash
# Build essentials
sudo apt install -y build-essential pkg-config libssl-dev

# Git (để clone repo nếu cần)
sudo apt install -y git

# curl và các tool cần thiết
sudo apt install -y curl wget

# CMake (cần cho một số thư viện)
sudo apt install -y cmake

# Clang (optional, nhưng giúp compile nhanh hơn)
sudo apt install -y clang
```

### 3. Cài đặt Rust:

```bash
# Cài Rust qua rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Chọn option 1 (default) khi được hỏi

# Load environment variables
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version

# Cập nhật Rust lên mới nhất
rustup update
```

### 4. Cấu hình Cargo cho WSL (tối ưu hiệu năng):

```bash
# Tạo file cấu hình Cargo
mkdir -p ~/.cargo
cat > ~/.cargo/config.toml << EOF
[build]
# Dùng nhiều jobs hơn cho compile nhanh
jobs = 4

[target.x86_64-unknown-linux-gnu]
# Tối ưu cho CPU hiện tại
rustflags = ["-C", "target-cpu=native"]

[net]
# Tăng timeout cho mạng (cần khi download crates)
git-fetch-with-cli = true
EOF
```

## 📦 Tạo và build project

### 1. Tạo project mới:

```bash
cd ~
cargo new nova-post-demo
cd nova-post-demo
```

### 2. Copy source files:

Copy 3 files (`main.rs`, `constants.rs`, `poseidon2_gadget.rs`) vào thư mục `src/`:

```bash
# Tạo lib.rs (bắt buộc)
cat > src/lib.rs << 'EOF'
pub mod constants;
pub mod poseidon2_gadget;
EOF

# Sau đó copy 3 file còn lại vào src/
# (dùng nano, vim, hoặc copy từ Windows)
```

### 3. Tạo Cargo.toml:

```bash
cat > Cargo.toml << 'EOF'
[package]
name = "nova-post-demo"
version = "0.1.0"
edition = "2021"

[dependencies]
nova-snark = "0.34.0"
pasta_curves = "0.5.0"
ff = "0.13.0"
bellpepper-core = "0.3.0"
lazy_static = "1.4"
hex = "0.4"
rand = "0.8"
blake3 = "1.5"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
EOF
```

### 4. Build project:

```bash
# Check compile trước (nhanh hơn)
cargo check

# Build release (tốn thời gian nhưng chạy nhanh)
cargo build --release
```

## ⚡ Chạy chương trình

```bash
# Chạy trực tiếp
cargo run --release

# Hoặc chạy binary đã compile
./target/release/nova-post-demo
```

## 🔧 Xử lý lỗi thường gặp trên WSL

### Lỗi 1: `failed to run custom build command for 'librocksdb-sys'`

```bash
sudo apt install -y clang llvm
```

### Lỗi 2: `cannot find -lssl`

```bash
sudo apt install -y pkg-config libssl-dev
```

### Lỗi 3: `memory allocation failed`

Tăng swap memory trong WSL:

```bash
# Tạo swap file 8GB
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Auto-mount khi boot
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### Lỗi 4: `thread 'main' has overflowed its stack`

Tăng stack size:

```bash
# Thêm vào ~/.bashrc
echo 'export RUST_MIN_STACK=8388608' >> ~/.bashrc
source ~/.bashrc
```

### Lỗi 5: WSL bị kill process do thiếu RAM

Kiểm tra và tăng RAM trong `.wslconfig`:

```ini
[wsl2]
memory=20GB  # Tăng lên 20GB hoặc 24GB
processors=6
swap=16GB    # Tăng swap
```

Sau đó restart WSL:
```powershell
# Trong PowerShell (Admin)
wsl --shutdown
```

## 📊 Monitoring hiệu năng

### Kiểm tra tài nguyên WSL:

```bash
# Trong WSL
htop
# Hoặc
free -h
```

### Xem log chi tiết khi chạy:

```bash
RUST_LOG=debug cargo run --release 2>&1 | tee output.log
```

## 💾 Lưu ý đặc biệt cho WSL

### 1. **File system performance**:
- Code nên để trong WSL filesystem (`~/project`), **KHÔNG** để trong `/mnt/c/`
- Vì I/O qua driver 9p rất chậm

### 2. **Path Windows**:
Truy cập file từ Windows:
```bash
# Mở explorer tại thư mục hiện tại
explorer.exe .
```

Copy file từ Windows vào WSL:
```bash
cp /mnt/c/Users/YourName/Desktop/source.rs .
```

### 3. **Tắt Windows Defender real-time scan** (tạm thời):
- Vào Windows Security > Virus & threat protection
- Tắt real-time protection khi build (tăng tốc đáng kể)

### 4. **Dùng WSLg để chạy GUI** (nếu cần):
```bash
# Cài thêm (optional)
sudo apt install -y x11-apps
```

## 🐛 Debug trên WSL

### Nếu compile quá lâu:

```bash
# Clear cache và build lại
cargo clean
cargo build --release --verbose
```

### Nếu bị out-of-memory:

```bash
# Giảm số threads khi build
CARGO_BUILD_JOBS=2 cargo build --release

# Hoặc dùng
cargo build --release --jobs 2
```

### Nếu lỗi linker:

```bash
# Cài thêm linker
sudo apt install -y mold
# Sử dụng mold (nhanh hơn)
RUSTFLAGS="-C linker=mold" cargo build --release
```

## ✅ Kiểm tra cài đặt thành công

Chạy test nhanh:

```bash
# Tạo file test đơn giản
echo 'fn main() { println!("WSL ready!"); }' > test.rs
rustc test.rs && ./test
rm test test.rs
```

## 📈 Expected output trên WSL

```
╔════════════════════════════════════════════════════════════════╗
║     PROOF OF SPACE-TIME (PoSt) WITH NOVA FOLDING SCHEME        ║
╚════════════════════════════════════════════════════════════════╝

🔧 Đang thiết lập Public Params...
   ✅ Hoàn tất sau 60-90s (chậm hơn WSL một chút)

⏰ Bắt đầu chạy các Epoch...
      ✅ Epoch 1 folding thành công sau 3-5s
      ✅ Epoch 2 folding thành công sau 3-5s
      ✅ Epoch 3 folding thành công sau 3-5s

🔍 Đang xác minh bằng chứng...
   ⏱️  Thời gian verify: 1-2s

  ✅✅✅  XÁC MINH THÀNH CÔNG!
```

## 🎯 Tối ưu hiệu năng cho WSL

1. **Dùng WSL2** (không dùng WSL1)
2. **Đặt project trong WSL filesystem**, không dùng `/mnt/`
3. **Tăng RAM** trong `.wslconfig` lên 16GB+
4. **Tắt Windows Defender** khi build
5. **Dùng `mold` linker** để compile nhanh hơn
6. **Đóng các app Windows nặng** (Chrome, Docker, VS Code)

## 🔄 Restart WSL khi cần

```bash
# Exit WSL
exit

# Trong PowerShell
wsl --shutdown
wsl
```

## 📚 Tham khảo thêm

- [WSL Documentation](https://docs.microsoft.com/en-us/windows/wsl/)
- [Nova Snark](https://github.com/microsoft/Nova)
- [Rust on WSL](https://www.rust-lang.org/tools/install)

---

**⚠️ Lưu ý**: WSL thường chậm hơn Linux native khoảng 10-20%. Nếu có thể, nên chạy trực tiếp trên Ubuntu/Debian để có hiệu năng tốt nhất.
```