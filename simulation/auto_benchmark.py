import os
import shutil
import subprocess
import time
import sys

# Khắc phục lỗi in Emoji ra console trên Windows (cp1252 -> utf-8)
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# Danh sách các cấu hình chạy (Sector Size GB, Tree Height, Challenges)
CONFIGS = [
    {"gb": 1, "height": 18, "challenges": 50},
    # {"gb": 1, "height": 18, "challenges": 100},
    # {"gb": 1, "height": 18, "challenges": 460},
    # {"gb": 2, "height": 19, "challenges": 50},
    # {"gb": 2, "height": 19, "challenges": 100},
    # {"gb": 2, "height": 19, "challenges": 460},
    # {"gb": 4, "height": 20, "challenges": 50},
    # {"gb": 4, "height": 20, "challenges": 100},
    # {"gb": 4, "height": 20, "challenges": 460},
    # {"gb": 8, "height": 21, "challenges": 50},
    # {"gb": 8, "height": 21, "challenges": 100},
    # {"gb": 8, "height": 21, "challenges": 460},
    # {"gb": 16, "height": 22, "challenges": 50},

    # {"gb": 16, "height": 22, "challenges": 100},
    # {"gb": 16, "height": 22, "challenges": 460},
    {"gb": 32, "height": 23, "challenges": 460},
]

CONFIG_PATH = "core_primitives/src/config.rs"
MOCKDATA_PATH = "mockdata"
# Đường dẫn output nằm ở cấp ngoài cùng với simulation theo như cấu trúc cây thư mục
OUTPUT_BASE_PATH = "../output/Do_RAM_THEO_TUNG_CHU_KI"

def update_rust_config(config):
    """Ghi đè sạch sẽ cấu hình vào file config.rs theo template để tránh lỗi trùng lặp field"""
    print(f"\n[*] Đang cấu hình: Sector {config['gb']}GB | Tree Height {config['height']} | Challenges {config['challenges']}")
    
    new_config_content = f"""// file này để đặt các cấu hình mặc định cho Engram, có thể mở rộng thêm sau này

#[derive(Clone, Debug)]
pub struct EngramConfig {{
    pub sector_size_bytes: usize,
    pub chunk_size_bytes: usize,
    pub tree_height: usize,
    pub challenges_per_epoch: usize,
    pub epochs_per_window: usize,
}}

impl EngramConfig {{
    /// Cấu hình dùng để chạy Simulation và Test kịch bản tấn công (nhanh, nhẹ)
    pub fn mock_dev() -> Self {{
        Self {{
            sector_size_bytes: {config['gb']} * 1024 * 1024 * 1024, // Tự động set {config['gb']}GB
            chunk_size_bytes: 4096,                // 4KB (1 shard/chunk)
            tree_height: {config['height']},                       // Tự động set height {config['height']}
            challenges_per_epoch: {config['challenges']},
            epochs_per_window: 5, // chuẩn bị cho tương lai simulation
        }}
    }}

    /// Cấu hình thực tế theo báo cáo (benchmark thời gian thật)
    pub fn production() -> Self {{
        Self {{
            sector_size_bytes: 32 * 1024 * 1024 * 1024, // 32GB
            chunk_size_bytes: 4096,
            tree_height: 23,                            // 2^23 lá = 32GB
            challenges_per_epoch: 100,
            epochs_per_window: 48,
        }}
    }}
}}
"""
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(new_config_content)

def clean_mockdata():
    """Xóa vĩnh viễn các thư mục/file trong mockdata"""
    print("[*] Đang dọn dẹp thư mục mockdata...")
    if os.path.exists(MOCKDATA_PATH):
        for filename in os.listdir(MOCKDATA_PATH):
            file_path = os.path.join(MOCKDATA_PATH, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f"Lỗi khi xóa {file_path}: {e}")
    else:
        os.makedirs(MOCKDATA_PATH)
    print("[+] Đã dọn dẹp xong!")

def run_command_and_wait(command, success_message):
    """Chạy command Cargo và đọc stdout để chờ thông báo thành công"""
    print(f"[*] Đang thực thi: {' '.join(command)}")
    process = subprocess.Popen(
        command, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        text=True,
        encoding='utf-8'
    )

    while True:
        line = process.stdout.readline()
        if not line and process.poll() is not None:
            break
        
        if line:
            print(f"  {line.strip()}")
            if success_message in line:
                print(f"[+] Đã nhận diện tín hiệu: '{success_message}'")
                process.wait() 
                break

def save_benchmarks(config):
    """Tạo thư mục đích và gom các file benchmark vào"""
    folder_name = f"sector_{config['gb']}GB_challenge_{config['challenges']}_scenario_5(1)"
    target_dir = os.path.join(OUTPUT_BASE_PATH, folder_name)

    print(f"[*] Đang lưu benchmark vào: {target_dir}")
    os.makedirs(target_dir, exist_ok=True)

    # Tìm tất cả các file JSON/CSV/TXT được sinh ra (bắt đầu bằng benchmark)
    files_to_move = ["benchmark_metadata.json"]
    for file in os.listdir('.'):
        if file.startswith('benchmark') and file.endswith(('.json', '.csv', '.txt', '.log')):
            if file not in files_to_move:
                files_to_move.append(file)

    for file in files_to_move:
        if os.path.exists(file):
            shutil.move(file, os.path.join(target_dir, file))
            print(f"  -> Đã di chuyển: {file}")
        else:
            print(f"  -> Bỏ qua: Không tìm thấy {file}")

def main():
    os.makedirs(OUTPUT_BASE_PATH, exist_ok=True)

    for config in CONFIGS:
        print(f"\n{'='*60}\n🚀 BẮT ĐẦU CHẠY CẤU HÌNH {config['gb']}GB\n{'='*60}")
        
        # 1 & Cấu hình lại file rust
        update_rust_config(config)
        clean_mockdata()

        # 2. Sinh dữ liệu
        run_command_and_wait(
            ["cargo", "run", "-p", "data_generator"],
            "✅ Hoàn tất sinh Mock Data!"
        )

        # 3. Chạy Simulation
        run_command_and_wait(
            ["cargo", "run", "--release", "-p", "simulator_runner", "--bin", "simulator_runner"],
            "📋 Metadata môi trường đã được xuất ra file 'benchmark_metadata.json'"
        )

        # 4. Lưu lại kết quả
        save_benchmarks(config)
        
        # Đợi 1 chút để giải phóng tài nguyên I/O trước khi chạy vòng lặp mới
        time.sleep(2)

    print("\n🎉 ĐÃ HOÀN TẤT TOÀN BỘ QUÁ TRÌNH BENCHMARK!")

if __name__ == "__main__":
    main()