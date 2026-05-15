import os
import shutil
import sys

# =====================================================================
# --- CẤU HÌNH ĐƯỜNG DẪN ---
# =====================================================================
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR    = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
L1_OUTPUT_DIR = os.path.join(CURRENT_DIR, "output")
L3_DIR = os.path.join(ROOT_DIR, "Layer_3")
CONFIG_FILE = os.path.join(ROOT_DIR, "CURRENT_EPOCH_IN_BITCOIN.conf")

# =====================================================================

def get_current_epoch():
    """Đọc Epoch hiện tại từ file config chung ở thư mục gốc"""
    if not os.path.exists(CONFIG_FILE):
        print(f"❌ Lỗi: Không tìm thấy file {CONFIG_FILE}")
        sys.exit(1)
    
    # 🛠 SỬA TẠI ĐÂY: Thêm encoding='utf-8' để đọc được tiếng Việt
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if 'CURRENT_EPOCH=' in line:
                return line.split('=')[1].strip()
    return None

def commit_proofs():
    epoch = get_current_epoch()
    if not epoch:
        print("❌ Lỗi: Không thể xác định Epoch hiện tại.")
        return

    print(f"\n🚀 [Layer 1] Bắt đầu commit bằng chứng cho Epoch: {epoch}")

    if not os.path.exists(L3_DIR):
        print(f"❌ Lỗi: Thư mục Layer 3 không tồn tại tại {L3_DIR}")
        return

    sequencers = [d for d in os.listdir(L3_DIR) 
                  if d.startswith("sequencer_") and os.path.isdir(os.path.join(L3_DIR, d))]
    
    if not sequencers:
        print("⚠️ Cảnh báo: Không tìm thấy Sequencer nào trong Layer 3.")
        return

    if not os.path.exists(L1_OUTPUT_DIR):
        print("⚠️ Cảnh báo: Thư mục output của Layer 1 trống.")
        return

    files_found = 0
    prover_dirs = [d for d in os.listdir(L1_OUTPUT_DIR) if d.startswith("prover_")]

    for prover_dir in prover_dirs:
        prover_path = os.path.join(L1_OUTPUT_DIR, prover_dir)
        prover_id = prover_dir.replace("prover_", "")

        # Kiểm tra file theo định dạng có Prover ID
        target_files = [
            f"input_{epoch}_{prover_id}.json",
            f"compressed_proof_{epoch}_{prover_id}.bin"
        ]

        for filename in target_files:
            src_file = os.path.join(prover_path, filename)
            
            if os.path.exists(src_file):
                for seq in sequencers:
                    dest_batch_dir = os.path.join(L3_DIR, seq, "mempool", f"batch_{epoch}")
                    os.makedirs(dest_batch_dir, exist_ok=True)
                    
                    dest_path = os.path.join(dest_batch_dir, filename)
                    shutil.copy2(src_file, dest_path)
                    print(f"  ✅ [Epoch {epoch}] {filename} -> {seq}/mempool")
                files_found += 1
            else:
                # Fallback cho file không có ID (nếu ông chưa kịp chạy lại Layer 1)
                legacy_filename = filename.replace(f"_{prover_id}", "")
                legacy_src = os.path.join(prover_path, legacy_filename)
                
                if os.path.exists(legacy_src):
                    for seq in sequencers:
                        dest_batch_dir = os.path.join(L3_DIR, seq, "mempool", f"batch_{epoch}")
                        os.makedirs(dest_batch_dir, exist_ok=True)
                        shutil.copy2(legacy_src, os.path.join(dest_batch_dir, filename))
                    files_found += 1

    if files_found == 0:
        print(f"⚠️ Không tìm thấy bằng chứng nào cho Epoch {epoch}. Hãy chạy Prover trước!")
    else:
        print(f"\n✨ Hoàn tất! Đã đồng bộ bằng chứng tới {len(sequencers)} Sequencer.")

if __name__ == "__main__":
    commit_proofs()