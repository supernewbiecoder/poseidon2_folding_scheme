import os
import sys
import subprocess

# =====================================================================
# --- CẤU HÌNH MẠNG LƯỚI & THƯ MỤC ---
# =====================================================================

# 1. Tự động định vị thư mục gốc (Root) bất kể chạy script từ đâu
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) # Thư mục Layer_3
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..")) # Thư mục Layers_of_PoSt

# 2. Cấu hình định dạng tên thư mục / file nội bộ
SEQ_DIR_PREFIX     = "sequencer_"
MEMPOOL_DIR_NAME   = "mempool"
BATCH_DIR_PREFIX   = "batch_"
COMMIT_DIR_PREFIX  = "commit_"
VERIFY_SCRIPT_NAME = "verify_spartan_proof.py"
COMMIT_FILE_NAME   = "commit_data.json"

# 3. Cấu hình kết nối Layer 2 (Đường dẫn chuẩn tuyệt đối)
LAYER2_DIR_PATH    = os.path.join(ROOT_DIR, "Layer_2", "Node_of_Layer_2")
LAYER2_RUN_CMD     = "cargo"
LAYER2_RUN_ARGS    = ["run", "--"]

# =====================================================================

def get_network_epoch():
    """Tìm và đọc file CURRENT_EPOCH_IN_BITCOIN.conf từ thư mục gốc"""
    config_path = os.path.join(ROOT_DIR, 'CURRENT_EPOCH_IN_BITCOIN.conf')
    
    if not os.path.exists(config_path):
        print(f"❌ Không tìm thấy file cấu hình tại: {config_path}")
        sys.exit(1)
        
    with open(config_path, 'r', encoding='utf-8') as f:
        for line in f:
            if '=' in line:
                k, v = line.strip().split('=')
                if k == "CURRENT_EPOCH":
                    return v
    return "unknown_epoch"

def get_next_sequencer_id():
    """Quét các folder hiện tại trong Layer_3 để cấp phát ID."""
    ids = []
    for d in os.listdir(CURRENT_DIR):
        full_path = os.path.join(CURRENT_DIR, d)
        if d.startswith(SEQ_DIR_PREFIX) and os.path.isdir(full_path):
            try:
                ids.append(int(d.split('_')[1]))
            except ValueError:
                continue
    return max(ids) + 1 if ids else 1

def create_verify_script(sequencer_path, sequencer_id, epoch):
    """Sinh ra script xác minh với các hằng số được inject tự động lên đầu file."""
    
    script_content = f'''import os
import json
import hashlib
import subprocess
import sys

# =====================================================================
# --- CẤU HÌNH SEQUENCER NODE ---
# =====================================================================
NODE_ID       = "{sequencer_id}"
EPOCH         = "{epoch}"

# Đường dẫn tuyệt đối an toàn
LAYER2_DIR    = r"{LAYER2_DIR_PATH}"
MEMPOOL_DIR   = "{MEMPOOL_DIR_NAME}"
BATCH_PREFIX  = "{BATCH_DIR_PREFIX}"
COMMIT_PREFIX = "{COMMIT_DIR_PREFIX}"
COMMIT_FILE   = "{COMMIT_FILE_NAME}"
VERIFIER_SCRIPT = "run_verifier.sh"  # Tên script bash của Layer 2
# =====================================================================

def hash_pair(left, right):
    \"\"\"Hàm băm 2 node lại thành node cha trên Merkle Tree\"\"\"
    return hashlib.sha256((left + right).encode('utf-8')).hexdigest()

def build_merkle_root(hashes):
    \"\"\"Dựng Merkle Tree từ danh sách proof hashes\"\"\"
    if not hashes: return "0x" + "0" * 64
    nodes = hashes
    while len(nodes) > 1:
        new_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i+1] if i+1 < len(nodes) else left
            new_level.append(hash_pair(left, right))
        nodes = new_level
    return nodes[0]

def run_verify():
    seq_dir = os.path.dirname(os.path.abspath(__file__))
    batch_dir = os.path.join(seq_dir, MEMPOOL_DIR, f"{{BATCH_PREFIX}}{{EPOCH}}")
    
    # Kiểm tra xem có file bằng chứng trong mempool không
    proof_files = []
    if os.path.exists(batch_dir):
        # Tìm tất cả file proof cho epoch này
        for f in os.listdir(batch_dir):
            if f.startswith(f"compressed_proof_{{EPOCH}}_") and f.endswith('.bin'):
                # Trích xuất prover_id từ tên file
                prover_id = f.replace(f"compressed_proof_{{EPOCH}}_", "").replace(".bin", "")
                proof_files.append({{
                    "file": f,
                    "prover_id": prover_id
                }})
    
    if not proof_files:
        print(f"\\n[Sequencer {{NODE_ID}}] ⚠️ Không tìm thấy bằng chứng nào cho epoch {{EPOCH}}")
        print(f"📂 Đã tìm tại: {{batch_dir}}")
        print(f"💡 Cần copy file: compressed_proof_{{EPOCH}}_<prover_id>.bin và input_{{EPOCH}}_<prover_id>.json")
        return
    
    print(f"\\n[Sequencer {{NODE_ID}}] Bắt đầu xác minh Batch {{EPOCH}}...")
    print(f"📊 Tìm thấy {{len(proof_files)}} bằng chứng cần xác minh")
    
    verifier_script_path = os.path.join(LAYER2_DIR, VERIFIER_SCRIPT)
    
    # Kiểm tra script có tồn tại không
    if not os.path.exists(verifier_script_path):
        print(f"❌ Không tìm thấy script verifier tại: {{verifier_script_path}}")
        print(f"💡 Hãy đảm bảo file run_verifier.sh tồn tại trong thư mục Layer 2")
        return
    
    # Đảm bảo script có quyền thực thi
    os.chmod(verifier_script_path, 0o755)
    
    all_results = []
    proof_hashes = []
    
    for proof_info in proof_files:
        prover_id = proof_info["prover_id"]
        
        print(f"\\n{'='*60}")
        print(f"🔍 Kiểm tra Prover: {{prover_id}}")
        print(f"{'='*60}")
        
        # Đọc proof hash từ input json
        input_json = os.path.join(batch_dir, f"input_{{EPOCH}}_{{prover_id}}.json")
        if os.path.exists(input_json):
            with open(input_json, 'r') as f:
                data = json.load(f)
                if 'spartan_proof_hash' in data:
                    proof_hashes.append(data['spartan_proof_hash'])
                    print(f"📝 Proof hash: {{data['spartan_proof_hash'][:50]}}...")
        
        # GỌI BASH SCRIPT CỦA LAYER 2
        try:
            # Chạy script bash với các tham số
            cmd = [verifier_script_path, f"DVN_{{NODE_ID}}", EPOCH, prover_id]
            
            print(f"🚀 Chạy lệnh: {{' '.join(cmd)}}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=LAYER2_DIR  # Chạy trong thư mục Layer 2
            )
            
            # In output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(f"⚠️ Stderr: {{result.stderr}}", file=sys.stderr)
            
            # Kiểm tra kết quả từ file output của Layer 2
            results_dir = os.path.join(LAYER2_DIR, "verifier_results")
            result_file = os.path.join(results_dir, f"dvn_DVN_{{NODE_ID}}_epoch_{{EPOCH}}.txt")
            
            if os.path.exists(result_file):
                with open(result_file, 'r') as f:
                    content = f.read()
                    # Tìm dòng có chứa prover_id và status
                    if f"Prover {{prover_id}}" in content and "✅ PASS" in content:
                        print(f"✅ Prover {{prover_id}} xác minh THÀNH CÔNG")
                        all_results.append(True)
                    else:
                        print(f"❌ Prover {{prover_id}} xác minh THẤT BẠI")
                        all_results.append(False)
            else:
                # Nếu không có file, dựa vào exit code
                if result.returncode == 0:
                    print(f"✅ Prover {{prover_id}} xác minh THÀNH CÔNG (exit code 0)")
                    all_results.append(True)
                else:
                    print(f"❌ Prover {{prover_id}} xác minh THẤT BẠI (exit code {{result.returncode}})")
                    all_results.append(False)
                    
        except Exception as e:
            print(f"❌ Lỗi khi chạy verifier cho Prover {{prover_id}}: {{e}}")
            all_results.append(False)
    
    # Tính Batch Merkle Root
    batch_root = build_merkle_root(proof_hashes)
    
    # Tạo chữ ký
    signature_data = f"{{NODE_ID}}{{EPOCH}}{{batch_root}}"
    signature = hashlib.sha256(signature_data.encode()).hexdigest()
    
    # Đóng gói kết quả
    commit_dir = os.path.join(seq_dir, f"{{COMMIT_PREFIX}}{{EPOCH}}")
    os.makedirs(commit_dir, exist_ok=True)
    
    success_count = sum(all_results)
    total_count = len(proof_files)
    
    commit_data = {{
        "epoch_id": int(EPOCH),
        "id_node_sequencer": f"DVN_{{NODE_ID}}",
        "batch_merkle_root": batch_root,
        "signature": signature,
        "total_proofs": total_count,
        "successful_verifications": success_count,
        "failed_verifications": total_count - success_count,
        "status": "Verified & Ready for L1" if success_count == total_count else "Partial Verification",
        "verification_details": [
            {{
                "prover_id": p["prover_id"],
                "success": all_results[i] if i < len(all_results) else False
            }}
            for i, p in enumerate(proof_files)
        ]
    }}
    
    commit_path = os.path.join(commit_dir, COMMIT_FILE)
    with open(commit_path, "w", encoding="utf-8") as f:
        json.dump(commit_data, f, indent=4)
    
    print(f"\\n{'='*60}")
    print(f"✅ ĐÃ ĐÓNG GÓI BATCH {{EPOCH}}!")
    print(f"   - Tổng số bằng chứng: {{total_count}}")
    print(f"   - Xác minh thành công: {{success_count}}")
    print(f"   - Batch Merkle Root: {{batch_root}}")
    print(f"📂 Dữ liệu (chờ gửi lên Bitcoin): {{commit_path}}")
    print(f"{'='*60}\\n")

if __name__ == "__main__":
    run_verify()
'''
    script_path = os.path.join(sequencer_path, VERIFY_SCRIPT_NAME)
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script_content)

def main():
    # 1. Đọc Epoch toàn cục từ thư mục gốc
    current_epoch = get_network_epoch()
    
    # 2. Tạo folder Sequencer mới
    seq_id = get_next_sequencer_id()
    folder_name = f"{SEQ_DIR_PREFIX}{seq_id}"
    node_name = f"{seq_id}"
    
    folder_path = os.path.join(CURRENT_DIR, folder_name)
    os.makedirs(folder_path, exist_ok=True)
    
    print(f"\n--- 🚀 KHỞI TẠO HỆ THỐNG SEQUENCER LAYER 3 ---")
    
    # 3. Tạo thư mục Mempool của epoch hiện tại
    mempool_path = os.path.join(folder_path, MEMPOOL_DIR_NAME, f"{BATCH_DIR_PREFIX}{current_epoch}")
    os.makedirs(mempool_path, exist_ok=True)
    
    # 4. Đẻ ra file script chạy engine
    create_verify_script(folder_path, node_name, current_epoch)
    
    print(f"✅ Đã tạo Node: {folder_name} (ID: DVN_{node_name})")
    print(f"📅 Phụ trách Epoch: {current_epoch}")
    print(f"📂 Đường dẫn Mempool: {mempool_path}")
    print(f"📜 Script thực thi: {folder_name}/{VERIFY_SCRIPT_NAME}")
    print(f"💡 Hướng dẫn:")
    print(f"   1. Thả file input_{current_epoch}.json và compressed_proof_{current_epoch}.bin của L1 vào Mempool.")
    print(f"   2. Vào thư mục {folder_name} và chạy: python {VERIFY_SCRIPT_NAME}")
    print(f"--------------------------------------------------\n")

if __name__ == "__main__":
    main()