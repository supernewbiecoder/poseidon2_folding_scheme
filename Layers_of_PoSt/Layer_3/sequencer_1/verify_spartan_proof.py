import os
import json
import hashlib
import subprocess
import time

# =====================================================================
NODE_ID       = "1"
EPOCH         = "10000"
LAYER2_DIR    = r"c:/Users/Admin/Desktop/poseidon2_folding_scheme/Layers_of_PoSt/Layer_2"
MEMPOOL_DIR   = "mempool"
BATCH_PREFIX  = "batch_"
RESULT_PREFIX = "result_"
REPORT_FILE   = "summary_report.json"
VERIFIER_SH   = "run_verifier.sh"
# =====================================================================

def build_merkle_root(hashes):
    if not hashes: return "0x" + "0" * 64
    nodes = sorted(hashes)
    while len(nodes) > 1:
        new_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]; right = nodes[i+1] if i+1 < len(nodes) else left
            new_level.append(hashlib.sha256((left + right).encode('utf-8')).hexdigest())
        nodes = new_level
    return nodes[0]

def run_main():
    seq_dir = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')
    batch_dir = f"{seq_dir}/{MEMPOOL_DIR}/{BATCH_PREFIX}{EPOCH}"
    result_dir = f"{seq_dir}/{RESULT_PREFIX}{EPOCH}"
    os.makedirs(result_dir, exist_ok=True)

    print(f"\n🚀 [Layer 3 - Sequencer {NODE_ID}] Bắt đầu xác minh Batch Epoch: {EPOCH}")
    
    prover_ids = []; proof_hashes = []
    if os.path.exists(batch_dir):
        for f in os.listdir(batch_dir):
            if f.startswith(f"input_{EPOCH}_") and f.endswith(".json"):
                pid = f.replace(f"input_{EPOCH}_", "").replace(".json", "")
                prover_ids.append(pid)
                with open(os.path.join(batch_dir, f), 'r') as jf:
                    data = json.load(jf)
                    if 'spartan_proof_hash' in data: proof_hashes.append(data['spartan_proof_hash'])

    if not prover_ids:
        print("⚠️ Mempool trống.")
        return

    report_name = f"dvn_DVN_{NODE_ID}_epoch_{EPOCH}.txt"
    report_path = os.path.join(LAYER2_DIR, "verifier_results", report_name)

    # BƯỚC SỬA LỖI 1: Xóa file kết quả cũ (nếu có) trước khi chạy vòng lặp
    if os.path.exists(report_path):
        try:
            os.remove(report_path)
        except:
            pass

    summary_list = []
    for pid in prover_ids:
        print(f"\n--- 🛰️ Đang gọi [Layer 2] {VERIFIER_SH} cho Prover {pid} ---")
        try:
            wsl_exe = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'wsl.exe')
            cmd = [wsl_exe, "bash", f"./{VERIFIER_SH}", f"DVN_{NODE_ID}", str(EPOCH), pid]
            
            subprocess.run(cmd, cwd=LAYER2_DIR, shell=False)
            
            # BƯỚC SỬA LỖI 2: Nghỉ 0.5 giây để đợi WSL lưu file lên Windows
            time.sleep(0.5)
            
            status = "not pass"
            if os.path.exists(report_path):
                with open(report_path, 'r', encoding='utf-8') as rf:
                    # BƯỚC SỬA LỖI 3: Chuyển hết thành CHỮ IN HOA để chống sai sót cú pháp
                    content = rf.read().upper()
                    
                    # In ra màn hình để bạn dễ debug xem Layer 2 trả về cái gì
                    print(f"   [Debug Nội dung file]: {content.strip()}")
                    
                    # Kiểm tra linh hoạt hơn (bỏ qua hoa/thường)
                    if f"PROVER {pid}: PASS" in content or f"PROVER {pid} : PASS" in content: 
                        status = "pass"
            else:
                print(f"   [Debug]: Không tìm thấy file {report_path}!")
                
            print(f"➡️ Kết quả nhận diện: {status.upper()}")
            summary_list.append({"prover_id": pid, "result": status})
            
        except Exception as e:
            print(f"❌ Lỗi thực thi Layer 2: {e}")

    report_data = {
        "sequencer_id": f"DVN_{NODE_ID}",
        "epoch": EPOCH,
        "batch_merkle_root": build_merkle_root(proof_hashes),
        "summary": summary_list
    }
    
    with open(os.path.join(result_dir, REPORT_FILE), 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=4)
        
    print(f"\n✅ Đã tổng hợp kết quả vào: {result_dir}")
    print(f"➡️ Gợi ý bước tiếp theo: Chạy file 'submit_to_ethereum_l4.py' để gửi bằng chứng lên Layer 4 (Optimistic Ethereum)!")

if __name__ == "__main__":
    run_main()
