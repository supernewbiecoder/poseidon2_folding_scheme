import os
import sys
import subprocess

# =====================================================================
# --- CẤU HÌNH ĐƯỜNG DẪN CHUẨN ---
# =====================================================================
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')
ROOT_DIR    = os.path.abspath(os.path.join(CURRENT_DIR, "..")).replace('\\', '/')

SEQ_DIR_PREFIX     = "sequencer_"
MEMPOOL_DIR_NAME   = "mempool"
BATCH_DIR_PREFIX   = "batch_"
RESULT_DIR_PREFIX  = "result_"
VERIFY_SCRIPT_NAME = "verify_spartan_proof.py"
# ĐỔI TÊN: Layer 3 sẽ submit lên Layer 4 (Ethereum) thay vì Bitcoin
SUBMIT_SCRIPT_NAME = "submit_to_ethereum_l4.py" 
REPORT_FILE_NAME   = "summary_report.json"

# Trỏ thẳng vào Layer_2 và Layer_4
LAYER2_DIR_PATH    = f"{ROOT_DIR}/Layer_2"
LAYER4_DIR_PATH    = f"{ROOT_DIR}/Layer_4"
VERIFIER_SCRIPT    = "run_verifier.sh" 

# =====================================================================

def get_network_epoch():
    config_path = f"{ROOT_DIR}/CURRENT_EPOCH_IN_BITCOIN.conf"
    if not os.path.exists(config_path):
        return "10000"
    with open(config_path, 'r', encoding='utf-8') as f:
        for line in f:
            if 'CURRENT_EPOCH=' in line:
                return line.strip().split('=')[1]
    return "10000"

def get_next_sequencer_id():
    ids = []
    if os.path.exists(CURRENT_DIR):
        for d in os.listdir(CURRENT_DIR):
            if d.startswith(SEQ_DIR_PREFIX):
                try: ids.append(int(d.split('_')[1]))
                except: continue
    return max(ids) + 1 if ids else 1

def create_verify_script(sequencer_path, sequencer_id, epoch):
    """Sinh ra script gọi run_verifier.sh (Layer 2) qua WSL"""
    script_content = f'''import os
import json
import hashlib
import subprocess
import time

# =====================================================================
NODE_ID       = "{sequencer_id}"
EPOCH         = "{epoch}"
LAYER2_DIR    = r"{LAYER2_DIR_PATH}"
MEMPOOL_DIR   = "{MEMPOOL_DIR_NAME}"
BATCH_PREFIX  = "{BATCH_DIR_PREFIX}"
RESULT_PREFIX = "{RESULT_DIR_PREFIX}"
REPORT_FILE   = "{REPORT_FILE_NAME}"
VERIFIER_SH   = "{VERIFIER_SCRIPT}"
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
    seq_dir = os.path.dirname(os.path.abspath(__file__)).replace('\\\\', '/')
    batch_dir = f"{{seq_dir}}/{{MEMPOOL_DIR}}/{{BATCH_PREFIX}}{{EPOCH}}"
    result_dir = f"{{seq_dir}}/{{RESULT_PREFIX}}{{EPOCH}}"
    os.makedirs(result_dir, exist_ok=True)

    print(f"\\n🚀 [Layer 3 - Sequencer {{NODE_ID}}] Bắt đầu xác minh Batch Epoch: {{EPOCH}}")
    
    prover_ids = []; proof_hashes = []
    if os.path.exists(batch_dir):
        for f in os.listdir(batch_dir):
            if f.startswith(f"input_{{EPOCH}}_") and f.endswith(".json"):
                pid = f.replace(f"input_{{EPOCH}}_", "").replace(".json", "")
                prover_ids.append(pid)
                with open(os.path.join(batch_dir, f), 'r') as jf:
                    data = json.load(jf)
                    if 'spartan_proof_hash' in data: proof_hashes.append(data['spartan_proof_hash'])

    if not prover_ids:
        print("⚠️ Mempool trống.")
        return

    report_name = f"dvn_DVN_{{NODE_ID}}_epoch_{{EPOCH}}.txt"
    report_path = os.path.join(LAYER2_DIR, "verifier_results", report_name)

    # BƯỚC SỬA LỖI 1: Xóa file kết quả cũ (nếu có) trước khi chạy vòng lặp
    if os.path.exists(report_path):
        try:
            os.remove(report_path)
        except:
            pass

    summary_list = []
    for pid in prover_ids:
        print(f"\\n--- 🛰️ Đang gọi [Layer 2] {{VERIFIER_SH}} cho Prover {{pid}} ---")
        try:
            wsl_exe = os.path.join(os.environ.get('SystemRoot', 'C:\\\\Windows'), 'System32', 'wsl.exe')
            cmd = [wsl_exe, "bash", f"./{{VERIFIER_SH}}", f"DVN_{{NODE_ID}}", str(EPOCH), pid]
            
            subprocess.run(cmd, cwd=LAYER2_DIR, shell=False)
            
            # BƯỚC SỬA LỖI 2: Nghỉ 0.5 giây để đợi WSL lưu file lên Windows
            time.sleep(0.5)
            
            status = "not pass"
            if os.path.exists(report_path):
                with open(report_path, 'r', encoding='utf-8') as rf:
                    # BƯỚC SỬA LỖI 3: Chuyển hết thành CHỮ IN HOA để chống sai sót cú pháp
                    content = rf.read().upper()
                    
                    # In ra màn hình để bạn dễ debug xem Layer 2 trả về cái gì
                    print(f"   [Debug Nội dung file]: {{content.strip()}}")
                    
                    # Kiểm tra linh hoạt hơn (bỏ qua hoa/thường)
                    if f"PROVER {{pid}}: PASS" in content or f"PROVER {{pid}} : PASS" in content: 
                        status = "pass"
            else:
                print(f"   [Debug]: Không tìm thấy file {{report_path}}!")
                
            print(f"➡️ Kết quả nhận diện: {{status.upper()}}")
            summary_list.append({{"prover_id": pid, "result": status}})
            
        except Exception as e:
            print(f"❌ Lỗi thực thi Layer 2: {{e}}")

    report_data = {{
        "sequencer_id": f"DVN_{{NODE_ID}}",
        "epoch": EPOCH,
        "batch_merkle_root": build_merkle_root(proof_hashes),
        "summary": summary_list
    }}
    
    with open(os.path.join(result_dir, REPORT_FILE), 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=4)
        
    print(f"\\n✅ Đã tổng hợp kết quả vào: {{result_dir}}")
    print(f"➡️ Gợi ý bước tiếp theo: Chạy file '{SUBMIT_SCRIPT_NAME}' để gửi bằng chứng lên Layer 4 (Optimistic Ethereum)!")

if __name__ == "__main__":
    run_main()
'''
    with open(os.path.join(sequencer_path, VERIFY_SCRIPT_NAME), "w", encoding="utf-8") as f:
        f.write(script_content)
        
def create_submit_l4_script(sequencer_path, sequencer_id, epoch):
    """Sinh ra script đọc báo cáo và gửi lên Smart Contract Layer 4 (Ethereum)"""
    script_content = f'''import os
import json
import hashlib
import sys
import time
try:
    from ecdsa import SigningKey, SECP256k1, VerifyingKey
    from ecdsa.util import sigencode_der, sigdecode_der
except ImportError:
    print("❌ Lỗi: Chưa cài đặt thư viện ecdsa.")
    print("Vui lòng chạy lệnh: pip install ecdsa")
    sys.exit(1)

# =====================================================================
NODE_ID       = "{sequencer_id}"
EPOCH         = "{epoch}"
RESULT_DIR    = "{RESULT_DIR_PREFIX}{epoch}"
REPORT_FILE   = "{REPORT_FILE_NAME}"
LAYER4_DIR    = r"{LAYER4_DIR_PATH}"
# L4 nhận dữ liệu vào Inbox, chưa phải sổ cái (Ledger) cuối cùng
L4_CONTRACT_INBOX = os.path.join(LAYER4_DIR, "ethereum_rollup_inbox.json")
# =====================================================================

def main():
    seq_dir = os.path.dirname(os.path.abspath(__file__)).replace('\\\\', '/')
    report_path = f"{{seq_dir}}/{{RESULT_DIR}}/{{REPORT_FILE}}"
    
    if not os.path.exists(report_path):
        print(f"❌ Không tìm thấy file báo cáo tại: {{report_path}}")
        print(f"💡 Hãy chạy file '{VERIFY_SCRIPT_NAME}' trước để sinh ra báo cáo.")
        return

    # 1. Đọc báo cáo do Layer 3 sinh ra
    with open(report_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # =================================================================
    # BƯỚC MỚI: MÔ PHỎNG DATA AVAILABILITY (Đẩy file lên IPFS/Arweave giả lập)
    # =================================================================
    layer_da_dir = os.path.join(LAYER4_DIR, "..", "Layer_DA")
    os.makedirs(layer_da_dir, exist_ok=True)
    
    file_content = json.dumps(data, sort_keys=True).encode('utf-8')
    file_hash = hashlib.sha256(file_content).hexdigest()
    cid = "ipfs://" + file_hash
    
    da_file_path = os.path.join(layer_da_dir, f"{{file_hash}}.json")
    with open(da_file_path, 'w', encoding='utf-8') as da_f:
        json.dump(data, da_f, indent=4)
        
    print(f"🌐 [Data Availability] Đã publish chi tiết báo cáo lên DA Layer.")
    print(f"🔗 CID: {{cid}}")

    # =================================================================
    # TẠO GIAO DỊCH GỬI LÊN LAYER 4 (OPTIMISTIC ETHEREUM)
    # =================================================================
    payload = {{
        "epoch": data["epoch"],
        "batch_merkle_root": data["batch_merkle_root"],
        "da_reference": cid,
        "stake_amount": "10 ETH" # Mô phỏng tiền cọc của Sequencer
    }}
    
    payload_str = json.dumps(payload, sort_keys=True)
    payload_hash = hashlib.sha256(payload_str.encode()).digest()

    print(f"\\n🔑 [Layer 3 - Sequencer {{NODE_ID}}] Khởi tạo ví ECDSA (Mạng Ethereum L4)...")
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.get_verifying_key()
    
    # 3. Ký số bằng Private Key
    signature = sk.sign_deterministic(payload_hash, sigencode=sigencode_der)
    
    tx = {{
        "sequencer_id": data["sequencer_id"],
        "timestamp": int(time.time()),
        "payload": payload,
        "signature_hex": signature.hex(),
        "public_key_hex": pk.to_string().hex(),
        "status": "PENDING_CHALLENGE" # Trạng thái Lạc quan (Đợi Layer 4 xử lý)
    }}
    
    print(f"📤 [Layer 3 - Sequencer {{NODE_ID}}] Ký giao dịch thành công. Đang gửi lên Layer 4...")

    # 4. Giao tiếp với Layer 4 (Ghi vào Inbox của Smart Contract)
    os.makedirs(LAYER4_DIR, exist_ok=True)
    inbox = []
    
    if os.path.exists(L4_CONTRACT_INBOX):
        with open(L4_CONTRACT_INBOX, 'r', encoding='utf-8') as f:
            try:
                inbox = json.load(f)
            except:
                pass
                
    # Chống Replay Attack (Mỗi epoch 1 sequencer chỉ gửi 1 lần)
    for existing_tx in inbox:
        if existing_tx["payload"]["epoch"] == payload["epoch"] and existing_tx["sequencer_id"] == data["sequencer_id"]:
            print(f"⚠️ Epoch {{payload['epoch']}} đã được bạn gửi lên Layer 4 trước đó. Từ chối gửi đè!")
            return
            
    inbox.append(tx)
    
    with open(L4_CONTRACT_INBOX, 'w', encoding='utf-8') as f:
        json.dump(inbox, f, indent=4)
        
    print(f"\\n=======================================================")
    print(f"📜 [Layer 4 Smart Contract] Nhận thành công State Root từ Sequencer {{NODE_ID}}.")
    print(f"💰 Đã khóa cọc: {{payload['stake_amount']}}")
    print(f"⏳ Trạng thái: ĐANG CHỜ THỬ THÁCH (Challenge Period)")
    print(f"📂 Hộp thư L4: {{L4_CONTRACT_INBOX}}")
    print(f"=======================================================\\n")
    print(f"➡️ [Next Step]: Hãy chạy Script của Layer 4 để xử lý tranh chấp và chốt sổ lên Layer 5 (Bitcoin)!")

if __name__ == "__main__":
    main()
'''
    with open(os.path.join(sequencer_path, SUBMIT_SCRIPT_NAME), "w", encoding="utf-8") as f:
        f.write(script_content)

def main():
    epoch = get_network_epoch()
    sid = get_next_sequencer_id()
    folder = os.path.join(CURRENT_DIR, f"sequencer_{sid}")
    
    # Tạo thư mục
    os.makedirs(os.path.join(folder, MEMPOOL_DIR_NAME, f"batch_{epoch}"), exist_ok=True)
    os.makedirs(LAYER4_DIR_PATH, exist_ok=True) # Tạo sẵn Layer 4
    
    # Sinh ra 2 script vận hành
    create_verify_script(folder, sid, epoch)
    create_submit_l4_script(folder, sid, epoch)
    
    print(f"✅ Đã tạo Node: Sequencer_{sid} (Layer 3)")
    print(f"📜 Đã đính kèm công cụ: {VERIFY_SCRIPT_NAME} (Xác minh qua L2) & {SUBMIT_SCRIPT_NAME} (Gửi lên L4)")

if __name__ == "__main__":
    main()