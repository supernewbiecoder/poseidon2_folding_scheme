import os
import json
import time
import hashlib

# =====================================================================
# --- CẤU HÌNH ĐƯỜNG DẪN ---
# =====================================================================
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')
ROOT_DIR    = os.path.abspath(os.path.join(CURRENT_DIR, "..")).replace('\\', '/')

INBOX_FILE       = os.path.join(CURRENT_DIR, "ethereum_rollup_inbox.json")
FINALIZED_FILE   = os.path.join(CURRENT_DIR, "ethereum_finalized_state.json")
BITCOIN_LEDGER   = os.path.join(CURRENT_DIR, "bitcoin_ledger.json") # Layer 5
CHALLENGE_WINDOW = 60 # Giả lập 60 giây (trong thực tế là 7 ngày)

# =====================================================================

class EngramOptimisticContract:
    def __init__(self):
        self.inbox = self._load_json(INBOX_FILE)
        self.finalized = self._load_json(FINALIZED_FILE)

    def _load_json(self, path):
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                try: return json.load(f)
                except: return []
        return []

    def _save_json(self, path, data):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)

    def list_pending(self):
        """Liệt kê các State Root đang trong giai đoạn thử thách"""
        print(f"\n--- ⏳ CÁC BẢN TIN ĐANG CHỜ THỬ THÁCH (CHALLENGE WINDOW) ---")
        now = int(time.time())
        found = False
        for tx in self.inbox:
            if tx['status'] == "PENDING_CHALLENGE":
                remaining = (tx['timestamp'] + CHALLENGE_WINDOW) - now
                status_str = f"{remaining}s còn lại" if remaining > 0 else "Hết thời gian - Có thể Finalize"
                print(f"ID: {tx['sequencer_id']} | Epoch: {tx['payload']['epoch']} | {status_str}")
                found = True
        if not found: print("Trống.")

    def challenge_fraud(self, epoch, sequencer_id):
        """Mô phỏng việc một Challenger gửi Fraud Proof thành công"""
        print(f"\n🚨 [Layer 4] Nhận được Fraud Proof cho Epoch {epoch} từ {sequencer_id}...")
        
        updated_inbox = []
        for tx in self.inbox:
            if tx['payload']['epoch'] == epoch and tx['sequencer_id'] == sequencer_id:
                print(f"⚖️ [Slashing] Bằng chứng gian lận ĐÚNG!")
                print(f"🔪 Tịch thu {tx['payload']['stake_amount']} của {sequencer_id}!")
                print(f"🗑️ Loại bỏ State Root độc hại khỏi hệ thống.")
                # Không đưa vào updated_inbox = Xóa
            else:
                updated_inbox.append(tx)
        
        self.inbox = updated_inbox
        self._save_json(INBOX_FILE, self.inbox)

    def finalize_and_anchor(self):
        """Chốt các bản tin đã qua thời gian thử thách và gửi lên Layer 5 (Bitcoin)"""
        now = int(time.time())
        new_inbox = []
        to_finalize = []

        for tx in self.inbox:
            if tx['status'] == "PENDING_CHALLENGE" and (tx['timestamp'] + CHALLENGE_WINDOW) <= now:
                tx['status'] = "FINALIZED"
                to_finalize.append(tx)
            else:
                new_inbox.append(tx)

        if not to_finalize:
            print("\n☕ Chưa có bản tin nào đủ điều kiện Finalize.")
            return

        # 1. Cập nhật trạng thái Ethereum (Layer 4)
        for tx in to_finalize:
            print(f"\n✅ [Layer 4] Chốt sổ Epoch {tx['payload']['epoch']}. Trạng thái: IMMUTABLE.")
            self.finalized.append(tx)
            
            # 2. GỌI TẦNG 5 (BITCOIN SETTLEMENT)
            self._anchor_to_bitcoin(tx)

        self.inbox = new_inbox
        self._save_json(INBOX_FILE, self.inbox)
        self._save_json(FINALIZED_FILE, self.finalized)

    def _anchor_to_bitcoin(self, tx):
        """Mô phỏng gửi dữ liệu lên Bitcoin Layer 5"""
        print(f"₿ [Layer 5] Đang khắc State Root {tx['payload']['batch_merkle_root']} lên Bitcoin...")
        
        ledger = self._load_json(BITCOIN_LEDGER)
        
        bitcoin_block = {
            "btc_txid": hashlib.sha256(str(time.time()).encode()).hexdigest(),
            "engram_epoch": tx['payload']['epoch'],
            "state_root": tx['payload']['batch_merkle_root'],
            "da_reference": tx['payload']['da_reference'],
            "confirmed_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        ledger.append(bitcoin_block)
        self._save_json(BITCOIN_LEDGER, ledger)
        print(f"🧱 [Layer 5] Đã đúc thành công Block Bitcoin cho Epoch {tx['payload']['epoch']}.")

def main():
    contract = EngramOptimisticContract()
    
    while True:
        print("\n=== MÁY CHỦ LAYER 4 (ETHEREUM OPTIMISTIC CONTRACT) ===")
        print("1. Xem danh sách chờ (Inbox)")
        print("2. Chốt sổ và gửi lên Bitcoin (Finalize & Layer 5)")
        print("3. Giả lập thách thức (Challenge/Slashing)")
        print("4. Thoát")
        
        choice = input("Chọn thao tác (1-4): ")
        
        if choice == '1':
            contract.list_pending()
        elif choice == '2':
            contract.finalize_and_anchor()
        elif choice == '3':
            ep = input("Nhập Epoch muốn thách thức: ")
            sid = input("Nhập Sequencer ID muốn thách thức (VD: DVN_1): ")
            contract.challenge_fraud(ep, sid)
        elif choice == '4':
            break
        else:
            print("Lựa chọn không hợp lệ.")

if __name__ == "__main__":
    main()