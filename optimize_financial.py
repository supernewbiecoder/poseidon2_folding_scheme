import numpy as np
import math
from scipy.optimize import minimize_scalar
import matplotlib.pyplot as plt
from tabulate import tabulate

# =====================================================================
# 1. THÔNG SỐ KỸ THUẬT CỐT LÕI (TECHNICAL PARAMS)
# =====================================================================
SECTOR_SIZE_GB = 32          
SECTOR_SIZE_BYTES = SECTOR_SIZE_GB * 1024**3
W = 64              
C_POS = 250         
CHALLENGES = 460    

MAX_RAM_GB = 2.0 
BASE_RAM_BYTES = 500 * 1024**2  
RAM_PER_CONSTRAINT = 150        
TIME_PER_CONSTRAINT_SEC = 0.00002  
IO_SPEED_MBPS = 500  
TIME_PER_POSEIDON_HASH_SEC = 0.000001              
TIME_PER_SPARTAN_PROVE_SEC = 0.0001 
SSD_PAGE_SIZE = 4096  # Kích thước Block vật lý của ổ SSD/NVMe (4KB)

# =====================================================================
# 2. THÔNG SỐ TÀI CHÍNH (FINANCIAL PARAMS - USD)
# =====================================================================
AWS_HOURLY_RATE = 0.0208           
ETH_PRICE_USD = 3000.0             
GAS_PRICE_GWEI = 15.0              
L4_TX_GAS_LIMIT = 50000            
BATCH_SIZE = 10000                 

# =====================================================================
# 3. THÔNG SỐ VDF & BẢO MẬT (SECURITY PARAMS)
# =====================================================================
RAW_HASH_TIME_SEC_PER_SHARD = 0.00005  
NETWORK_BUFFER_SEC = 30  

# =====================================================================
# CÁC HÀM TÍNH TOÁN
# =====================================================================
def calc_merkle_depth(b):
    return max(1, math.ceil(math.log2(SECTOR_SIZE_BYTES / b)))

def calc_c_step(b):
    return C_POS * (b / W) + C_POS * math.log2(SECTOR_SIZE_BYTES / b)

def calc_peak_ram(c_step):
    return BASE_RAM_BYTES + (c_step * RAM_PER_CONSTRAINT * 2)

def calc_l1_compute_cost(b, c_step):
    # ---------------------------------------------------------
    # TÍNH TOÁN HIỆU SUẤT I/O THỰC TẾ CỦA SSD (READ AMPLIFICATION)
    # ---------------------------------------------------------
    if b < SSD_PAGE_SIZE:
        # Bị phạt hiệu suất nếu Shard nhỏ hơn Block Size vật lý
        io_efficiency = b / SSD_PAGE_SIZE
        effective_io_speed = IO_SPEED_MBPS * io_efficiency
    else:
        # Đạt 100% băng thông I/O nếu Shard >= Block Size
        effective_io_speed = IO_SPEED_MBPS
        
    # 1. Thời gian đọc ổ cứng với tốc độ thực tế
    io_read_time_sec = (SECTOR_SIZE_BYTES / (1024**2)) / effective_io_speed
    
    # 2. Thời gian CPU băm cây Merkle (Sealing Compute)
    N = SECTOR_SIZE_BYTES / b
    hash_leaves = N * math.ceil(b / W)
    hash_internal = N - 1               
    total_poseidon_hashes = hash_leaves + hash_internal
    
    merkle_compute_time_sec = total_poseidon_hashes * TIME_PER_POSEIDON_HASH_SEC
    sealing_time_sec = io_read_time_sec + merkle_compute_time_sec
    
    # 3. Thời gian ZK Folding & Spartan
    folding_time_sec = c_step * CHALLENGES * TIME_PER_CONSTRAINT_SEC
    spartan_time_sec = c_step * TIME_PER_SPARTAN_PROVE_SEC
    
    total_time_sec = sealing_time_sec + folding_time_sec + spartan_time_sec
    cost_usd = (total_time_sec / 3600.0) * AWS_HOURLY_RATE
    
    return total_time_sec, cost_usd

def calc_l4_gas_cost_per_proof():
    return (L4_TX_GAS_LIMIT * (GAS_PRICE_GWEI * 10**-9) * ETH_PRICE_USD) / BATCH_SIZE

def calc_vdf_security(b, proof_time_sec):
    N = SECTOR_SIZE_BYTES / b
    total_malicious_hashes = N + (N - 1) 
    malicious_reseal_time_sec = total_malicious_hashes * RAW_HASH_TIME_SEC_PER_SHARD

    total_cheat_time_sec = malicious_reseal_time_sec + proof_time_sec
    is_secure = total_cheat_time_sec > (proof_time_sec + NETWORK_BUFFER_SEC + 60)
    return malicious_reseal_time_sec, total_cheat_time_sec, is_secure

# =====================================================================
# THỰC THI TỐI ƯU HÓA (OPTIMIZATION RUNNER)
# =====================================================================
def run_optimization():
    print("╔══════════════════════════════════════════════════════════════════════════════════════╗")
    print("║     ENGRAM MEGA OPTIMIZER - TỔNG HỢP KỸ THUẬT, TÀI CHÍNH & AN NINH MẠNG LƯỚI       ║")
    print("╚══════════════════════════════════════════════════════════════════════════════════════╝")
    
    l4_amortized_cost = calc_l4_gas_cost_per_proof()
    
    print("\n[1] 🖥️ MÔ PHỎNG VỚI CÁC KÍCH THƯỚC SHARD THỰC TẾ:")
    powers_of_2 = [64, 128, 256, 512, 1024, 2048, 4096, 8192]
    table_data = []
    
    # Biến lưu trữ cấu hình tối ưu nhất
    best_b = None
    min_total_cost = float('inf')
    
    for b in powers_of_2:
        c_step = calc_c_step(b)
        depth = calc_merkle_depth(b)
        peak_ram_mb = calc_peak_ram(c_step) / (1024**2)
        
        proof_time_sec, l1_cost = calc_l1_compute_cost(b, c_step)
        total_usd = l1_cost + l4_amortized_cost
        
        _, cheat_time, is_secure = calc_vdf_security(b, proof_time_sec)
        
        ram_status = "✅" if peak_ram_mb <= (MAX_RAM_GB * 1024) else "❌"
        sec_status = "🛡️ TỐT" if is_secure else "⚠️ NGUY HIỂM"

        table_data.append([
            f"{b} B", 
            depth, 
            f"{int(c_step):,}", 
            f"{peak_ram_mb:.0f} MB {ram_status}", 
            f"{proof_time_sec:.0f} s", 
            f"{cheat_time:.0f} s", 
            sec_status,
            f"${total_usd:.5f}"
        ])

        # TỰ ĐỘNG TÌM ĐIỂM TỐI ƯU NHẤT DỰA TRÊN CHI PHÍ
        if total_usd < min_total_cost:
            min_total_cost = total_usd
            best_b = b

    headers = ["Shard", "Độ sâu", "Constraints", "Peak RAM", "T_honest (s)", "T_cheat (s)", "An toàn VDF", "Phí/Epoch ($)"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    # ========================================================
    # 2. XUẤT BÁO CÁO TỰ ĐỘNG DỰA TRÊN ĐIỂM TỐI ƯU TÌM ĐƯỢC
    # ========================================================
    c_step_opt = calc_c_step(best_b)
    ram_opt_mb = calc_peak_ram(c_step_opt) / (1024**2)
    proof_time_opt, l1_cost_opt = calc_l1_compute_cost(best_b, c_step_opt)
    total_cost_opt = l1_cost_opt + l4_amortized_cost
    reseal_time, cheat_time, _ = calc_vdf_security(best_b, proof_time_opt)
    
    epoch_window = proof_time_opt + NETWORK_BUFFER_SEC
    
    print(f"\n[2] 🎯 BÁO CÁO CẤU HÌNH TỐI ƯU ĐỀ XUẤT (SHARD {best_b} BYTES):")
    print(f"  A. THÔNG SỐ KỸ THUẬT (Hardware & Crypto)")
    print(f"     - Kích thước Sector             : {SECTOR_SIZE_GB} GB")
    print(f"     - Tổng số Shard                 : {int(SECTOR_SIZE_BYTES/best_b):,} mảnh (Tương thích ổ cứng chuẩn {int(best_b/1024)}KB)")
    print(f"     - Độ sâu Merkle Tree (Depth)    : {calc_merkle_depth(best_b)} tầng")
    print(f"     - Kích thước mạch ZK (C_step)   : {int(c_step_opt):,} R1CS Constraints")
    print(f"     - Đỉnh mức RAM tiêu thụ         : {ram_opt_mb:.2f} MB (Rất nhẹ, an toàn < {MAX_RAM_GB}GB)")

    print(f"\n  B. THIẾT LẬP CỬA SỔ EPOCH & BẢO MẬT (Security Window)")
    print(f"     - Thời gian Prover trung thực   : {proof_time_opt:.1f} giây")
    print(f"     - Biên độ trễ mạng (Buffer)     : {NETWORK_BUFFER_SEC} giây")
    print(f"     => CỬA SỔ EPOCH TIÊU CHUẨN      : {epoch_window:.0f} giây (~ {epoch_window/60:.1f} phút)")
    print(f"     - Thời gian Prover gian lận cần : {cheat_time:.1f} giây (Trễ {cheat_time - epoch_window:.1f} giây -> Bị Slashing)")

    print(f"\n  C. BÀI TOÁN KINH TẾ TÀI CHÍNH (USD Cost)")
    print(f"     - Phí điện toán L1 (AWS)        : ${l1_cost_opt:.6f} / Epoch")
    print(f"     - Phí xác minh L4 (ETH Gas)     : ${l4_amortized_cost:.6f} / Epoch (Đã batch {BATCH_SIZE:,} proofs)")
    print(f"     => TỔNG CHI PHÍ VẬN HÀNH        : ${total_cost_opt:.5f} / Epoch")
    print(f"     => CHI PHÍ DUY TRÌ HÀNG NĂM     : ${(total_cost_opt * 365 * 24 / (epoch_window/3600)):.2f} / Năm / Node 32GB")

    plot_optimization_curve(best_b)

def plot_optimization_curve(best_b):
    x_vals = np.linspace(64, 8192, 500)
    y_time = []
    y_cost = []
    
    l4_amortized_cost = calc_l4_gas_cost_per_proof()
    for x in x_vals:
        c = calc_c_step(x)
        t, l1_c = calc_l1_compute_cost(x, c) 
        y_time.append(t)
        y_cost.append(l1_c + l4_amortized_cost)

    fig, ax1 = plt.subplots(figsize=(10, 6))

    color = 'tab:red'
    ax1.set_xlabel('Kích thước Shard - b (Bytes)', fontsize=12)
    ax1.set_ylabel('Thời gian tổng cộng (giây)', color=color, fontsize=12)
    ax1.plot(x_vals, y_time, color=color, label="Tổng thời gian (Merkle + ZK)")
    ax1.tick_params(axis='y', labelcolor=color)
    ax1.set_xscale('log', base=2)

    ax2 = ax1.twinx()
    color = 'tab:blue'
    ax2.set_ylabel('Tổng chi phí USD ($)', color=color, fontsize=12)
    ax2.plot(x_vals, y_cost, color=color, linestyle='--', label="Chi phí L1 + L4")
    ax2.tick_params(axis='y', labelcolor=color)

    plt.title("Sự Đánh Đổi: Thời Gian Tính Toán và Chi Phí Vận Hành", fontsize=14)
    plt.axvline(x=best_b, color='green', linestyle='-', linewidth=2, label=f"Điểm tối ưu thực tế ({best_b} bytes)")
    
    fig.tight_layout()
    plt.grid(True, which="both", ls="--", alpha=0.5)
    
    output_filename = "Engram_Ultimate_Optimization.png"
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"\n    📊 Đã xuất biểu đồ tổng hợp vào file: {output_filename}")

if __name__ == "__main__":
    run_optimization()