import pandas as pd

def calculate_r1cs_constraints(t, R_F, R_P, d=5):
    """
    Tính số lượng ràng buộc R1CS cho mạch Poseidon/Poseidon2
    t: Width (Arity + 1)
    R_F: Số vòng Full Rounds
    R_P: Số vòng Partial Rounds
    d: Bậc S-box (thường là 5, tốn 3 ràng buộc R1CS cho mỗi S-box)
    """
    constraints_per_sbox = 3 # x^5 tốn 3 phép nhân (3 ràng buộc)
    
    # Full round: t S-boxes mỗi vòng
    full_round_cost = R_F * t * constraints_per_sbox
    
    # Partial round: 1 S-box mỗi vòng
    partial_round_cost = R_P * constraints_per_sbox
    
    # Cộng thêm chi phí ma trận (Poseidon2 tối ưu phần này so với Plonk, 
    # nhưng trong R1CS phép cộng tuyến tính là miễn phí, nên chi phí chính là S-box)
    total_constraints = full_round_cost + partial_round_cost
    return total_constraints

# Tạo các kịch bản (Scenarios) để so sánh
scenarios = [
    {"Mode": "Merkle Binary", "t": 3, "R_F": 8, "R_P": 56},
    {"Mode": "Merkle Quaternary", "t": 5, "R_F": 8, "R_P": 60},
    {"Mode": "Merkle Octal", "t": 9, "R_F": 8, "R_P": 63},
]

results = []
for s in scenarios:
    cost = calculate_r1cs_constraints(s['t'], s['R_F'], s['R_P'])
    results.append({
        "Cấu trúc cây (Arity)": f"{s['t']-1}-ary",
        "Chiều rộng (t)": s['t'],
        "Full Rounds": s['R_F'],
        "Partial Rounds": s['R_P'],
        "Số ràng buộc relaxed R1CS": cost,
        "Thời gian Fold ước tính (ms)": round(cost * 0.002, 2) # Giả định 0.002ms/ràng buộc trong Nova
    })

df = pd.DataFrame(results)
print("BẢNG SO SÁNH CHI PHÍ MẠCH CHO CÁC THAM SỐ POSEIDON2")
print(df.to_markdown(index=False))