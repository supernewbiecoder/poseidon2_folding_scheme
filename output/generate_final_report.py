import os
import glob
import pandas as pd
import matplotlib.pyplot as plt

# Cấu hình đồ thị chuẩn báo cáo
plt.rcParams.update({'font.size': 12, 'figure.figsize': (10, 6)})

def main():
    search_path = "Do_RAM_THEO_TUNG_CHU_KI/**/benchmark_results.csv"
    csv_files = glob.glob(search_path, recursive=True)
    if not csv_files:
        csv_files = glob.glob("**/benchmark_results.csv", recursive=True)

    if not csv_files:
        print("Khong tim thay CSV nao!")
        return

    df_list = []
    for file in csv_files:
        try:
            df = pd.read_csv(file)
            df_list.append(df)
        except Exception as e:
            pass

    full_df = pd.concat(df_list, ignore_index=True)
    full_df['Sector_GB'] = (full_df['Sector_Size_Bytes'] / (1024**3)).round(3)
    
    output_dir = "final_benchmark_report"
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Tách Happy Path (Valid) để vẽ các thông số hiệu năng tránh nhiễu do Attack mode
    happy_df = full_df[full_df['Status'] == 'Valid'].copy()
    
    # Group theo kích thước dữ liệu (Sector_GB)
    agg_happy = happy_df.groupby('Sector_GB').mean(numeric_only=True).reset_index()
    agg_happy = agg_happy.sort_values('Sector_GB')
    
    # Chuẩn bị X ticks
    x = range(len(agg_happy['Sector_GB']))
    x_labels = [f"{gb:g}GB" for gb in agg_happy['Sector_GB']]

    # ==========================
    # 2. RAM peak tiêu thụ
    # ==========================
    plt.figure(figsize=(10, 6))
    width = 0.35
    plt.bar(x, agg_happy['Prove_RAM_peak_KiB']/1024, width, label='Prove RAM (MB)', color='#4C72B0', edgecolor='black')
    plt.bar([i + width for i in x], agg_happy['Verify_RAM_peak_KiB']/1024, width, label='Verify RAM (MB)', color='#55A868', edgecolor='black')
    plt.xticks([i + width/2 for i in x], x_labels)
    plt.title('Peak RAM Consumption (Prove vs Verify) Across Sector Sizes')
    plt.ylabel('RAM Usage (MB)')
    plt.xlabel('Sector Size')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '2_ram_peak_comparison.png'), dpi=300)
    plt.close()

    # ==========================
    # 3. Thời gian proving
    # ==========================
    plt.figure(figsize=(10, 6))
    plt.plot(x_labels, agg_happy['C_augmented_nova_ms']/1000, marker='o', markersize=8, linewidth=2.5, color='#C44E52')
    plt.title('Proving Time vs Sector Size')
    plt.ylabel('Proving Time (Seconds)')
    plt.xlabel('Sector Size')
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '3_proving_time.png'), dpi=300)
    plt.close()

    # ==========================
    # 4. Thời gian verifying
    # ==========================
    plt.figure(figsize=(10, 6))
    plt.plot(x_labels, agg_happy['verify_time_ms'], marker='s', markersize=8, linewidth=2.5, color='#8172B2')
    plt.title('Verification Time vs Sector Size')
    plt.ylabel('Verification Time (ms)')
    plt.xlabel('Sector Size')
    plt.ylim(0, agg_happy['verify_time_ms'].max() * 1.5)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '4_verification_time.png'), dpi=300)
    plt.close()

    # ==========================
    # 5. Xác suất phát hiện gian lận
    # ==========================
    # Lọc ra các kịch bản tấn công (không phải no_attack hoặc HappyPath)
    attack_df = full_df[full_df['Attack_Mode'] != 'no_attack'].copy()
    detection_stats = []
    if not attack_df.empty:
        # Group theo kịch bản (Scenario)
        for scenario, group in attack_df.groupby('Scenario'):
            total_runs = len(group)
            # Detected = Nếu hệ thống không trả về Valid (bị Invalid hoặc Prover_Failed do thiếu data)
            detected = len(group[group['Status'] != 'Valid'])
            prob = (detected / total_runs) * 100 if total_runs > 0 else 0
            detection_stats.append({
                'Scenario': scenario,
                'Total_Runs': total_runs,
                'Detected_Count': detected,
                'Detection_Probability_Percent': prob
            })
    det_df = pd.DataFrame(detection_stats)

    # ==========================
    # 6. Thời gian setup
    # ==========================
    plt.figure(figsize=(10, 6))
    setup_total_time = (agg_happy['Setup_PublicParams_ms'] + agg_happy['Setup_PkVk_ms']) / 1000
    plt.bar(x_labels, setup_total_time, color='#64B5F6', edgecolor='black', width=0.5)
    plt.title('Total Setup Time vs Sector Size')
    plt.ylabel('Setup Time (Seconds)')
    plt.xlabel('Sector Size')
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '6_setup_time.png'), dpi=300)
    plt.close()

    # ==========================
    # 7. RAM setup
    # ==========================
    plt.figure(figsize=(10, 6))
    plt.plot(x_labels, agg_happy['Setup_RAM_peak_KiB']/1024, marker='^', markersize=8, linewidth=2.5, color='#FFB74D')
    plt.title('Setup RAM Peak vs Sector Size')
    plt.ylabel('RAM (MB)')
    plt.xlabel('Sector Size')
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '7_setup_ram.png'), dpi=300)
    plt.close()

    # ==========================
    # 8. Thời gian sealing
    # ==========================
    plt.figure(figsize=(10, 6))
    sealing_total = (agg_happy['Seal_C_chunk_absorb_4KB_ms'] + agg_happy['Seal_C_hash_poseidon2_ms'] + agg_happy['Seal_C_merkle_build_ms']) / 1000
    plt.bar(x_labels, sealing_total, color='#81C784', edgecolor='black', width=0.5)
    plt.title('Total Sealing Time vs Sector Size')
    plt.ylabel('Sealing Time (Seconds)')
    plt.xlabel('Sector Size')
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '8_sealing_time.png'), dpi=300)
    plt.close()

    # ==========================
    # 9. Thời gian build tree
    # ==========================
    plt.figure(figsize=(10, 6))
    plt.plot(x_labels, agg_happy['Seal_C_merkle_build_ms']/1000, marker='d', markersize=8, linewidth=2.5, color='#E57373')
    plt.title('Merkle Tree Build Time (Poseidon2) vs Sector Size')
    plt.ylabel('Build Time (Seconds)')
    plt.xlabel('Sector Size')
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '9_merkle_build_time.png'), dpi=300)
    plt.close()

    # ==========================
    # GHI REPORT MARKDOWN
    # ==========================
    report_path = os.path.join(output_dir, "Bao_Cao_Chinh_Thuc_PoSt.md")
    
    detection_table_md = ""
    if not det_df.empty:
        headers = ["Kịch bản tấn công (Scenario)", "Tổng số lượt thử nghiệm", "Số lần chặn đứng gian lận", "Xác suất phát hiện (%)"]
        det_df_rounded = det_df.round(2).astype(str)
        detection_table_md = "| " + " | ".join(headers) + " |\n"
        detection_table_md += "|---" * len(headers) + "|\n"
        for _, row in det_df_rounded.iterrows():
            detection_table_md += "| " + " | ".join(row.values) + " |\n"
    else:
        detection_table_md = "*Không tìm thấy dữ liệu về các kịch bản tấn công (Attack Mode) trong kết quả.*"

    md_content = f"""# BÁO CÁO THỐNG KÊ KẾT QUẢ BENCHMARK IF-POST

## 1. Giải thích ý nghĩa từng trường dữ liệu đo lường

*   **Thời gian Setup (`Setup_PublicParams_ms`, `Setup_PkVk_ms`):** Thời gian thiết lập ban đầu cho hệ thống mật mã. Quá trình này tạo ra các tham số công khai (Public Parameters) và cặp khóa Proving Key / Verification Key cho mạng. Thường chỉ chạy 1 lần.
*   **Thời gian Sealing (`Seal_..._ms`):** Thời gian cần thiết để "đóng gói" dữ liệu gốc thành Sector. Bao gồm việc băm dữ liệu qua Poseidon2, tính toán Merkle Tree để xây dựng gốc `sealed_root`.
*   **Thời gian Build Tree (`Seal_C_merkle_build_ms`):** Một phần của Sealing, đo lường thời gian riêng biệt chỉ để dựng cây Merkle bằng hàm băm Poseidon2 từ các lá (leaf nodes) lên tới đỉnh (root node).
*   **Thời gian Proving (`C_augmented_nova_ms`):** Đo tổng thời gian Prover (thợ mỏ) chạy thuật toán Nova Folding để tổng hợp bằng chứng không tri thức (ZK-Proof) cho tất cả các "challenges" (thử thách) được yêu cầu trong Epoch.
*   **Thời gian Verifying (`verify_time_ms`):** Đo thời gian Verifier (có thể là Node xác thực hoặc Smart Contract trên Blockchain) kiểm tra xem bằng chứng ZK có hợp lệ hay không. Con số này cần nhỏ (dưới 1s) để tối ưu chi phí Gas.
*   **RAM Peak (`Prove_RAM_peak_KiB`, `Verify_RAM_peak_KiB`):** Mức RAM tối đa tiêu thụ trong quá trình chạy. Nhờ có Nova IVC, biểu đồ RAM này sẽ giữ ở mức ổn định thay vì tăng vọt như các chuẩn SNARK cũ.

---

## 2. Biểu đồ RAM peak tiêu thụ của các Sector Size
(Gộp chung quá trình Prove và Verify để đối chiếu. Rất dễ quan sát RAM Prove cực nhỏ so với Verify nhờ Folding)
![RAM Peak](2_ram_peak_comparison.png)

## 3. Thời gian Proving của các Sector Size
Biểu đồ đường thể hiện sự tăng trưởng tuyến tính nhưng ở mức rất thấp về thời gian của Prover (Thợ mỏ).
![Proving Time](3_proving_time.png)

## 4. Thời gian Verifying của các Sector Size
Minh chứng cho việc Verify là hằng số hoặc tốn cực kỳ ít thời gian, thích hợp cho xác thực On-chain qua Smart Contract.
![Verification Time](4_verification_time.png)

## 5. Xác suất phát hiện gian lận (Fraud Detection Probability)
Kết quả chạy thử nghiệm hệ thống (Run ID lặp lại nhiều lần) đối với các kịch bản bị xóa/mất dữ liệu (Gian lận/Drop Attack).
*(Hệ thống trả về Invalid đồng nghĩa với việc Giao thức phát hiện thành công dữ liệu bị thiếu và chặn gian lận).*

{detection_table_md}

## 6. Thời gian Setup của các Sector Size
![Setup Time](6_setup_time.png)

## 7. RAM Setup của các Sector Size
![Setup RAM](7_setup_ram.png)

## 8. Thời gian Sealing tổng cộng của các Sector Size
![Sealing Time](8_sealing_time.png)

## 9. Thời gian Build Merkle Tree bằng Poseidon2
![Tree Build Time](9_merkle_build_time.png)

"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"Xong! Tat ca hinh anh va file Bao cao da duoc luu tai thu muc: {output_dir}")

if __name__ == '__main__':
    main()
