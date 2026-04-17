# *Hướng dẫn cài đặt môi trường và triển khai*
## Mô tả giả lập
Sau đây là mô tả giả lập trong bài báo phần 3.4.

1. Gọi $p$ là nhà cung cấp lưu trữ chịu trách nhiệm cho một tập hợp con các chỉ mục phân mảnh do giao thức xác định cho đối tượng $D_i$. 
   Giả sử: $A_{i,p} \subseteq \{1, \dots, n\} \quad$
   >Ý nghĩa: Giả sử file $D_i$ được chia thành $n$ mảnh (từ 1 đến $n$). Một nhà cung cấp có tên là $p$ sẽ được giao cho một tập hợp vài mảnh trong số đó. Tập hợp các mảnh mà $p$ phải giữ được gọi là $A_{i,p}$.

   **Yêu cầu**: tại mỗi thử thách (challange), p (nhà cung cấp lưu trữ) cần phải gửi bằng chứng để chứng minh nó đang giữ dữ liệu

   :arrow_right: Trong giả lập, p là nhà cung cấp duy nhất trong đó cam kết sẽ lưu trữ data các shards (phân mảnh), **trong giả lập này em chỉ cho phép tối đa có 8 phân mảnh**

2. Tạo thử thách: 

    $J_{i,p,t} = \text{Chal}(c_{i}^{stor}, A_{i,p}, \eta_{t}, p)$

   >Ở một thời điểm $t$ (kỷ nguyên $t$), hệ thống không bắt $p$ gửi lại toàn bộ các mảnh đang giữ (vì thế tốn rất nhiều băng thông). Hệ thống dùng hàm $\text{Chal}$ (Challenge - Thử thách) để chọn ngẫu nhiên một vài mảnh trong tay $p$ để kiểm tra.
   
   Các biến số:
      - $c^{stor}_i$: "Dấu vân tay" (Merkle root) của toàn bộ file gốc. Đóng vai trò là mỏ neo bảo mật.
      - $A_{i,p}$: Danh sách các mảnh mà $p$ đang giữ.
      - $\eta_t$: Một con số ngẫu nhiên công khai sinh ra tại thời điểm $t$. Điều này khiến thử thách là không thể đoán trước.
      - $p$: Danh tính của nhà cung cấp.

   Kết quả: $J_{i,p,t}$ là danh sách các chỉ mục (ví dụ: "Hãy đưa tôi xem mảnh số 3, số 7 và số 12").
   :arrow_right: Tại mỗi challange, hệ thống sẽ đưa ra một mảng các shard ngẫu nhiên mà p phải chứng minh. **Hiện nay thì em để mặc định là p phải chứng minh 4 shards trong 1 lần challange**, nếu như p giữ ít hơn 4 shard thì p sẽ phải tự chứng minh 1 shard nhiều lần.
3. Tạo bí mật (chỉ p biết)
    - $w_{i,p,t} := \{(s_{i,j}, \text{path}_{i,j}) : j \in J_{i,p,t}\}$
   - $s_{i,j}$: Nội dung thực sự của mảnh dữ liệu đó.
   - $\text{path}_{i,j}$: Đường dẫn xác thực Merkle Path (chứng minh mảnh $s_{i,j}$ này thực sự thuộc về gốc $c^{stor}_i$ trong đề bài).
   > ứng với mỗi shard mà p phải chứng minh trong một challange, p sẽ phải tạo ra witness tương ứng. **Rồi nối với nhau tạo thành một tập các witness cho một challange**
4. **Hệ thống sinh ra mạch R1CS ứng với một tập các witness đó**, sau đó từ đấy sẽ sinh ra bằng chứng ZK-proof để chứng minh. Nếu như bằng chứng là hợp lệ thì kết quả sẽ là hợp lệ, còn nếu không thì sẽ in ra thất bại.

## Các tham số được thiết lập trong giả lập
1. Độ sâu cây Merkle (Merkle Tree Depth - $d$): thiết lập $d=3$
   - Ý nghĩa: Xác định tổng số phân mảnh ($n$) tối đa mà một Provider có thể lưu trữ cho một đối tượng $D_i$. Công thức là $n = 2^d$. Với $d=3$, chúng ta có tối đa 8 phân mảnh
   - Trong thực tế: Tham số này sẽ được đẩy lên cao (ví dụ $d=20$ để chứa $\approx 1$ triệu phân mảnh). Khi $d$ tăng, số lượng ràng buộc (constraints) chỉ tăng theo hàm tuyến tính bậc thấp, giúp hệ thống mở rộng quy mô (scalability) rất tốt.
2. Kích thước tập thử thách (Batch Size - $k$): thiết lập $k=4$
   - Ý nghĩa: Đây chính là kích thước của tập $J_{i,p,t}$ trong phương trình. Nó quy định Provider phải chứng minh cùng lúc bao nhiêu phân mảnh trong một bằng chứng duy nhất.
   - Nếu bạn lưu 8 mảnh mà mạng lưới kiểm tra ngẫu nhiên 4 mảnh, xác suất để bạn gian lận (xóa 1 mảnh mà không bị bắt) là cực thấp.
3. Hàm băm: Poseidon với constraint $C_{poseidon} \approx 300$
   - Trong giả lập này, chúng ta sử dụng Poseidon dựa trên thư viện chuẩn circomlib. Các tham số này được tối ưu hóa cho đường cong Elliptic bn128 (đường cong mặc định của Ethereum và nhiều hệ thống ZK).
   - Width ($t$) = 3
   - S-box ($\alpha$) = 5
   - Full Rounds ($R_f$) = 8
   - Partial Rounds ($R_p$) = 57
   - Prime Field ($p$)$ = 218...827$
   > Lưu ý: bộ tham số cho poseidon này là mặc định với thư viện chuẩn circomlib, em ghi như này chỉ để tham khảo thêm
4. Hệ thống chứng minh Groth16 (Proving System):
   - Thiết lập: thuật toán Groth16 trên đường cong Elliptic bn128
   - Ý nghĩa: Giao thức nén dữ liệu từ Witness thành Proof $\pi$.
   - Kích thước nhỏ nhất: Trong các loại zk-SNARK, Groth16 cho ra bằng chứng có kích thước nhỏ nhất thế giới (chỉ khoảng 128-800 bytes).
5. Hạt giống thử thách ngẫu nhiên (Public Challenge Seed - $\eta_t$)
 - Thiết lập: Sinh ra ngẫu nhiên tại mỗi Epoch $t$ từ phía mạng lưới.

## Môi trường và dependency cần thiết
1. Nodejs & npm: Dùng để chạy mã mô phỏng và thư viện snarkjs
2. Rust & Cargo: Dùng để biên dịch circom từ mã nguồn. Tải rustup-init.exe tại https://rustup.rs/ và cài đặt (cứ ấn Enter chọn default)
3. Cài đặt Global CLI: Mở Terminal mới và chạy 2 lệnh sau:
- `npm install -g snarkjs`
- `cargo install --git https://github.com/iden3/circom.git`
- Kiểm tra: `circom --version`
4. clone code về, mở powershell thư mục và chạy lần lượt các bước sau:
   - Nếu thư mục của bạn chưa có node_modules, hãy chạy lệnh này để tải các thư viện mật mã chuẩn:
      - `npm init -y`
      - `npm install circomlib snarkjs circomlibjs`
   - Biên dịch mạch ZKP (Circuit Compilation): Lệnh này sẽ đọc file mạch .circom, chuyển đổi logic thành hệ phương trình ràng buộc (R1CS) và tạo ra file WebAssembly (.wasm) để tính toán
      - `circom circuits/storage_batch_proof.circom --r1cs --wasm --sym`
   - Thiết lập niềm tin & Khởi tạo khóa (Trusted Setup): Đây là chuỗi lệnh bắt buộc của thuật toán Groth16 để tạo ra khóa chứng minh (Proving Key) và khóa xác minh (Verification Key). Chạy từng dòng một:
      - Khởi tạo tham số ngẫu nhiên ban đầu: `snarkjs powersoftau new bn128 14 pot14_0000.ptau -v`
      - Đóng góp entropy (nó có thể yêu cầu bạn gõ entropy, hãy gõ bừa 1 cái gì đó): `snarkjs powersoftau contribute pot14_0000.ptau pot14_0001.ptau --name="Phase 1 Batch" -v`
      - Chuẩn bị cho phase2: `snarkjs powersoftau prepare phase2 pot14_0001.ptau pot14_final.ptau -v`
      - Sinh khóa chứng minh .zkey cho mạch tổng hợp: `snarkjs groth16 setup storage_batch_proof.r1cs pot14_final.ptau storage_batch_final.zkey`
      - Trích xuất khóa xác minh .json cho mạng lưới: `snarkjs zkey export verificationkey storage_batch_final.zkey verification_key.json`

      > Lưu ý: Phần Trusted Setup: bước này sinh ra file pot14. Lý do có sô 14 là vì $2^{14} = 16,384$, đủ để chứa 3,648 constraints của em. Nếu dùng 12 ($2^{12} = 4,096$) thì vẫn được nhưng sẽ sát nút hơn nhưng thực tế với lượng constraints là 3.648 thì dùng 12 nó có thể bị tràn số.
5. Chạy Mô phỏng (Simulator): Sau khi Bước 3 hoàn tất, bạn sẽ thấy file verification_key.json xuất hiện trong thư mục. Lúc này mọi thứ đã sẵn sàng, hãy chạy file mô phỏng báo cáo
- `node report_simulator.js`

## DEMO
Sau khi chạy `node report_simulator.js`, hệ thống sẽ cần bạn:
- nhập các dữ liệu phân mảnh cần lưu trữ (cách nhau bằng dấu phẩy, tối đa 8 mục) (hiện tại mới chỉ demo 8 mục, tức là độ sâu của cây sẽ = 3 thôi, do là cây merkle tree).

```Xin lưu ý cho, dữ liệu phân mảnh cần lưu trữ chính là dữ liệu mà p (storage provider) cam kết sẽ lưu trữ```

- nhập số vòng kiểm tra (Epochs).

``` mỗi một epoch mới sẽ sinh ra một challange ngẫu nhiên mới```

## Rút ra được từ kết quả chạy
1. Số lượng constrant trong hệ phương trình R1CS:
- Ở trong code demo, số lượng constraint mặc định cho R1CS e đang để ở dạng hằng số: 3648, tuy nhiên thì thực tế số lượng constraints bị ảnh hưởng bởi: C: constraints
   - $C \approx k \cdot (d \cdot C_{hash})$
   - k: số lượng thử thách trong 1 batch
   - d: độ sâu của cây merkle tree: ví dụ $2^3=8$  shards thì $d=3$
   - $C_{hash}:$ số ràng buộc của hàm băm ($poseidon \approx 300 $, $SHA256 \approx 30,000$)
2. Thời gian proof: ($T_{prove}$)
Đây là công việc nặng nhất, phụ thuộc vào tốc độ máy tính giải hệ phương trình $C$.
- $T_{prove} = C \cdot \tau + T_{wit}$
- $\tau$: Thời gian xử lý một ràng buộc trên CPU/GPU cụ thể.
- $T_{wit}$: Thời gian trích xuất dữ liệu từ ổ cứng (Witness generation).
3. Kích thước Proof ($S_{\pi}$)
Với Groth16, bằng chứng là 3 điểm trên đường cong Elliptic ($A, B, C$).
$S_{\pi} \approx 3 \cdot \text{size}(\text{EllipticPoint}) = \text{Constant}$
Dù bạn kiểm tra 1 triệu file, bằng chứng gửi đi vẫn chỉ nặng tầm 128 - 800 Bytes. Đây là lý do ZKP cực kỳ tiết kiệm băng thông.
4. Phân tích Xác suất Gian lận
- Nếu một Provider xóa mất $m$ phân mảnh trong tổng số $n$ phân mảnh, xác suất để Provider đó vượt qua được một thử thách gồm $k$ chỉ số ngẫu nhiên là: 
$P_{cheat} = \frac{\binom{n-m}{k}}{\binom{n}{k}}$
- Ví dụ trong demo ($n=8, k=4$): Nếu Provider xóa 1 mảnh ($m=1$), xác suất để mạng lưới chọn trúng mảnh đó là $50\%$. Nếu chạy 5 Epochs, xác suất gian lận thành công chỉ còn $(0.5)^5 \approx 3\%$. Đây là lý do tại sao hệ thống cần chạy định kỳ (Recurring)

## Kết quả
![kết quả 1](result_image\result_1.png)
![kết quả tiếp](result_image\result_2.png)