# Giao thức chứng minh lưu trữ trong Engram
***Mục tiêu: Chuyển đổi cơ chế chứng minh lưu trữ hiện tại để phù hợp với những máy tính có cấu hình thấp hơn.***

# Tổng quan
Hiện nay, các cơ chế chứng minh lưu trữ mặc dù đang được phát triển để tối ưu hóa hiệu năng cho Prover, giảm áp lực phần cứng cũng như chi phí cho Verifier. Tuy nhiên, yêu cầu phần cứng tối thiểu cho RAM ở máy Prover vẫn lên tới 128GB, điều này khiến cho một số máy tính có dung lượng dư dả nhưng lại không thể tham gia vào mạng lưới vì yêu cầu về phần cứng đòi hỏi rất cao.
Vì thế mục tiêu của dự án này là đề xuất phương pháp khả thi, kết hợp những phương pháp hiện tại để chuyển đổi cơ chế chứng minh lưu trữ sao cho phù hợp với các máy có cấu hình thấp hơn.

## Đặc tả ngắn cho lõi giao thức
Gọi $\lambda$ là tham số an toàn (Security Parameter), hệ thống Engram được định nghĩa bởi một tuple 6 thuật toán thời gian đa thức: ($\Pi_{Engram} = (Setup, Seal, Commit, Challenge, Prove, Verify)$) như sau:
1. Setup($\lambda$, $C_{step}$) $\rightarrow$ ($pp, pk, vk$)
    - Mục tiêu: Khởi tạo các tham số công khai và khóa mật mã cho hệ thống ZK-SNARK (Nova + Spartan).
    - Thực thi: Hệ thống khởi tạo đường cong elliptic Pallas/Vesta. Biên dịch mạch $C_{step}$ (chứa logic băm Merkle và logic sealing dữ liệu) để sinh ra:
        - $pp$: Public Parameters (Tham số công khai).
        - $pk$: Prover Key (Khóa chứng minh cho Prover).
        - $vk$: Verifier Key (Khóa xác minh cho Verifier/Smart Contract).
2. Seal($D, S_{info}$) $\rightarrow$ ($R_{sealed},root, aux$)
    - Mục tiêu cốt lõi của Sealing:
        1. Đảm bảo Bằng chứng Nhân bản (Proof of Replication - PoRep) & Chống Deduplication
            - Bài toán: Nếu 100 khách hàng cùng tải lên một bộ phim 32GB giống hệt nhau, một Prover gian lận có thể chỉ lưu 1 bản sao duy nhất trong ổ cứng của hắn, nhưng lại báo cáo với mạng lưới là đang lưu 100 bản để nhận thưởng gấp 100 lần (Tấn công Sybil)
            - Mục tiêu của Seal: Bằng cách băm dữ liệu gốc $D$ cùng với định danh duy nhất $replica\_id$ (chứa ID khách hàng, ID thợ đào, số thứ tự bản sao), hàm Seal tạo ra các "bản mã hóa" ($R_{sealed}$) khác biệt hoàn toàn ở mức độ Bit (Bit-wise unqiue).
        2. Ràng buộc Tọa độ Không gian (Position / Space Binding)
            - Bài toán: Trong một Sector 32GB có rất nhiều mảnh Shard rỗng (Zero-padding). Kẻ tấn công có thể thay đổi vị trí của các mảnh dữ liệu hoặc xáo trộn chúng để qua mặt các phép kiểm tra ngẫu nhiên của cây Merkle.
            - Mục tiêu của Seal: Tham số $i$ (tọa độ của Shard) được nén vào trong $Mask_i$ và hòa trộn với dữ liệu trước khi băm. Điều này "khóa" chặt nội dung của Shard vào đúng vị trí vật lý của nó trên cây Merkle.
    
    - Hàm sealing:
        Định danh replica được sinh từ các metadata cố định của hợp đồng lưu trữ:
        $$Replica_{id} = Poseidon2(\text{clientid},\text{dealid}, \text{sectorid}, \text{copyindex}, \text{nonce})$$
        Trong đó: 
        - $\text{clientid}$: Định danh client lưu trữ.
        - $\text{dealid}$: Định danh hợp đồng lưu trữ.
        - $\text{sectorid}$ : Định danh Sector lưu trữ.
        - $\text{copyindex}$ : Chỉ số replica vật lý.
        - $\text{nonce}$ : Giá  trị ngẫu nhiên chống replay/deduplication
    
        Khởi tạo trạng thái ban đầu: $S_{0} = Replica_{id}$ (Trạng thái cơ sở)
        Replica encoding: $R_{i} = Poseidon2 (D_{i}, S_{i-1}, i, Replica_{id})$
        Trong đó: 
        - $D_{i}$: Raw data chunk tại vị trí i.
        - $S_{i-1}$: Trạng thái tích lũy trước đó.
        - $R_{i}$: Chunk đã được sealing/mã hóa.
        
        State transition: $S_{i} = Poseidon2 (S_{i-1}, R_{i})$
        Merkle commitment: $R_{sealed} = MerkleRoot(R_{1}, R_{2}, \dots R_{n})$

3. Commit ($R_{sealed}$, $\text{metadata}$) $\rightarrow$ onchain_commit
    - metadata: thông tin metadata cơ bản, thông tin replica.
4. Challenge($\text{epoch}$, $\text{beacon}$, $\text{sector\_id}$) $\rightarrow$ $J = \left\{j_{1},j_{2},...j_{c} \right\}$
    - Beacon: nguồn randomness
    - c: số lượng challenge
    - $j_{i}$: chỉ mục challenge thứ i
    - Challenge binding: $j_{i} = Poseidon2(Beacon, Sector_{id}, epoch, i)$ mod N
5. Prove($D_{J},aux_{J},J,pp, pk$) $\rightarrow$ $\pi$
    - $D_{j}$: Các chunk dữ liệu tại vị trí challenge.
    - $\text{aux}_{j}$: Witness phụ trợ.
    - $\text{pp}$: Public parameters
    - $\text{pk}$: Proving key
    - $\pi$: zk-proof cuối cùng.
6. Verify($\pi,R_{\text{sealed}}, J, vk$) $\rightarrow$ accept/reject

## Step circuit cụ thể:
### Public Inputs
Các dữ liệu công khai tối thiểu cần có để phân định ranh giới tính toán:

$$\text{public} = (\text{sector\_id}, R_{\text{sealed}}, \text{epoch}, j_i, Beacon, Replica_{id})$$

* $\text{sector\_id}$: Định danh duy nhất của sector đang được kiểm tra.
* $R_{\text{sealed}}$: Khóa cam kết gốc (Root Hash) của cây Merkle đại diện cho dữ liệu đã được mã hóa (Sealed Sector).
* $\text{epoch}$: Mốc thời gian hoặc chu kỳ tạo thử thách (challenge).
* $j_i$: Chỉ mục (index) của lá dữ liệu được chọn làm thử thách tại bước $i$.

### Private Witness
Các chứng nhân bí mật do Prover cung cấp để chứng minh tính hợp lệ mà không làm lộ dữ liệu thô:

$$\text{witness} = (D_{j_i}, S_{j_i-1}, S_{j_i}, \text{path}_{j_i}, Replica_{id})$$

* $D_{j_i}$: Dữ liệu thô (hoặc dữ liệu trung gian) của lá tại vị trí thử thách $j_i$.
* $S_{j_i-1}$: Trạng thái (State) trước khi cập nhật lá $j_i$.
* $S_{j_i}$: Trạng thái (State) sau khi cập nhật lá $j_i$.
* $\text{path}_{j_i}$: Lộ trình xác thực Merkle (Merkle Inclusion Path) tương ứng với vị trí $j_i$.

---

## 2. Constraint Groups

Mạch logic của StepCircuit bắt buộc phải thỏa mãn đồng thời 5 nhóm ràng buộc (constraints) sau đây:

### 1. Replica Reconstruction
Circuit phải tái tạo chính xác replica chunk:

$$R_{j_i} = \text{Poseidon2}(D_{j_i}, S_{j_i-1}, j_{i}, \text{Replica\_{id}})$$

> **Ý nghĩa:** đảm bảo replica được sinh đúng từ dữ liệu gốc, liên kết với trạng thái trước đó và replica identifier.
### 2. State check
Circuit xác minh cập nhật trạng thái:
$$S_{j_i} = \text{Poseidon2}(S_{j_i - 1}, R_{j_i})$$

> **Ý nghĩa:** duy trì dependency tuần tự giữa các chunk

### 3. Path Check (`path_check`)
Xác thực tính hợp lệ của dữ liệu nằm trong cây Merkle đã cam kết:

$$\text{MerkleVerify}(R_{j_i}, \text{path}_{j_i}, j_i, R_{\text{sealed}}) = 1$$

> **Ý nghĩa:** Đảm bảo rằng trạng thái $R_{j_i}$ nằm đúng vị trí $j_i$ trong cây Merkle có gốc là $R_{\text{sealed}}$ thông qua bằng chứng xác thực $\text{path}_{j_i}$.

### 4. Challenge Binding (`challenge_binding`)
Ràng buộc này triệt tiêu khả năng Prover tự chọn vị trí thử thách có lợi cho mình:

$$j_i = \text{Poseidon2}(\text{beacon}, \text{sector\_id}, \text{epoch}, i) \pmod N$$

> **Ý nghĩa:** prover không thể tự chọn vị trí challenge.

### 5. State Accumulation (`state_accumulation`)
Ràng buộc tích lũy trạng thái phục vụ cho cơ chế đệ quy (Folding Scheme).

Gọi $z_i$ là trạng thái tích lũy IVC (Incrementally Verifiable Computation) tại bước $i$, được khởi tạo bằng $z_0 = \text{Replica\_{id}}$:

$$z_i = \text{Poseidon2}(z_{i-1}, j_i, S_{j_i}, R_{\text{sealed}})$$

> **Ý nghĩa:** Trạng thái tích lũy tổng thể $z_i$ tại bước hiện tại phải nén (hash) toàn bộ thông tin từ bước trước $z_{i-1}$ cùng với các dữ liệu cốt lõi của bước này ($j_i, S_{j_i}, R_{\text{sealed}}$), phục vụ việc xác minh chuỗi tính toán liên tục gọn nhẹ.


### 1. Trả lời về chu trình đường cong (BN254/Grumpkin vs Pallas/Vesta) và Groth16

Về mặt lý thuyết, Folding Scheme **có hoạt động** với chu trình BN254/Grumpkin. Vì Groth16 yêu cầu một đường cong hỗ trợ pairing (như BN254), việc fold trên chu trình BN254/Grumpkin sau đó bọc (wrap) bằng Groth16 ở bước cuối là "chén thánh" để xác minh giá rẻ trên Ethereum.

Việc này **không gây bùng nổ RAM** cho prover. Lý do là Folding Scheme đã nén toàn bộ $n$ bước kiểm tra thành một Relaxed R1CS instance duy nhất. Khi chuyển sang Groth16, mạch Groth16 không phải chứng minh lại $n$ bước đó, mà nó chỉ đóng vai trò là một "Decider Circuit" — chứng minh rằng instance đã được fold kia là hợp lệ. Kích thước mạch Groth16 lúc này rất nhỏ và cố định, nên RAM cần cho Trusted Setup (SRS) của Groth16 là cực kỳ thấp.

**Tuy nhiên, xét theo nguyên tắc thực tiễn bạn đề ra:**
Mặc dù lý thuyết là hoàn hảo, nhưng hiện tại **không có thư viện Rust nào off-the-shelf (sẵn sàng dùng ngay) và ổn định** cho BN254/Grumpkin folding kết hợp Groth16. Các dự án như `sirius` hay các ProtoStar/Sangria implement vẫn đang trong giai đoạn experimental (thử nghiệm), API thay đổi liên tục và thiếu tài liệu.

Do đó, theo quyết định của bạn: **Chúng ta sẽ sử dụng Pallas/Vesta kết hợp với Spartan.** 
Thư viện `nova-snark` của Microsoft hỗ trợ chu trình Pasta (Pallas/Vesta) cực kỳ ổn định. File `poseidon2_rust_params.sage` bạn cung cấp cũng đã tự động gen ra code tương thích với `pasta_curves::pallas::Scalar` và tham số `t=3` rất chuẩn cho Pallas. Spartan chứng minh cũng không cần Trusted Setup, nên bạn không bao giờ phải lo về RAM blowup ở bước proving cuối.

---

### 2. Phân tích hàm Sealing và Step Circuit

Logic toán học bạn thiết kế cho Sealing và Challenge rất chặt chẽ và thể hiện đúng tinh thần của Proof of Spacetime (PoSt): xích dữ liệu lại với nhau (chaining) qua các state $S_i$ để chống lại việc sinh dữ liệu lazy (đợi bị challenge mới tính toán).

Tuy nhiên, khi ánh xạ cơ chế này vào kiến trúc mạch gập (Step Circuit) của Nova, có một lỗ hổng logic nhỏ cần vá ở phần **Private Witness**.

#### Vấn đề của biến trạng thái $S_{j_i-1}$:

Ở bước Challenge, bạn chọn ngẫu nhiên một index $j_i$. Để tính toán lại $R_{j_i}$ và $S_{j_i}$ trong mạch, Prover phải truyền $S_{j_i-1}$ vào làm Private Witness.

* Logic của bạn: $R_{j_i} = Poseidon2(D_{j_i}, S_{j_i-1}, j_i, Replica_{id})$
* Xác minh Merkle: $R_{sealed} == MerkleRoot(R_{j_i}, \text{path}_{j_i})$

**Lỗ hổng:** Merkle Tree của bạn ($R_{sealed}$) hiện tại chỉ cam kết (commit) các giá trị $R_i$. Verifier (hoặc Mạch ZK) chỉ kiểm tra được $R_{j_i}$ có nằm trong cây hay không. Hệ thống **không có cách nào xác minh** xem Prover đưa cái $S_{j_i-1}$ vào có đúng là state thực sự tại bước đó không, hay là một state giả mạo mà Prover tự bịa ra để khớp với một $D_{j_i}$ rác. Bởi vì $S_{j_i-1}$ là Private Witness không bị ràng buộc (unconstrained).

#### Cách khắc phục (Cập nhật Merkle Tree)

Để mạch ZK có thể ép Prover trung thực về $S_{j_i-1}$, Merkle Tree không chỉ lưu $R_i$, mà mỗi lá (leaf) của Merkle Tree phải là một cam kết của cả $R_i$ và $S_i$.

Sửa đổi quá trình Sealing:


$$Leaf_i = Poseidon2(R_i, S_i)$$

$$R_{sealed} = MerkleRoot(Leaf_1, Leaf_2, \dots, Leaf_n)$$

Khi đó, ở bước Proof cho challenge $j_i$, Prover cung cấp Merkle Path cho $Leaf_{j_i}$. Mạch ZK sẽ chạy logic:

1. Tính lại $R_{j_i}$ từ $D_{j_i}$ và $S_{j_i-1}$.
2. Tính lại $S_{j_i}$ từ $S_{j_i-1}$ và $R_{j_i}$.
3. Tính lại $Leaf_{j_i} = Poseidon2(R_{j_i}, S_{j_i})$.
4. Kiểm tra $Leaf_{j_i}$ với Merkle Path và $R_{sealed}$.

Lúc này, Prover bắt buộc phải lưu (hoặc tính lại từ đầu) state $S_i$ chính xác thì mới qua được Merkle proof.

---

### 3. Định hình đầu vào cho Nova Step Circuit

Trong Nova, tại mỗi bước gập thứ $k$ (tương ứng với việc kiểm tra challenge $j_k$), mạch sẽ nhận trạng thái công khai $z_k$ và witness riêng tư $w_k$.

**State vector $z_k$ (Truyền tuần tự qua các bước gập):**
Nova yêu cầu kích thước của $z$ không đổi qua các bước. Ta sẽ dùng $z$ để lưu trữ các thông tin Public.


$$z_k = [R_{sealed}, Replica_{id}, \text{epoch}, Beacon]$$

**Witness vector $w_k$ (Đầu vào riêng tại mỗi bước $k$):**


$$w_k = (j_k, D_{j_k}, S_{j_k-1}, \text{path}_{j_k})$$

**Logic thực thi bên trong mạch gập tại bước $k$:**

1. **Challenge Binding:** Khẳng định $j_k = Poseidon2(Beacon, Sector_{id}, epoch, k) \pmod N$.
2. **Sealing logic:** Tính $R_{j_k}$ và $S_{j_k}$ như đã nêu trên.
3. **Merkle Verify:** Xác minh $Leaf_{j_k}$ tạo thành từ $R_{j_k}, S_{j_k}$ hợp lệ với $\text{path}_{j_k}$ và gốc $R_{sealed}$.
4. **Forward State:** Trả về $z_{k+1} = z_k$ (vì các public input này cố định cho toàn bộ epoch).

Bạn có muốn tôi bắt tay vào viết crate `core_primitives` (gồm Poseidon2 Pallas và Merkle Tree) bằng Rust dựa trên tham số sinh ra từ script của bạn không, hay bạn muốn chốt lại cấu trúc lá Merkle Tree trước khi chúng ta code?