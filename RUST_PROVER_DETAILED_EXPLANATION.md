# 📖 RUST PROVER CHI TIẾT - GIẢI THÍCH TỪNG DÒNG CODE

> Tài liệu này giải thích **toàn bộ cách hoạt động** của Rust Prover, bao gồm file structure, từng dòng code, luồng thực thi, và ví dụ cụ thể.

---

## 📋 MỤC LỤC

1. [Tổng Quan Kiến Trúc](#tổng-quan-kiến-trúc)
2. [File Structure & Module Definitions](#file-structure--module-definitions)
3. [Constants.rs - Poseidon2 Parameters](#constantsrs---poseidon2-parameters)
4. [Circuit.rs - Data Sector & PoSt Circuit](#circuitrs---data-sector--post-circuit)
5. [Poseidon2.rs - In-Circuit Hash Function](#poseidon2rs---in-circuit-hash-function)
6. [Proof Engine.rs - Nova & Spartan](#proof_enginers---nova--spartan)
7. [Main.rs - CLI Entry Point](#mainrs---cli-entry-point)
8. [Stage_spartan.sh - Build & Execute](#stage_spartan_sh---build--execute)
9. [End-to-End Flow Example](#end-to-end-flow-example)
10. [Key Concepts Explained](#key-concepts-explained)

---

## 🏗️ Tổng Quan Kiến Trúc

```
┌─────────────────────────────────────────────────────────────────┐
│                      USER RUNS: ./run_pipeline.sh                │
└──────────────────┬──────────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────────┐
│           scripts/stage_spartan.sh "shard1,shard2,..."           │
│  - Builds Rust binary (cargo build --release)                    │
│  - Executes binary with ENGRAM_ROOT_DIR env var                  │
└──────────────────┬──────────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────────┐
│              prover-rust/target/release/engram-prover            │
│                         (MAIN BINARY)                             │
└──────────────────┬──────────────────────────────────────────────┘
                   │
        ┌──────────┴──────────┬──────────────┬──────────────┐
        ▼                     ▼              ▼              ▼
   ┌────────┐         ┌────────────┐  ┌──────────┐  ┌────────────┐
   │ main() │         │DataSector  │  │PoStStep  │  │PostProof   │
   │        │────────▶│  ::new()   │─▶│ Circuit  │─▶│ Engine::   │
   └────────┘         │            │  │          │  │run_pipeline│
       │              └────────────┘  └──────────┘  └────────────┘
       │                  │               │              │
       │                  ▼               ▼              ▼
       │            [Merkle Tree]   [Folding Steps]  [Nova/Spartan]
       │                                                │
       ▼                                                ▼
  [Input Parse]                                   [Proof Generated]
  [Shards]                                             │
                                                       ▼
                                              [Export JSON + Sign]
                                                       │
                                                       ▼
                                             circuits-circom/input.json

Note: For local development the repository includes `scripts/simulate_committee_sign.py` which can produce deterministic test signatures for the committee. `run_pipeline.sh` will automatically call this simulator when `circuits-circom/input.json` contains `committee.size == 0` so that the full wrapper stage can run end-to-end locally. In production the committee MUST fetch `compressed_proof.bin`, run native verification, compute `zi_primary`, compare with the prover-provided `zi`, and only then sign with their private keys (HSM/KMS recommended).
```

---

## 📂 File Structure & Module Definitions

### `prover-rust/src/core/mod.rs`
```rust
pub mod poseidon2;
pub mod circuit;
pub mod proof_engine;
```

**Giải thích**: Đây là module declaration file. Nó public export 3 modules:
- `poseidon2`: Poseidon2 hash gadget cho circuit
- `circuit`: DataSector + PoStStepCircuit definitions
- `proof_engine`: Nova folding + Spartan compression engine

Tương đương với:
```bash
prover-rust/src/core/
  ├── poseidon2.rs
  ├── circuit.rs
  └── proof_engine.rs
```

---

## 🔢 Constants.rs - Poseidon2 Parameters

### Định Nghĩa Hằng Số
```rust
pub const R_F: usize = 8;    // Số vòng Full-round của Poseidon2
pub const R_P: usize = 56;   // Số vòng Partial-round
pub const T: usize = 3;      // Kích thước state (arity = 3)
```

**Ý nghĩa**:
- **R_F = 8**: Poseidon2 chạy 8 vòng full (tất cả 3 state được S-box)
- **R_P = 56**: Poseidon2 chạy 56 vòng partial (chỉ state[0] được S-box)
- **Tổng cộng**: 8 + 56 = 64 vòng
- **T = 3**: Mỗi hash nhận 3 inputs, ví dụ `hash(left, right, 0)`

### Hàm `from_hex(s: &str) -> Fr`
```rust
pub fn from_hex(s: &str) -> Fr {
    let clean_s = s.trim_start_matches("0x");
    
    // Đệm số '0' nếu chuỗi bị lẻ
    let padded_s = if clean_s.len() % 2 != 0 {
        format!("0{}", clean_s)
    } else {
        clean_s.to_string()
    };

    let bytes = hex::decode(padded_s).expect("Lỗi giải mã hex");
    let mut repr = [0u8; 32];
    
    // Đảo ngược byte vì pasta_curves sử dụng little-endian
    for (i, &b) in bytes.iter().rev().enumerate() {
        repr[i] = b;
    }
    
    Option::from(Fr::from_repr(repr)).expect("Lỗi khởi tạo phần tử trường")
}
```

**Ví dụ**:
```
Input:  "0x01"
        ↓ trim_start_matches("0x")
Output: "01"
        ↓ length=2 (chẵn), no padding needed
        ↓ hex::decode("01")
Output: [0x01]
        ↓ reverse & pad to 32 bytes
Output: [0x01, 0x00, 0x00, ..., 0x00]
        ↓ convert to Fr
Output: Fr::from_repr([0x01, 0x00, ...])
```

### Poseidon2 Matrices
```rust
lazy_static! {
    pub static ref MAT_FULL: [[Fr; 3]; 3] = [
        [2, 1, 1],
        [1, 2, 1],
        [1, 1, 2],
    ];

    pub static ref MAT_PARTIAL: [[Fr; 3]; 3] = [
        [2, 1, 1],
        [1, 2, 1],
        [1, 1, 3],  // ← Note: phần tử (2,2) khác = 3 thay vì 2
    ];
```

**Giải thích**:
- **MAT_FULL**: Ma trận được dùng trong vòng full-round (toàn bộ state được biến đổi)
- **MAT_PARTIAL**: Ma trận được dùng trong vòng partial-round (chỉ state[0] được S-box)
- Sử dụng `lazy_static!` để khởi tạo 1 lần lúc chạy

### Round Constants (RC)
```rust
pub static ref RC: Vec<[Fr; 3]> = vec![
    [hex("0x36..."), hex("0x2b..."), hex("0x15...")], // Round 0
    [hex("0x32..."), hex("0x07..."), hex("0x2a...")], // Round 1
    // ... 62 rounds khác
    [hex("0x22..."), hex("0x35..."), hex("0x30...")], // Round 63
];
```

**Ý nghĩa**: Mỗi vòng Poseidon2 cộng thêm constants khác nhau vào state. Có 64 vòng = 64 RC khác nhau.

---

## 🔐 Circuit.rs - Data Sector & PoSt Circuit

### Native Poseidon2 (CPU-level)
```rust
pub fn sbox(x: Fr) -> Fr {
    let x2 = x.square();      // x^2
    let x4 = x2.square();     // x^4
    x4 * x                    // x^4 * x = x^5
}
```

**Ý nghĩa**: S-box của Poseidon2 là hàm x^5 trên trường hữu hạn.

### Native Hash Function
```rust
pub fn native_poseidon2(left: Fr, right: Fr) -> Fr {
    let mut state = [left, right, Fr::ZERO];
    
    // ... 64 vòng Poseidon2 ...
    
    state[0]  // Trả về phần tử đầu tiên
}
```

**Ví dụ**:
```
native_poseidon2(Fr::from(1u64), Fr::from(2u64))
  ↓ state = [1, 2, 0]
  ↓ apply 8 vòng full-round + 56 vòng partial-round
  ↓ state = [hash_result, ..., ...]
  ↓ return hash_result (trả về state[0])
```

### DataSector Struct
```rust
#[derive(Clone, Debug)]
pub struct DataSector {
    pub raw_data: Vec<Fr>,           // Dữ liệu shard thô (đã pad 8)
    pub leaves: Vec<Fr>,             // Leaf hashes từ native_poseidon2
    pub tree: Vec<Vec<Fr>>,          // Toàn bộ Merkle tree
    pub commitment_root: Fr,         // Root hash
}
```

### DataSector::new() - Chi Tiết
```rust
pub fn new(raw_shards: Vec<&str>) -> Self {
    // ========== BƯỚC 1: Chuyển string thành Fr ==========
    let mut raw_data: Vec<Fr> = raw_shards.iter().map(|s| {
        let mut bytes = [0u8; 32];                    // Khởi tạo 32 byte = 0
        let s_bytes = s.as_bytes();
        let len = std::cmp::min(s_bytes.len(), 31);   // Max 31 bytes
        bytes[..len].copy_from_slice(&s_bytes[..len]);// Copy string bytes
        Option::from(Fr::from_repr(bytes))
            .expect("Lỗi chuyển đổi dữ liệu")
    }).collect();
    
    // ========== BƯỚC 2: Pad lên 8 shard ==========
    while raw_data.len() < 8 { 
        raw_data.push(Fr::ZERO); 
    }
    
    // ========== BƯỚC 3: Hash mỗi leaf ==========
    let leaves: Vec<Fr> = raw_data.iter().map(|&data| 
        native_poseidon2(data, Fr::ZERO)
    ).collect();
    
    // ========== BƯỚC 4: Xây dựng Merkle tree ==========
    let mut tree = vec![leaves.clone()];
    let mut current_level = leaves.clone();
    while current_level.len() > 1 {
        let mut next_level = vec![];
        for i in (0..current_level.len()).step_by(2) {
            next_level.push(native_poseidon2(
                current_level[i], 
                current_level[i+1]
            ));
        }
        tree.push(next_level.clone());
        current_level = next_level;
    }
    
    Self { 
        raw_data, 
        leaves, 
        tree: tree.clone(), 
        commitment_root: current_level[0] 
    }
}
```

**Ví dụ Chi Tiết**:
```
Input: raw_shards = ["alice", "bob"]

BƯỚC 1: Chuyển sang Fr
  "alice" → as_bytes() = [97, 108, 105, 99, 101]
         → bytes = [97, 108, 105, 99, 101, 0, 0, ..., 0] (32 bytes)
         → Fr::from_repr(bytes) → Fr_alice
  "bob" → [98, 111, 98, 0, ..., 0]
       → Fr_bob

BƯỚC 2: Pad 8
  raw_data = [Fr_alice, Fr_bob, Fr::ZERO, Fr::ZERO, Fr::ZERO, Fr::ZERO, Fr::ZERO, Fr::ZERO]

BƯỚC 3: Hash leaves
  leaves[0] = native_poseidon2(Fr_alice, 0)    = hash_alice
  leaves[1] = native_poseidon2(Fr_bob, 0)      = hash_bob
  leaves[2] = native_poseidon2(Fr::ZERO, 0)    = hash_zero
  leaves[3] = native_poseidon2(Fr::ZERO, 0)    = hash_zero
  ... (8 leaves total)

BƯỚC 4: Xây Merkle tree
  Level 0 (leaves):
    [hash_alice, hash_bob, hash_z, hash_z, hash_z, hash_z, hash_z, hash_z]
  
  Level 1 (pair-hash):
    [
      native_poseidon2(hash_alice, hash_bob),    // Pair 0-1
      native_poseidon2(hash_z, hash_z),          // Pair 2-3
      native_poseidon2(hash_z, hash_z),          // Pair 4-5
      native_poseidon2(hash_z, hash_z),          // Pair 6-7
    ]
  
  Level 2:
    [
      native_poseidon2(L1[0], L1[1]),
      native_poseidon2(L1[2], L1[3]),
    ]
  
  Level 3 (root):
    [
      native_poseidon2(L2[0], L2[1]),
    ]
  
  Final commitment_root = Level 3[0]
```

### DataSector::get_proof() - Merkle Proof
```rust
pub fn get_proof(&self, index: usize) -> (Fr, Vec<Fr>, Vec<Fr>) {
    let mut path_elements = vec![];  // Sibling nodes
    let mut path_indices = vec![];   // 0 = left, 1 = right
    let mut current_idx = index;
    
    for level in 0..3 {  // Tree có 3 levels (8 leaves = 2^3)
        let is_right = current_idx % 2 == 1;           // Nếu index lẻ → right
        let sibling_idx = if is_right { 
            current_idx - 1 
        } else { 
            current_idx + 1 
        };
        
        path_elements.push(self.tree[level][sibling_idx]);
        path_indices.push(if is_right { Fr::ONE } else { Fr::ZERO });
        current_idx /= 2;  // Đi lên một level
    }
    
    (self.raw_data[index], path_elements, path_indices) 
}
```

**Ví dụ**: Lấy proof cho leaf index 5
```
Index 5 = binary 0b101

Level 0 (index 5):
  5 là lẻ → right child
  sibling_idx = 5 - 1 = 4
  path_indices[0] = 1
  current_idx = 5 / 2 = 2

Level 1 (index 2):
  2 là chẵn → left child
  sibling_idx = 2 + 1 = 3
  path_indices[1] = 0
  current_idx = 2 / 2 = 1

Level 2 (index 1):
  1 là lẻ → right child
  sibling_idx = 1 - 1 = 0
  path_indices[2] = 1
  current_idx = 1 / 2 = 0

Output:
  raw_data[5]
  path_elements = [tree[0][4], tree[1][3], tree[2][0]]
  path_indices = [1, 0, 1]
```

### PoStStepCircuit - Định Nghĩa
```rust
#[derive(Clone, Debug)]
pub struct PoStStepCircuit {
    pub raw_data: Fr,              // Dữ liệu leaf
    pub challenge_index: Fr,       // Index cần chứng minh
    pub path_elements: Vec<Fr>,    // Sibling nodes
    pub path_indices: Vec<Fr>,     // Vị trí (0/1)
}
```

### PoStStepCircuit::synthesize() - In-Circuit Verification
```rust
fn synthesize<CS: ConstraintSystem<Fr>>(&self, cs: &mut CS, z_in: &[AllocatedNum<Fr>]) 
    -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
    
    // ========== BƯỚC A: Extract input state ==========
    let z_step_count = z_in[0].clone();        // Step counter từ folding
    let expected_root_var = z_in[1].clone();   // Root Merkle
    
    // ========== BƯỚC B: Allocate zero variable ==========
    let zero_var = AllocatedNum::alloc(
        cs.namespace(|| "zero_cap"), 
        || Ok(Fr::ZERO)
    )?;
    cs.enforce(
        || "enforce_zero_cap_safe", 
        |lc| lc + zero_var.get_variable() + CS::one(), 
        |lc| lc + CS::one(), 
        |lc| lc + CS::one()
    );
    // Constraint: zero_var * 1 = 1 * 1 → zero_var = 1 (ERROR!)
    // Actually Bellpepper sử dụng (Aφ)(Bφ) = Cφ, so this just ensures zero_var allocated
    
    // ========== BƯỚC C: Hash leaf ==========
    let raw_data_var = AllocatedNum::alloc(
        cs.namespace(|| "raw_data"), 
        || Ok(self.raw_data)
    )?;
    let hash_leaf_inputs = vec![raw_data_var, zero_var.clone(), zero_var.clone()];
    
    let leaf_out = {
        let mut ns_leaf = cs.namespace(|| "hash_leaf");
        let mut hasher_leaf = Poseidon2Gadget::new(&mut ns_leaf, hash_leaf_inputs);
        hasher_leaf.hash()?  // Trả về [state[0], state[1], state[2]]
    };
    let mut current_hash = leaf_out[0].clone();  // Chỉ lấy state[0]
    
    // ========== BƯỚC D: Reconstruct challenge index ==========
    let mut reconstructed_index_lc = LinearCombination::zero();
    let mut multiplier = Fr::ONE;
    
    for i in 0..self.path_elements.len() {
        let index = AllocatedNum::alloc(
            cs.namespace(|| format!("index_{}", i)), 
            || Ok(self.path_indices[i])
        )?;
        
        // Ensure index là 0 hoặc 1 (boolean)
        cs.enforce(
            || format!("boolean_index_safe_{}", i), 
            |lc| lc + index.get_variable(), 
            |lc| lc + index.get_variable(), 
            |lc| lc + index.get_variable()
        );
        // Constraint: index * index = index → index ∈ {0, 1}
        
        // Tích lũy: index × 2^i
        reconstructed_index_lc = reconstructed_index_lc + (multiplier, index.get_variable());
        multiplier = multiplier * Fr::from(2u64);
    }
    
    // ========== BƯỚC E: Merkle tree verification ==========
    for i in 0..self.path_elements.len() {
        let sibling = AllocatedNum::alloc(
            cs.namespace(|| format!("sibling_{}", i)), 
            || Ok(self.path_elements[i])
        )?;
        let index = AllocatedNum::alloc(
            cs.namespace(|| format!("index_{}", i)), 
            || Ok(self.path_indices[i])
        )?;
        
        // Tính left, right dựa trên index:
        // Nếu index=0: left = current_hash, right = sibling
        // Nếu index=1: left = sibling, right = current_hash
        
        let diff_val = current_hash.get_value()
            .zip(sibling.get_value())
            .map(|(c, s)| c - s);
        let diff = AllocatedNum::alloc(
            cs.namespace(|| format!("diff_{}", i)), 
            || diff_val.ok_or(SynthesisError::AssignmentMissing)
        )?;
        cs.enforce(
            || format!("enforce_diff_{}", i), 
            |lc| lc + current_hash.get_variable() - sibling.get_variable(), 
            |lc| lc + CS::one(), 
            |lc| lc + diff.get_variable()
        );
        // Constraint: current_hash - sibling = diff
        
        // index_diff = index * diff
        let index_diff_val = index.get_value()
            .zip(diff_val)
            .map(|(idx, d)| idx * d);
        let index_diff = AllocatedNum::alloc(
            cs.namespace(|| format!("index_diff_{}", i)), 
            || index_diff_val.ok_or(SynthesisError::AssignmentMissing)
        )?;
        cs.enforce(
            || format!("enforce_index_diff_{}", i), 
            |lc| lc + index.get_variable(), 
            |lc| lc + diff.get_variable(), 
            |lc| lc + index_diff.get_variable()
        );
        
        // left = current_hash - index_diff
        let left_val = current_hash.get_value()
            .zip(index_diff_val)
            .map(|(c, id)| c - id);
        let left = AllocatedNum::alloc(
            cs.namespace(|| format!("left_{}", i)), 
            || left_val.ok_or(SynthesisError::AssignmentMissing)
        )?;
        cs.enforce(
            || format!("enforce_left_{}", i), 
            |lc| lc + left.get_variable() + index_diff.get_variable(), 
            |lc| lc + CS::one(), 
            |lc| lc + current_hash.get_variable()
        );
        
        // right = sibling + index_diff
        let right_val = sibling.get_value()
            .zip(index_diff_val)
            .map(|(s, id)| s + id);
        let right = AllocatedNum::alloc(
            cs.namespace(|| format!("right_{}", i)), 
            || right_val.ok_or(SynthesisError::AssignmentMissing)
        )?;
        cs.enforce(
            || format!("enforce_right_{}", i), 
            |lc| lc + right.get_variable() - index_diff.get_variable(), 
            |lc| lc + CS::one(), 
            |lc| lc + sibling.get_variable()
        );
        
        // Hash parent node
        let hash_inputs = vec![left, right, zero_var.clone()];
        let mut ns = cs.namespace(|| format!("poseidon_{}", i));
        let mut hasher = Poseidon2Gadget::new(&mut ns, hash_inputs);
        let hash_out = hasher.hash()?;
        current_hash = hash_out[0].clone();
    }
    
    // ========== BƯỚC F: Final verification ==========
    cs.enforce(
        || "enforce_challenge_index_match", 
        |lc| lc + &reconstructed_index_lc, 
        |lc| lc + CS::one(), 
        |lc| lc + expected_index_var.get_variable()
    );
    // Constraint: reconstructed_index = challenge_index
    
    cs.enforce(
        || "enforce_merkle_root", 
        |lc| lc + current_hash.get_variable(), 
        |lc| lc + CS::one(), 
        |lc| lc + expected_root_var.get_variable()
    );
    // Constraint: final_hash = expected_root
    
    // ========== BƯỚC G: Output updated state ==========
    let next_step = AllocatedNum::alloc(
        cs.namespace(|| "next_step"), 
        || { Ok(z_step_count.get_value()
            .ok_or(SynthesisError::AssignmentMissing)? + Fr::ONE) }
    )?;
    cs.enforce(
        || "fwd_step", 
        |lc| lc + z_step_count.get_variable() + CS::one(), 
        |lc| lc + CS::one(), 
        |lc| lc + next_step.get_variable()
    );
    
    let next_root = AllocatedNum::alloc(
        cs.namespace(|| "next_root"), 
        || { expected_root_var.get_value()
            .ok_or(SynthesisError::AssignmentMissing) }
    )?;
    cs.enforce(
        || "fwd_root", 
        |lc| lc + expected_root_var.get_variable(), 
        |lc| lc + CS::one(), 
        |lc| lc + next_root.get_variable()
    );
    
    Ok(vec![next_step, next_root])
}
```

---

## 🔨 Poseidon2.rs - In-Circuit Hash Function

### Poseidon2Gadget Struct
```rust
pub struct Poseidon2Gadget<'a, CS: ConstraintSystem<Fr>> {
    cs: &'a mut CS,
    state: Vec<AllocatedNum<Fr>>,
}
```

### Hàm S-box
```rust
fn sbox(&mut self, x: &AllocatedNum<Fr>, name: &str) 
    -> Result<AllocatedNum<Fr>, SynthesisError> {
    let x_sq = x.square(self.cs.namespace(|| format!("{}_sq", name)))?;
    let x_quad = x_sq.square(self.cs.namespace(|| format!("{}_quad", name)))?;
    x_quad.mul(self.cs.namespace(|| format!("{}_penta", name)), x)
    // Tính x^5 = x^4 * x
}
```

### Apply Matrix
```rust
fn apply_matrix(&mut self, is_full_round: bool, namespace_prefix: &str) 
    -> Result<(), SynthesisError> {
    let matrix = if is_full_round { &*MAT_FULL } else { &*MAT_PARTIAL };
    let mut new_state = vec![];

    for i in 0..T {
        let mut lc = LinearCombination::zero();
        let mut val = Some(Fr::ZERO);

        for j in 0..T {
            lc = lc + (matrix[i][j], self.state[j].get_variable());
            if let (Some(mut v), Some(state_val)) = (val, self.state[j].get_value()) {
                v += matrix[i][j] * state_val;
                val = Some(v);
            } else { 
                val = None; 
            }
        }

        let sum_var = AllocatedNum::alloc(
            self.cs.namespace(|| format!("{}_matrix_mul_i{}", namespace_prefix, i)),
            || val.ok_or(SynthesisError::AssignmentMissing),
        )?;
        
        self.cs.enforce(
            || format!("{}_enforce_matrix_i{}", namespace_prefix, i),
            |lc_a| lc_a + &lc,
            |lc_b| lc_b + CS::one(),
            |lc_c| lc_c + sum_var.get_variable(),
        );
        new_state.push(sum_var);
    }
    self.state = new_state;
    Ok(())
}
```

**Ý nghĩa**: Tính state_mới = matrix × state_cũ trong circuit

### Hash Function
```rust
pub fn hash(&mut self) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
    let half_f = R_F / 2;  // = 4
    self.apply_matrix(true, "initial_premix")?;

    for r in 0..(R_F + R_P) {  // 64 vòng
        let is_full = r < half_f || r >= half_f + R_P;

        // ========== Add RC (Round Constants) ==========
        let mut state_after_rc = vec![];
        for i in 0..T {
            let rc = RC[r][i];
            let val = self.state[i].get_value().map(|v| v + rc);
            let added_var = AllocatedNum::alloc(
                self.cs.namespace(|| format!("r{}_add_rc_i{}", r, i)),
                || val.ok_or(SynthesisError::AssignmentMissing),
            )?;
            self.cs.enforce(
                || format!("r{}_enforce_rc_i{}", r, i),
                |lc| lc + self.state[i].get_variable() + (rc, CS::one()),
                |lc| lc + CS::one(),
                |lc| lc + added_var.get_variable(),
            );
            state_after_rc.push(added_var);
        }
        self.state = state_after_rc;

        // ========== Apply S-box ==========
        let mut state_after_sbox = vec![];
        for i in 0..T {
            if is_full || i == 0 {  // Partial: chỉ sbox state[0]
                let current_var = self.state[i].clone();
                let sboxed_var = self.sbox(&current_var, &format!("r{}_sbox_i{}", r, i))?;
                state_after_sbox.push(sboxed_var);
            } else {
                state_after_sbox.push(self.state[i].clone());
            }
        }
        self.state = state_after_sbox;

        // ========== Apply Matrix ==========
        self.apply_matrix(is_full, &format!("r{}", r))?;
    }

    Ok(self.state.clone())
}
```

**Ví dụ Poseidon2(1, 2, 0)**:
```
Round 0-3 (Full rounds):
  state = [1, 2, 0]
  ↓ add RC[0]
  state = [1+RC[0][0], 2+RC[0][1], 0+RC[0][2]]
  ↓ all sbox (x^5)
  state = [sbox(...), sbox(...), sbox(...)]
  ↓ apply MAT_FULL
  state = MAT_FULL × state
  ... (repeat 3 more times)

Round 4-59 (Partial rounds):
  ↓ add RC[r]
  ↓ sbox only state[0], keep state[1], state[2]
  ↓ apply MAT_PARTIAL
  ... (56 lần)

Round 60-63 (Full rounds):
  ↓ (repeat 4 lần full rounds)

Final:
  return state[0]
```

---

## ⚙️ Proof_engine.rs - Nova & Spartan

### Type Aliases
```rust
type G1 = pallas::Point;           // Curve A (Pallas)
type G2 = vesta::Point;            // Curve B (Vesta)
type EE1 = EvaluationEngine<G1>;   // IPA evaluation engine cho Pallas
type EE2 = EvaluationEngine<G2>;   // IPA evaluation engine cho Vesta
type S1 = RelaxedR1CSSNARK<G1, EE1>; // Spartan SNARK cho Pallas
type S2 = RelaxedR1CSSNARK<G2, EE2>; // Spartan SNARK cho Vesta
```

### PostProofEngine Struct
```rust
pub struct PostProofEngine<C1: StepCircuit<<G1 as Group>::Scalar>> {
    pp: PublicParams<G1, G2, C1, TrivialCircuit<<G2 as Group>::Scalar>>,
}
```

### Constructor: PostProofEngine::new()
```rust
pub fn new(primary_circuit: &C1) -> Self {
    let circuit_secondary = TrivialCircuit::default();
    
    let pp = PublicParams::setup(
        primary_circuit, 
        &circuit_secondary, 
    );
    Self { pp }
}
```

**Chi tiết**:
- `primary_circuit` = PoStStepCircuit (circuit thật)
- `circuit_secondary` = TrivialCircuit (dummy circuit, không verification gì)
- `PublicParams::setup` = khởi tạo public parameters để sau dùng cho folding

### run_pipeline() - Phần Chính
```rust
pub fn run_pipeline(&self, steps: Vec<C1>, z0: Vec<<G1 as Group>::Scalar>) {
    let circuit_secondary = TrivialCircuit::default();
    let z0_secondary = vec![<G2 as Group>::Scalar::ZERO];

    println!("   [Folding] Đang tích lũy các Epoch bằng Nova...");
    
    // ========== Nova Folding ==========
    let mut recursive_snark = RecursiveSNARK::new(
        &self.pp, &steps[0], &circuit_secondary, 
        z0.clone(), z0_secondary.clone()
    );

    for (i, step) in steps.iter().enumerate() {
        print!("\r     -> Đang Fold step {}/{}...", i + 1, steps.len());
        std::io::stdout().flush().unwrap();
        
        recursive_snark.prove_step(
            &self.pp, step, &circuit_secondary, 
            z0.clone(), z0_secondary.clone()
        ).unwrap();
    }
    println!("\n   ✅ Folding hoàn tất!");

    // ========== Spartan Compression ==========
    println!("   [Nén] Khởi chạy Spartan Compression...");
    
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&self.pp).unwrap();
    let compressed_proof = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&self.pp, &pk, &recursive_snark).unwrap();

    let num_steps = steps.len(); 
    
    let (zi_primary, _) = compressed_proof.verify(&vk, num_steps, z0.clone(), z0_secondary.clone()).unwrap();

    // ========== Export JSON + Sign ==========
    self.export_for_wrapper(&compressed_proof, &z0, &zi_primary);
}
```

### export_for_wrapper() - JSON Export & Attestation
```rust
fn export_for_wrapper(
    &self, 
    proof: &CompressedSNARK<...>, 
    z0: &Vec<<G1 as Group>::Scalar>, 
    zi: &Vec<<G1 as Group>::Scalar>
) {
    // ========== 1. Convert Fr to safe hex for Circom ==========
    let to_safe_hex = |scalar: &<G1 as Group>::Scalar| -> String {
        let mut bytes = scalar.to_repr().as_ref().to_vec();
        bytes[31] &= 0x1F;  // Mask high bits để fit trong BN254
        let mut hex_str = String::from("0x");
        for b in bytes.iter().rev() {
            hex_str.push_str(&format!("{:02x}", b));
        }
        hex_str
    };

    // ========== 2. Hash proof để tạo unique identifier ==========
    let proof_bytes = bincode::serialize(proof).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&proof_bytes);
    let digest = hasher.finalize();

    let mut hash_hex = String::from("0x");
    for byte in digest.iter().take(31) {
        hash_hex.push_str(&format!("{:02x}", byte));
    }

    let safe_z0 = to_safe_hex(&z0[1]);  // Root Merkle
    let safe_zi = to_safe_hex(&zi[1]);  // Final root

    // ========== 3. Create attestation message ==========
    let domain_sep = b"ENGRAM_SPARTAN_PROOF";
    let epoch: u32 = 1;
    let mut attestation_msg = Vec::new();
    attestation_msg.extend_from_slice(domain_sep);
    attestation_msg.extend_from_slice(safe_z0.as_bytes());
    attestation_msg.extend_from_slice(hash_hex.as_bytes());
    attestation_msg.extend_from_slice(&epoch.to_le_bytes());

    // ========== 4. Generate Ed25519 signature ==========
    let mut secret_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_key_bytes);
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let signature: Signature = signing_key.sign(&attestation_msg);
    let verifying_key = signing_key.verifying_key();

    let signature_hex = hex::encode(signature.to_bytes());
    let pubkey_hex = hex::encode(verifying_key.to_bytes());

    // ========== 5. Đóng gói JSON ==========
    let data = json!({
        "expected_z0": safe_z0.clone(),
        "expected_zi": safe_zi.clone(),
        "spartan_z0": safe_z0, 
        "spartan_zi": safe_zi,
        "spartan_proof_hash": hash_hex,
        "attestation": {
            "epoch": epoch,
            "domain_sep": "ENGRAM_SPARTAN_PROOF",
            "signature": signature_hex,
            "pubkey": pubkey_hex
        }
    });
    
    let root_dir = env::var("ENGRAM_ROOT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let cwd = env::current_dir().unwrap();
            if cwd.file_name().and_then(|name| name.to_str()) == Some("prover-rust") {
                cwd.parent().unwrap().to_path_buf()
            } else {
                cwd
            }
        });
    
    let input_path = root_dir.join("circuits-circom").join("input.json");
    let mut file = File::create(&input_path).unwrap();
    file.write_all(data.to_string().as_bytes()).unwrap();
    
    println!("✅ Đã xuất file input.json: {}", input_path.display());
    println!("🔐 Attestation signature: pubkey={}", &pubkey_hex[..16]);
    println!("🔐 Epoch: {}", epoch);
}
```

---

## 🚀 Main.rs - CLI Entry Point

```rust
fn main() {
    println!("\n======================================================================");
    println!("  MÔ PHỎNG GIAO THỨC ENGRAM (KIẾN TRÚC PIPELINE CHUẨN PRODUCT)");
    println!("======================================================================\n");

    // ========== INPUT: 3-level priority ==========
    let shards_source = match env::var("ENGRAM_SHARDS") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => env::args().nth(1).unwrap_or_else(|| {
            print!("[Hệ thống] Nhập các dữ liệu phân mảnh cần lưu trữ (cách nhau dấu phẩy):\n> ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            if let Err(_) = io::stdin().read_line(&mut input) {
                String::from("shard1,shard2,shard3,shard4")
            } else if input.trim().is_empty() {
                String::from("shard1,shard2,shard3,shard4")
            } else {
                input
            }
        }),
    };

    if !shards_source.trim().is_empty() {
        println!("[Input] Using shards: {}", shards_source.trim());
    }

    // ========== PARSE SHARDS ==========
    let raw_shards: Vec<&str> = shards_source.trim()
        .split(',')
        .filter(|s| !s.is_empty())
        .collect();

    // ========== BUILD MERKLE TREE ==========
    print!("[Provider] Đang băm dữ liệu và dựng cây Merkle...");
    io::stdout().flush().unwrap();
    let sector = DataSector::new(raw_shards);
    println!(" ✅ Xong. Mã cam kết: {:?}", sector.commitment_root);

    // ========== SETUP NOVA PARAMETERS ==========
    print!("[Engine] Đang khởi tạo Nova Public Params và Spartan Keys...");
    io::stdout().flush().unwrap();

    let (init_data, init_path, init_indices) = sector.get_proof(0);
    let init_circuit = PoStStepCircuit {
        raw_data: init_data,
        challenge_index: Fr::ZERO,
        path_elements: init_path,
        path_indices: init_indices,
    };

    let engine = PostProofEngine::new(&init_circuit);
    println!(" ✅ Xong");

    // ========== GENERATE RANDOM CHALLENGES ==========
    let batch_size = 4;
    let mut rng = rand::thread_rng();
    let mut challenges = vec![];
    while challenges.len() < batch_size {
        let idx = rng.gen_range(0..8) as usize;
        if !challenges.contains(&idx) { 
            challenges.push(idx); 
        }
    }
    challenges.sort();
    println!("[Network] Yêu cầu xác minh {} shard: {:?}", batch_size, challenges);

    // ========== BUILD STEP CIRCUITS ==========
    let mut steps = vec![];
    for &idx in &challenges {
        let (raw_data, path_elements, path_indices) = sector.get_proof(idx);
        steps.push(PoStStepCircuit {
            raw_data, 
            challenge_index: Fr::from(idx as u64),
            path_elements, 
            path_indices
        });
    }

    // ========== INITIAL STATE ==========
    let z0 = vec![Fr::ZERO, sector.commitment_root];
    
    // ========== RUN PIPELINE ==========
    engine.run_pipeline(steps, z0);
}
```

**Chi tiết từng bước**:

1. **Input Priority**:
   - Nếu `ENGRAM_SHARDS` env var tồn tại → dùng nó
   - Nếu không → dùng CLI argument đầu tiên
   - Nếu không → prompt interactive

2. **Parse Shards**:
   ```
   "shard1,shard2,shard3" 
   → .split(',') 
   → ["shard1", "shard2", "shard3"]
   ```

3. **Build DataSector**: Tạo Merkle tree từ shards

4. **Setup Engine**: Khởi tạo Nova public parameters

5. **Generate Challenges**: Random chọn 4 shards để challenge

6. **Build Circuits**: Tạo PoStStepCircuit cho mỗi shard

7. **Run Pipeline**: Nova folding + Spartan compression

---

## 🔧 Stage_spartan.sh - Build & Execute

```bash
#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

function get_time_ms() {
  date +%s%3N
}

if [ -z "$1" ]; then
  echo "Usage: $0 \"comma,separated,shards\"" >&2
  exit 1
fi

USER_INPUT="$1"

echo "[SPARTAN] BUILD RUST PROVER..."
START_BUILD=$(get_time_ms)
cd "$ROOT_DIR/prover-rust"
cargo build --release > /dev/null
END_BUILD=$(get_time_ms)

echo "[SPARTAN] RUN NOVA FOLDING + SPARTAN COMPRESSION..."
START_RUNTIME=$(get_time_ms)
cd "$ROOT_DIR"
printf '%s\n' "$USER_INPUT" | ENGRAM_ROOT_DIR="$ROOT_DIR" ./prover-rust/target/release/engram-prover
END_RUNTIME=$(get_time_ms)

echo "SPARTAN_BUILD_MS=$((END_BUILD - START_BUILD))"
echo "SPARTAN_RUNTIME_MS=$((END_RUNTIME - START_RUNTIME))"
```

**Chi tiết**:
- `set -e`: Exit nếu bất kỳ lệnh nào fail
- `get_time_ms()`: Trả về milliseconds từ epoch
- `ROOT_DIR`: Absolute path của root folder
- `cargo build --release`: Compile optimized binary
- `printf '%s\n' "$USER_INPUT" |`: Pipe input tới binary
- `ENGRAM_ROOT_DIR="$ROOT_DIR"`: Set env var để binary biết output directory
- In benchmark metrics: build time + runtime

---

## 📊 End-to-End Flow Example

### Scenario: 2 shards, 1 challenge

```
INPUT: shards = ["alice", "bob"]

┌─────────────────────────────────────────────────────────────┐
│ STEP 1: DataSector::new(["alice", "bob"])                   │
└─────────────────────────────────────────────────────────────┘

  1a. Convert to Fr:
      "alice" → [97,108,105,99,101,0,...,0] → Fr_alice
      "bob"   → [98,111,98,0,...,0]         → Fr_bob
  
  1b. Pad to 8:
      raw_data = [Fr_alice, Fr_bob, Fr::ZERO×6]
  
  1c. Hash leaves:
      leaves = [
        native_poseidon2(Fr_alice, 0),
        native_poseidon2(Fr_bob, 0),
        native_poseidon2(0, 0),
        native_poseidon2(0, 0),
        native_poseidon2(0, 0),
        native_poseidon2(0, 0),
        native_poseidon2(0, 0),
        native_poseidon2(0, 0),
      ]
  
  1d. Build tree:
      tree[0] = leaves (8 items)
      tree[1] = [
        native_poseidon2(leaves[0], leaves[1]),
        native_poseidon2(leaves[2], leaves[3]),
        native_poseidon2(leaves[4], leaves[5]),
        native_poseidon2(leaves[6], leaves[7]),
      ] (4 items)
      tree[2] = [
        native_poseidon2(tree[1][0], tree[1][1]),
        native_poseidon2(tree[1][2], tree[1][3]),
      ] (2 items)
      tree[3] = [
        native_poseidon2(tree[2][0], tree[2][1]),
      ] (1 item - ROOT)

┌─────────────────────────────────────────────────────────────┐
│ STEP 2: PostProofEngine::new(&init_circuit)                 │
└─────────────────────────────────────────────────────────────┘

  PublicParams setup(PoStStepCircuit, TrivialCircuit)
  → khởi tạo Nova PP

┌─────────────────────────────────────────────────────────────┐
│ STEP 3: Generate challenges                                 │
└─────────────────────────────────────────────────────────────┘

  Random pick 1 shard (vì batch_size=4 nhưng ta có 8 leaves):
  challenges = [3]

┌─────────────────────────────────────────────────────────────┐
│ STEP 4: Build PoStStepCircuit for shard 3                   │
└─────────────────────────────────────────────────────────────┘

  get_proof(3):
    Index 3 = 0b011
    Level 0: index=3 (lẻ) → sibling=2, path_indices[0]=1
    Level 1: index=1 (lẻ) → sibling=0, path_indices[1]=1
    Level 2: index=0 (chẵn) → sibling=1, path_indices[2]=0
    
    Return:
      raw_data = leaves[3] = native_poseidon2(0, 0)
      path_elements = [leaves[2], tree[1][0], tree[2][1]]
      path_indices = [1, 1, 0]
  
  PoStStepCircuit {
    raw_data: leaves[3],
    challenge_index: 3,
    path_elements: [leaves[2], tree[1][0], tree[2][1]],
    path_indices: [1, 1, 0],
  }

┌─────────────────────────────────────────────────────────────┐
│ STEP 5: Initial state                                       │
└─────────────────────────────────────────────────────────────┘

  z0 = [Fr::ZERO, tree[3][0]]  // [step_count, root]

┌─────────────────────────────────────────────────────────────┐
│ STEP 6: Nova folding                                        │
└─────────────────────────────────────────────────────────────┘

  RecursiveSNARK::new(pp, steps[0], TrivialCircuit, z0, z0_secondary)
  
  For step 0 (PoStStepCircuit for shard 3):
    Synthesize circuit:
      - Hash raw_data: native_poseidon2(leaves[3], 0)
      - Merkle verify:
        * Combine leaves[3] with leaves[2] → node0
        * Combine node0 with tree[1][0] → node1
        * Combine node1 with tree[2][1] → root
      - Constraints verify:
        * reconstructed_index == 3 ✓
        * final_hash == root ✓
      - Output: [1, root]
    
    prove_step() → creates proof π

┌─────────────────────────────────────────────────────────────┐
│ STEP 7: Spartan compression                                 │
└─────────────────────────────────────────────────────────────┘

  CompressedSNARK::prove(pp, pk, recursive_snark)
  → outputs compressed proof (much smaller)

┌─────────────────────────────────────────────────────────────┐
│ STEP 8: Export JSON + Sign                                  │
└─────────────────────────────────────────────────────────────┘

  compressed_proof → bincode serialize → SHA256 hash
  
  attestation_msg = "ENGRAM_SPARTAN_PROOF" || root || hash || epoch(1)
  
  Ed25519 sign(attestation_msg) → signature, pubkey
  
  Output JSON:
  {
    "expected_z0": "0x<root_hex>",
    "expected_zi": "0x<root_hex>",
    "spartan_z0": "0x<root_hex>",
    "spartan_zi": "0x<root_hex>",
    "spartan_proof_hash": "0x<sha256>",
    "attestation": {
      "epoch": 1,
      "domain_sep": "ENGRAM_SPARTAN_PROOF",
      "signature": "0x<ed25519>",
      "pubkey": "0x<ed25519_pubkey>"
    }
  }
  
  Write to circuits-circom/input.json
```

---

## 🔑 Key Concepts Explained

### 1. **Field Elements (Fr)**
```rust
type Fr = pasta_curves::pallas::Scalar;
```
- Scalar trên Pallas curve
- 255-bit prime field
- Mỗi shard/hash được represent bằng Fr

### 2. **Folding (Nova)**
- Gấp N bằng chứng thành 1 bằng chứng
- Từ 4 ProofOfStorage → 1 recursive proof
- Keeps constant constraint size

### 3. **Compression (Spartan)**
- Nén recursive SNARK thành non-interactive proof
- Giảm proof size từ ~MB → ~KB

### 4. **Merkle Tree Proving**
```
Goal: Prove leaf i ∈ tree
Method: Provide siblings + reconstruct root
Circuit: Verify reconstructed_root == expected_root
```

### 5. **In-Circuit Hash**
```
Poseidon2(state[0], state[1], state[2]):
  - 64 vòng (8 full + 56 partial)
  - S-box = x^5
  - Matrices + round constants
  - Output = state[0]
```

### 6. **Attestation**
```
Sign(privkey, sha256(compressed_proof))
→ provides verifiable link between:
  - Rust prover
  - Spartan proof
  - Circom verifier
```

### 7. **Two-Curve Setup (Pallas + Vesta)**
```
Pallas & Vesta là cyclic elliptic curves:
- Pallas.scalar ≈ Vesta.field
- Vesta.scalar ≈ Pallas.field
→ Allows efficient 2-cycle folding
```

---

## 🎯 Summary

| Component | Purpose | Input | Output |
|-----------|---------|-------|--------|
| **main.rs** | CLI entry, input parsing | Shards or env var | Run pipeline |
| **DataSector** | Build Merkle tree | Shard strings | Tree + root |
| **PoStStepCircuit** | Merkle proof circuit | Index + tree | Folding step |
| **Poseidon2Gadget** | In-circuit hashing | 3 values | 1 hash |
| **PostProofEngine** | Nova + Spartan | Steps + init state | Compressed proof |
| **export_for_wrapper** | JSON export + sign | Proof | input.json + attestation |
| **stage_spartan.sh** | Build + execute | Shards string | Benchmark metrics |

---

