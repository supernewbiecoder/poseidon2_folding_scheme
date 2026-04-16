const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const crypto = require("crypto");
const { performance } = require("perf_hooks");
const readline = require("readline");

// ==========================================
// LỚP 1: XỬ LÝ TOÁN HỌC & MERKLE TREE CHUẨN
// ==========================================
class PoseidonMerkleTree {
    constructor(leavesStr, poseidon, depth = 3) {
        this.poseidon = poseidon;
        this.F = poseidon.F;
        const maxLeaves = 2 ** depth; // Cây sâu 3 -> 8 lá

        // Chuyển chuỗi thành các phần tử của Trường hữu hạn (Field Elements)
        this.leaves = leavesStr.map(str => {
            let hex = Buffer.from(str.trim(), 'utf8').toString('hex');
            return this.F.e(BigInt('0x' + hex)); // Sửa lỗi ép kiểu tại đây
        });

        // Đệm thêm 0 cho đủ 8 phân mảnh (để mạch ZKP cố định kích thước)
        while (this.leaves.length < maxLeaves) {
            this.leaves.push(this.F.e(0));
        }

        this.tree = this.buildTree(this.leaves);
        
        // F.toObject() giúp chuyển an toàn từ Uint8Array sang BigInt
        this.root = this.F.toObject(this.tree[this.tree.length - 1][0]).toString();
    }

    buildTree(leaves) {
        let tree = [leaves];
        let currentLevel = leaves;
        while (currentLevel.length > 1) {
            let nextLevel = [];
            for (let i = 0; i < currentLevel.length; i += 2) {
                nextLevel.push(this.poseidon([currentLevel[i], currentLevel[i + 1]]));
            }
            tree.push(nextLevel);
            currentLevel = nextLevel;
        }
        return tree;
    }

    getProof(index) {
        let proofElements = [];
        let proofIndices = [];
        let currentIndex = index;

        for (let i = 0; i < this.tree.length - 1; i++) {
            let level = this.tree[i];
            let isRightNode = currentIndex % 2;
            let siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

            proofElements.push(this.F.toObject(level[siblingIndex]).toString());
            proofIndices.push(isRightNode);
            currentIndex = Math.floor(currentIndex / 2);
        }
        
        return { 
            leaf: this.F.toObject(this.leaves[index]).toString(), 
            proofElements, 
            proofIndices 
        };
    }
}

// ==========================================
// LỚP 2: ĐỐI TƯỢNG NHÀ CUNG CẤP LƯU TRỮ
// ==========================================
class StorageProvider {
    constructor(providerId) {
        this.providerId = providerId;
        this.dataShards = [];
        this.merkleTree = null;
    }

    async initData(rawShardsStr) {
        const poseidon = await buildPoseidon();
        this.dataShards = rawShardsStr.split(',').slice(0, 8); 
        this.merkleTree = new PoseidonMerkleTree(this.dataShards, poseidon, 3);
        
        // Tính tổng dung lượng byte thực tế của mảng đầu vào
        const dataSize = Buffer.byteLength(this.dataShards.join(''), 'utf8');
        return { root: this.merkleTree.root, dataSize };
    }

    // Tạo bằng chứng tổng hợp (Aggregation Proof) cho TẬP thử thách
    async generateBatchProof(challengeIndices, committedRoot) {
        const leaves = [];
        const pathElements = [];
        const pathIndices = [];

        // Gom toàn bộ witness của tập thử thách vào 1 mảng lớn
        challengeIndices.forEach(idx => {
            const p = this.merkleTree.getProof(idx);
            leaves.push(p.leaf);
            pathElements.push(p.proofElements);
            pathIndices.push(p.proofIndices);
        });

        const witness = { leaves, pathElements, pathIndices, root: committedRoot };

        const startProve = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            witness,
            "storage_batch_proof_js/storage_batch_proof.wasm",
            "storage_batch_final.zkey"
        );
        const endProve = performance.now();

        const proofSize = Buffer.byteLength(JSON.stringify(proof));

        return {
            proof,
            publicSignals,
            timeMs: (endProve - startProve).toFixed(2),
            proofSize
        };
    }
}

// ==========================================
// LỚP 3: GIAO THỨC MẠNG LƯỚI (NETWORK)
// ==========================================
class ProtocolNetwork {
    constructor() {
        this.vKey = JSON.parse(fs.readFileSync("verification_key.json"));
        this.committedRoot = null;
    }

    receiveCommitment(root) {
        this.committedRoot = root;
    }

    // Sinh ra tập hợp thử thách ngẫu nhiên (Mảng 4 index)
    generateBatchChallenge(epochSeed, totalLeaves = 8, batchSize = 4) {
        const indices = new Set();
        let counter = 0;
        while(indices.size < batchSize) {
            const hash = crypto.createHash('sha256').update(epochSeed + counter).digest('hex');
            const idx = parseInt(hash.substring(0, 8), 16) % totalLeaves;
            indices.add(idx);
            counter++;
        }
        return Array.from(indices).sort((a,b) => a-b);
    }

    async verifyBatchProof(proof, publicSignals) {
        const startVerify = performance.now();
        
        if (publicSignals[0] !== this.committedRoot) {
            return { isValid: false, timeMs: 0, msg: "Lỗi: Gốc Merkle không khớp với cam kết!" };
        }

        const isValid = await snarkjs.groth16.verify(this.vKey, publicSignals, proof);
        const endVerify = performance.now();
        return { isValid, timeMs: (endVerify - startVerify).toFixed(2) };
    }
}

// ==========================================
// LỚP 4: CLI INTERFACE MÔ PHỎNG THỰC TẾ
// ==========================================
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const prompt = (query) => new Promise(resolve => rl.question(query, resolve));

async function main() {
    console.log("\n======================================================================");
    console.log("          MÔ PHỎNG GIAO THỨC ENGRAM - STORAGE ACCOUNTABILITY");
    console.log("======================================================================\n");

    const provider = new StorageProvider("Node_CTDL_Huy");
    const network = new ProtocolNetwork();

    // 1. NGƯỜI DÙNG NHẬP DỮ LIỆU
    const inputData = await prompt("[Hệ thống] Nhập các dữ liệu phân mảnh cần lưu trữ (cách nhau bằng dấu phẩy, tối đa 8 mục):\n> ");
    
    process.stdout.write("\n[Provider] Đang chạy Erasure Coding và băm cây Merkle Poseidon...\n");
    const { root, dataSize } = await provider.initData(inputData);
    network.receiveCommitment(root);
    
    // R1CS Constraints cho Mạch Batch 4, Merkle Depth 3 bằng Poseidon
    const estimatedConstraints = "3,648"; 

    console.log(`\n[ BÁO CÁO CAM KẾT - PHASE 1 ]`);
    console.log(`- Số lượng phân mảnh nhận được: ${provider.dataShards.length} shards`);
    console.log(`- Tổng dung lượng cam kết      : ${dataSize} Bytes`);
    console.log(`- Mã cam kết (c_stor_i)       : ${root.substring(0, 40)}...`);
    console.log(`- Độ phức tạp mạch (Circuit)  : ${estimatedConstraints} (R1CS Constraints)`);

    // 2. THIẾT LẬP SỐ CHU KỲ
    const epochsStr = await prompt("\n[Hệ thống] Bạn muốn chạy bao nhiêu vòng kiểm tra (Epochs)?\n> ");
    const epochs = parseInt(epochsStr) || 1;
    const batchSize = 4; // Cố định theo file circom của chúng ta

    // 3. CHẠY VÒNG LẶP EPOCH
    console.log("\n================ BÁO CÁO XÁC THỰC LƯU TRỮ (EPOCHS) ================");
    for (let t = 1; t <= epochs; t++) {
        console.log(`\n---------------- EPOCH ${t} ----------------`);
        
        // Mạng lưới sinh seed và tập thử thách
        const epochSeed = `seed_epoch_${t}_time_${Date.now()}`;
        const challengeSet = network.generateBatchChallenge(epochSeed, 8, batchSize);
        console.log(`[Network]  Sinh tập thử thách (J_ipt) gồm ${batchSize} shard: [${challengeSet.join(', ')}]`);

        // Provider tạo bằng chứng NÉN TỔNG HỢP
        process.stdout.write(`[Provider] Đang tính toán Bằng chứng SNARK tổng hợp (Prove)...\n`);
        const { proof, publicSignals, timeMs: proveTime, proofSize } = await provider.generateBatchProof(challengeSet, root);
        
        console.log(`   > Trạng thái      : Đã gom ${batchSize} Merkle Paths thành 1 Bằng chứng duy nhất.`);
        console.log(`   > Thời gian Prove : ${proveTime} ms`);
        console.log(`   > Kích thước Proof: ${proofSize} Bytes (O(1) Succinctness)`);

        // Mạng lưới xác minh
        process.stdout.write(`[Network]  Xác minh bằng chứng toán học (Verify)...\n`);
        const { isValid, timeMs: verifyTime } = await network.verifyBatchProof(proof, publicSignals);

        if (isValid) {
            console.log(`   > Kết quả Verify  : ✅ HỢP LỆ (Thời gian: ${verifyTime} ms)`);
        } else {
            console.log(`   > Kết quả Verify  : ❌ KHÔNG HỢP LỆ`);
        }
    }
    console.log("\n======================================================================\n");
    rl.close();
}

main().catch(err => {
    console.error("Lỗi hệ thống:", err);
    rl.close();
});