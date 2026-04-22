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
        const maxLeaves = 2 ** depth;

        this.leaves = leavesStr.map(str => {
            let hex = Buffer.from(str.trim(), 'utf8').toString('hex');
            return this.F.e(BigInt('0x' + hex)); 
        });

        while (this.leaves.length < maxLeaves) {
            this.leaves.push(this.F.e(0));
        }

        this.tree = this.buildTree(this.leaves);
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
// LỚP 2: ĐỐI TƯỢNG NHÀ CUNG CẤP LƯU TRỮ (BACKEND NODE)
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
        
        const dataSize = Buffer.byteLength(this.dataShards.join(''), 'utf8');
        return { root: this.merkleTree.root, dataSize };
    }

    async generateBatchProof(challengeIndices, committedRoot) {
        const leaves = [];
        const pathElements = [];
        const pathIndices = [];

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

        // 1. Kích thước API (JSON String) dùng cho Web Backend -> Frontend
        const jsonProofSize = Buffer.byteLength(JSON.stringify(proof));
        
        // 2. Kích thước On-chain (Raw Bytes) dùng cho Smart Contract
        // Groth16 luôn có định dạng cố định: 2 điểm G1 (64*2) + 1 điểm G2 (128) = 256 bytes
        const onChainProofSize = 256; 

        return {
            proof,
            publicSignals,
            timeMs: (endProve - startProve).toFixed(2),
            jsonProofSize,
            onChainProofSize
        };
    }
}

// ==========================================
// LỚP 3: GIAO THỨC MẠNG LƯỚI / SMART CONTRACT
// ==========================================
class ProtocolNetwork {
    constructor() {
        this.vKey = JSON.parse(fs.readFileSync("verification_key.json"));
        this.committedRoot = null;
    }

    receiveCommitment(root) {
        this.committedRoot = root;
    }

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
// LỚP 4: KỊCH BẢN CHẠY THỬ NGHIỆM TÍCH HỢP
// ==========================================
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const prompt = (query) => new Promise(resolve => rl.question(query, resolve));

async function main() {
    console.log("\n======================================================================");
    console.log("          MÔ PHỎNG GIAO THỨC ENGRAM - BẰNG CHỨNG LƯU TRỮ");
    console.log("======================================================================\n");

    const provider = new StorageProvider("Node_CTDL_Huy");
    const network = new ProtocolNetwork();

    const inputData = await prompt("[Hệ thống] Nhập các dữ liệu phân mảnh cần lưu trữ (cách nhau bằng dấu phẩy, tối đa 8 mục):\n> ");
    
    process.stdout.write("\n[Provider] Đang chạy mã hóa và băm cây Merkle Poseidon...\n");
    const { root, dataSize } = await provider.initData(inputData);
    network.receiveCommitment(root);
    
    const estimatedConstraints = "3,648"; 

    console.log(`\n[ BÁO CÁO CAM KẾT - PHASE 1 ]`);
    console.log(`- Số lượng phân mảnh nhận được: ${provider.dataShards.length} shards`);
    console.log(`- Tổng dung lượng cam kết      : ${dataSize} Bytes`);
    console.log(`- Mã cam kết (c_stor_i)       : ${root.substring(0, 40)}...`);
    console.log(`- Độ phức tạp mạch (Circuit)  : ${estimatedConstraints} (R1CS Constraints)`);

    const epochsStr = await prompt("\n[Hệ thống] Bạn muốn chạy bao nhiêu vòng kiểm tra (Epochs)?\n> ");
    const epochs = parseInt(epochsStr) || 1;
    const batchSize = 4; 

    console.log("\n================ BÁO CÁO XÁC THỰC LƯU TRỮ (EPOCHS) ================");
    for (let t = 1; t <= epochs; t++) {
        console.log(`\n---------------- EPOCH ${t} ----------------`);
        
        const epochSeed = `seed_epoch_${t}_time_${Date.now()}`;
        const challengeSet = network.generateBatchChallenge(epochSeed, 8, batchSize);
        console.log(`[Network]  Sinh tập thử thách gồm ${batchSize} shard: [${challengeSet.join(', ')}]`);

        process.stdout.write(`[Provider] Đang tính toán Bằng chứng SNARK tổng hợp (Prove)...\n`);
        const { proof, publicSignals, timeMs: proveTime, jsonProofSize, onChainProofSize } = await provider.generateBatchProof(challengeSet, root);
        
        console.log(`   > Trạng thái      : Đã gom ${batchSize} Merkle Paths thành 1 Bằng chứng.`);
        console.log(`   > Thời gian Prove : ${proveTime} ms`);
        console.log(`   > Kích thước API  : ${jsonProofSize} Bytes (JSON String)`);
        console.log(`   > Kích thước Chain: ${onChainProofSize} Bytes (Raw EVM Calldata)`);

        process.stdout.write(`[Network]  Xác minh bằng chứng (Smart Contract Verify)...\n`);
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