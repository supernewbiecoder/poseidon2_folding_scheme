pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

// Mạch xác minh 1 Merkle Path
template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input root;

    component hashers[levels];
    component mux[levels][2];

    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        mux[i][0] = Mux1();
        mux[i][1] = Mux1();

        mux[i][0].c[0] <== levelHashes[i];
        mux[i][0].c[1] <== pathElements[i];
        mux[i][0].s <== pathIndices[i];
        hashers[i].inputs[0] <== mux[i][0].out;

        mux[i][1].c[0] <== pathElements[i];
        mux[i][1].c[1] <== levelHashes[i];
        mux[i][1].s <== pathIndices[i];
        hashers[i].inputs[1] <== mux[i][1].out;

        levelHashes[i + 1] <== hashers[i].out;
    }
    root === levelHashes[levels];
}

// MẠCH TỔNG HỢP (Batch/Aggregation)
template StorageBatchProof(levels, batchSize) {
    signal input leaves[batchSize];
    signal input pathElements[batchSize][levels];
    signal input pathIndices[batchSize][levels];
    signal input root; // Gốc chung duy nhất

    component checkers[batchSize];

    for (var i = 0; i < batchSize; i++) {
        checkers[i] = MerkleTreeChecker(levels);
        checkers[i].leaf <== leaves[i];
        checkers[i].root <== root;
        for (var j = 0; j < levels; j++) {
            checkers[i].pathElements[j] <== pathElements[i][j];
            checkers[i].pathIndices[j] <== pathIndices[i][j];
        }
    }
}

// Giả định cây Merkle sâu 3 (8 shards), kiểm tra tập 4 shards mỗi lần
component main {public [root]} = StorageBatchProof(3, 4);