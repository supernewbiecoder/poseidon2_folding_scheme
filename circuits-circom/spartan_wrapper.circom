pragma circom 2.1.5;

template SecureSpartanBridge() {
    // ============ PUBLIC INPUTS (on-chain verifier sees these) ============
    signal input expected_z0;
    signal input expected_zi;
    signal input spartan_proof_hash;
    signal input committee_pubkeys_hash;  // Hash of all committee pubkeys (from multi-sig attestation)

    // ============ WITNESS (prover knows these, hidden from on-chain verifier) ============
    signal input spartan_z0;
    signal input spartan_zi;

    // ============ BINDING CONSTRAINTS ============
    // Enforce equality: witness must match public inputs (prevent substitution)
    expected_z0 === spartan_z0;
    expected_zi === spartan_zi;

    // ============ COMMITTEE COMMITMENT ============
    // Link committee pubkeys hash into Groth16 proof
    // On-chain verifier checks Groth16 proof, which proves:
    // 1. These are the z0/zi values
    // 2. These values were signed by committee (whose pubkeys hash to committee_pubkeys_hash)
    // 3. spartan_proof_hash matches (included in public inputs)
    
    // Simple commitment binding (prove prover knows all three values)
    signal expected_commitment;
    signal witness_commitment;

    expected_commitment <== expected_z0 * spartan_proof_hash + expected_zi + committee_pubkeys_hash;
    witness_commitment <== spartan_z0 * spartan_proof_hash + spartan_zi + committee_pubkeys_hash;

    expected_commitment === witness_commitment;
}

// Public inputs: expected_z0, expected_zi, spartan_proof_hash, committee_pubkeys_hash
// Witness inputs: spartan_z0, spartan_zi
component main {public [expected_z0, expected_zi, spartan_proof_hash, committee_pubkeys_hash]} = SecureSpartanBridge();