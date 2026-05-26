use reqwest::Client;
use core::types::{DealMetadata, Proof};
use serde_json::json;

const VERIFIER_URL: &str = "http://localhost:8080";

pub async fn commit_sector(r_sealed: Vec<u8>, meta: DealMetadata) -> Result<(), reqwest::Error> {
    let client = Client::new();
    client.post(format!("{}/deal", VERIFIER_URL))
        .json(&json!({ "r_sealed": r_sealed, "metadata": meta }))
        .send()
        .await?;
    Ok(())
}

pub async fn get_challenge(epoch: &str, beacon: &str, sector_id: &str) -> Result<Vec<u64>, reqwest::Error> {
    let client = Client::new();
    let res = client.get(format!("{}/challenge", VERIFIER_URL))
        .query(&[("epoch", epoch), ("beacon", beacon), ("sector_id", sector_id)])
        .send()
        .await?;
    
    let challenges: Vec<u64> = res.json().await?;
    Ok(challenges)
}

pub async fn verify_proof(proof: Proof, r_sealed: Vec<u8>) -> Result<bool, reqwest::Error> {
    let client = Client::new();
    let res = client.post(format!("{}/verify", VERIFIER_URL))
        .json(&json!({ "proof": proof, "r_sealed": r_sealed }))
        .send()
        .await?;
    
    let status: bool = res.json().await?;
    Ok(status)
}