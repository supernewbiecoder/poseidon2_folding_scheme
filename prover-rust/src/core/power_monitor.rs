use std::env;

pub fn estimate_energy_joules(elapsed_ms: u128, average_power_watts: f64) -> f64 {
    (elapsed_ms as f64 / 1000.0) * average_power_watts
}

pub fn stage_average_watts(stage: &str) -> f64 {
    let env_key = match stage {
        "Nova Init" => "ENGRAM_WATTS_NOVA_INIT",
        "Nova Folding" => "ENGRAM_WATTS_NOVA_FOLDING",
        "Spartan Setup" => "ENGRAM_WATTS_SPARTAN_SETUP",
        "Spartan Prove" => "ENGRAM_WATTS_SPARTAN_PROVE",
        "Spartan Verify" => "ENGRAM_WATTS_SPARTAN_VERIFY",
        "Export + Attestation" => "ENGRAM_WATTS_EXPORT",
        "Pipeline Total" => "ENGRAM_WATTS_TOTAL",
        _ => "ENGRAM_WATTS_DEFAULT",
    };

    env::var(env_key)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or_else(|| match stage {
            "Nova Init" => 45.0,
            "Nova Folding" => 85.0,
            "Spartan Setup" => 65.0,
            "Spartan Prove" => 95.0,
            "Spartan Verify" => 55.0,
            "Export + Attestation" => 25.0,
            "Pipeline Total" => 80.0,
            _ => 60.0,
        })
}

pub fn print_stage_power_report(stage: &str, elapsed_ms: u128, average_power_watts: f64) {
    let estimated_energy_joules = estimate_energy_joules(elapsed_ms, average_power_watts);
    println!(
        "[Power][{}] elapsed={} ms | avg={:.1} W | estimated={:.3} J",
        stage, elapsed_ms, average_power_watts, estimated_energy_joules
    );
}