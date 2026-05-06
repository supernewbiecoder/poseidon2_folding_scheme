#!/usr/bin/env python3
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
circuits = root / 'circuits-circom'
src = circuits / 'input_wrapper.json'
dst = circuits / 'public_fixed.json'

with open(src, 'r', encoding='utf-8') as f:
    d = json.load(f)

pub = [
    d['expected_z0'],
    d['expected_zi'],
    d['spartan_proof_hash'],
    d['committee_pubkeys_hash'],
]

with open(dst, 'w', encoding='utf-8') as f:
    json.dump(pub, f)

print('WROTE', dst)
