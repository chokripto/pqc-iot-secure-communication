# Threat Model

## Attacker Capabilities
- Passive eavesdropping on the network
- Active tampering (modify/inject/drop packets)
- Replay attempts
- “Store now, decrypt later” strategy

## Security Goals
- Confidentiality of IoT telemetry
- Integrity and authenticity of messages
- Replay resistance at the session level
- Quantum-resistant key establishment

## Out of Scope (v1)
- Physical compromise / hardware extraction
- Side-channel resistance
- Full PKI lifecycle (certificates)
