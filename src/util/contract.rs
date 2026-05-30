use bech32::{FromBase32, ToBase32, Variant};

use crate::chain::{Network, Script};

const CONTRACT_MAINNET_PREFIX: &str = "ca";
const CONTRACT_TESTNET_PREFIX: &str = "tc";
const CONTRACT_ADDRESS_VERSION_V1: u8 = 1;
const CONTRACT_MAGIC: &[u8] = b"CT";
const CONTRACT_MIN_PAYLOAD_LEN: usize = 3;
const MAX_DIRECT_PUSH_LEN: usize = 75;

const OP_FALSE: u8 = 0x00;
const OP_IF: u8 = 0x63;
const OP_ENDIF: u8 = 0x68;

pub fn contract_prefix_for_network(network: Network) -> &'static str {
    match network {
        #[cfg(not(feature = "liquid"))]
        Network::Bitcoin | Network::Satsnet => CONTRACT_MAINNET_PREFIX,
        #[cfg(not(feature = "liquid"))]
        Network::Testnet
        | Network::Testnet4
        | Network::Regtest
        | Network::Signet
        | Network::Satstestnet => CONTRACT_TESTNET_PREFIX,
        #[cfg(feature = "liquid")]
        _ => CONTRACT_TESTNET_PREFIX,
    }
}

pub fn is_contract_script(script: &Script) -> bool {
    parse_contract_payload(script.as_bytes()).is_some()
}

pub fn contract_address_to_script(addr: &str, network: Network) -> Result<Script, String> {
    let (hrp, data, variant) = bech32::decode(addr).map_err(|err| err.to_string())?;
    if variant != Variant::Bech32 {
        return Err("invalid contract address checksum variant".to_string());
    }

    let expected_prefix = contract_prefix_for_network(network);
    if hrp.to_lowercase() != expected_prefix {
        return Err("contract address on invalid network".to_string());
    }

    let payload = Vec::<u8>::from_base32(&data).map_err(|err| err.to_string())?;
    validate_contract_payload(&payload)?;
    contract_script_from_payload(&payload)
}

pub fn contract_address_from_script(script: &Script, network: Network) -> Option<String> {
    let payload = parse_contract_payload(script.as_bytes())?;
    bech32::encode(
        contract_prefix_for_network(network),
        payload.to_base32(),
        Variant::Bech32,
    )
    .ok()
}

fn contract_script_from_payload(payload: &[u8]) -> Result<Script, String> {
    validate_contract_payload(payload)?;
    if payload.len() > MAX_DIRECT_PUSH_LEN {
        return Err("contract payload too long".to_string());
    }

    let mut script = Vec::with_capacity(6 + payload.len() + 2);
    script.push(OP_FALSE);
    script.push(OP_IF);
    script.push(CONTRACT_MAGIC.len() as u8);
    script.extend_from_slice(CONTRACT_MAGIC);
    script.push(payload.len() as u8);
    script.extend_from_slice(payload);
    script.push(OP_ENDIF);
    script.push(OP_FALSE);
    Ok(Script::from(script))
}

fn parse_contract_payload(script: &[u8]) -> Option<&[u8]> {
    if script.len() < 11 {
        return None;
    }
    if script[0] != OP_FALSE
        || script[1] != OP_IF
        || script[2] != CONTRACT_MAGIC.len() as u8
        || &script[3..5] != CONTRACT_MAGIC
    {
        return None;
    }

    let payload_len = script[5] as usize;
    let payload_start = 6;
    let payload_end = payload_start + payload_len;
    if payload_len < CONTRACT_MIN_PAYLOAD_LEN
        || script.len() != payload_end + 2
        || script[payload_end] != OP_ENDIF
        || script[payload_end + 1] != OP_FALSE
    {
        return None;
    }

    let payload = &script[payload_start..payload_end];
    validate_contract_payload(payload).ok()?;
    Some(payload)
}

fn validate_contract_payload(payload: &[u8]) -> Result<(), String> {
    if payload.len() < CONTRACT_MIN_PAYLOAD_LEN {
        return Err("contract address payload too short".to_string());
    }
    if payload[0] != CONTRACT_ADDRESS_VERSION_V1 {
        return Err(format!(
            "unsupported contract address version: {}",
            payload[0]
        ));
    }
    if payload[1] == 0 {
        return Err("contract address type must be non-zero".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_address_roundtrip_evm_payload() {
        let payload = [
            1, 2, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
        ];
        let script = contract_script_from_payload(&payload).unwrap();

        let address = contract_address_from_script(&script, Network::Satstestnet).unwrap();
        assert!(address.starts_with("tc1"));

        let decoded = contract_address_to_script(&address, Network::Satstestnet).unwrap();
        assert_eq!(script, decoded);
        assert!(is_contract_script(&decoded));
    }

    #[test]
    fn test_contract_address_roundtrip_template_payload() {
        let mut payload = vec![1, 1];
        payload.extend_from_slice(&[0x42; 32]);
        let script = contract_script_from_payload(&payload).unwrap();

        let address = contract_address_from_script(&script, Network::Satsnet).unwrap();
        assert!(address.starts_with("ca1"));

        let decoded = contract_address_to_script(&address, Network::Satsnet).unwrap();
        assert_eq!(script, decoded);
    }

    #[test]
    fn test_contract_address_rejects_wrong_network() {
        let mut payload = vec![1, 3];
        payload.extend_from_slice(&[0x24; 20]);
        let script = contract_script_from_payload(&payload).unwrap();
        let address = contract_address_from_script(&script, Network::Satsnet).unwrap();

        assert!(contract_address_to_script(&address, Network::Satstestnet).is_err());
    }
}
