



use std::str::FromStr;

use bitcoin::{Amount, FeeRate};
use bitcoin::secp256k1::SecretKey;
use elements::AssetId;
use serde_json::json;
use wasm_bindgen::prelude::*;

use crate::BondSpec;



/// Create a segwit bond and address.
///
/// Input:
/// - `network`: "liquid", "liquidtestnet" or "elements"
/// - `pubkey`: public key in hex that will commit to the bond
/// - `bond_value`: value in sats
/// - `bond_asset`: asset id in hex, or "lbtc"
/// - `lock_time_unix`: locktime as a unix timestamp (like block timestamps)
/// - `reclaim_pubkey`: public key in hex to be used for reclaiming the bond
///
/// Output: object with following fields:
/// - spec: base64 bond specification
/// - address: Elements/Liquid address to send money into the bond
#[wasm_bindgen]
pub fn create_segwit_bond_address(
	network: &str,
	pubkey: &str,
	bond_value_sat: u64,
	bond_asset: &str,
	lock_time_unix: u64,
	reclaim_pubkey: &str,
) -> Result<JsValue, JsValue> {
	let network = parse_elements_network(network)?;
	let pubkey = pubkey.parse().map_err(|e| format!("invalid pubkey: {}", e))?;
	let bond_value = Amount::from_sat(bond_value_sat);
	let bond_asset = parse_asset_id(bond_asset)?;
	let locktime = lock_time_from_unix(lock_time_unix)?;
	let reclaim_pubkey = reclaim_pubkey.parse().map_err(|e| format!("invalid pubkey: {}", e))?;

	let (spec, addr) = crate::create_segwit_bond_address(
		network, pubkey, bond_value, bond_asset, locktime, reclaim_pubkey,
	);
	Ok(serde_wasm_bindgen::to_value(&json!({
		"spec": spec.to_base64(),
		"address": addr.to_string(),
	})).unwrap())
}

/// Create a transaction to burn a bond.
///
/// Input:
/// - `utxo`: the Elements/Liquid UTXO in the format of [ElementsUtxo]
/// - `spec_base64`: bond spec encoded as base64
/// - `double_spend_utxo`: the Bitcoin UTXO that was double spend in the format of [BitcoinUtxo]
/// - `tx1_hex`: first double spend Bitcoin tx in hex
/// - `tx2_hex`: second double spend Bitcoin tx in hex
/// - `fee_rate_sat_per_vb`: the fee rate to use in satoshi per virtual byte
/// - `reward_address`: the reward Elements/Liquid address where to send the reward
///
/// Output: an Elements/Liquid transaction in hex
#[wasm_bindgen]
pub fn create_burn_tx(
	utxo: JsValue,
	spec_base64: &str,
	double_spend_utxo: JsValue,
	tx1_hex: &str,
	tx2_hex: &str,
	fee_rate_sat_per_vb: u64,
	reward_address: &str,
) -> Result<String, JsValue> {
	let utxo = serde_wasm_bindgen::from_value(utxo)
		.map_err(|e| format!("invalid bond UTXO: {}", e))?;
	let spec = BondSpec::from_base64(spec_base64)
		.map_err(|e| format!("invalid spec: {}", e))?;
	let double_spend_utxo = serde_wasm_bindgen::from_value(double_spend_utxo)
		.map_err(|e| format!("invalid bond UTXO: {}", e))?;
	let tx1 = elem_deserialize_hex(tx1_hex)
		.map_err(|e| format!("bad tx1_hex: {}", e))?;
	let tx2 = elem_deserialize_hex(tx2_hex)
		.map_err(|e| format!("bad tx2_hex: {}", e))?;
	let fee_rate = FeeRate::from_sat_per_vb(fee_rate_sat_per_vb)
		.ok_or_else(|| "invalid feerate")?;
	let reward_address = elements::Address::from_str(reward_address)
		.map_err(|e| format!("invalid reward address: {}", e))?;

	let tx = crate::create_burn_tx(
		&utxo, &spec, &double_spend_utxo, &tx1, &tx2, fee_rate, &reward_address,
	)?;
	Ok(elements::encode::serialize_hex(&tx))
}

/// Create a transaction to reclaim a bond after it has expired.
///
/// Input:
/// - `utxo`: the Elements/Liquid UTXO in the format of [ElementsUtxo]
/// - `spec_base64`: bond spec encoded as base64
/// - `fee_rate_sat_per_vb`: the fee rate to use in satoshi per virtual byte
/// - `reclaim_sk`: secret key of the reclaim pubkey in either WIF or hex
/// - `claim_address`: the claim Elements/Liquid address where to send the funds
///
/// Output: an Elements/Liquid transaction in hex
#[wasm_bindgen]
pub fn create_reclaim_tx(
	utxo: JsValue,
	spec_base64: &str,
	fee_rate_sat_per_vb: u64,
	reclaim_sk: &str,
	claim_address: &str,
) -> Result<String, JsValue> {
	let utxo = serde_wasm_bindgen::from_value(utxo)
		.map_err(|e| format!("invalid bond UTXO: {}", e))?;
	let spec = BondSpec::from_base64(spec_base64)
		.map_err(|e| format!("invalid spec: {}", e))?;
	let fee_rate = FeeRate::from_sat_per_vb(fee_rate_sat_per_vb).ok_or_else(|| "invalid feerate")?;
	let reclaim_sk = parse_secret_key(reclaim_sk)?;
	let claim_address = elements::Address::from_str(claim_address)
		.map_err(|e| format!("invalid reward address: {}", e))?;

	let tx = crate::create_reclaim_tx(&utxo, &spec, fee_rate, &reclaim_sk, &claim_address)?;
	Ok(elements::encode::serialize_hex(&tx))
}

/// Deserialize an elements object from hex.
pub fn elem_deserialize_hex<T: elements::encode::Decodable>(hex: &str) -> Result<T, String> {
	let mut iter = hex_conservative::HexToBytesIter::new(hex)
		.map_err(|e| format!("invalid hex string: {}", e))?;
	Ok(T::consensus_decode(&mut iter).map_err(|e| format!("decoding failed: {}", e))?)
}

/// Parse a secret key from a string.
/// Supports both WIF format and hexadecimal.
pub fn parse_secret_key(s: &str) -> Result<SecretKey, String> {
	if let Ok(k) = bitcoin::PrivateKey::from_str(&s) {
		Ok(k.inner)
	} else {
		Ok(SecretKey::from_str(&s).map_err(|_| "invalid secret key")?)
	}
}

/// Parse an Elements network address params identifier from string.
///
/// Values supported:
/// - "liquid"
/// - "liquidtestnet"
/// - "elements"
pub fn parse_elements_network(s: &str) -> Result<&'static elements::AddressParams, String> {
	match s {
		"liquid" => Ok(&elements::AddressParams::LIQUID),
		"liquidtestnet" => Ok(&elements::AddressParams::LIQUID_TESTNET),
		"elements" => Ok(&elements::AddressParams::ELEMENTS),
		_ => Err("invalid network")?,
	}
}

/// Parse an Elements asset ID from hex.
///
/// Special case: "lbtc".
pub fn parse_asset_id(s: &str) -> Result<AssetId, String> {
	match s {
		"lbtc" => Ok(AssetId::LIQUID_BTC),
		_ => Ok(AssetId::from_str(s).map_err(|_| "invalid asset id")?),
	}
}

/// Convert a UNIX timestamp in seconds to a valid [LockTime] value.
pub fn lock_time_from_unix(secs: u64) -> Result<elements::LockTime, String> {
	let secs_u32 = secs.try_into().map_err(|_| "timelock overflow")?;
	Ok(elements::LockTime::from_time(secs_u32).map_err(|e| format!("invalid timelock: {}", e))?)
}

