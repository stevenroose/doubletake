



use std::str::FromStr;

use bitcoin::{Amount, FeeRate};
use bitcoin::secp256k1::SecretKey;
use elements::AssetId;
use hex_conservative::DisplayHex;
use wasm_bindgen::prelude::*;

use crate::{segwit, BondSpec};



/// Create a segwit bond and address.
///
/// Input:
/// - `pubkey`: public key in hex that will commit to the bond
/// - `bond_value`: value in sats
/// - `bond_asset`: asset id in hex, or "lbtc"
/// - `lock_time_unix`: locktime as a unix timestamp (like block timestamps)
/// - `reclaim_pubkey`: public key in hex to be used for reclaiming the bond
///
/// Output is the same as the [bond_inspect] function.
#[wasm_bindgen]
pub fn create_segwit_bond_spec(
	pubkey: &str,
	bond_value_sat: u64,
	bond_asset: &str,
	lock_time_unix: u64,
	reclaim_pubkey: &str,
) -> Result<String, JsValue> {
	let pubkey = pubkey.parse().map_err(|e| format!("invalid pubkey: {}", e))?;
	let bond_value = Amount::from_sat(bond_value_sat);
	let bond_asset = parse_asset_id(bond_asset)?;
	let lock_time = lock_time_from_unix(lock_time_unix)?;
	let reclaim_pubkey = reclaim_pubkey.parse().map_err(|e| format!("invalid pubkey: {}", e))?;

	let spec = segwit::BondSpec { pubkey, bond_value, bond_asset, lock_time, reclaim_pubkey };
	Ok(BondSpec::Segwit(spec).to_base64())
}

/// Inspect a base64-encoded bond spec.
///
/// Input:
/// - `spec`: the base64 bond spec
///
/// Output: object with following fields:
/// - `type`: bond type
/// - `pubkey`: public key holding the bond
/// - `bond_value`: the value in satoshi
/// - `bond_asset`: the asset ID
/// - `lock_time`: the locktime of the expiry
/// - `reclaim_pubkey`: the reclaim pubkey
/// - `script_pubkey`: the script pubkey for the bond address
/// - `witness_script`: the witness script used for the address
#[wasm_bindgen]
pub fn inspect_bond(spec: &str) -> Result<JsValue, JsValue> {
	let spec = BondSpec::from_base64(&spec)
		.map_err(|e| format!("invalid spec: {}", e))?;
	let (ws, spk) = match spec {
		BondSpec::Segwit(ref s) => segwit::create_bond_script(&s),
	};
	let mut json = serde_json::to_value(&spec).unwrap();
	assert!(json.is_object());
	let obj = json.as_object_mut().unwrap();
	obj.insert("script_pubkey".into(), spk.to_bytes().as_hex().to_string().into());
	obj.insert("witness_script".into(), ws.to_bytes().as_hex().to_string().into());
	Ok(serde_wasm_bindgen::to_value(&json).unwrap())
}

/// Create a Liquid/Elements address for the bond, given the spec.
///
/// Input:
/// - `spec`: the base64 encoded bond spec
/// - `network`: "liquid", "liquidtestnet" or "elements"
///
/// Output: a Liquid/Elements address
#[wasm_bindgen]
pub fn bond_address(spec: &str, network: &str) -> Result<String, JsValue> {
	let spec = BondSpec::from_base64(&spec)
		.map_err(|e| format!("invalid spec: {}", e))?;
	let network = parse_elements_network(network)?;
	let (_, spk) = match spec {
		BondSpec::Segwit(ref s) => segwit::create_bond_script(&s),
	};
	let addr = elements::Address::from_script(&spk, None, network).expect("valid spk");
	Ok(addr.to_string())
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
fn elem_deserialize_hex<T: elements::encode::Decodable>(hex: &str) -> Result<T, String> {
	let mut iter = hex_conservative::HexToBytesIter::new(hex)
		.map_err(|e| format!("invalid hex string: {}", e))?;
	Ok(T::consensus_decode(&mut iter).map_err(|e| format!("decoding failed: {}", e))?)
}

/// Parse a secret key from a string.
/// Supports both WIF format and hexadecimal.
fn parse_secret_key(s: &str) -> Result<SecretKey, String> {
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
fn parse_elements_network(s: &str) -> Result<&'static elements::AddressParams, String> {
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
fn parse_asset_id(s: &str) -> Result<AssetId, String> {
	match s {
		"lbtc" => Ok(AssetId::LIQUID_BTC),
		_ => Ok(AssetId::from_str(s).map_err(|_| "invalid asset id")?),
	}
}

/// Convert a UNIX timestamp in seconds to a valid [LockTime] value.
fn lock_time_from_unix(secs: u64) -> Result<elements::LockTime, String> {
	let secs_u32 = secs.try_into().map_err(|_| "timelock overflow")?;
	Ok(elements::LockTime::from_time(secs_u32).map_err(|e| format!("invalid timelock: {}", e))?)
}

