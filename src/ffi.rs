



use std::io;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::{Amount, FeeRate};
use bitcoin::secp256k1::{self, PublicKey};
use elements::AssetId;
use elements::encode::{Decodable, Encodable};
use serde_json::json;
use wasm_bindgen::prelude::*;

use crate::{segwit, util};
use crate::{BitcoinUtxo, ElementsUtxo, BondSpec};


// #[derive(Debug, Clone)]
// pub struct BitcoinUtxo {
// 	pub outpoint: bitcoin::OutPoint,
// 	pub output: bitcoin::TxOut,
// }

// /// A UTXO on the Liquid or an Elements network.
// #[derive(Debug, Clone)]
// pub struct ElementsUtxo {
// 	pub outpoint: elements::OutPoint,
// 	pub output: elements::TxOut,
// }


///// Specification of a bond.
/////
///// With this, a bond can be exactly reconstructed and this information is
///// needed for all interactions with the bond.
//#[derive(Debug, PartialEq, Eq)]
//pub enum BondSpec {
//	Segwit(segwit::BondSpec),
//}

///// This can go away once MR #172 lands in rust-elements.
/////
///// https://github.com/ElementsProject/rust-elements/pull/172
//fn ioerr<T>(ret: Result<T, elements::encode::Error>) -> Result<T, io::Error> {
//	match ret {
//		Ok(v) => Ok(v),
//		Err(elements::encode::Error::Io(e)) => Err(e),
//		Err(other) => unreachable!("encode trait returned non-IO error: {}", other),
//	}
//}

//impl BondSpec {
//	/// The spec version byte for segwit v0 bonds.
//	const VERSION_SEGWIT: u8 = 0;

//	/// Max length of a serialized [BondSpec].
//	const MAX_LEN: usize = 1 + 33 + 8 + 32 + 4 + 33;

//	/// Serialize the spec into the writer.
//	pub fn serialize_into(&self, mut w: impl io::Write) -> Result<(), io::Error> {
//		match self {
//			Self::Segwit(spec) => {
//				w.write_all(&[Self::VERSION_SEGWIT])?;
//				ioerr(spec.pubkey.consensus_encode(&mut w))?;
//				ioerr(spec.bond_value.to_sat().consensus_encode(&mut w))?;
//				ioerr(spec.bond_asset.consensus_encode(&mut w))?;
//				ioerr(spec.lock_time.consensus_encode(&mut w))?;
//				ioerr(spec.reclaim_pubkey.consensus_encode(&mut w))?;
//			}
//		}
//		Ok(())
//	}

//	/// Serialize the spec to bytes.
//	pub fn serialize(&self) -> Vec<u8> {
//		let mut buf = Vec::with_capacity(Self::MAX_LEN);
//		self.serialize_into(&mut buf).expect("vec has no IO errors");
//		buf
//	}

//	/// Deserialize the spec from bytes.
//	pub fn deserialize(mut r: impl io::Read) -> Result<Self, BondSpecParseError> {
//		let mut buf = [0u8; 1];
//		r.read_exact(&mut buf[0..1])?;
//		let version = buf[0];
//		match version {
//			0 => {
//				Ok(Self::Segwit(segwit::BondSpec {
//					pubkey: Decodable::consensus_decode(&mut r)?,
//					bond_value: Amount::from_sat(Decodable::consensus_decode(&mut r)?),
//					bond_asset: Decodable::consensus_decode(&mut r)?,
//					lock_time: Decodable::consensus_decode(&mut r)?,
//					reclaim_pubkey: Decodable::consensus_decode(&mut r)?,
//				}))
//			}
//			v => return Err(BondSpecParseError::BadVersion(v)),
//		}
//	}

//	/// Serialize the spec to a base64 string.
//	pub fn to_base64(&self) -> String {
//		base64::encode_config(&self.serialize(), base64::URL_SAFE)
//	}

//	/// Deserialize the spec from a base64 string.
//	pub fn from_base64(s: &str) -> Result<Self, BondSpecParseError> {
//		let b = base64::decode_config(s, base64::URL_SAFE).map_err(BondSpecParseError::Base64)?;
//		Ok(Self::deserialize(&b[..])?)
//	}
//}


fn parse_elements_network(s: &str) -> Result<&'static elements::AddressParams, String> {
	match s {
		"liquid" => Ok(&elements::AddressParams::LIQUID),
		"liquidtestnet" => Ok(&elements::AddressParams::LIQUID_TESTNET),
		"elements" => Ok(&elements::AddressParams::ELEMENTS),
		_ => Err("invalid network")?,
	}
}

fn parse_asset_id(s: &str) -> Result<AssetId, String> {
	match s {
		"lbtc" => Ok(AssetId::LIQUID_BTC),
		_ => Ok(AssetId::from_str(s).map_err(|_| "invalid asset id")?),
	}
}

fn lock_time_from_unix(secs: u64) -> Result<elements::LockTime, String> {
	let secs_u32 = secs.try_into().map_err(|_| "timelock overflow")?;
	Ok(elements::LockTime::from_time(secs_u32).map_err(|e| format!("invalid timelock: {}", e))?)
}

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
	let spec = segwit::BondSpec {
		pubkey: pubkey.parse().map_err(|e| format!("invalid pubkey: {}", e))?,
		bond_value: Amount::from_sat(bond_value_sat),
		bond_asset: parse_asset_id(bond_asset)?,
		lock_time: lock_time_from_unix(lock_time_unix)?,
		reclaim_pubkey: pubkey.parse().map_err(|e| format!("invalid pubkey: {}", e))?,
	};
	let (_, spk) = segwit::create_bond_script(&spec);
	let addr = elements::Address::from_script(&spk, None, network).expect("legit script");
	let spec = BondSpec::Segwit(spec);
	Ok(serde_wasm_bindgen::to_value(&json!({
		"spec": spec.to_base64(),
		"address": addr.to_string(),
	})).unwrap())
}

/// Deserialize an elements object from hex.
fn elem_deserialize_hex<T: elements::encode::Decodable>(hex: &str) -> Result<T, String> {
	let mut iter = hex_conservative::HexToBytesIter::new(hex)
		.map_err(|e| format!("invalid hex string: {}", e))?;
	Ok(T::consensus_decode(&mut iter).map_err(|e| format!("decoding failed: {}", e))?)
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
	let secp = secp256k1::Secp256k1::new();
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

	let tx = match spec {
		BondSpec::Segwit(spec) => {
			segwit::create_burn_tx(
				&secp, &utxo, &spec, &double_spend_utxo, &tx1, &tx2, fee_rate, reward_address,
			)?
		}
	};
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
	let secp = secp256k1::Secp256k1::new();
	let utxo = serde_wasm_bindgen::from_value(utxo)
		.map_err(|e| format!("invalid bond UTXO: {}", e))?;
	let spec = BondSpec::from_base64(spec_base64)
		.map_err(|e| format!("invalid spec: {}", e))?;
	let fee_rate = FeeRate::from_sat_per_vb(fee_rate_sat_per_vb).ok_or_else(|| "invalid feerate")?;
	let reclaim_sk = util::parse_secret_key(reclaim_sk)?;
	let claim_address = elements::Address::from_str(claim_address)
		.map_err(|e| format!("invalid reward address: {}", e))?;

	let tx = match spec {
		BondSpec::Segwit(spec) => {
			segwit::create_reclaim_tx(
				&secp, &utxo, &spec, fee_rate, &reclaim_sk, &claim_address.script_pubkey(),
			)?
		}
	};
	Ok(elements::encode::serialize_hex(&tx))
}
