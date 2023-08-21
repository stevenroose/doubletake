


use std::str::FromStr;

use bitcoin::{Amount, FeeRate};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use clap::Parser;
use elements::AssetId;
use serde_json::json;
use hex_conservative::DisplayHex;

use doubletake::{BitcoinUtxo, BondSpec, ElementsUtxo};


/// Create, burn and reclaim double spend bonds deployed on Liquid.
#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
enum App {
	/// Create new double spend bond
	#[command()]
	Create {
		/// Create this bond for segwit v0 spends.
		#[arg(long, required = true)]
		segwit: bool,
		/// The public key that will commit to the bond.
		#[arg(long)]
		pubkey: PublicKey,
		/// The actual bond burn amount. Make sure you send more money
		/// than this value into the bond address.
		#[arg(long)]
		bond_value: Amount,
		/// The expiry time of the bond as a unix timestamp.
		#[arg(long)]
		expiry: u64,
		/// The public key used to sign the reclaim tx after the bond expired.
		#[arg(long)]
		reclaim_pubkey: PublicKey,
		/// The Elements/Liquid network to deploy this bond on.
		///
		/// Possible options: "liquid", "liquidtestnet", "elements".
		///
		/// Default value: Liquid mainnet.
		#[arg(long, default_value = "liquid", value_parser = parse_elements_network)]
		network: &'static elements::AddressParams,
		/// The asset ID for the burn amount.
		///
		/// Default value: L-BTC.
		#[arg(long, default_value_t = AssetId::LIQUID_BTC, value_parser(parse_asset_id))]
		bond_asset: AssetId,
	},
	/// Inspect a bond spec.
	#[command()]
	Inspect {
		/// The bond spec in base64.
		spec: String,
	},
	/// Get the address for a bond.
	#[command()]
	Address {
		/// The bond spec in base64.
		spec: String,
		/// The Elements/Liquid network to create an address for.
		///
		/// Possible options: "liquid", "liquidtestnet", "elements".
		///
		/// Default value: Liquid mainnet.
		#[arg(long, default_value = "liquid", value_parser = parse_elements_network)]
		network: &'static elements::AddressParams,
	},
	/// Burn a double spend bond by providing proof of a double spend
	#[command()]
	Burn {
		/// The Elements/Liquid UTXO (`<txid>:<vout>`) of the bond.
		#[arg(long)]
		bond_utxo: elements::OutPoint,
		/// The bond tx in hex.
		#[arg(long)]
		bond_tx: String,
		/// The bond spec in base64.
		#[arg(long)]
		spec: String,
		/// The UTXO (`<txid>:<vout>`) that was double spent.
		#[arg(long)]
		double_spend_utxo: bitcoin::OutPoint,
		/// The tx of the UTXO that was double spent.
		#[arg(long)]
		double_spend_tx: String,
		/// The first double spending transaction in hex.
		#[arg(long)]
		tx1: String,
		/// The second double spending transaction in hex.
		#[arg(long)]
		tx2: String,
		/// The Elements/Liquid address to send the reward to.
		#[arg(long)]
		reward_address: elements::Address,
		/// The fee rate for the resulting tx in satoshi per virtual byte.
		///
		/// Default value: 1 sat/vb
		#[arg(long, default_value_t = 1)]
		feerate: u64,
	},
	/// Reclaim your bond after it has expired.
	#[command()]
	Reclaim {
		/// The Elements/Liquid UTXO (`<txid>:<vout>`) of the bond.
		#[arg(long)]
		bond_utxo: elements::OutPoint,
		/// The bond tx in hex.
		#[arg(long)]
		bond_tx: String,
		/// The bond spec in base64.
		#[arg(long)]
		spec: String,
		/// The address to send the claimed funds to.
		#[arg(long)]
		claim_address: elements::Address,
		/// The fee rate for the resulting tx in satoshi per virtual byte.
		///
		/// Default value: 1 sat/vb
		#[arg(long, default_value_t = 1)]
		feerate: u64,
		/// The secret key for the reclaim public key, in WIF or hex.
		#[arg(long)]
		reclaim_sk: Option<String>,
	},
}

fn inner_main() -> Result<(), String> {
	match App::parse() {
		App::Create { segwit, network, pubkey, bond_value, bond_asset, expiry, reclaim_pubkey } => {
			if !segwit {
				return Err("please use the --segwit flag to indicate you want a segwit v0 bond")?;
			}
			let lock_time = lock_time_from_unix(expiry)?;

			let spec = doubletake::segwit::BondSpec {
				pubkey, bond_value, bond_asset, lock_time, reclaim_pubkey,
			};
			let (script, spk) = doubletake::segwit::create_bond_script(&spec);
			let addr = elements::Address::from_script(&spk, None, network).expect("legit script");
			serde_json::to_writer_pretty(::std::io::stdout(), &json!({
				"spec": doubletake::BondSpec::Segwit(spec).to_base64(),
				"address": addr.to_string(),
				"witness_script": script.to_bytes().as_hex().to_string(),
			})).unwrap();
			println!();
		},
		App::Inspect { spec } => {
			let spec = BondSpec::from_base64(&spec)
				.map_err(|e| format!("invalid spec: {}", e))?;
			let (ws, spk) = match spec {
				BondSpec::Segwit(ref s) => doubletake::segwit::create_bond_script(&s),
				_ => unreachable!(),
			};
			let mut json = serde_json::to_value(&spec).unwrap();
			assert!(json.is_object());
			let obj = json.as_object_mut().unwrap();
			obj.insert("script_pubkey".into(), spk.to_bytes().as_hex().to_string().into());
			obj.insert("witness_script".into(), ws.to_bytes().as_hex().to_string().into());
			serde_json::to_writer_pretty(::std::io::stdout(), &json).unwrap();
			println!();
		},
		App::Address { spec, network } => {
			let spec = BondSpec::from_base64(&spec)
				.map_err(|e| format!("invalid spec: {}", e))?;
			let (_, spk) = match spec {
				BondSpec::Segwit(ref s) => doubletake::segwit::create_bond_script(&s),
				_ => unreachable!(),
			};
			let addr = elements::Address::from_script(&spk, None, network).expect("legit script");
			println!("{}", addr);
		},
		App::Burn {
			bond_utxo, bond_tx, spec, double_spend_utxo, double_spend_tx, tx1, tx2, feerate,
			reward_address,
		} => {
			let utxo = ElementsUtxo {
				outpoint: bond_utxo,
				output: {
					let tx = elem_deserialize_hex::<elements::Transaction>(&bond_tx)
						.map_err(|e| format!("invalid bond tx hex: {}", e))?;
					tx.output.get(bond_utxo.vout as usize)
						.ok_or("invalid tx for bond UTXO")?
						.clone()
				},
			};
			let spec = BondSpec::from_base64(&spec)
				.map_err(|e| format!("invalid spec: {}", e))?;
			let double_spend_utxo = BitcoinUtxo {
				outpoint: double_spend_utxo,
				output: {
					let tx = btc_deserialize_hex::<bitcoin::Transaction>(&double_spend_tx)
						.map_err(|e| format!("invalid bond tx hex: {}", e))?;
					tx.output.get(double_spend_utxo.vout as usize)
						.ok_or("invalid tx for double spend UTXO")?
						.clone()
				},
			};
			let tx1 = elem_deserialize_hex(&tx1)
				.map_err(|e| format!("bad tx1 hex: {}", e))?;
			let tx2 = elem_deserialize_hex(&tx2)
				.map_err(|e| format!("bad tx2 hex: {}", e))?;
			let fee_rate = FeeRate::from_sat_per_vb(feerate).ok_or_else(|| "invalid feerate")?;

			let tx = doubletake::create_burn_tx(
				&utxo, &spec, &double_spend_utxo, &tx1, &tx2, fee_rate, &reward_address,
			)?;
			println!("{}", elements::encode::serialize_hex(&tx));
		},
		App::Reclaim { bond_utxo, bond_tx, spec, feerate, reclaim_sk, claim_address } => {
			let utxo = ElementsUtxo {
				outpoint: bond_utxo,
				output: {
					let tx = elem_deserialize_hex::<elements::Transaction>(&bond_tx)
						.map_err(|e| format!("invalid bond tx hex: {}", e))?;
					tx.output.get(bond_utxo.vout as usize)
						.ok_or("invalid tx for bond UTXO")?
						.clone()
				},
			};
			let spec = BondSpec::from_base64(&spec)
				.map_err(|e| format!("invalid spec: {}", e))?;
			let fee_rate = FeeRate::from_sat_per_vb(feerate).ok_or_else(|| "invalid feerate")?;

			let tx = if let Some(reclaim_sk) = reclaim_sk {
				let reclaim_sk = parse_secret_key(&reclaim_sk)?;
				doubletake::create_signed_ecdsa_reclaim_tx(
					&utxo, &spec, fee_rate, &claim_address, &reclaim_sk,
				)?
			} else {
				doubletake::create_unsigned_reclaim_tx(
					&utxo, &spec, fee_rate, &claim_address,
				)
			};

			println!("{}", elements::encode::serialize_hex(&tx));
		},
	}
	Ok(())
}

fn main() {
	if let Err(e) = inner_main() {
		eprintln!("ERROR: {}", e);
	}
}

/// Deserialize an bitcoin object from hex.
fn btc_deserialize_hex<T: bitcoin::consensus::Decodable>(hex: &str) -> Result<T, String> {
	let mut iter = hex_conservative::HexToBytesIter::new(hex)
		.map_err(|e| format!("invalid hex string: {}", e))?;
	Ok(T::consensus_decode(&mut iter).map_err(|e| format!("decoding failed: {}", e))?)
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
		Ok(SecretKey::from_str(&s).map_err(|e| format!("invalid secret key: {}", e))?)
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

