
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

mod util;
pub mod segwit;

#[cfg(feature = "wasm")]
mod ffi;


use std::{fmt, io};

use bitcoin::{Amount, FeeRate};
use bitcoin::secp256k1::{self, PublicKey, SecretKey};
use elements::AssetId;
use elements::encode::{Decodable, Encodable};


/// A UTXO on the Bitcoin network.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BitcoinUtxo {
	pub outpoint: bitcoin::OutPoint,
	pub output: bitcoin::TxOut,
}

/// A UTXO on the Liquid or an Elements network.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ElementsUtxo {
	pub outpoint: elements::OutPoint,
	pub output: elements::TxOut,
}

#[derive(Debug)]
pub enum BondSpecParseError {
	Io(io::Error),
	Format(elements::encode::Error),
	Base64(base64::DecodeError),
	BadVersion(u8),
}

impl From<io::Error> for BondSpecParseError {
	fn from(e: io::Error) -> BondSpecParseError {
		BondSpecParseError::Io(e)
	}
}

impl From<elements::encode::Error> for BondSpecParseError {
	fn from(e: elements::encode::Error) -> BondSpecParseError {
		BondSpecParseError::Format(e)
	}
}

impl fmt::Display for BondSpecParseError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Io(e) => write!(f, "I/O error: {}", e),
			Self::Format(e) => write!(f, "encoding error: {}", e),
			Self::Base64(e) => write!(f, "invalid base64: {}", e),
			Self::BadVersion(v) => write!(f, "invalid spec version number: {}", v),
		}
	}
}

/// Specification of a bond.
///
/// With this, a bond can be exactly reconstructed and this information is
/// needed for all interactions with the bond.
#[derive(Debug, PartialEq, Eq)]
pub enum BondSpec {
	Segwit(segwit::BondSpec),
}

/// This can go away once MR #172 lands in rust-elements.
///
/// https://github.com/ElementsProject/rust-elements/pull/172
fn ioerr<T>(ret: Result<T, elements::encode::Error>) -> Result<T, io::Error> {
	match ret {
		Ok(v) => Ok(v),
		Err(elements::encode::Error::Io(e)) => Err(e),
		Err(other) => unreachable!("encode trait returned non-IO error: {}", other),
	}
}

impl BondSpec {
	/// The spec version byte for segwit v0 bonds.
	const VERSION_SEGWIT: u8 = 0;

	/// Max length of a serialized [BondSpec].
	const MAX_LEN: usize = 1 + 33 + 8 + 32 + 4 + 33;

	/// Serialize the spec into the writer.
	pub fn serialize_into(&self, mut w: impl io::Write) -> Result<(), io::Error> {
		match self {
			Self::Segwit(spec) => {
				w.write_all(&[Self::VERSION_SEGWIT])?;
				ioerr(spec.pubkey.consensus_encode(&mut w))?;
				ioerr(spec.bond_value.to_sat().consensus_encode(&mut w))?;
				ioerr(spec.bond_asset.consensus_encode(&mut w))?;
				ioerr(spec.lock_time.consensus_encode(&mut w))?;
				ioerr(spec.reclaim_pubkey.consensus_encode(&mut w))?;
			}
		}
		Ok(())
	}

	/// Serialize the spec to bytes.
	pub fn serialize(&self) -> Vec<u8> {
		let mut buf = Vec::with_capacity(Self::MAX_LEN);
		self.serialize_into(&mut buf).expect("vec has no IO errors");
		buf
	}

	/// Deserialize the spec from bytes.
	pub fn deserialize(mut r: impl io::Read) -> Result<Self, BondSpecParseError> {
		let mut buf = [0u8; 1];
		r.read_exact(&mut buf[0..1])?;
		let version = buf[0];
		match version {
			0 => {
				Ok(Self::Segwit(segwit::BondSpec {
					pubkey: Decodable::consensus_decode(&mut r)?,
					bond_value: Amount::from_sat(Decodable::consensus_decode(&mut r)?),
					bond_asset: Decodable::consensus_decode(&mut r)?,
					lock_time: Decodable::consensus_decode(&mut r)?,
					reclaim_pubkey: Decodable::consensus_decode(&mut r)?,
				}))
			}
			v => return Err(BondSpecParseError::BadVersion(v)),
		}
	}

	/// Serialize the spec to a base64 string.
	pub fn to_base64(&self) -> String {
		base64::encode_config(&self.serialize(), base64::URL_SAFE)
	}

	/// Deserialize the spec from a base64 string.
	pub fn from_base64(s: &str) -> Result<Self, BondSpecParseError> {
		let b = base64::decode_config(s, base64::URL_SAFE).map_err(BondSpecParseError::Base64)?;
		Ok(Self::deserialize(&b[..])?)
	}
}

pub fn create_segwit_bond_address(
	network: &'static elements::AddressParams,
	pubkey: PublicKey,
	bond_value: Amount,
	bond_asset: AssetId,
	lock_time: elements::LockTime,
	reclaim_pubkey: PublicKey,
) -> (BondSpec, elements::Address) {
	let spec = segwit::BondSpec {
		pubkey, bond_value, bond_asset, lock_time, reclaim_pubkey,
	};
	let (_, spk) = segwit::create_bond_script(&spec);
	let addr = elements::Address::from_script(&spk, None, network).expect("legit script");
	(BondSpec::Segwit(spec), addr)
}

pub fn create_burn_tx(
	utxo: &ElementsUtxo,
	spec: &BondSpec,
	double_spend_utxo: &BitcoinUtxo,
	tx1: &bitcoin::Transaction,
	tx2: &bitcoin::Transaction,
	fee_rate: FeeRate,
	reward_address: &elements::Address,
) -> Result<elements::Transaction, String> {
	let secp = secp256k1::Secp256k1::new();
	let tx = match spec {
		BondSpec::Segwit(spec) => {
			segwit::create_burn_tx(
				&secp, utxo, spec, double_spend_utxo, tx1, tx2, fee_rate, reward_address,
			)?
		}
	};
	Ok(tx)
}

pub fn create_reclaim_tx(
	utxo: &ElementsUtxo,
	spec: &BondSpec,
	fee_rate: FeeRate,
	reclaim_sk: &SecretKey,
	claim_address: &elements::Address,
) -> Result<elements::Transaction, String> {
	let secp = secp256k1::Secp256k1::new();
	let tx = match spec {
		BondSpec::Segwit(spec) => {
			segwit::create_reclaim_tx(
				&secp, utxo, spec, fee_rate, &reclaim_sk, &claim_address.script_pubkey(),
			)?
		}
	};
	Ok(tx)
}
