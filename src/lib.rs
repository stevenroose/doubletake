
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

mod util;
pub mod segwit;

#[cfg(feature = "wasm")]
mod ffi;


use std::{fmt, io};

use bitcoin::{Amount, FeeRate};
use bitcoin::secp256k1::{self, ecdsa, Secp256k1, SecretKey};
use elements::encode::{Decodable, Encodable};
use elements::pset;


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
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "type"))]
#[non_exhaustive]
pub enum BondSpec {
	#[cfg_attr(feature = "serde", serde(rename = "segwit"))]
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

pub fn create_burn_tx(
	secp: &Secp256k1<impl secp256k1::Signing + secp256k1::Verification>,
	bond_utxo: &ElementsUtxo,
	spec: &BondSpec,
	double_spend_utxo: &BitcoinUtxo,
	tx1: &bitcoin::Transaction,
	tx2: &bitcoin::Transaction,
	fee_rate: FeeRate,
	reward_address: &elements::Address,
) -> Result<elements::Transaction, &'static str> {
	let ret = match spec {
		BondSpec::Segwit(spec) => {
			segwit::create_burn_tx(
				&secp, bond_utxo, spec, double_spend_utxo, tx1, tx2, fee_rate, reward_address,
			)?
		}
	};
	Ok(ret)
}

pub fn create_unsigned_reclaim_tx(
	bond_utxo: &ElementsUtxo,
	spec: &BondSpec,
	fee_rate: FeeRate,
	claim_address: &elements::Address,
) -> Result<elements::Transaction, &'static str> {
	let ret = match spec {
		BondSpec::Segwit(spec) => {
			segwit::create_unsigned_reclaim_tx(
				bond_utxo, spec, fee_rate, &claim_address.script_pubkey(),
			)?
		}
	};

	Ok(ret)
}

pub fn finalize_ecdsa_reclaim_tx(
	spec: &BondSpec,
	tx: elements::Transaction,
	sig: ecdsa::Signature,
) -> Result<elements::Transaction, &'static str> {
	let tx = match spec {
		BondSpec::Segwit(spec) => {
			segwit::finalize_reclaim_tx(spec, tx, sig)
		}
	};
	Ok(tx)
}

pub fn create_reclaim_pset(
	bond_utxo: &ElementsUtxo,
	spec: &BondSpec,
	fee_rate: FeeRate,
	claim_address: &elements::Address,
) -> Result<pset::PartiallySignedTransaction, &'static str> {
	let (tx, bond_script) = match spec {
		BondSpec::Segwit(spec) => {
			let tx = segwit::create_unsigned_reclaim_tx(
				bond_utxo, spec, fee_rate, &claim_address.script_pubkey(),
			)?;
			let (bond_script, _) = segwit::create_bond_script(spec);
			(tx, bond_script)
		}
	};
	let mut ret = pset::PartiallySignedTransaction::from_tx(tx);
	assert_eq!(ret.inputs().len(), 1);

	let input = &mut ret.inputs_mut()[0];
	input.witness_utxo = Some(bond_utxo.output.clone());
	input.sighash_type = Some(elements::EcdsaSighashType::All.into());
	input.witness_script = Some(bond_script);

	Ok(ret)
}

pub fn finalize_reclaim_pset(
	spec: &BondSpec,
	pset: &pset::PartiallySignedTransaction,
) -> Result<elements::Transaction, String> {
	let unsigned_tx = pset.extract_tx().map_err(|e| format!("pset extract error: {}", e))?;
	let ret = match spec {
		BondSpec::Segwit(spec) => {
			let reclaim_pk = spec.reclaim_pubkey;
			let signature_bytes = pset.inputs().get(0)
				.ok_or("pset has no inputs")?
				.partial_sigs.get(&bitcoin::PublicKey::new(reclaim_pk))
				.ok_or("partial signature for reclaim pubkey missing")?;
			let signature = util::parse_ecdsa_signature_all(signature_bytes)
				.map_err(|e| format!("invalid signature for reclaim key: {}", e))?;
			segwit::finalize_reclaim_tx(spec, unsigned_tx, signature)
		},
	};
	Ok(ret)
}

pub fn create_signed_ecdsa_reclaim_tx(
	secp: &Secp256k1<impl secp256k1::Signing>,
	bond_utxo: &ElementsUtxo,
	spec: &BondSpec,
	fee_rate: FeeRate,
	claim_address: &elements::Address,
	reclaim_sk: &SecretKey,
) -> Result<elements::Transaction, &'static str> {
	let tx = create_unsigned_reclaim_tx(bond_utxo, spec, fee_rate, &claim_address)?;
	let (bond_script, _) = match spec {
		BondSpec::Segwit(spec) => segwit::create_bond_script(spec),
	};
	let mut shc = elements::sighash::SighashCache::new(&tx);
	let sighash = shc.segwitv0_sighash(
		0, &bond_script, bond_utxo.output.value, elements::EcdsaSighashType::All,
	);
	let sig = secp.sign_ecdsa(&sighash.into(), &reclaim_sk);
	Ok(finalize_ecdsa_reclaim_tx(spec, tx, sig)?)
}
