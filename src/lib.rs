

mod util;
pub mod segwit;


use bitcoin::{Amount, FeeRate};
use bitcoin::secp256k1::{self, PublicKey};
use elements::AssetId;


/// A UTXO on the Bitcoin network.
#[derive(Debug, Clone)]
pub struct BitcoinUtxo {
	pub outpoint: bitcoin::OutPoint,
	pub output: bitcoin::TxOut,
}

/// A UTXO on the Liquid or an Elements network.
#[derive(Debug, Clone)]
pub struct ElementsUtxo {
	pub outpoint: elements::OutPoint,
	pub output: elements::TxOut,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BondSpec {
	Segwit(segwit::BondSpec),
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
	fee_rate_sat_per_vb: u64,
	reward_address: elements::Address,
) -> Result<elements::Transaction, String> {
	let secp = secp256k1::Secp256k1::new();
	let fee_rate = FeeRate::from_sat_per_vb(fee_rate_sat_per_vb).ok_or_else(|| "invalid feerate")?;
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
	fee_rate_sat_per_vb: u64,
	reclaim_sk_str: &str,
	claim_address: elements::Address,
) -> Result<elements::Transaction, String> {
	let secp = secp256k1::Secp256k1::new();
	let fee_rate = FeeRate::from_sat_per_vb(fee_rate_sat_per_vb).ok_or_else(|| "invalid feerate")?;
	let reclaim_sk = util::parse_secret_key(reclaim_sk_str)?;
	let tx = match spec {
		BondSpec::Segwit(spec) => {
			segwit::create_reclaim_tx(
				&secp, utxo, spec, fee_rate, &reclaim_sk, &claim_address.script_pubkey(),
			)?
		}
	};
	Ok(tx)
}
