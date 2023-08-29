
#[macro_use]
extern crate lazy_static;
extern crate link_cplusplus;


use std::collections::HashMap;
use std::convert::TryInto;
use std::str::{self, FromStr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::{Amount, Denomination, FeeRate};
use bitcoin::consensus::encode as btcencode;
use bitcoin::hashes::Hash;
use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
use bitcoin::secp256k1::rand::{self, Rng, SeedableRng};
use clap::Parser;
use jsonrpc::serde_json::value::{Value, RawValue};
use serde;
use serde_json;

use doubletake::*;

#[derive(Debug, Parser)]
struct Opts {
	/// Use an elementsregtest node to do tx validation.
	///
	/// Assumes the node's wallet has sufficient balance.
	#[arg(long)]
	regtest: bool,
	#[arg(long, default_value_t = 7040)]
	regtest_port: u16,
	#[arg(long)]
	regtest_user: Option<String>,
	#[arg(long)]
	regtest_pass: Option<String>,

	/// Use libelementsconsensus to do consensus validation.
	///
	/// This currently will fail.
	#[arg(long)]
	elementsconsensus: bool,

	#[arg(long)]
	cli: Option<String>,
}

lazy_static! {
	static ref OPT: Opts = Opts::parse();
	static ref RPC: Option<jsonrpc::Client> = {
		if OPT.regtest {
			Some(jsonrpc::Client::simple_http(
				&format!("http://localhost:{}", OPT.regtest_port),
				Some(OPT.regtest_user.clone().expect("need --rpc-user")),
				Some(OPT.regtest_pass.clone().expect("need --rpc-pass")),
			).expect("error creating regtest RPC client"))
		} else {
			None
		}
	};
}

/// Test network params;

static TEST_NET: &'static elements::AddressParams = &elements::AddressParams::ELEMENTS;
static TEST_ASSETID: &str = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23";
lazy_static! {
	static ref TEST_ASSET: elements::AssetId = TEST_ASSETID.parse().unwrap();
	static ref TEST_CASSET: elements::confidential::Asset =
		elements::confidential::Asset::Explicit(*TEST_ASSET);
}

/// Used to prepare RPC arguments.
fn arg(v: impl serde::Serialize) -> Box<RawValue> {
	let s = jsonrpc::serde_json::to_string(&v).unwrap();
	RawValue::from_string(s.into()).unwrap()
}

fn deploy_bond(
	addr: &elements::Address,
	value: Amount,
) -> Option<(elements::OutPoint, elements::Transaction)> {
	if let Some(ref rpc) = *RPC {
		let txid = rpc.call::<elements::Txid>("sendtoaddress", &[
			arg(addr.to_string()),
			arg(value.to_string_in(Denomination::Bitcoin)),
		]).unwrap();
		let tx_hex = rpc.call::<String>("getrawtransaction", &[
			arg(txid.to_string()),
		]).unwrap();
		println!("bond deploy tx: {}", tx_hex);
		let tx = elements::encode::deserialize::<elements::Transaction>(
			&Vec::<u8>::from_hex(&tx_hex).unwrap(),
		).unwrap();
		let vout = tx.output.iter().position(|o| {
			if o.script_pubkey == addr.script_pubkey() {
				assert_eq!(o.value.explicit().unwrap(), value.to_sat());
				true
			} else {
				false
			}
		}).unwrap();
		Some((elements::OutPoint::new(txid, vout as u32), tx))
	} else {
		None
	}
}

fn verify_tx(
	spec: &doubletake::segwit::BondSpec,
	utxo: &ElementsUtxo,
	tx: &elements::Transaction,
) {
	if OPT.elementsconsensus {
		let (script, _) = doubletake::segwit::create_bond_script(spec);
		verify_tx_elementsconsensus(&script, &utxo.output.value, 0, tx).expect("tx error");
	}

	if let Some(ref rpc) = *RPC {
		let ret = rpc.call::<Vec<HashMap<String, Value>>>("testmempoolaccept", &[
			arg(&[elements::encode::serialize_hex(tx)]),
		]).unwrap();
		println!("testmempoolaccept: {:?}", ret);
		if *ret[0].get("allowed").unwrap() != Value::Bool(true) {
			panic!("tx not accepted: {:?}", ret);
		}
	}
}

/// Generate sane random variables from a randomness source.
pub trait SaneRandom {
	fn sane_rand(rand: &mut impl Rng) -> Self;
}

impl SaneRandom for bitcoin::Txid {
	fn sane_rand(rand: &mut impl Rng) -> Self {
		bitcoin::Txid::from_byte_array(rand.gen())
	}
}

impl SaneRandom for elements::OutPoint {
	fn sane_rand(rand: &mut impl Rng) -> Self {
		let txid = elements::Txid::from_byte_array(rand.gen());
		elements::OutPoint::new(txid, rand.gen::<u8>() as u32)
	}
}

impl SaneRandom for bitcoin::WPubkeyHash {
	fn sane_rand(rand: &mut impl Rng) -> Self { Self::from_byte_array(rand.gen()) }
}

fn expl(amount: Amount) -> elements::confidential::Value {
	elements::confidential::Value::Explicit(amount.to_sat())
}

/// Create a tx that spends the given p2wpkh UTXO and signed with the given key.
fn create_p2wpkh_spend_with_key(
	secp: &Secp256k1<impl secp256k1::Signing>,
	rand: &mut impl Rng,
	utxo: &BitcoinUtxo,
	key: &SecretKey,
) -> bitcoin::Transaction {
	let mut ret = bitcoin::Transaction {
		version: 3,
		lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
		input: vec![
			bitcoin::TxIn {
				previous_output: utxo.outpoint,
				sequence: bitcoin::Sequence::MAX,
				script_sig: Default::default(),
				witness: Default::default(),
			}
		],
		output: vec![
			bitcoin::TxOut {
				value: 350,
				script_pubkey: bitcoin::ScriptBuf::new_v0_p2wpkh(
					&bitcoin::WPubkeyHash::sane_rand(rand),
				),
			}
		],
	};

	let mut shc = bitcoin::sighash::SighashCache::new(&ret);
	let sighash = shc.segwit_signature_hash(
		0,
		&utxo.output.script_pubkey.p2wpkh_script_code().unwrap(),
		utxo.output.value,
		bitcoin::sighash::EcdsaSighashType::All,
	).expect("error doing sighash");
	let signature = secp.sign_ecdsa(&sighash.into(), &key);

	ret.input[0].witness.push_bitcoin_signature(
		&signature.serialize_der(), bitcoin::sighash::EcdsaSighashType::All,
	);
	ret.input[0].witness.push(key.public_key(secp).serialize());

	ret
}

/// Complete test for a bond.
///
/// - sets up a bond for a public key
/// - creates a bitcoin double spend from that key
/// - tests that the burn transaction works for taking the money
/// - tests that the money can be recovered after the timelock
fn test_v0_with_random(
	secp: &Secp256k1<secp256k1::All>,
	rand: &mut impl Rng,
) {
	//! A complete test that tests an entire bond setup, burn and expiration.

	// So let's start with our famous public key.
	let (bond_sk, bond_pk) = secp.generate_keypair(rand);

	// And generate a spec for our bond.
	let (reclaim_sk, reclaim_pk) = secp.generate_keypair(rand);
	// Use expiry in the past so that elements allows us to reclaim.
	let expiry = SystemTime::now()
		.checked_sub(Duration::from_secs(60 * 60 * 24 * 30)).unwrap()
		.duration_since(UNIX_EPOCH).unwrap()
		.as_secs()
		.try_into().unwrap();
	let bond_spec = doubletake::segwit::BondSpec {
		pubkey: bond_pk.clone(),
		bond_value: Amount::from_btc(5.0).unwrap(),
		bond_asset: *TEST_ASSET,
		lock_time: elements::LockTime::from_time(expiry).unwrap(),
		reclaim_pubkey: reclaim_pk,
	};

	// Then we can create our bond script.
	let (bond_script, bond_spk) = if OPT.cli.is_some() {
		cli::create_segwit(&bond_spec)
	} else {
		doubletake::segwit::create_bond_script(&bond_spec)
	};
	println!("bond script: {}", bond_script.asm());
	let bond_addr = elements::Address::from_script(&bond_spk, None, TEST_NET).unwrap();
	println!("bond addr: {}", bond_addr);
	assert_eq!(bond_addr.script_pubkey(), bond_spk);

	// And pretend we sent money to the address.
	let amount = Amount::from_btc(6.0).unwrap();
	let (bond_outpoint, bond_tx) = if let Some((utxo, tx)) = deploy_bond(&bond_addr, amount) {
		(utxo, Some(tx))
	} else {
		("0000000000000000000000000000000000000000000000000000000000000000:0".parse().unwrap(), None)
	};
	let bond_utxo = ElementsUtxo {
		outpoint: bond_outpoint,
		output: bond_tx.as_ref()
			.map(|tx| tx.output[bond_outpoint.vout as usize].clone())
			.unwrap_or_else(|| elements::TxOut {
				value: expl(amount),
				asset: *TEST_CASSET,
				nonce: elements::confidential::Nonce::Null,
				script_pubkey: bond_addr.script_pubkey(),
				witness: elements::TxOutWitness::default(),
			}),
	};
	
	// So now we need to fake a double spend from this key. Not easy.

	// The output we are going to double spend.
	let fake_double_spend_tx = bitcoin::Transaction {
		version: rand.gen::<u8>().into(),
		lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
		input: vec![bitcoin::TxIn::default()],
		output: vec![bitcoin::TxOut {
			value: Amount::from_btc(1.0).unwrap().to_sat(),
			script_pubkey: bitcoin::ScriptBuf::new_v0_p2wpkh(
				&bitcoin::PublicKey::new(bond_pk).wpubkey_hash().unwrap(),
			),
		}],
	};
	let double_spend_utxo = BitcoinUtxo {
		outpoint: bitcoin::OutPoint::new(fake_double_spend_tx.txid(), 0),
		output: fake_double_spend_tx.output[0].clone(),
	};

	// We create two different transactions that spend the same UTXO.
	let spend1 = create_p2wpkh_spend_with_key(&secp, rand, &double_spend_utxo, &bond_sk);
	let spend2 = create_p2wpkh_spend_with_key(&secp, rand, &double_spend_utxo, &bond_sk);

	// So let's BURN!
	let (_, reward_pk) = secp.generate_keypair(rand);
	let burn_tx = if OPT.cli.is_some() {
		cli::burn(
			bond_utxo.outpoint,
			bond_tx.as_ref().expect("can't use --cli without --regtest"),
			&BondSpec::Segwit(bond_spec.clone()),
			double_spend_utxo.outpoint,
			&fake_double_spend_tx,
			&spend1,
			&spend2,
			&elements::Address::p2wpkh(&bitcoin::PublicKey::new(reward_pk), None, TEST_NET),
			FeeRate::from_sat_per_vb(1).unwrap(),
		)
	} else {
		doubletake::segwit::create_burn_tx(
			secp,
			&bond_utxo,
			&bond_spec,
			&double_spend_utxo,
			&spend1,
			&spend2,
			FeeRate::from_sat_per_vb(1).unwrap(),
			&elements::Address::p2wpkh(&bitcoin::PublicKey::new(reward_pk), None, TEST_NET),
		).unwrap()
	};

	println!("burn tx: {}", elements::encode::serialize_hex(&burn_tx));
	println!("burn tx witness element sizes (n={}): {:?}",
		burn_tx.input[0].witness.script_witness.len(),
		burn_tx.input[0].witness.script_witness.iter().map(|i| i.len()).collect::<Vec<_>>(),
	);
	verify_tx(&bond_spec, &bond_utxo, &burn_tx);

	// Now try reclaim after the timelock

	let output = elements::Address::from_str("ert1q76vrm2xyvjgl6g392srk5pwas44twu6rpd8tk5").unwrap();
	let reclaim_tx = if OPT.cli.is_some() {
		cli::reclaim(
			bond_utxo.outpoint,
			bond_tx.as_ref().expect("can't use --cli without --regtest"),
			&BondSpec::Segwit(bond_spec.clone()),
			&output,
			FeeRate::from_sat_per_vb(1).unwrap(),
			reclaim_sk,
		)
	} else {
		doubletake::create_signed_ecdsa_reclaim_tx(
			&secp,
			&bond_utxo,
			&BondSpec::Segwit(bond_spec.clone()),
			FeeRate::from_sat_per_vb(1).unwrap(),
			&output,
			&reclaim_sk,
		).unwrap()
	};

	println!("reclaim tx: {}", elements::encode::serialize_hex(&reclaim_tx));
	println!("reclaim tx witness element sizes (n={}): {:?}",
		reclaim_tx.input[0].witness.script_witness.len(),
		reclaim_tx.input[0].witness.script_witness.iter().map(|i| i.len()).collect::<Vec<_>>(),
	);
	verify_tx(&bond_spec, &bond_utxo, &reclaim_tx);
}

fn verify_tx_elementsconsensus(
	_script: &elements::Script,
	_value: &elements::confidential::Value,
	_index: usize,
	_transaction: &elements::Transaction,
) -> Result<(), String> {
	// use elements_consensus::elements::encode::deserialize;
	// use elements::encode::serialize;

	// if let Err(e) = elements_consensus::verify(
	// 	deserialize(&serialize(script)).unwrap(),
	// 	&deserialize(&serialize(value)).unwrap(),
	// 	index,
	// 	&deserialize(&serialize(transaction)).unwrap(),
	// ).expect("index error") {
	// 	return Err(e.to_string());
	// }

	Ok(())
}

mod cli {
	use super::*;
	use std::process;

	fn cmd(args: &[&str]) -> String {
		println!("CLI: executing: doubletake {}", args.join(" "));
		let out = process::Command::new(OPT.cli.as_ref().unwrap())
			.args(args)
			.output()
			.expect("error running CLI command");
		if !out.stderr.is_empty() {
			panic!("CLI err: {}", str::from_utf8(&out.stderr).expect("stderr not utf8"));
		}
		let ret = String::from_utf8(out.stdout).expect("output not UTF8");
		println!("CLI output: {}", ret);
		ret
	}

	pub fn create_segwit(spec: &doubletake::segwit::BondSpec) -> (elements::Script, elements::Script) {
		let out = cmd(&["create",
			"--segwit",
			"--pubkey", &spec.pubkey.to_string(),
			"--bond-value", &spec.bond_value.to_string(),
			"--bond-asset", &spec.bond_asset.to_string(),
			"--expiry", &spec.lock_time.to_consensus_u32().to_string(),
			"--reclaim-pubkey", &spec.reclaim_pubkey.to_string(),
			"--network", "elements",
		]);
		#[derive(serde::Deserialize)]
		struct Ret {
			spec: String,
			address: elements::Address,
			witness_script: String,
		}
		let ret = serde_json::from_str::<Ret>(&out).expect("unexpected CLI output");
		let out_spec = BondSpec::from_base64(&ret.spec).unwrap();
		assert_eq!(out_spec, BondSpec::Segwit(spec.clone()));
		let script = Vec::<u8>::from_hex(&ret.witness_script).unwrap().into();
		(script, ret.address.script_pubkey())
	}

	pub fn burn(
		bond_utxo: elements::OutPoint,
		bond_tx: &elements::Transaction,
		spec: &BondSpec,
		double_spend_utxo: bitcoin::OutPoint,
		double_spend_tx: &bitcoin::Transaction,
		tx1: &bitcoin::Transaction,
		tx2: &bitcoin::Transaction,
		reward_addr: &elements::Address,
		fee_rate: FeeRate,
	) -> elements::Transaction {
		let out = cmd(&["burn",
			"--bond-utxo", &bond_utxo.to_string(),
			"--bond-tx", &elements::encode::serialize_hex(bond_tx),
			"--spec", &spec.to_base64(),
			"--double-spend-utxo", &double_spend_utxo.to_string(),
			"--double-spend-tx", &btcencode::serialize_hex(double_spend_tx),
			"--tx1", &btcencode::serialize_hex(tx1),
			"--tx2", &btcencode::serialize_hex(tx2),
			"--reward-address", &reward_addr.to_string(),
			"--feerate", &fee_rate.to_sat_per_vb_ceil().to_string(),
		]);
		let mut bytes = hex_conservative::HexToBytesIter::new(
			&out.split_whitespace().next().unwrap(),
		).unwrap();
		elements::encode::Decodable::consensus_decode(&mut bytes).unwrap()
	}

	pub fn reclaim(
		bond_utxo: elements::OutPoint,
		bond_tx: &elements::Transaction,
		spec: &BondSpec,
		claim_addr: &elements::Address,
		fee_rate: FeeRate,
		reclaim_sk: secp256k1::SecretKey,
	) -> elements::Transaction {
		let out = cmd(&["reclaim",
			"--bond-utxo", &bond_utxo.to_string(),
			"--bond-tx", &elements::encode::serialize_hex(bond_tx),
			"--spec", &spec.to_base64(),
			"--claim-address", &claim_addr.to_string(),
			"--feerate", &fee_rate.to_sat_per_vb_ceil().to_string(),
			"--reclaim-sk", &reclaim_sk.display_secret().to_string(),
		]);
		let mut bytes = hex_conservative::HexToBytesIter::new(
			&out.split_whitespace().next().unwrap(),
		).unwrap();
		elements::encode::Decodable::consensus_decode(&mut bytes).unwrap()
	}
}

fn main() {
	let secp = Secp256k1::new();

	if !OPT.regtest && !OPT.elementsconsensus {
		panic!("provide either --regtest or --elementsconsensus, otherwise you're doing nothing");
	}

	// First run we do with deterministic randomness.
	let mut rand = rand::rngs::StdRng::from_seed([
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	]);

	if let Some(ref rpc) = *RPC {
		let balance = rpc.call::<Value>("getbalance", &[]).unwrap();
		println!("{:?}", balance);
	}

	test_v0_with_random(&secp, &mut rand);

	// // Then we do a bunch of rounds with actual randomness.
	// let mut rand = rand::thread_rng();
	// for _ in 0..1000 {
	// 	test_v0_with_random(&secp, &mut rand, &deploy, &verify);
	// }
}
