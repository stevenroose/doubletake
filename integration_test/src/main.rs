
extern crate link_cplusplus;


use std::str::FromStr;
use std::sync::Arc;

use bitcoin::{Amount, Denomination, FeeRate, Weight};
use bitcoin::hashes::Hash;
use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::rand::{self, Rng, SeedableRng};
use jsonrpc::serde_json::json;
use jsonrpc::serde_json::value::{Value, RawValue};

use doubletake::*;

/// Test network params;
static TEST_NET: &'static elements::AddressParams = &elements::AddressParams::ELEMENTS;
static TEST_ASSETID: elements::AssetId = elements::AssetId::LIQUID_BTC;
static TEST_ASSET: elements::confidential::Asset =
	elements::confidential::Asset::Explicit(TEST_ASSETID);


fn arg(v: Value) -> Box<RawValue> {
	let s = jsonrpc::serde_json::to_string(&v).unwrap();
	RawValue::from_string(s.into()).unwrap()
}

fn main() {
	let secp = Secp256k1::new();

	// First run we do with deterministic randomness.
	let mut rand = rand::rngs::StdRng::from_seed([
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	]);

	let (deploy, verify): (
		Box<dyn Fn(&elements::Address, Amount) -> elements::OutPoint>,
		Box<dyn Fn(&SegwitV0BondSpec, &ElementsUtxo, &elements::Transaction)>,
	) = match std::env::args().nth(1) {
		Some(s) if s == "elementsconsensus" => {
			let deploy = Box::new(|addr: &_, amount| {
				elements::OutPoint::new(
					"0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap(),
					0,
				)
			});
			let verify = Box::new(|spec: &_, utxo: &ElementsUtxo, tx: &_| {
				let (script, _) = create_segwit_v0_bond_script(spec);
				verify_tx_elementsconsensus(&script, &utxo.output.value, 0, tx).expect("tx error");
			});
			(deploy, verify)
		}
		Some(s) if s == "regtest" => {
			let client = Arc::new(jsonrpc::Client::simple_http(
				"http://localhost:8888",
				Some("testuser".into()),
				Some("testpass".into()),
			).unwrap());

			let balance = client.call::<Value>("getbalance", &[]).unwrap();
			println!("{:?}", balance);

			let client2 = client.clone();
			let deploy = Box::new(move |addr: &elements::Address, amount: Amount| {
				let txid = client2.call::<elements::Txid>("sendtoaddress", &[
					arg(json!(addr.to_string())),
					arg(json!(amount.to_string_in(Denomination::Bitcoin))),
				]).unwrap();
				let tx_hex = client2.call::<String>("getrawtransaction", &[
					arg(json!(txid.to_string())),
				]).unwrap();
				println!("bond deploy tx: {}", tx_hex);
				let tx = elements::encode::deserialize::<elements::Transaction>(
					&Vec::<u8>::from_hex(&tx_hex).unwrap(),
				).unwrap();
				let vout = tx.output.iter().position(|o| {
					if o.script_pubkey == addr.script_pubkey() {
						assert_eq!(o.value.explicit().unwrap(), amount.to_sat());
						true
					} else {
						false
					}
				}).unwrap();
				elements::OutPoint::new(txid, vout as u32)
			});

			let verify = Box::new(move |spec: &_, utxo: &ElementsUtxo, tx: &_| {
				let ret = client.call::<Value>("testmempoolaccept", &[
					arg(json!([elements::encode::serialize_hex(tx)])),
				]).unwrap();
				println!("checkmempoolaccept: {:?}", ret);
			});

			(deploy, verify)
		},
		_ => panic!("must either provide libelementsconsensus or regtest argument"),
	};


	test_v0_with_random(&secp, &mut rand, &deploy, &verify);

	// // Then we do a bunch of rounds with actual randomness.
	// let mut rand = rand::thread_rng();
	// for _ in 0..1000 {
	// 	test_v0_with_random(&secp, &mut rand, &deploy, &verify);
	// }
}

/// Generate sane random variables from a randomness source.
pub trait SaneRandom {
	fn sane_rand(rand: &mut impl Rng) -> Self;
}

impl SaneRandom for bitcoin::OutPoint {
	fn sane_rand(rand: &mut impl Rng) -> Self {
		let txid = bitcoin::Txid::from_byte_array(rand.gen());
		bitcoin::OutPoint::new(txid, rand.gen::<u8>() as u32)
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
	deploy_bond: impl Fn(&elements::Address, Amount) -> elements::OutPoint,
	verify_tx: impl Fn(&SegwitV0BondSpec, &ElementsUtxo, &elements::Transaction),
) {
	//! A complete test that tests an entire bond setup, burn and expiration.

	// So let's start with our famous public key.
	let (bond_sk, bond_pk) = secp.generate_keypair(rand);

	// And generate a spec for our bond.
	let expiry = 1722369854; // some unix timestamp
	let (reclaim_sk, reclaim_pk) = secp.generate_keypair(rand);
	let bond_spec = SegwitV0BondSpec {
		pubkey: bond_pk.clone(),
		bond_value: Amount::from_btc(5.0).unwrap(),
		lock_time: elements::LockTime::from_time(expiry).unwrap(),
		reclaim_pubkey: reclaim_pk,
	};

	// Then we can create our bond script.
	let (bond_script, bond_spk) = create_segwit_v0_bond_script(&bond_spec);
	println!("bond script: {}", bond_script.asm());
	let bond_addr = elements::Address::from_script(&bond_spk, None, TEST_NET).unwrap();
	println!("bond addr: {}", bond_addr);
	assert_eq!(bond_addr.script_pubkey(), bond_spk);

	// And pretend we sent money to the address.
	let amount = Amount::from_btc(6.0).unwrap();
	let bond_outpoint = deploy_bond(&bond_addr, amount);
	let bond_utxo = ElementsUtxo {
		outpoint: bond_outpoint,
		output: elements::TxOut {
			value: expl(amount),
			asset: TEST_ASSET,
			nonce: elements::confidential::Nonce::Null,
			script_pubkey: bond_addr.script_pubkey(),
			witness: elements::TxOutWitness::default(),
		},
	};
	
	// So now we need to fake a double spend from this key. Not easy.

	// The output we are going to double spend.
	let double_spend_utxo = BitcoinUtxo {
		outpoint: bitcoin::OutPoint::sane_rand(rand),
		output: bitcoin::TxOut {
			value: Amount::from_btc(1.0).unwrap().to_sat(),
			script_pubkey: bitcoin::ScriptBuf::new_v0_p2wpkh(
				&bitcoin::PublicKey::new(bond_pk).wpubkey_hash().unwrap(),
			),
		},
	};

	// We create two different transactions that spend the same UTXO.
	let spend1 = create_p2wpkh_spend_with_key(&secp, rand, &double_spend_utxo, &bond_sk);
	let spend2 = create_p2wpkh_spend_with_key(&secp, rand, &double_spend_utxo, &bond_sk);

	// So let's BURN!
	let (_, reward_pk) = secp.generate_keypair(rand);
	let burn_tx = create_burn_segwit_v0_bond_tx(
		secp,
		&bond_utxo,
		&bond_spec,
		&double_spend_utxo,
		&spend1,
		&spend2,
		FeeRate::from_sat_per_vb(1).unwrap(),
		elements::Address::p2wpkh(&bitcoin::PublicKey::new(reward_pk), None, TEST_NET),
	).unwrap();
	for (i, w) in burn_tx.input[0].witness.script_witness.iter().enumerate() {
		println!("witness element {}: {}", i, hex_conservative::DisplayHex::as_hex(w));
	}

	println!("burn tx: {}", elements::encode::serialize_hex(&burn_tx));
	println!("burn tx: in={}, out={}",
		bond_utxo.output.value.explicit().unwrap(),
		burn_tx.output.iter().map(|o| o.value.explicit().unwrap()).sum::<u64>(),
	);
	verify_tx(&bond_spec, &bond_utxo, &burn_tx);

	// Now try reclaim after the timelock

	let output = elements::Address::from_str("ert1q76vrm2xyvjgl6g392srk5pwas44twu6rpd8tk5").unwrap();
	let reclaim_tx = create_reclaim_segwit_v0_bond_tx(
		secp,
		&bond_utxo,
		&bond_spec,
		FeeRate::from_sat_per_vb(1).unwrap(),
		&reclaim_sk,
		&output.script_pubkey(),
	).unwrap();
	for (i, w) in reclaim_tx.input[0].witness.script_witness.iter().enumerate() {
		println!("witness element {}: {}", i, hex_conservative::DisplayHex::as_hex(w));
	}

	println!("reclaim tx: {}", elements::encode::serialize_hex(&reclaim_tx));
	println!("reclaim tx: in={}, out={}",
		bond_utxo.output.value.explicit().unwrap(),
		reclaim_tx.output.iter().map(|o| o.value.explicit().unwrap()).sum::<u64>(),
	);
	// verify_tx(&bond_spec, &bond_utxo, &reclaim_tx);
}

fn verify_tx_elementsconsensus(
	script: &elements::Script,
	value: &elements::confidential::Value,
	index: usize,
	transaction: &elements::Transaction,
) -> Result<(), elements_consensus::ConsensusViolation> {
	use elements_consensus::elements::encode::deserialize;
	use elements::encode::serialize;

	elements_consensus::verify(
		deserialize(&serialize(script)).unwrap(),
		&deserialize(&serialize(value)).unwrap(),
		index,
		&deserialize(&serialize(transaction)).unwrap(),
	).expect("index error")
}
