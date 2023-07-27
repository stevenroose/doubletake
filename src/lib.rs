
#[cfg(test)]
extern crate link_cplusplus;



mod util;



use std::io::{self, Cursor, Seek};

use bitcoin::{Amount, FeeRate, Weight};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use elements::script::Builder;
use elements::opcodes::all::*;
use elements::opcodes::*;

use crate::util::{BitcoinEncodableExt, ElementsEncodableExt};

#[derive(Debug, Clone)]
pub struct BitcoinUtxo {
	pub outpoint: bitcoin::OutPoint,
	pub output: bitcoin::TxOut,
}
#[derive(Debug, Clone)]
pub struct ElementsUtxo {
	pub outpoint: elements::OutPoint,
	pub output: elements::TxOut,
}

trait BuilderExt: Into<Builder> + From<Builder> {
	/// Check that the top stack item is of the required size.
	fn check_stack_item_size(self, size: i64) -> Self {
		self.into()
			.push_opcode(OP_SIZE)
			.push_int(size)
			.push_opcode(OP_EQUALVERIFY)
			.into()
	}

	/// Check that the input is a valid sighash in the following format
	/// and a correct corresponding signature.
	///
	/// - `<version><prevouts><sequences>` (exact 68 bytes)
	/// - `<prevout>` (exact 36 bytes)
	/// - `<script-code><value><sequence>` (free form, minimum 16 bytes I guess)
	/// - `<outputs>` (exact 32 bytes)
	/// - `<locktime><sighashtype>` (exact 8 bytes)
	/// - `<signature>`
	///
	/// Also leaves the on the altstack:
	/// - <prevout>
	/// - <outputs>
	fn check_input_sighash(self, pubkey: &PublicKey) -> Self {
		self.into()
			// check the size of first push
			// <ver><prevs><seqs>
			.check_stack_item_size(68)
			// copy <prev> to front
			.push_opcode(OP_OVER)
			// check size of <prev>
			.check_stack_item_size(36)
			// put <prev> on altstack
			.push_opcode(OP_TOALTSTACK)
			// cat <ver><prevs><seqs> <prev>
			.push_opcode(OP_SWAP)
			.push_opcode(OP_CAT)
			// because the next element is flexible in size, just cat it too
			// cat: <ver><prev><seqs> <prev> <sc><val><seq>
			// TODO(stevenroose) maybe check minimum length
			.push_opcode(OP_SWAP)
			.push_opcode(OP_CAT)
			// copy <outs> to front
			.push_opcode(OP_OVER)
			// check size of <outs>
			.check_stack_item_size(32)
			// put outputs on altstack
			// altstack: <prev1><outs1>
			.push_opcode(OP_TOALTSTACK)
			// cat: <ver><prev><seqs><prev><sc><val><seq><outs>
			.push_opcode(OP_SWAP)
			.push_opcode(OP_CAT)
			// swap <lt><sht> to the front
			.push_opcode(OP_SWAP)
			.check_stack_item_size(8)
			// cat: <ver><prev><seqs><prev><sc><val><seq><outs><lt><sht>
			.push_opcode(OP_CAT)
			// now we have the entire sighash data, hash it
			.push_opcode(OP_SHA256)
			// then check signature
			.push_slice(&pubkey.serialize())
			.push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
			.into()
	}

	/// Create a covenant that forces the current tx to burn a given amount
	/// and allow one extra output that can take the remaining money.
	fn burn_covenant(self, burn_amount: Amount) -> Self {
		let burn_txout = elements::TxOut {
			asset: elements::confidential::Asset::Explicit(elements::AssetId::LIQUID_BTC),
			value: elements::confidential::Value::Explicit(burn_amount.to_sat()),
			nonce: elements::confidential::Nonce::Null,
			script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
			witness: elements::TxOutWitness::default(),
		};
		self.into()
			// build the outputs hash
			.push_slice(&elements::encode::serialize(&burn_txout))
			.push_opcode(OP_SWAP)
			.push_opcode(OP_CAT)
			.push_opcode(OP_SHA256)

			// cat with first part of sighash
			.push_opcode(OP_CAT)

			// cat last part
			.push_opcode(OP_SWAP)
			.push_opcode(OP_CAT)

			// hash to real sighash
			.push_opcode(OP_SHA256)

			// then check signature of this sighash
			// and later against tx

			// put sighash on the altstack so we can duplicate
			// pubkey and signature
			.push_opcode(OP_TOALTSTACK)
			.push_opcode(OP_2DUP)
			.push_opcode(OP_FROMALTSTACK)

			// swap sighash and pubkey to prepare for CSFS
			.push_opcode(OP_SWAP)
			.push_opcode(OP_CHECKSIGFROMSTACKVERIFY)

			// then the checksig on the tx
			.push_opcode(OP_CHECKSIGVERIFY)
			.into()
	}
}

impl BuilderExt for Builder {}

trait ReadExt: io::Read {
	fn take_bytes(&mut self, n: usize) -> Result<Vec<u8>, io::Error> {
		let mut buf = vec![0; n];
		self.read_exact(&mut buf)?;
		Ok(buf)
	}
}
impl<T: AsRef<[u8]>> ReadExt for Cursor<T> {}

pub struct SegwitV0BondSpec {
	pub pubkey: PublicKey,
	pub bond_value: Amount,
	pub lock_time: elements::LockTime,
	/// Key to reclaim the bond after it expires. Construction
	/// will require a signature verified by OP_CHECKSIGVERIFY.
	pub reclaim_pubkey: PublicKey,
}

/// Creates the full bond script and respective scriptPubkey.
///
/// First return value is the full script, second is the scriptPubkey.
pub fn create_segwit_v0_bond_script(
	spec: &SegwitV0BondSpec,
) -> (elements::Script, elements::Script) {
	let script = Builder::new()
		// first add the locktime clause for when the bond expires
		.push_opcode(OP_DUP) // so the if doesn't take stuff from the stack
		.push_opcode(OP_NOTIF)
		.push_opcode(OP_DROP)
		.push_int(spec.lock_time.to_consensus_u32() as i64)
		.push_opcode(OP_CLTV)
		.push_opcode(OP_DROP)
		.push_slice(&spec.reclaim_pubkey.serialize())
		.push_opcode(OP_CHECKSIGVERIFY)
		.push_opcode(OP_ELSE)

		// check the two sighashes of the double spend
		.check_input_sighash(&spec.pubkey)
		.check_input_sighash(&spec.pubkey)

		// so now we checked that our pubkey signed two sighashes
		// altstack: <prev1><outs1><prev2><outs2>
		
		// pop all four items from altstack
		.push_opcode(OP_FROMALTSTACK)
		.push_opcode(OP_FROMALTSTACK)
		.push_opcode(OP_FROMALTSTACK)
		.push_opcode(OP_FROMALTSTACK)

		// so the stack is now
		// <outs2><prev2><outs1><prev1>
		
		// put prevouts and outputs next to eachother
		.push_int(2)
		.push_opcode(OP_ROLL)
		// now the stack is <outs2><outs1><prev1><prev2>

		// check that prevouts are identical
		.push_opcode(OP_EQUALVERIFY)

		// Now the stack is <outs2><outs1>
		// Check that outputs are not identical
		.push_opcode(OP_EQUAL)
		.push_int(0)
		.push_opcode(OP_EQUALVERIFY)

		// Covenant to enforce burn amount
		.burn_covenant(spec.bond_value)

		// end the if clause
		.push_opcode(OP_ENDIF)

		.into_script();

	let spk = elements::Script::new_v0_wsh(&elements::WScriptHash::hash(&script[..]));
	(script, spk)
}

/// Info needed to proof one of the two sides of a doublespend.
struct SpendDataV0<'a> {
	tx: &'a bitcoin::Transaction,
	input_idx: usize,
	input_value: u64,
	script_code: bitcoin::ScriptBuf,
	signature: bitcoin::ecdsa::Signature,
}

fn determine_scriptcode_v0(
	spk: &bitcoin::Script,
	witness: &bitcoin::Witness,
) -> Result<bitcoin::ScriptBuf, &'static str> {
	//TODO(stevenroose) this can be a method on spk once new rust-bitcoin version gets merged
	if let Some(sc) = bitcoin::ScriptBuf::from(spk).p2wpkh_script_code() {
		Ok(sc)
	} else if spk.is_v0_p2wsh() {
		let bytes = witness.last().ok_or("p2wsh scriptPubkey but invalid witness")?;
		let script = bitcoin::Script::from_bytes(bytes);
		// Quick sanity check on the script.
		if script.instructions().all(|r| r.is_ok()) {
			Ok(script.into())
		} else {
			Err("invalid script in witness push")
		}
	} else {
		Err("scriptPubkey is not p2wpkh or p2wsh")
	}
}

impl<'a> SpendDataV0<'a> {
	fn determine(
		secp: &Secp256k1<impl secp256k1::Verification>,
		pubkey: &PublicKey,
		tx: &'a bitcoin::Transaction,
		utxo: &BitcoinUtxo,
	) -> Result<SpendDataV0<'a>, &'static str> {
		let input_idx = tx.input.iter()
			.position(|i| i.previous_output == utxo.outpoint)
			.ok_or("tx doesn't spend utxo")?;

		let script_code = determine_scriptcode_v0(
			&utxo.output.script_pubkey, &tx.input[input_idx].witness,
		)?;

		let sig = tx.input[input_idx].witness.iter()
			// first filter valid signatures
			.filter_map(|b| bitcoin::ecdsa::Signature::from_slice(b).ok())
			.find_map(|sig| {
				let sighash_data = Self::create_sighash_data(
					tx, input_idx, utxo.output.value, &script_code, sig.hash_ty,
				);
				let sighash = Self::sighash(&sighash_data);
				if secp.verify_ecdsa(&sighash, &sig.sig, pubkey).is_ok() {
					Some(sig)
				} else {
					None
				}
			})
			.ok_or("no signature found in witness")?;

		Ok(SpendDataV0 {
			tx: tx,
			input_idx: input_idx,
			input_value: utxo.output.value,
			script_code: script_code,
			signature: sig,
		})
	}

	fn create_sighash_data(
		tx: &bitcoin::Transaction,
		input_idx: usize,
		input_value: u64,
		script_code: &bitcoin::Script,
		sighash_type: bitcoin::sighash::EcdsaSighashType
	) -> Vec<u8> {
		let scriptcode_len = script_code.encoded_len();
		let supposed_len = 156 + scriptcode_len;
		let mut buf = Vec::with_capacity(supposed_len);
		let mut shc = bitcoin::sighash::SighashCache::new(tx);
		shc.segwit_encode_signing_data_to(
			&mut buf,
			input_idx,
			script_code,
			input_value,
			sighash_type,
		).expect("error doing sighash");
		debug_assert_eq!(buf.len(), supposed_len);
		buf
	}

	fn sighash(sighash_data: &[u8]) -> secp256k1::Message {
		secp256k1::Message::from_hashed_data::<bitcoin::sighash::SegwitV0Sighash>(&sighash_data)
	}

	fn sighash_data(&self) -> Vec<u8> {
		Self::create_sighash_data(
			self.tx, self.input_idx, self.input_value, &self.script_code, self.signature.hash_ty,
		)
	}

	/// Push the sighash items on the stack for the given index of the given tx.
	///
	/// Items are pushed in reverse order than they should actually appear
	/// in the witness.
	///
	/// They are pushed as follows:
	///
	/// - `<version><prevouts><sequences>` (exact 68 bytes)
	/// - `<prevout>` (exact 36 bytes)
	/// - `<script-code><value><sequence>` (free form, minimum 12 bytes I guess)
	/// - `<outputs>` (exact 32 bytes)
	/// - `<locktime><sighashtype>` (exact 8 bytes)
	/// - `<signature>`
	fn push_segwit_v0_sighash_items(&self, witness: &mut Vec<Vec<u8>>) {
		let sighash_data = self.sighash_data();

		let scriptcode_len = self.script_code.as_script().encoded_len();
		assert_eq!(sighash_data.len(), 156 + scriptcode_len);

		let mut cur = Cursor::new(&sighash_data);
		witness.push(cur.take_bytes(68).unwrap());
		witness.push(cur.take_bytes(36).unwrap());
		witness.push(cur.take_bytes(12 + scriptcode_len).unwrap());
		witness.push(cur.take_bytes(32).unwrap());
		witness.push(cur.take_bytes(8).unwrap());
		witness.push(self.signature.to_vec());
	}
}


/// Push the input data to the burn covenant on the stack.
///
/// Items are pushed in reverse order than they should actually appear
/// in the witness.
///
/// They are pushed as follows:
///
/// - `<other-output>`: output to claim non-burn amount
/// - `<version><prevouts><sequences><prevout><script-code><value><sequence>`:
///		pre-outputs sighash items
/// - `<locktime><sighashtype>`: post-outputs sighash items
/// - `<pubkey>`: the pubkey that signed the tx
/// - `<signature>`: the signature on the tx
fn push_v0_burn_covenant_items(
	secp: &Secp256k1<impl secp256k1::Signing>,
	witness: &mut Vec<Vec<u8>>,
	other_output: &elements::TxOut,
	spending_tx: &elements::Transaction,
	bond_script: &elements::Script,
	total_amount: Amount,
) {
	let mut shc = elements::sighash::SighashCache::new(spending_tx);
	// we're going to write the sighash data to a buffer
	// and break it into 5 pieces.
	let covenant_script_len = bond_script.encoded_len();
	let mut buf = Vec::with_capacity(160 + 1 + covenant_script_len);
	shc.encode_segwitv0_signing_data_to(
		&mut buf,
		0,
		bond_script,
		elements::confidential::Value::Explicit(total_amount.to_sat()),
		elements::EcdsaSighashType::All,
	).expect("error doing sighash");
	assert_eq!(buf.len(), 189 + bond_script.encoded_len(),
		"covenant len {}", bond_script.encoded_len(),
	);

	// We want our signature to be 70 bytes, and we are lucky we can
	// chose our own secret key here. There about a 50% chance the signature
	// is 70 bytes, so let's just brute force it.
	let sign_msg = secp256k1::Message::from_hashed_data::<elements::Sighash>(&buf);
	let (signing_pk, signature) = loop {
		let (sk, pk) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
		let sig = secp.sign_ecdsa(&sign_msg, &sk);
		if sig.serialize_der().len() == 70 {
			break (pk, sig);
		}
	};
	
	// first we just take the major part of the first part.
	let mut cur = Cursor::new(&buf);
	let first_part = cur.take_bytes(4 + 32 + 32 + 36 + covenant_script_len + 8 + 4).unwrap();
	// then discard the 32-byte outputs hash, we're gonna create it
	cur.seek(io::SeekFrom::Current(32)).unwrap();
	let last_part = cur.take_bytes(4 + 4).unwrap();

	witness.push(elements::encode::serialize(other_output));
	witness.push(first_part);
	witness.push(last_part);
	witness.push(signing_pk.serialize().to_vec());
	witness.push(signature.serialize_der().to_vec());
}

pub fn create_burn_segwit_v0_bond_tx(
	secp: &Secp256k1<impl secp256k1::Signing + secp256k1::Verification>,
	bond_utxo: &ElementsUtxo,
	spec: &SegwitV0BondSpec,
	double_spend_utxo: &BitcoinUtxo,
	tx1: &bitcoin::Transaction,
	tx2: &bitcoin::Transaction,
	fee_rate: FeeRate,
	reward_address: elements::Address,
) -> Result<elements::Transaction, &'static str> {
	// We start by actually finding our double spend.

	let spend1 = SpendDataV0::determine(secp, &spec.pubkey, tx1, double_spend_utxo)?;
	let spend2 = SpendDataV0::determine(secp, &spec.pubkey, tx2, double_spend_utxo)?;

	let mut ret = elements::Transaction {
		version: 3,
		lock_time: elements::LockTime::ZERO,
		input: vec![elements::TxIn {
			previous_output: bond_utxo.outpoint,
			is_pegin: false,
			script_sig: elements::Script::new(), // segwit
			sequence: elements::Sequence::MAX,
			asset_issuance: elements::AssetIssuance::default(),
			witness: elements::TxInWitness {
				amount_rangeproof: None,
				inflation_keys_rangeproof: None,
				pegin_witness: Vec::new(),
				// we will fill this later
				script_witness: Vec::new(),
			},
		}],
		output: vec![
			elements::TxOut {
				asset: elements::confidential::Asset::Explicit(elements::AssetId::LIQUID_BTC),
				value: elements::confidential::Value::Explicit(spec.bond_value.to_sat()),
				nonce: elements::confidential::Nonce::Null,
				script_pubkey: Builder::new()
					.push_opcode(OP_RETURN)
					.into_script(),
				witness: elements::TxOutWitness::default(),
			},
			elements::TxOut {
				asset: elements::confidential::Asset::Explicit(elements::AssetId::LIQUID_BTC),
				// will change this later
				value: elements::confidential::Value::Explicit(0),
				nonce: elements::confidential::Nonce::Null,
				script_pubkey: reward_address.script_pubkey(),
				witness: elements::TxOutWitness::default(),
			},
			// will change value later
			elements::TxOut::new_fee(0, elements::AssetId::LIQUID_BTC),
		],
	};

	let (bond_script, bond_spk) = create_segwit_v0_bond_script(spec);
	assert_eq!(bond_utxo.output.script_pubkey, bond_spk,
		"bond UTXO doesn't match expected bond scriptPubkey",
	);

	// calculate the fee so we know what we can add a claim output
	let sc1_len = spend1.script_code.as_script().encoded_len();
	let sc2_len = spend2.script_code.as_script().encoded_len();
	let reward_len = reward_address.script_pubkey().encoded_len();
	let total_tx_weight = 1680 + sc1_len + sc2_len + reward_len
		+ BitcoinEncodableExt::encoded_len(&spend1.signature.to_vec())
		+ BitcoinEncodableExt::encoded_len(&spend2.signature.to_vec())
		+ bond_script.encoded_len();
	let fee = fee_rate * Weight::from_wu(total_tx_weight as u64);
	let change = bond_utxo.output.value.explicit().unwrap() - fee.to_sat();
	ret.output[2].value = elements::confidential::Value::Explicit(fee.to_sat());
	ret.output[1].value = elements::confidential::Value::Explicit(change);

	// create a nums key and sign the tx

	let mut witness = Vec::with_capacity(6 + 6 + 5 + 1);
	spend1.push_segwit_v0_sighash_items(&mut witness);
	spend2.push_segwit_v0_sighash_items(&mut witness);

	push_v0_burn_covenant_items(
		secp,
		&mut witness,
		&ret.output[1],
		&ret,
		&bond_script,
		Amount::from_sat(bond_utxo.output.value.explicit().unwrap()),
	);

	// We added the elements in reverse, so let's reverse the stack
	// before we add the witnessScript.
	witness.reverse();

	// finally add the witness script element
	//TODO(stevenroose) doesn't need length prefix here, right?
	// witness.push(elements::encode::serialize(&bond_script));
	witness.push(bond_script.to_bytes());

	ret.input[0].witness.script_witness = witness;

	assert_eq!(ret.weight(), total_tx_weight,
		"sc1: {}; sc2: {}, reward: {}, sig1: {}, sig2: {}", sc1_len, sc2_len, reward_len,
		spend1.signature.to_vec().len(), spend2.signature.to_vec().len(),
	);
	Ok(ret)
}

pub fn create_reclaim_segwit_v0_bond_tx(
	secp: &Secp256k1<impl secp256k1::Signing + secp256k1::Verification>,
	bond_utxo: &ElementsUtxo,
	spec: &SegwitV0BondSpec,
	fee_rate: FeeRate,
	reclaim_sk: &SecretKey,
	output_spk: &elements::Script,
) -> Result<elements::Transaction, &'static str> {
	let mut ret = elements::Transaction {
		version: 3,
		lock_time: spec.lock_time,
		input: vec![elements::TxIn {
			previous_output: bond_utxo.outpoint,
			is_pegin: false,
			script_sig: elements::Script::new(), // segwit
			sequence: elements::Sequence::ZERO,
			asset_issuance: elements::AssetIssuance::default(),
			witness: elements::TxInWitness {
				amount_rangeproof: None,
				inflation_keys_rangeproof: None,
				pegin_witness: Vec::new(),
				// we will fill this later
				script_witness: Vec::new(),
			},
		}],
		output: vec![
			elements::TxOut {
				asset: elements::confidential::Asset::Explicit(elements::AssetId::LIQUID_BTC),
				// will change this value later
				value: elements::confidential::Value::Explicit(0),
				nonce: elements::confidential::Nonce::Null,
				script_pubkey: output_spk.clone(),
				witness: elements::TxOutWitness::default(),
			},
			// will change this value later
			elements::TxOut::new_fee(0, elements::AssetId::LIQUID_BTC),
		],
	};

	let (bond_script, bond_spk) = create_segwit_v0_bond_script(spec);
	assert_eq!(bond_utxo.output.script_pubkey, bond_spk,
		"bond UTXO doesn't match expected bond scriptPubkey",
	);
	let max_tx_weight = ret.weight()
		+ 8	  // non-empty witness
		+ 1 + 72 //sig
		+ 1 + 1  // OP_FALSE
		+ 1 + bond_script.encoded_len();
	let fee = fee_rate * bitcoin::Weight::from_wu(max_tx_weight as u64);
	let remaining = bond_utxo.output.value.explicit().unwrap() - fee.to_sat();
	ret.output[0].value = elements::confidential::Value::Explicit(remaining);
	ret.output[1].value = elements::confidential::Value::Explicit(fee.to_sat());

	let mut shc = elements::sighash::SighashCache::new(&mut ret);
	let sighash = shc.segwitv0_sighash(
		0,
		&bond_script,
		bond_utxo.output.value,
		elements::EcdsaSighashType::All,
	);
	let sig = secp.sign_ecdsa(&sighash.into(), &reclaim_sk);

	ret.input[0].witness.script_witness.push(
		bitcoin::ecdsa::Signature::sighash_all(sig).to_vec(),
	);
	ret.input[0].witness.script_witness.push(vec![OP_FALSE.into_u8()]);
	//TODO(stevenroose) doesn't need length prefix here, right?
	//ret.input[0].witness.script_witness.push(elements::encode::serialize(&bond_script));
	ret.input[0].witness.script_witness.push(bond_script.to_bytes());

	for (i, w) in ret.input[0].witness.script_witness.iter().enumerate() {
		println!("witness element {}: {}", i, hex_conservative::DisplayHex::as_hex(w));
	}

	// Check that our calculation made sense.
	assert!(ret.weight() <= max_tx_weight,
		"max_tx_weight: {}; actual: {}", max_tx_weight, ret.weight(),
	);

	Ok(ret)
}

#[cfg(test)]
mod test {
	use super::*;

	use std::str::FromStr;

	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::SecretKey;
	use bitcoin::secp256k1::rand::{self, Rng, SeedableRng};

	/// Test network params;
	static TEST_NET: &'static elements::AddressParams = &elements::AddressParams::ELEMENTS;
	static TEST_ASSETID: elements::AssetId = elements::AssetId::LIQUID_BTC;
	static TEST_ASSET: elements::confidential::Asset =
		elements::confidential::Asset::Explicit(TEST_ASSETID);

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

	fn btc(amount: Amount) -> elements::confidential::Value {
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
	fn test_v0_with_random(secp: &Secp256k1<secp256k1::All>, rand: &mut impl Rng) {
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
		println!("bond addr: {}", elements::Address::from_script(&bond_spk, None, TEST_NET).unwrap());

		// And pretend we sent money to the address.
		let bond_utxo = ElementsUtxo {
			outpoint: elements::OutPoint::sane_rand(rand),
			output: elements::TxOut {
				value: btc(Amount::from_btc(6.0).unwrap()),
				asset: TEST_ASSET,
				nonce: elements::confidential::Nonce::Null,
				script_pubkey: bond_spk,
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
		if let Err(e) = verify_tx(&bond_script, &bond_utxo.output.value, 0, &burn_tx) {
			//TODO(stevenroose) return back to panic
			println!("ERROR for burn: {}", e);
		}


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
		if let Err(e) = verify_tx(&bond_script, &bond_utxo.output.value, 0, &reclaim_tx) {
			panic!("ERROR for reclaim: {}", e);
		}
	}

	#[test]
	fn test_v0_fo_real() {
		let secp = Secp256k1::new();

		// First run we do with deterministic randomness.
		let mut rand = rand::rngs::StdRng::from_seed([
			1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		]);
		test_v0_with_random(&secp, &mut rand);

		// Then we do a bunch of rounds with actual randomness.
		let mut rand = rand::thread_rng();
		for _ in 0..1000 {
			test_v0_with_random(&secp, &mut rand);
		}
	}

	fn verify_tx(
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
}
