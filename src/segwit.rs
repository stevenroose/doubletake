

use std::io::{self, Cursor, Seek};

use bitcoin::{Amount, FeeRate, Weight};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, ecdsa, PublicKey, Secp256k1};
use elements::AssetId;
use elements::script::Builder;
use elements::opcodes::all::*;
use elements::opcodes::*;

use crate::{BitcoinUtxo, ElementsUtxo};
use crate::util::{self, BitcoinEncodableExt, BuilderExt, ElementsEncodableExt, ReadExt};

use self::bitcoin_sighash::SegwitBitcoinSighashBuilder;
use self::burn_covenant::SegwitBurnCovenantBuilder;

/// The maximum size of the scriptCode that the bond can have effect on.
/// For users, this is an important value because they cannot trust any p2wsh
/// output that has a witness script larger than this value.
///
/// This value is calculated so that the entire sighash data fits within the 520
/// max stack item size limit.
pub const MAX_SCRIPTCODE_LEN: usize = 520 - ( 4 + 32 + 32 + 36 + 8 + 4 + 32 + 4 + 4 );

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct BondSpec {
	pub pubkey: PublicKey,
	#[cfg_attr(feature = "serde", serde(with = "bitcoin::amount::serde::as_sat"))]
	pub bond_value: Amount,
	pub bond_asset: AssetId,
	#[cfg_attr(feature = "serde", serde(with = "util::serde::locktime_as_int"))]
	pub lock_time: elements::LockTime,
	/// Key to reclaim the bond after it expires. Construction
	/// will require a signature verified by OP_CHECKSIGVERIFY.
	pub reclaim_pubkey: PublicKey,
}


/// Creates the full bond script and respective scriptPubkey.
///
/// First return value is the full witness script, second is the scriptPubkey.
pub fn create_bond_script(
	spec: &BondSpec,
) -> (elements::Script, elements::Script) {
	let script = Builder::new()
		// first add the locktime clause for when the bond expires
		.push_opcode(OP_NOTIF)
		.spend_with_locktime(&spec.reclaim_pubkey, spec.lock_time)
		.push_opcode(OP_ELSE)

		// check the two sighashes of the double spend
		.check_input_bitcoin_sighash(&spec.pubkey)
		.check_input_bitcoin_sighash(&spec.pubkey)

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
		.burn_covenant(spec.bond_value, spec.bond_asset)

		// end the if clause
		.push_opcode(OP_ENDIF)

		// if no VERIFY operations failed, exit succesfully
		.push_opcode(OP_TRUE)

		.into_script();

	let expected_len = 263
		+ util::scriptint_size(spec.lock_time.to_consensus_u32() as i64);
	assert_eq!(expected_len, script.len());

	let spk = elements::Script::new_v0_wsh(&elements::WScriptHash::hash(&script[..]));
	(script, spk)
}

/// Info needed to proof one of the two sides of a doublespend.
pub struct SpendData<'a> {
	tx: &'a bitcoin::Transaction,
	input_idx: usize,
	input_value: u64,
	script_code: bitcoin::ScriptBuf,
	signature: bitcoin::ecdsa::Signature,
}

fn determine_scriptcode(
	spk: &bitcoin::Script,
	witness: &bitcoin::Witness,
) -> Result<bitcoin::ScriptBuf, &'static str> {
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

impl<'a> SpendData<'a> {
	fn determine(
		secp: &Secp256k1<impl secp256k1::Verification>,
		pubkey: &PublicKey,
		tx: &'a bitcoin::Transaction,
		utxo: &BitcoinUtxo,
	) -> Result<SpendData<'a>, &'static str> {
		let input_idx = tx.input.iter()
			.position(|i| i.previous_output == utxo.outpoint)
			.ok_or("tx doesn't spend utxo")?;

		let script_code = determine_scriptcode(
			&utxo.output.script_pubkey, &tx.input[input_idx].witness,
		)?;
		if script_code.as_script().encoded_len() > MAX_SCRIPTCODE_LEN {
			return Err("scriptCode too large");
		}

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

		Ok(SpendData {
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
			&mut buf, input_idx, script_code, input_value, sighash_type,
		).expect("error doing sighash");
		assert_eq!(buf.len(), supposed_len);
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
	// We start by actually finding our double spend.

	let spend1 = SpendData::determine(secp, &spec.pubkey, tx1, double_spend_utxo)?;
	let spend2 = SpendData::determine(secp, &spec.pubkey, tx2, double_spend_utxo)?;

	let mut ret = elements::Transaction {
		version: 2,
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
			util::burn_output(spec.bond_value, spec.bond_asset),
			elements::TxOut {
				asset: elements::confidential::Asset::Explicit(spec.bond_asset),
				// will change this later
				value: elements::confidential::Value::Explicit(0),
				nonce: elements::confidential::Nonce::Null,
				script_pubkey: reward_address.script_pubkey(),
				witness: elements::TxOutWitness::default(),
			},
			// will change value later
			elements::TxOut::new_fee(0, spec.bond_asset),
		],
	};

	let (bond_script, bond_spk) = create_bond_script(spec);
	if bond_utxo.output.script_pubkey != bond_spk {
		return Err("bond UTXO doesn't match expected bond scriptPubkey");
	}

	// calculate the fee so we know what we can add a claim output
	let total_tx_weight = 1687 // this value is just hardcoded all the fixed parts
		+ spend1.script_code.as_script().len()
		+ spend2.script_code.as_script().len()
		+ reward_address.script_pubkey().encoded_len()
		+ spend1.signature.sig.serialize_der().len()
		+ spend2.signature.sig.serialize_der().len()
		+ util::scriptint_size(spec.lock_time.to_consensus_u32() as i64)
		+ bond_script.encoded_len()
		+ ret.output[1..].to_vec().encoded_len();
	let fee = fee_rate * Weight::from_wu(total_tx_weight as u64);
	let in_value = bond_utxo.output.value.explicit()
		.ok_or("broken bond: blinded value")?;
	let reward_budget = in_value.checked_sub(spec.bond_value.to_sat())
		.ok_or("broken bond: burn value higher than utxo value")?;
	let change = reward_budget.checked_sub(fee.to_sat())
		.ok_or("not enough money for fee, try lower feerate")?;
	ret.output[2].value = elements::confidential::Value::Explicit(fee.to_sat());
	ret.output[1].value = elements::confidential::Value::Explicit(change);

	// Then we construct the witness to the bond smart contract.
	// We add the items in reverse order because that's easier to reason about
	// we then reverse the witness before we add the witnessScript in the end.

	let mut witness = Vec::with_capacity(1 + 6 + 6 + 5 + 1);
	witness.push(vec![1]); // this is the TRUE for the IF

	bitcoin_sighash::push_witness_items(&mut witness, &spend1);
	bitcoin_sighash::push_witness_items(&mut witness, &spend2);

	let input_amount = Amount::from_sat(bond_utxo.output.value.explicit().unwrap());
	burn_covenant::push_witness_items(
		secp, &mut witness, &ret.output[1..], &ret, &bond_script, input_amount,
	);

	// We added the elements in reverse, so let's reverse the stack
	// before we add the witnessScript.
	witness.reverse();

	// finally add the witness script element
	witness.push(bond_script.to_bytes());

	ret.input[0].witness.script_witness = witness;

	assert_eq!(ret.weight(), total_tx_weight);
	Ok(ret)
}

/// Calculate the maximum tx weight of the reclaim tx.
fn max_reclaim_tx_weight(
	unsigned_tx: &elements::Transaction,
	bond_script: &elements::Script,
) -> usize {
	unsigned_tx.weight()
		+ 8	     // basic non-empty witness structure
		+ 1 + 72 // signature
		+ 1      // FALSE witness element
		+ 1 + bond_script.encoded_len()
}

pub fn create_unsigned_reclaim_tx(
	bond_utxo: &ElementsUtxo,
	spec: &BondSpec,
	fee_rate: FeeRate,
	output_spk: &elements::Script,
) -> Result<elements::Transaction, &'static str> {
	let mut ret = elements::Transaction {
		version: 2,
		lock_time: spec.lock_time,
		input: vec![elements::TxIn {
			previous_output: bond_utxo.outpoint,
			is_pegin: false,
			script_sig: elements::Script::new(), // segwit
			sequence: elements::Sequence::ZERO, // to allow timelock
			asset_issuance: elements::AssetIssuance::default(),
			witness: elements::TxInWitness {
				amount_rangeproof: None,
				inflation_keys_rangeproof: None,
				pegin_witness: Vec::new(),
				script_witness: Vec::new(),
			},
		}],
		output: vec![
			elements::TxOut {
				asset: elements::confidential::Asset::Explicit(spec.bond_asset),
				// will change this value later
				value: elements::confidential::Value::Explicit(0),
				nonce: elements::confidential::Nonce::Null,
				script_pubkey: output_spk.clone(),
				witness: elements::TxOutWitness::default(),
			},
			// will change this value later
			elements::TxOut::new_fee(0, spec.bond_asset),
		],
	};

	let (bond_script, bond_spk) = create_bond_script(spec);
	if bond_utxo.output.script_pubkey != bond_spk {
		return Err("bond UTXO doesn't match expected bond scriptPubkey");
	}
	let max_tx_weight = max_reclaim_tx_weight(&ret, &bond_script);
	let fee = fee_rate * bitcoin::Weight::from_wu(max_tx_weight as u64);
	let in_value = bond_utxo.output.value.explicit().ok_or("broken bond: blinded value")?;
	let remaining = in_value.checked_sub(fee.to_sat()).ok_or("fee higher than input amount")?;
	ret.output[0].value = elements::confidential::Value::Explicit(remaining);
	ret.output[1].value = elements::confidential::Value::Explicit(fee.to_sat());

	Ok(ret)
}

pub fn finalize_reclaim_tx(
	spec: &BondSpec,
	mut tx: elements::Transaction,
	sig: ecdsa::Signature,
) -> elements::Transaction {
	let mut witness = Vec::with_capacity(3);

	// we only need push the signature since the pubkey is hardcoded, ofc
	witness.push(bitcoin::ecdsa::Signature::sighash_all(sig).to_vec());

	// this is the FALSE value that make us go into the CLTV clause
	witness.push(vec![]);

	// add witnessScript at the end
	let (bond_script, _) = create_bond_script(spec);
	witness.push(bond_script.to_bytes());

	tx.input[0].witness.script_witness = witness;

	// Check that our calculation made sense.
	let max_tx_weight = max_reclaim_tx_weight(&tx, &bond_script);
	assert!(tx.weight() <= max_tx_weight,
		"max_tx_weight: {}; actual: {}", max_tx_weight, tx.weight(),
	);

	tx
}

pub mod bitcoin_sighash {
	use super::*;

	/// Number of stack items we have to provide for the stack element
	/// containing the scriptCode.
	///
	/// The total item size is 376 bytes (max scriptCode len + 12).
	const SCRIPTCODE_SECTION_ITEMS: usize = 5;

	pub trait SegwitBitcoinSighashBuilder: BuilderExt {
		/// Check that the input is a valid *Bitcoin* sighash in the following format
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
		fn check_input_bitcoin_sighash(self, pubkey: &PublicKey) -> Self {
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
				// the next element is <script-code><value><sequence>
				// This is variable in size, with a maximum length is 376 bytes
				// (max scriptCode len + 12). With a maximum standard stack
				// element size of 80 bytes, this means we need to provide 5
				// stack elements for the user to add this section.
				// Ofc usually, most of them will be empty.
				//
				// cat: <ver><prev><seqs> <prev> <sc><val><seq>
				.repeat(SCRIPTCODE_SECTION_ITEMS, |b| b
					.push_opcode(OP_SWAP)
					.push_opcode(OP_CAT)
				)
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
	}
	impl SegwitBitcoinSighashBuilder for Builder {}

	/// Push the *Bitcoin* sighash items on the stack for the given index
	/// of the given tx.
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
	pub fn push_witness_items(witness: &mut Vec<Vec<u8>>, spend_data: &SpendData) {
		let sighash_data = spend_data.sighash_data();

		let scriptcode_len = spend_data.script_code.as_script().encoded_len();
		assert_eq!(sighash_data.len(), 156 + scriptcode_len);

		let mut cur = Cursor::new(&sighash_data);
		witness.push(cur.take_bytes(68).unwrap());
		witness.push(cur.take_bytes(36).unwrap());
		// The next element is <script-code><value><sequence>
		// The max size of this element is 10,012 bytes so we
		// have to split it up in pushes of 520 max each.
		let next_element = cur.take_bytes(12 + scriptcode_len).unwrap();
		util::divide_witness_pushes(witness, SCRIPTCODE_SECTION_ITEMS, false, &next_element);
		witness.push(cur.take_bytes(32).unwrap());
		witness.push(cur.take_bytes(8).unwrap());
		assert_eq!(cur.position() as usize, sighash_data.len());
		witness.push(spend_data.signature.sig.serialize_der().to_vec());
	}
}

pub mod burn_covenant {
	use super::*;

	pub trait SegwitBurnCovenantBuilder: BuilderExt {
		/// Create a covenant that forces the current tx to burn a given amount
		/// and allow one extra output that can take the remaining money.
		///
		/// The following input is expected, for the *Liquid* sighash:
		///
		/// - `<other-outputs>`: outputs to claim non-burn amount
		/// - `<version><prevouts><sequences><prevout><script-code><value><sequence>`:
		///		pre-outputs sighash items
		/// - `<locktime><sighashtype>`: post-outputs sighash items
		/// - `<pubkey>`: the pubkey that signed the tx
		/// - `<signature>`: the signature on the tx
		fn burn_covenant(self, burn_amount: Amount, asset: AssetId) -> Self {
			let burn_txout = util::burn_output(burn_amount, asset);
			self.into()
				// build the outputs hash
				.push_slice(&elements::encode::serialize(&burn_txout))
				// Provide two pushes for the "other outputs" part to
				// make a simple tx fit in standardness.
				.repeat(2, |b| b
					.push_opcode(OP_SWAP)
					.push_opcode(OP_CAT)
				)
				.push_opcode(OP_HASH256)

				// cat with first part of sighash
				// We provide 6 pushes for this. They will have to be reversed.
				.repeat(6, |b| b.push_opcode(OP_CAT))

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
				// add the SIGHASH_ALL byte before CHECKSIGVERIFY
				.push_opcode(OP_SWAP)
				.push_int(1)
				.push_opcode(OP_CAT)
				.push_opcode(OP_SWAP)
				.push_opcode(OP_CHECKSIGVERIFY)
				.into()
		}
	}
	impl SegwitBurnCovenantBuilder for Builder {}

	/// Push the input data to the burn covenant on the stack.
	///
	/// Items are pushed in reverse order than they should actually appear
	/// in the witness.
	///
	/// They are pushed as follows, as items of a *Liquid* sighash:
	///
	/// - `<other-output>`: output to claim non-burn amount
	/// - `<version><prevouts><sequences><prevout><script-code><value><sequence>`:
	///		pre-outputs sighash items
	/// - `<locktime><sighashtype>`: post-outputs sighash items
	/// - `<pubkey>`: the pubkey that signed the tx
	/// - `<signature>`: the signature on the tx
	pub fn push_witness_items(
		secp: &Secp256k1<impl secp256k1::Signing>,
		witness: &mut Vec<Vec<u8>>,
		other_outputs: &[elements::TxOut],
		spending_tx: &elements::Transaction,
		bond_script: &elements::Script,
		input_amount: Amount,
	) {
		let mut shc = elements::sighash::SighashCache::new(spending_tx);
		// we're going to write the sighash data to a buffer
		// and break it into 5 pieces.
		let bond_script_len = bond_script.encoded_len();
		let mut buf = Vec::with_capacity(189 + bond_script_len);
		let input_amount = elements::confidential::Value::Explicit(input_amount.to_sat());
		shc.encode_segwitv0_signing_data_to(
			&mut buf, 0, bond_script, input_amount, elements::EcdsaSighashType::All,
		).expect("error doing sighash");
		assert_eq!(buf.len(), 189 + bond_script_len, "bond script len {}", bond_script_len);

		// We want our signature to be 70 bytes, and we are lucky we can
		// chose our own secret key here. There about a 50% chance the signature
		// is 70 bytes, so let's just brute force it.
		let sign_msg = secp256k1::Message::from_hashed_data::<elements::Sighash>(&buf);
		let (signing_pk, signature) = loop {
			let mut buf = [0u8; 32];
			getrandom::getrandom(&mut buf[..]).expect("error getting randomness");
			let pair = secp256k1::KeyPair::from_seckey_slice(&secp, &buf[..]).unwrap();
			let sig = secp.sign_ecdsa(&sign_msg, &pair.secret_key());
			if sig.serialize_der().len() == 70 {
				break (pair.public_key(), sig);
			}
		};
		
		// first we just take the major part of the first part.
		let mut cur = Cursor::new(&buf);
		// <version><prevouts><sequences><issuances><prevout><script-code><value><sequence>
		let first_part = cur.take_bytes(4 + 32 + 32 + 32 + 36 + bond_script_len + 9 + 4).unwrap();
		// then discard the 32-byte outputs hash, we're gonna create it
		cur.seek(io::SeekFrom::Current(32)).unwrap();
		// <locktime><sighashtype>
		let last_part = cur.take_bytes(4 + 4).unwrap();
		assert_eq!(cur.position() as usize, buf.len(), "bond script len: {}", bond_script_len);

		let other_outputs_serialized = {
			let mut buf = Vec::new();
			for out in other_outputs {
				elements::encode::Encodable::consensus_encode(out, &mut buf).unwrap();
			}
			buf
		};
		util::divide_witness_pushes(witness, 2, false, &other_outputs_serialized);
		util::divide_witness_pushes(witness, 6, true, &first_part);
		witness.push(last_part);
		witness.push(signing_pk.serialize().to_vec());
		witness.push(signature.serialize_der().to_vec());
	}
}
