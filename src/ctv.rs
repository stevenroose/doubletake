

use bitcoin::Amount;
use bitcoin::hashes::{sha256, Hash};
use elements::AssetId;
use elements::encode::Encodable;
use elements::script::Builder;
use elements::opcodes::all::*;
use elements::opcodes::*;

use crate::util::BuilderExt;

/// The OP_CHECKTEMPLATEVERIFY opcode.
const OP_CTV: All = OP_NOP4; // 0xb3

/// Calculate the CTV template hash for the tx at input.
///
/// NB this method is the Bitcoin impl of CTV applied to elements,
/// of course this should also commit to asset ids etc, but it's just
/// a proof of concept.
pub fn template_hash(tx: &elements::Transaction, input_idx: usize) -> sha256::Hash {
	// from CTV MR from AJ in INQ
	//
	// auto h = CHashWriter(SER_GETHASH, 0)
	//     << tx.nVersion
	//     << tx.nLockTime
	//     << uint32_t(tx.vin.size())
	//     << sequences_hash
	//     << uint32_t(tx.vout.size())
	//     << outputs_hash
	//     << input_index;
	// return h.GetSHA256();

	let mut engine = sha256::Hash::engine();
	tx.version.consensus_encode(&mut engine).unwrap();
	tx.lock_time.consensus_encode(&mut engine).unwrap();
	(tx.input.len() as u32).consensus_encode(&mut engine).unwrap();
	let sequences = {
			let mut eng = sha256::Hash::engine();
			for txin in tx.input.iter() {
				txin.sequence.consensus_encode(&mut eng).unwrap();
			}
			sha256::Hash::from_engine(eng)
	};
	sequences.consensus_encode(&mut engine).unwrap();
	(tx.output.len() as u32).consensus_encode(&mut engine).unwrap();
	let outputs = {
		let mut eng = sha256::Hash::engine();
		for txout in tx.output.iter() {
			txout.consensus_encode(&mut eng).unwrap();
		}
		sha256::Hash::from_engine(eng)
	};
	outputs.consensus_encode(&mut engine).unwrap();
	(input_idx as u32).consensus_encode(&mut engine).unwrap();

	sha256::Hash::from_engine(engine)
}

pub trait CtvBurnCovenantBuilder: BuilderExt {
	/// Create a covenant that forces the current tx to burn a given amount
	/// and allow one extra output that can take the remaining money.
	fn ctv_burn_covenant(self, burn_amount: Amount, asset: AssetId) -> Self {
		let burn_tx = elements::Transaction {
			version: 2,
			lock_time: elements::LockTime::ZERO,
			input: vec![elements::TxIn::default()],
			output: vec![
				elements::TxOut {
					asset: elements::confidential::Asset::Explicit(asset),
					value: elements::confidential::Value::Explicit(burn_amount.to_sat()),
					nonce: elements::confidential::Nonce::Null,
					script_pubkey: Builder::new()
						.push_opcode(OP_RETURN)
						.into_script(),
					witness: elements::TxOutWitness::default(),
				},
			],
		};

		let template = template_hash(&burn_tx, 0);

		self.into()
			.push_opcode(OP_CTV)
			.push_slice(&template[..])
			.into()
	}
}
impl CtvBurnCovenantBuilder for Builder {}
