

use std::io;

use bitcoin::Amount;
use bitcoin::secp256k1::{ecdsa, PublicKey};
use elements::AssetId;
use elements::opcodes::all::*;
use elements::script::Builder;

/// Parse an ECDSA signature from bytes that may or may not contain a sighash byte.
/// 
/// If it does, it must be ALL.
pub fn parse_ecdsa_signature_all(bytes: &[u8]) -> Result<ecdsa::Signature, String> {
	match ecdsa::Signature::from_der(bytes) {
		Ok(s) => Ok(s),
		Err(e) => {
			// maybe it's serialized with sighash..
			if let Ok(sig) = bitcoin::ecdsa::Signature::from_slice(bytes) {
				let ht = sig.hash_ty;
				if ht != bitcoin::sighash::EcdsaSighashType::All {
					Err(format!("signature contains sighash type that is not ALL: {}", ht))
				} else {
					Ok(sig.sig)
				}
			} else {
				Err(format!("invalid signature: {}", e))
			}
		}
	}
}

/// Divide a large byte push into at most [n] pushes.
///
/// This method will try make 80-byte pushes if possible and at most 520-byte pushes.
/// It will always push exactly n pushes, that will be empty if needed.
///
/// If [reverse] is true, the pushes will be pushed in reverse order.
///
/// NB: Panics if the size of [push] exceeds 520 * [n].
pub fn divide_witness_pushes(
	witness: &mut Vec<Vec<u8>>,
	n: usize,
	reverse: bool,
	total_push: &[u8],
) {
	const STD_MAX_SIZE: usize = 80;
	const CNS_MAX_SIZE: usize = 520;

	if total_push.len() > n * CNS_MAX_SIZE {
		panic!("tried to push more bytes than space available: {} bytes ({} available)",
			total_push.len(), n * CNS_MAX_SIZE,
		);
	}

	let elem_size = if total_push.len() <= n * STD_MAX_SIZE {
		STD_MAX_SIZE
	} else {
		CNS_MAX_SIZE
	};

	let mut pushes = Vec::with_capacity(n);
	for chunk in total_push.chunks(elem_size) {
		pushes.push(chunk.to_vec());
	}
	assert!(pushes.len() <= n);
	pushes.resize(n, Vec::new());

	if reverse {
		witness.extend(pushes.into_iter().rev());
	} else {
		witness.extend(pushes.into_iter());
	}
}

/// Create a burn output, this is critical as this will be encoded
/// into the covenant script, so it needs to be deterministic.
pub fn burn_output(amount: Amount, asset: AssetId) -> elements::TxOut {
	elements::TxOut {
		value: elements::confidential::Value::Explicit(amount.to_sat()),
		asset: elements::confidential::Asset::Explicit(asset),
		nonce: elements::confidential::Nonce::Null,
		script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
		witness: elements::TxOutWitness::default(),
	}
}

pub trait BuilderExt: Into<Builder> + From<Builder> {
	/// Repeat the same operation a certain number of times.
	fn repeat(self, n: usize, f: impl Fn(Builder) -> Builder) -> Self {
		let mut builder = self.into();
		for _ in 0..n {
			builder = f(builder);
		}
		builder.into()
	}

	/// Check that the top stack item is of the required size.
	fn check_stack_item_size(self, size: i64) -> Self {
		self.into()
			.push_opcode(OP_SIZE)
			.push_int(size)
			.push_opcode(OP_EQUALVERIFY)
			.into()
	}

	/// Add a CLTV-encubered OP_CHECKSIGVERIFY for the given locktime and pubkey.
	fn spend_with_locktime(self, pubkey: &PublicKey, lock_time: elements::LockTime) -> Self {
		self.into()
			.push_int(lock_time.to_consensus_u32() as i64)
			.push_opcode(OP_CLTV)
			.push_opcode(OP_DROP)
			.push_slice(&pubkey.serialize())
			.push_opcode(OP_CHECKSIGVERIFY)
			.into()
	}
}

/// Give the encoded size of the integer when pushed as a stack element.
pub fn scriptint_size(int: i64) -> usize {
	let script = Builder::new()
		.push_int(int)
		.into_script();
	let len = script.encoded_len();
	len - 1
}

impl BuilderExt for Builder {}

pub trait BitcoinEncodableExt: bitcoin::consensus::encode::Encodable {
	fn encoded_len(&self) -> usize {
		let mut counter = ByteCountSink::default();
		self.consensus_encode(&mut counter).unwrap();
		counter.count
	}
}

impl<T: bitcoin::consensus::encode::Encodable + ?Sized> BitcoinEncodableExt for T {}

pub trait ElementsEncodableExt: elements::encode::Encodable {
	fn encoded_len(&self) -> usize {
		let mut counter = ByteCountSink::default();
		self.consensus_encode(&mut counter).unwrap();
		counter.count
	}
}

impl<T: elements::encode::Encodable + ?Sized> ElementsEncodableExt for T {}

#[derive(Default)]
struct ByteCountSink {
	count: usize,
}

impl io::Write for ByteCountSink {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
		let len = buf.len();
		self.count += len;
		Ok(len)
	}
    fn flush(&mut self) -> Result<(), io::Error> {
		Ok(())
	}
}

pub trait ReadExt: io::Read {
	fn take_bytes(&mut self, n: usize) -> Result<Vec<u8>, io::Error> {
		let mut buf = vec![0; n];
		self.read_exact(&mut buf)?;
		Ok(buf)
	}
}
impl<T: AsRef<[u8]>> ReadExt for io::Cursor<T> {}

#[cfg(feature = "serde")]
pub mod serde {
	pub mod locktime_as_int {
		use elements::LockTime;

		pub fn serialize<S: serde::Serializer>(locktime: &LockTime, s: S) -> Result<S::Ok, S::Error> {
			serde::Serialize::serialize(&locktime.to_consensus_u32(), s)
		}

		pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<LockTime, D::Error> {
			let lt: u32 = serde::Deserialize::deserialize(d)?;
			Ok(LockTime::from_consensus(lt))
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use hex_conservative::FromHex;

	#[test]
	fn test_divide_witness_pushes() {
		let total = vec![1, 2, 3];
		let mut witness = vec![];
		divide_witness_pushes(&mut witness, 3, false, &total[..]);
		assert_eq!(witness, vec![vec![1,2,3], vec![], vec![]]);

		let bytes_80 = Vec::<u8>::from_hex("05dcafc73348d3e030357c8c29666e47399930238e7e5d459236da467305a39111cb6f29c93c3c571c9258e5c57dd5e860dd52f6b56dfeb8c9f4dc59f62bf455178c556b2c1d24913f46831ca23028c5").unwrap();

		let mut total = bytes_80.clone();
		total.extend_from_slice(&[1, 2]);
		let mut witness = vec![];
		divide_witness_pushes(&mut witness, 3, false, &total[..]);
		assert_eq!(witness, vec![bytes_80.clone(), vec![1, 2], vec![]]);
	}
}
