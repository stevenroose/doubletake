

use std::io;



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


