use aes::{
	cipher::generic_array::{typenum, GenericArray},
	Aes128,
};
use async_std::io::{self, Stdin};
use block_modes::{block_padding::NoPadding, BlockMode, Cbc};
use futures::executor::block_on;
use num_cpus;
use rayon::prelude::*;
use std::{
	env,
	fs::File,
	io::{BufReader, Read},
};

type Aes128Cbc = Cbc<Aes128, NoPadding>;

fn main() -> io::Result<()> {
	// Handle program arguments
	let args: Vec<String> = env::args().collect();
	if args.len() < 3 {
		println!("args: <file_path> <known_plaintext (hex)> [<iv = 0x00 * 16> <num_threads = 4> <output_bad_attempts = false>]");
		return Ok(());
	}
	let file_path = &args[1];
	let known_plaintext = parse_hex(&args[2]);
	let iv = if args.len() >= 4 {
		parse_16_hex(&args[3])
	} else {
		[0u8; 16]
	};
	let cpu_threads = num_cpus::get();
	let mut num_threads = if args.len() >= 5 {
		args[4].parse::<usize>().unwrap()
	} else {
		4
	};
	if cpu_threads < num_threads {
		num_threads = cpu_threads;
	}
	let output_bad_attempts =
		args.len() >= 6 && args[5].to_lowercase().chars().next().unwrap() == 't';

	// Set maximum threads to use
	rayon::ThreadPoolBuilder::new()
		.num_threads(num_threads)
		.build_global()
		.unwrap();

	// Read the file into blocks in memory
	let file = File::open(file_path).expect("File not found.");
	let mut reader = BufReader::new(file);
	let mut file_blocks = Vec::new();
	let mut buffer = [0u8; 16]; // 16 is block size for 128-bit AES
	while reader
		.read(&mut buffer)
		.expect("Encountered an error reading the file.")
		> 0
	{
		file_blocks.push(GenericArray::<u8, typenum::U16>::from(buffer));
		buffer = [0u8; 16];
	}

	// Start checking keys from stdin
	Keys { buf: io::stdin() }
		.par_bridge()
		.find_any(|line| -> bool {
			match line {
				Ok(key) => {
					let res = check_key(&parse_16_hex(key), &iv, &file_blocks, &known_plaintext);
					if res {
						println!("Found: {}", key);
					} else if output_bad_attempts {
						println!("Nope:  {}", key);
					}
					res
				}
				_ => false,
			}
		});

	Ok(())
}

fn check_key(
	key: &[u8; 16],
	iv: &[u8; 16],
	file_blocks: &Vec<GenericArray<u8, typenum::U16>>,
	known_plaintext: &Vec<u8>,
) -> bool {
	let cipher = Aes128Cbc::new_var(key, iv).unwrap();
	let mut block = file_blocks[0].clone();
	cipher
		.decrypt(&mut block)
		.expect("An error occurred while decrypting the first block.");
	let mut i = 0;
	for b in known_plaintext {
		if *b != block[i] {
			return false;
		}
		i += 1;
	}

	true
}

// Stdin Lines implementation
pub struct Keys {
	buf: Stdin,
}

impl Keys {
	async fn async_next(&mut self) -> Option<io::Result<String>> {
		let mut buf = String::new();

		match self.buf.read_line(&mut buf).await {
			Ok(0) => None,
			Ok(_n) => {
				if buf.ends_with('\n') {
					buf.pop();
					if buf.ends_with('\r') {
						buf.pop();
					}
				}
				Some(Ok(buf))
			}
			Err(e) => Some(Err(e)),
		}
	}
}

impl Iterator for Keys {
	type Item = io::Result<String>;

	fn next(&mut self) -> Option<io::Result<String>> {
		block_on(self.async_next())
	}
}

// Written by Jake Goulding
// https://codereview.stackexchange.com/a/201699
fn parse_hex(hex_asm: &str) -> Vec<u8> {
	let mut hex_bytes = hex_asm
		.as_bytes()
		.iter()
		.filter_map(|b| match b {
			b'0'..=b'9' => Some(b - b'0'),
			b'a'..=b'f' => Some(b - b'a' + 10),
			b'A'..=b'F' => Some(b - b'A' + 10),
			_ => None,
		})
		.fuse();

	let mut bytes = Vec::new();
	while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
		bytes.push(h << 4 | l)
	}
	bytes
}

fn parse_16_hex(hex_asm: &str) -> [u8; 16] {
	let mut hex_bytes = hex_asm
		.as_bytes()
		.iter()
		.filter_map(|b| match b {
			b'0'..=b'9' => Some(b - b'0'),
			b'a'..=b'f' => Some(b - b'a' + 10),
			b'A'..=b'F' => Some(b - b'A' + 10),
			_ => None,
		})
		.fuse();

	let mut bytes = [0u8; 16];
	let mut i = 0;
	while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
		bytes[i] = h << 4 | l;
		i += 1;
	}
	bytes
}
