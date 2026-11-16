//! Chunked STREAM-style blob encryption (XChaCha20-Poly1305).
//!
//! Format: `b"PMB1" || nonce_prefix(19)` then chunks of `ciphertext(len+16)`.
//! Chunk nonce: `prefix(19) || counter u32 BE || last_flag u8`. Every non-final
//! chunk holds exactly `CHUNK` plaintext bytes; the final chunk (last_flag = 1)
//! holds 0..CHUNK bytes and is always emitted by `finish`.
use super::{Key32, fill_random};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub const CHUNK: usize = 65536;
const MAGIC: &[u8; 4] = b"PMB1";
const PREFIX_LEN: usize = 19;
const TAG: usize = 16;
const FULL: usize = CHUNK + TAG;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn nonce(prefix: &[u8; PREFIX_LEN], counter: u32, last: bool) -> XNonce {
    let mut n = [0u8; 24];
    n[..PREFIX_LEN].copy_from_slice(prefix);
    n[PREFIX_LEN..PREFIX_LEN + 4].copy_from_slice(&counter.to_be_bytes());
    n[23] = last as u8;
    XNonce::from(n)
}

fn cipher(key: &Key32) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("32-byte key")
}

pub struct EncryptWriter<W: Write> {
    inner: W,
    cipher: XChaCha20Poly1305,
    aad: Vec<u8>,
    prefix: [u8; PREFIX_LEN],
    counter: u32,
    buf: Zeroizing<Vec<u8>>,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(mut inner: W, key: &Key32, aad: &[u8]) -> io::Result<Self> {
        let mut prefix = [0u8; PREFIX_LEN];
        fill_random(&mut prefix);
        inner.write_all(MAGIC)?;
        inner.write_all(&prefix)?;
        Ok(Self {
            inner,
            cipher: cipher(key),
            aad: aad.to_vec(),
            prefix,
            counter: 0,
            buf: Zeroizing::new(Vec::with_capacity(CHUNK)),
        })
    }

    fn emit(&mut self, last: bool) -> io::Result<()> {
        let ct = self
            .cipher
            .encrypt(
                &nonce(&self.prefix, self.counter, last),
                Payload {
                    msg: &self.buf,
                    aad: &self.aad,
                },
            )
            .map_err(|_| io::Error::other("encryption failed"))?;
        self.inner.write_all(&ct)?;
        self.buf.clear();
        if !last {
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or_else(|| io::Error::other("blob too large"))?;
        }
        Ok(())
    }

    /// Writes the final (possibly empty) chunk and returns the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.emit(true)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let n = data.len().min(CHUNK - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() == CHUNK {
            self.emit(false)?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct DecryptReader<R: Read> {
    inner: R,
    cipher: XChaCha20Poly1305,
    aad: Vec<u8>,
    prefix: [u8; PREFIX_LEN],
    counter: u32,
    lookahead: Option<u8>,
    plain: Zeroizing<Vec<u8>>,
    pos: usize,
    done: bool,
    failed: bool,
}

/// Read until `buf` is full or EOF; returns bytes read.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

impl<R: Read> DecryptReader<R> {
    pub fn new(mut inner: R, key: &Key32, aad: &[u8]) -> io::Result<Self> {
        let mut hdr = [0u8; 4 + PREFIX_LEN];
        if read_full(&mut inner, &mut hdr)? != hdr.len() || &hdr[..4] != MAGIC {
            return Err(invalid("bad blob header"));
        }
        let mut prefix = [0u8; PREFIX_LEN];
        prefix.copy_from_slice(&hdr[4..]);
        Ok(Self {
            inner,
            cipher: cipher(key),
            aad: aad.to_vec(),
            prefix,
            counter: 0,
            lookahead: None,
            plain: Zeroizing::new(Vec::new()),
            pos: 0,
            done: false,
            failed: false,
        })
    }

    /// Reads and authenticates the next chunk into `self.plain`.
    fn next_chunk(&mut self) -> io::Result<()> {
        let mut raw = vec![0u8; FULL];
        let mut n = 0;
        if let Some(b) = self.lookahead.take() {
            raw[0] = b;
            n = 1;
        }
        n += read_full(&mut self.inner, &mut raw[n..])?;
        let last = if n == FULL {
            let mut b = [0u8; 1];
            if read_full(&mut self.inner, &mut b)? == 0 {
                true
            } else {
                self.lookahead = Some(b[0]);
                false
            }
        } else {
            true
        };
        if n < TAG {
            return Err(invalid("truncated blob"));
        }
        let pt = self
            .cipher
            .decrypt(
                &nonce(&self.prefix, self.counter, last),
                Payload {
                    msg: &raw[..n],
                    aad: &self.aad,
                },
            )
            .map_err(|_| invalid("blob authentication failed"))?;
        self.plain = Zeroizing::new(pt);
        self.pos = 0;
        if last {
            self.done = true;
        } else {
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or_else(|| invalid("blob too large"))?;
        }
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(invalid("blob authentication failed"));
        }
        while self.pos >= self.plain.len() {
            if self.done {
                return Ok(0);
            }
            if let Err(e) = self.next_chunk() {
                if e.kind() == io::ErrorKind::InvalidData {
                    self.failed = true;
                }
                return Err(e);
            }
        }
        let n = out.len().min(self.plain.len() - self.pos);
        out[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Key32;
    use std::io::{ErrorKind, Read, Write};

    fn enc(data: &[u8], key: &Key32, aad: &[u8]) -> Vec<u8> {
        let mut w = EncryptWriter::new(Vec::new(), key, aad).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    fn dec(blob: &[u8], key: &Key32, aad: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut r = DecryptReader::new(blob, key, aad)?;
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok(out)
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 % 251) as u8).collect()
    }

    const HDR: usize = 4 + 19;
    const FULL: usize = CHUNK + 16;

    #[test]
    fn roundtrip_sizes() {
        let k = Key32::random();
        for n in [0, 1, 65535, 65536, 65537, 3 * 65536, 200_000] {
            let d = data(n);
            let blob = enc(&d, &k, b"aad");
            assert_eq!(dec(&blob, &k, b"aad").unwrap(), d, "size {n}");
        }
    }

    #[test]
    fn roundtrip_with_small_writes() {
        let k = Key32::random();
        let d = data(150_000);
        let mut w = EncryptWriter::new(Vec::new(), &k, b"a").unwrap();
        for c in d.chunks(777) {
            w.write_all(c).unwrap();
        }
        let blob = w.finish().unwrap();
        assert_eq!(dec(&blob, &k, b"a").unwrap(), d);
    }

    #[test]
    fn truncated_final_chunk_detected() {
        let k = Key32::random();
        let blob = enc(&data(100_000), &k, b"a");
        for cut in [1, 16, 20] {
            let e = dec(&blob[..blob.len() - cut], &k, b"a").unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidData, "cut {cut}");
        }
    }

    #[test]
    fn dropping_whole_last_chunk_detected() {
        let k = Key32::random();
        let blob = enc(&data(CHUNK), &k, b"a");
        assert_eq!(blob.len(), HDR + FULL + 16);
        let e = dec(&blob[..blob.len() - 16], &k, b"a").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn reordered_chunks_detected() {
        let k = Key32::random();
        let mut blob = enc(&data(3 * CHUNK), &k, b"a");
        let (c0, rest) = blob[HDR..].split_at_mut(FULL);
        c0.swap_with_slice(&mut rest[..FULL]);
        let e = dec(&blob, &k, b"a").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn wrong_aad_detected() {
        let k = Key32::random();
        let blob = enc(b"hello", &k, b"a");
        assert_eq!(
            dec(&blob, &k, b"b").unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn wrong_key_detected() {
        let blob = enc(b"hello", &Key32::random(), b"a");
        assert_eq!(
            dec(&blob, &Key32::random(), b"a").unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn bad_magic_rejected() {
        let k = Key32::random();
        let mut blob = enc(b"hello", &k, b"a");
        blob[0] = b'X';
        let e = dec(&blob, &k, b"a").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
        assert_eq!(
            dec(b"PM", &k, b"a").unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn no_plaintext_released_before_tag_verifies() {
        let k = Key32::random();
        let mut blob = enc(&data(CHUNK + 100), &k, b"a");
        blob[HDR + 5] ^= 1; // corrupt first chunk
        let mut r = DecryptReader::new(&blob[..], &k, b"a").unwrap();
        let mut buf = [0u8; 10];
        assert_eq!(r.read(&mut buf).unwrap_err().kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn reader_stays_failed_after_auth_error() {
        let k = Key32::random();
        let mut blob = enc(&data(3 * CHUNK), &k, b"a");
        blob[HDR + 5] ^= 1;
        let mut r = DecryptReader::new(&blob[..], &k, b"a").unwrap();
        let mut buf = [0u8; 10];
        for _ in 0..3 {
            assert_eq!(r.read(&mut buf).unwrap_err().kind(), ErrorKind::InvalidData);
        }
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let k = Key32::random();
        let d = b"SECRET-MARKER-SECRET-MARKER".repeat(100);
        let blob = enc(&d, &k, b"a");
        assert!(!blob.windows(13).any(|w| w == b"SECRET-MARKER"));
        assert_eq!(&blob[..4], b"PMB1");
    }
}
