//! A minimal PDF writer: one JPEG per page, embedded unchanged with
//! `DCTDecode`. No image decoding happens here; only the JPEG's frame header
//! is read for the size and the number of colour components.

use std::fmt;

/// Resolution assumed for the page size: a page is the image at 300 dpi.
const DPI: f64 = 300.0;

#[derive(Debug, PartialEq, Eq)]
pub enum PdfError {
    /// No pages were given.
    NoPages,
    /// Page `n` (1-based) is a PNG, which the writer does not embed.
    Png(usize),
    /// Page `n` does not start like a JPEG file.
    NotJpeg(usize),
    /// Page `n` ends before the image data does, or its headers are cut off.
    Truncated(usize),
    /// Page `n` is a JPEG this writer cannot embed (CMYK, 12 bit, lossless, ...).
    Unsupported(usize, &'static str),
}

impl fmt::Display for PdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdfError::NoPages => write!(f, "no pages"),
            PdfError::Png(n) => write!(f, "page {n} is a PNG image; scan pages must be JPEG"),
            PdfError::NotJpeg(n) => write!(f, "page {n} is not a JPEG image"),
            PdfError::Truncated(n) => write!(f, "page {n} is a damaged or incomplete JPEG image"),
            PdfError::Unsupported(n, why) => write!(f, "page {n}: unsupported JPEG ({why})"),
        }
    }
}

impl std::error::Error for PdfError {}

struct Jpeg<'a> {
    data: &'a [u8],
    width: u32,
    height: u32,
    components: u8,
}

/// Reads the JPEG's frame header (SOF0, SOF1 or SOF2).
fn parse_jpeg(n: usize, data: &[u8]) -> Result<Jpeg<'_>, PdfError> {
    if data.starts_with(b"\x89PNG") {
        return Err(PdfError::Png(n));
    }
    if !data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Err(PdfError::NotJpeg(n));
    }
    // A complete file ends with EOI (some encoders pad with zero bytes).
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    if end < 4 || data[end - 2..end] != [0xFF, 0xD9] {
        return Err(PdfError::Truncated(n));
    }
    let mut i = 2;
    loop {
        // Skip to the next marker (fill bytes are allowed before it).
        while data.get(i) == Some(&0xFF) && data.get(i + 1) == Some(&0xFF) {
            i += 1;
        }
        if data.get(i) != Some(&0xFF) {
            return Err(PdfError::Truncated(n));
        }
        let marker = *data.get(i + 1).ok_or(PdfError::Truncated(n))?;
        i += 2;
        match marker {
            // Markers without a length.
            0x01 | 0xD0..=0xD8 => continue,
            // End of image or start of scan before any frame header.
            0xD9 | 0xDA => return Err(PdfError::Truncated(n)),
            _ => {}
        }
        let len = data
            .get(i..i + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
            .ok_or(PdfError::Truncated(n))?;
        if len < 2 || i + len > data.len() {
            return Err(PdfError::Truncated(n));
        }
        match marker {
            0xC0..=0xC2 => {
                let seg = &data[i + 2..i + len];
                if seg.len() < 6 {
                    return Err(PdfError::Truncated(n));
                }
                if seg[0] != 8 {
                    return Err(PdfError::Unsupported(n, "not 8 bits per sample"));
                }
                let height = u32::from(u16::from_be_bytes([seg[1], seg[2]]));
                let width = u32::from(u16::from_be_bytes([seg[3], seg[4]]));
                let components = seg[5];
                if width == 0 || height == 0 {
                    return Err(PdfError::Unsupported(n, "no dimensions"));
                }
                if components != 1 && components != 3 {
                    return Err(PdfError::Unsupported(n, "only grayscale and RGB"));
                }
                return Ok(Jpeg {
                    data,
                    width,
                    height,
                    components,
                });
            }
            // Other frame types: lossless, arithmetic coded, hierarchical.
            0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                return Err(PdfError::Unsupported(n, "unsupported JPEG encoding"));
            }
            _ => i += len,
        }
    }
}

fn points(px: u32) -> String {
    let p = f64::from(px) * 72.0 / DPI;
    let s = format!("{p:.2}");
    s.trim_end_matches('0').trim_end_matches('.').to_owned()
}

/// One PDF with one page per JPEG, in order. Each page is the image size at
/// 300 dpi and the image fills it.
pub fn jpegs_to_pdf(pages: &[&[u8]]) -> Result<Vec<u8>, PdfError> {
    if pages.is_empty() {
        return Err(PdfError::NoPages);
    }
    let jpegs = pages
        .iter()
        .enumerate()
        .map(|(i, p)| parse_jpeg(i + 1, p))
        .collect::<Result<Vec<_>, _>>()?;

    // Objects: 1 catalog, 2 page tree, then page / content / image per page.
    let mut out: Vec<u8> = Vec::with_capacity(pages.iter().map(|p| p.len()).sum::<usize>() + 1024);
    let mut offsets: Vec<usize> = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut obj = |out: &mut Vec<u8>, body: &[u8]| {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", offsets.len()).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    };

    obj(&mut out, b"<< /Type /Catalog /Pages 2 0 R >>");
    let kids = (0..jpegs.len())
        .map(|i| format!("{} 0 R", 3 + 3 * i))
        .collect::<Vec<_>>()
        .join(" ");
    obj(
        &mut out,
        format!("<< /Type /Pages /Kids [{kids}] /Count {} >>", jpegs.len()).as_bytes(),
    );
    for (i, j) in jpegs.iter().enumerate() {
        let page_obj = 3 + 3 * i;
        let (w, h) = (points(j.width), points(j.height));
        obj(
            &mut out,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w} {h}] \
                 /Resources << /XObject << /Im0 {} 0 R >> >> /Contents {} 0 R >>",
                page_obj + 2,
                page_obj + 1
            )
            .as_bytes(),
        );
        let content = format!("q {w} 0 0 {h} 0 0 cm /Im0 Do Q");
        obj(
            &mut out,
            format!(
                "<< /Length {} >>\nstream\n{content}\nendstream",
                content.len()
            )
            .as_bytes(),
        );
        let space = if j.components == 1 {
            "/DeviceGray"
        } else {
            "/DeviceRGB"
        };
        let mut image = format!(
            "<< /Type /XObject /Subtype /Image /Width {} /Height {} /ColorSpace {space} \
             /BitsPerComponent 8 /Filter /DCTDecode /Length {} >>\nstream\n",
            j.width,
            j.height,
            j.data.len()
        )
        .into_bytes();
        image.extend_from_slice(j.data);
        image.extend_from_slice(b"\nendstream");
        obj(&mut out, &image);
    }

    let xref = out.len();
    let count = offsets.len() + 1;
    out.extend_from_slice(format!("xref\n0 {count}\n0000000000 65535 f \n").as_bytes());
    for off in &offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    const GRAY: &[u8] = include_bytes!("../tests/fixtures/scan1.jpg");
    const RGB: &[u8] = include_bytes!("../tests/fixtures/scan2.jpg");
    const PNG: &[u8] = include_bytes!("../tests/fixtures/scan.png");

    fn pdfinfo(pdf: &[u8]) -> Option<String> {
        let mut child = Command::new("pdfinfo")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        child.stdin.take().unwrap().write_all(pdf).ok()?;
        let out = child.wait_with_output().ok()?;
        assert!(
            out.status.success(),
            "pdfinfo: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    #[test]
    fn parses_gray_and_rgb_headers() {
        let g = parse_jpeg(1, GRAY).unwrap();
        assert_eq!((g.width, g.height, g.components), (1400, 220, 1));
        let c = parse_jpeg(1, RGB).unwrap();
        assert_eq!((c.width, c.height, c.components), (1400, 220, 3));
    }

    #[test]
    fn single_page_pdf_is_valid() {
        let pdf = jpegs_to_pdf(&[RGB]).unwrap();
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        if let Some(info) = pdfinfo(&pdf) {
            assert!(info.contains("Pages:           1"), "{info}");
            // 1400x220 px at 300 dpi.
            assert!(info.contains("336 x 52.8 pts"), "{info}");
        }
    }

    #[test]
    fn xref_offsets_point_at_objects() {
        let pdf = jpegs_to_pdf(&[GRAY, RGB, GRAY]).unwrap();
        let tail = String::from_utf8_lossy(&pdf[pdf.len() - 300..]).into_owned();
        let start: usize = tail
            .rsplit("startxref\n")
            .next()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(&pdf[start..start + 4], b"xref");
        // Header lines, the free entry, then objects 1..=11.
        let table = String::from_utf8_lossy(&pdf[start..]).into_owned();
        let entries: Vec<&str> = table.lines().skip(3).take(11).collect();
        assert_eq!(entries.len(), 11);
        for (n, line) in entries.iter().enumerate() {
            let off: usize = line[..10].parse().unwrap();
            assert!(
                pdf[off..].starts_with(format!("{} 0 obj", n + 1).as_bytes()),
                "object {}",
                n + 1
            );
        }
    }

    #[test]
    fn multi_page_pdf_has_all_pages() {
        let pdf = jpegs_to_pdf(&[GRAY, RGB, GRAY]).unwrap();
        if let Some(info) = pdfinfo(&pdf) {
            assert!(info.contains("Pages:           3"), "{info}");
        } else {
            assert!(String::from_utf8_lossy(&pdf).contains("/Count 3"));
        }
    }

    #[test]
    fn grayscale_uses_device_gray() {
        let pdf = String::from_utf8_lossy(&jpegs_to_pdf(&[GRAY]).unwrap()).into_owned();
        assert!(pdf.contains("/DeviceGray"));
        assert!(!pdf.contains("/DeviceRGB"));
    }

    #[test]
    fn jpeg_is_embedded_unchanged() {
        let pdf = jpegs_to_pdf(&[RGB]).unwrap();
        assert!(pdf.windows(RGB.len()).any(|w| w == RGB));
    }

    #[test]
    fn rejects_png_and_garbage() {
        assert_eq!(jpegs_to_pdf(&[PNG]), Err(PdfError::Png(1)));
        assert_eq!(jpegs_to_pdf(&[GRAY, b"hello"]), Err(PdfError::NotJpeg(2)));
        assert_eq!(jpegs_to_pdf(&[]), Err(PdfError::NoPages));
        assert_eq!(jpegs_to_pdf(&[b""]), Err(PdfError::NotJpeg(1)));
    }

    #[test]
    fn rejects_truncated_jpeg() {
        assert_eq!(
            jpegs_to_pdf(&[&RGB[..RGB.len() / 2]]),
            Err(PdfError::Truncated(1))
        );
        // Cut inside the headers.
        assert_eq!(jpegs_to_pdf(&[&RGB[..20]]), Err(PdfError::Truncated(1)));
    }

    #[test]
    fn rejects_cmyk() {
        let mut cmyk = RGB.to_vec();
        let sof = cmyk.windows(2).position(|w| w == [0xFF, 0xC0]).unwrap();
        cmyk[sof + 9] = 4; // component count
        assert!(matches!(
            jpegs_to_pdf(&[&cmyk]),
            Err(PdfError::Unsupported(1, _))
        ));
    }
}
