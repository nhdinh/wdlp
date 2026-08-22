use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TailReadError {
    Io,
    InvalidText,
}

pub fn read_bounded_tail(
    path: &Path,
    requested_lines: usize,
    max_response_bytes: usize,
) -> Result<String, TailReadError> {
    if requested_lines == 0 || max_response_bytes == 0 {
        return Err(TailReadError::Io);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| TailReadError::Io)?;
    read_bounded_tail_file(&mut file, requested_lines, max_response_bytes)
}

pub fn read_bounded_tail_file(
    file: &mut File,
    requested_lines: usize,
    max_response_bytes: usize,
) -> Result<String, TailReadError> {
    if requested_lines == 0 || max_response_bytes == 0 {
        return Err(TailReadError::Io);
    }

    let length = file.metadata().map_err(|_| TailReadError::Io)?.len();
    let read_start = length.saturating_sub(max_response_bytes as u64);
    let starts_at_line_boundary = if read_start == 0 {
        true
    } else {
        file.seek(SeekFrom::Start(read_start - 1))
            .map_err(|_| TailReadError::Io)?;
        let mut preceding = [0_u8; 1];
        file.read_exact(&mut preceding)
            .map_err(|_| TailReadError::Io)?;
        preceding[0] == b'\n'
    };

    file.seek(SeekFrom::Start(read_start))
        .map_err(|_| TailReadError::Io)?;
    let mut bytes = Vec::with_capacity(length.min(max_response_bytes as u64) as usize);
    file.take(max_response_bytes as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| TailReadError::Io)?;

    if !starts_at_line_boundary {
        let Some(first_newline) = bytes.iter().position(|byte| *byte == b'\n') else {
            return Ok(String::new());
        };
        bytes.drain(..=first_newline);
    }
    let Some(last_newline) = bytes.iter().rposition(|byte| *byte == b'\n') else {
        return Ok(String::new());
    };
    bytes.truncate(last_newline + 1);

    let mut line_count = 0;
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate().rev() {
        if *byte == b'\n' {
            line_count += 1;
            if line_count > requested_lines {
                start = index + 1;
                break;
            }
        }
    }
    if start != 0 {
        bytes.drain(..start);
    }
    String::from_utf8(bytes).map_err(|_| TailReadError::InvalidText)
}
