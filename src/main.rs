use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use encoding_rs::SHIFT_JIS;
use miniz_oxide::inflate::{decompress_to_vec, TINFLStatus};
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

#[derive(Debug)]
enum MyError {
    NoFilenameArgument(String),
    MissingFile(String),
    MissingFileHeader,
    IO(std::io::Error),
    UnzipError(TINFLStatus),
    ZipError(zip::result::ZipError),
    InvalidKeyIvLength(block_modes::InvalidKeyIvLength),
    BlockModeError(block_modes::BlockModeError),
}

impl From<std::io::Error> for MyError {
    fn from(error: std::io::Error) -> MyError {
        MyError::IO(error)
    }
}

impl From<block_modes::InvalidKeyIvLength> for MyError {
    fn from(error: block_modes::InvalidKeyIvLength) -> MyError {
        MyError::InvalidKeyIvLength(error)
    }
}

impl From<block_modes::BlockModeError> for MyError {
    fn from(error: block_modes::BlockModeError) -> MyError {
        MyError::BlockModeError(error)
    }
}

impl From<TINFLStatus> for MyError {
    fn from(error: TINFLStatus) -> MyError {
        MyError::UnzipError(error)
    }
}

impl From<zip::result::ZipError> for MyError {
    fn from(error: zip::result::ZipError) -> MyError {
        MyError::ZipError(error)
    }
}

const EXPECTED_HEADER: [u8; 4] = *b"NPK2";

const KEY: [u8; 32] = [
    208, 183, 31, 60, 78, 36, 206, 207, 221, 238, 169, 29, 36, 176, 64, 50, 41, 163, 229, 51, 13,
    41, 81, 130, 96, 81, 214, 201, 74, 245, 175, 84,
];

struct ArchiveMeta {
    key: [u8; 32],
    iv: [u8; 16],
}

struct Segment {
    offset: u64,
    size_aligned: usize,
    size_comp: usize,
    size_orig: usize,
}

struct ArchiveEntry {
    segments: Vec<Segment>,
    path: String,
}
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn decrypt(input: &[u8], meta: &ArchiveMeta) -> Result<Vec<u8>, MyError> {
    let cipher = Aes256Cbc::new_var(&meta.key, &meta.iv)?;
    let mut buf = input.to_vec();
    Ok(cipher.decrypt(&mut buf)?.to_vec())
}

fn get_file() -> Result<(PathBuf, BufReader<File>), MyError> {
    let mut args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        return Err(MyError::NoFilenameArgument(
            "Pass filename as argument.".to_string(),
        ));
    }

    let filename = args.pop().unwrap();
    let filepath = std::path::Path::new(&filename);
    if !filepath.exists() {
        return Err(MyError::MissingFile(filename));
    }

    Ok((
        filepath.to_path_buf(),
        BufReader::new(File::open(filepath)?),
    ))
}

fn extract_encrypted_archive(
    file: &mut BufReader<File>,
) -> Result<Vec<(String, Vec<u8>)>, MyError> {
    verify_file(file)?;

    let (metadata, archive_entries) = decrypt_meta_data(file)?;
    let mut files = Vec::with_capacity(archive_entries.len());

    println!("Decoding files...");
    for entry in archive_entries {
        let file_contents = decrypt_file_data(file, &entry, &metadata)?;
        files.push((entry.path, file_contents));
    }

    Ok(files)
}

fn verify_file(file: &mut BufReader<File>) -> Result<(), MyError> {
    file.seek(SeekFrom::Start(0))?;

    let mut header_buffer = vec![0; EXPECTED_HEADER.len()];
    file.read_exact(&mut header_buffer)?;

    if header_buffer != EXPECTED_HEADER {
        return Err(MyError::MissingFileHeader);
    }

    Ok(())
}

fn decrypt_meta_data(
    file: &mut BufReader<File>,
) -> Result<(ArchiveMeta, Vec<ArchiveEntry>), MyError> {
    let mut buffer16 = [0; 2];
    let mut buffer32 = [0; 4];
    let mut buffer64 = [0; 8];
    let mut iv = [0; 16];

    file.seek(SeekFrom::Start(8))?;

    file.read_exact(&mut iv)?;
    let meta = ArchiveMeta { iv, key: KEY };

    file.read_exact(&mut buffer32)?;
    let file_count: u32 = u32::from_le_bytes(buffer32);

    println!("Found {} files inside.", file_count);

    file.read_exact(&mut buffer32)?;
    let table_size: u32 = u32::from_le_bytes(buffer32);

    let mut buffer = Vec::new();
    buffer.resize(table_size.try_into().unwrap(), 0);
    file.read_exact(&mut buffer)?;
    let mut decrypted_table = Cursor::new(decrypt(&buffer, &meta)?);

    decrypted_table.seek(SeekFrom::Start(0))?;
    let mut entries: Vec<ArchiveEntry> = Vec::with_capacity(file_count.try_into().unwrap());
    for _ in 0..file_count {
        decrypted_table.seek(SeekFrom::Current(1))?;

        decrypted_table.read_exact(&mut buffer16)?;
        let path_size = u16::from_le_bytes(buffer16);
        let path_size = usize::try_from(path_size).unwrap();

        buffer.resize(path_size, 0);
        decrypted_table.read_exact(&mut buffer)?;

        let path = {
            let (res, _enc, failed) = SHIFT_JIS.decode(&buffer);
            if failed {
                if let Ok(res) = std::str::from_utf8(&buffer) {
                    res.to_string()
                } else {
                    panic!("Failed to decode file path: {:?}", buffer);
                }
            } else {
                res.to_string()
            }
        };
        decrypted_table.seek(SeekFrom::Current(36))?;

        decrypted_table.read_exact(&mut buffer32)?;
        let segment_count: u32 = u32::from_le_bytes(buffer32);

        let mut segments = Vec::with_capacity(segment_count.try_into().unwrap());
        for _ in 0..segment_count {
            decrypted_table.read_exact(&mut buffer64)?;
            let offset = u64::from_le_bytes(buffer64);

            decrypted_table.read_exact(&mut buffer32)?;
            let size_aligned = u32::from_le_bytes(buffer32).try_into().unwrap();

            decrypted_table.read_exact(&mut buffer32)?;
            let size_comp = u32::from_le_bytes(buffer32).try_into().unwrap();

            decrypted_table.read_exact(&mut buffer32)?;
            let size_orig = u32::from_le_bytes(buffer32).try_into().unwrap();

            segments.push(Segment {
                offset,
                size_aligned,
                size_comp,
                size_orig,
            })
        }
        assert_eq!(segment_count, segments.len().try_into().unwrap());
        entries.push(ArchiveEntry { path, segments });
    }
    assert_eq!(file_count, entries.len().try_into().unwrap());

    Ok((meta, entries))
}

fn decrypt_file_data(
    file: &mut BufReader<File>,
    entry: &ArchiveEntry,
    metadata: &ArchiveMeta,
) -> Result<Vec<u8>, MyError> {
    let mut file_contents = Vec::with_capacity(100_000);
    let mut buffer = vec![0; 20_000];
    for segment in &entry.segments {
        file.seek(SeekFrom::Start(segment.offset))?;
        buffer.resize(segment.size_aligned, 0);
        file.read_exact(&mut buffer)?;
        let mut segment_data = {
            if segment.size_orig > segment.size_comp {
                decompress_to_vec(decrypt(&buffer, metadata)?.as_slice())?
            } else {
                decrypt(&buffer, metadata)?
            }
        };
        file_contents.append(&mut segment_data);
    }
    Ok(file_contents)
}

fn write_files_to_archive(
    archive_name: PathBuf,
    files: Vec<(String, Vec<u8>)>,
) -> Result<(), MyError> {
    if archive_name.exists() {
        println!(
            "Archive '{}' already exists - quitting.",
            archive_name.to_string_lossy()
        );
        return Ok(());
    }

    let mut zip_file = zip::ZipWriter::new(File::create(&archive_name)?);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

    println!(
        "Writing {} files to '{}'...",
        files.len(),
        archive_name.to_string_lossy()
    );

    for (file_name, file_contents) in files {
        zip_file.start_file(file_name, options)?;
        zip_file.write_all(&file_contents)?;
    }
    zip_file.finish()?;

    Ok(())
}

fn main() -> Result<(), MyError> {
    let (filepath, mut file) = get_file()?;

    println!("Starting to work on '{}'...", filepath.to_string_lossy());
    let decrypted_files = extract_encrypted_archive(&mut file)?;

    let archive_name = {
        let mut temp = PathBuf::new();
        temp.set_file_name(filepath.file_stem().unwrap());
        temp.set_extension("zip");
        temp
    };
    write_files_to_archive(archive_name, decrypted_files)?;
    println!("Successfully finished.");

    Ok(())
}
