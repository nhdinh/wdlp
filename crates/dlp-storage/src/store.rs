use crate::{
    CHUNK_SIZE, CapturedStoreIdentity, StorageError, StoreKey, VirtualPath,
    format::{CommitRecordV1, EncryptedManifestV1, EncryptedRecordV1, FORMAT_VERSION_V1},
};
use dlp_crypto::{NonceTracker, RecordAad, RecordCipher, RecordKind};
use dlp_domain::FileId;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_FILE: AtomicU64 = AtomicU64::new(1);
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DurabilityTrace {
    steps: Vec<&'static str>,
}
impl DurabilityTrace {
    fn record(&mut self, step: &'static str) {
        self.steps.push(step);
    }
    pub fn is_durably_published(&self) -> bool {
        let expected = [
            "chunk-flush",
            "manifest-flush",
            "commit-flush",
            "pointer-publish",
            "directory-flush",
        ];
        let mut position = 0;
        for step in &self.steps {
            if position < expected.len() && *step == expected[position] {
                position += 1;
            }
        }
        position == expected.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitOutcome {
    pub generation: u64,
    pub chunk_count: usize,
    pub nonces: Vec<[u8; 12]>,
    pub trace: DurabilityTrace,
}

/// A portable, SID-bound encrypted store. Backing paths use only captured opaque IDs.
pub struct LocalEncryptedStore {
    root: PathBuf,
    identity: CapturedStoreIdentity,
    key: StoreKey,
    staged: BTreeMap<String, Vec<u8>>,
    forced_duplicate: BTreeSet<String>,
    directories: BTreeMap<String, String>,
    files: BTreeMap<String, FileEntry>,
    handles: BTreeMap<u64, HandleState>,
    fail_next_write: bool,
}

#[derive(Clone)]
struct FileEntry {
    file_id: FileId,
    display: String,
    delete_pending: bool,
}
struct HandleState {
    path_key: String,
    allow_delete: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileHandle(u64);

impl LocalEncryptedStore {
    pub fn open(
        root: impl Into<PathBuf>,
        identity: CapturedStoreIdentity,
        key: StoreKey,
    ) -> Result<Self, StorageError> {
        let root = root.into();
        fs::create_dir_all(
            root.join("stores")
                .join(identity.store_id().to_wire())
                .join("files"),
        )
        .map_err(map_io)?;
        Ok(Self {
            root,
            identity,
            key,
            staged: BTreeMap::new(),
            forced_duplicate: BTreeSet::new(),
            directories: BTreeMap::new(),
            files: BTreeMap::new(),
            handles: BTreeMap::new(),
            fail_next_write: false,
        })
    }
    pub fn reopen(&self) -> Result<Self, StorageError> {
        Self::open(self.root.clone(), self.identity.clone(), self.key.clone())
    }
    pub fn write(&mut self, file: &FileId, bytes: &[u8]) -> Result<(), StorageError> {
        self.staged
            .insert(file.to_wire().to_owned(), bytes.to_vec());
        Ok(())
    }
    pub fn write_at(
        &mut self,
        file: &FileId,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let existing = self.read(file).unwrap_or_default();
        let entry = self
            .staged
            .entry(file.to_wire().to_owned())
            .or_insert(existing);
        let end = offset
            .checked_add(bytes.len())
            .ok_or(StorageError::IoFailure)?;
        if end > entry.len() {
            entry.resize(end, 0);
        }
        entry[offset..end].copy_from_slice(bytes);
        Ok(())
    }
    pub fn flush_file(&mut self, file: &FileId) -> Result<CommitOutcome, StorageError> {
        if self.fail_next_write {
            self.fail_next_write = false;
            return Err(StorageError::IoFailure);
        }
        let data = self
            .staged
            .get(file.to_wire())
            .ok_or(StorageError::NotFound)?
            .clone();
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        let cipher = RecordCipher::from_store_key(&self.key);
        let mut trace = DurabilityTrace::default();
        let mut nonces = NonceTracker::default();
        let mut nonce_list = Vec::new();
        let generation_dir = self.generation_dir(file, generation);
        fs::create_dir_all(&generation_dir).map_err(map_io)?;
        let mut lengths = Vec::new();
        let mut chunk_count = 0;
        for (index, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            let aad = self.aad(
                file,
                generation,
                RecordKind::Chunk,
                index as u64,
                chunk.len(),
            );
            let record = self.seal(&cipher, &mut nonces, file, aad, chunk)?;
            nonce_list.push(record.nonce);
            self.write_record(
                &generation_dir.join(format!("chunk-{index:08}.rec")),
                &record,
            )?;
            trace.record("chunk-flush");
            lengths.push(chunk.len() as u64);
            chunk_count += 1;
        }
        if data.is_empty() {
            chunk_count = 0;
        }
        // Even an empty logical file reaches the staged-record durability boundary.
        if !trace.steps.contains(&"chunk-flush") {
            trace.record("chunk-flush");
        }
        let manifest = EncryptedManifestV1 {
            generation,
            file_id: file.to_wire().to_owned(),
            logical_length: data.len() as u64,
            chunk_lengths: lengths,
        };
        let manifest_bytes = manifest.encode()?;
        let manifest_aad = self.aad(
            file,
            generation,
            RecordKind::Manifest,
            0,
            manifest_bytes.len(),
        );
        let manifest_record =
            self.seal(&cipher, &mut nonces, file, manifest_aad, &manifest_bytes)?;
        nonce_list.push(manifest_record.nonce);
        self.write_record(&generation_dir.join("manifest.rec"), &manifest_record)?;
        trace.record("manifest-flush");
        let commit = CommitRecordV1 {
            generation,
            file_id: file.to_wire().to_owned(),
        };
        let commit_bytes = commit.encode()?;
        let commit_aad = self.aad(file, generation, RecordKind::Commit, 0, commit_bytes.len());
        let commit_record = self.seal(&cipher, &mut nonces, file, commit_aad, &commit_bytes)?;
        nonce_list.push(commit_record.nonce);
        let staged_commit = generation_dir.join("commit.rec");
        self.write_record(&staged_commit, &commit_record)?;
        trace.record("commit-flush");
        let selected_tmp = self
            .file_dir(file)
            .join(format!("selected-{generation}.tmp"));
        self.write_record(&selected_tmp, &commit_record)?;
        let selected = self.file_dir(file).join("selected.commit");
        if selected.exists() {
            fs::remove_file(&selected).map_err(map_io)?;
        }
        fs::rename(&selected_tmp, &selected).map_err(map_io)?;
        trace.record("pointer-publish");
        self.flush_directory_marker(&self.file_dir(file))?;
        trace.record("directory-flush");
        self.staged.remove(file.to_wire());
        Ok(CommitOutcome {
            generation,
            chunk_count,
            nonces: nonce_list,
            trace,
        })
    }
    pub fn read(&self, file: &FileId) -> Result<Vec<u8>, StorageError> {
        let cipher = RecordCipher::from_store_key(&self.key);
        let selected = self.read_record(&self.file_dir(file).join("selected.commit"))?;
        self.ensure_identity(&selected, file, RecordKind::Commit, 0)?;
        let commit = CommitRecordV1::decode(&selected.open(&cipher)?)?;
        if commit.file_id != file.to_wire() {
            return Err(StorageError::IntegrityFailure);
        }
        let generation_dir = self.generation_dir(file, commit.generation);
        let manifest_record = self.read_record(&generation_dir.join("manifest.rec"))?;
        self.ensure_identity(&manifest_record, file, RecordKind::Manifest, 0)?;
        if manifest_record.generation != commit.generation {
            return Err(StorageError::IntegrityFailure);
        }
        let manifest = EncryptedManifestV1::decode(&manifest_record.open(&cipher)?)?;
        if manifest.file_id != file.to_wire() || manifest.generation != commit.generation {
            return Err(StorageError::IntegrityFailure);
        }
        let mut nonces = NonceTracker::default();
        nonces
            .insert(selected.nonce)
            .map_err(|_| StorageError::IntegrityFailure)?;
        nonces
            .insert(manifest_record.nonce)
            .map_err(|_| StorageError::IntegrityFailure)?;
        let mut out = Vec::with_capacity(manifest.logical_length as usize);
        for (index, length) in manifest.chunk_lengths.iter().enumerate() {
            if *length > CHUNK_SIZE as u64 {
                return Err(StorageError::IntegrityFailure);
            }
            let record = self.read_record(&generation_dir.join(format!("chunk-{index:08}.rec")))?;
            self.ensure_identity(&record, file, RecordKind::Chunk, index as u64)?;
            if record.generation != commit.generation || record.plaintext_length != *length {
                return Err(StorageError::IntegrityFailure);
            }
            nonces
                .insert(record.nonce)
                .map_err(|_| StorageError::IntegrityFailure)?;
            out.extend_from_slice(&record.open(&cipher)?);
        }
        if out.len() as u64 != manifest.logical_length {
            return Err(StorageError::IntegrityFailure);
        }
        Ok(out)
    }
    pub fn inject_duplicate_nonce_for_test(&mut self, file: &FileId) {
        self.forced_duplicate.insert(file.to_wire().to_owned());
    }
    pub fn inject_write_failure_for_test(&mut self) {
        self.fail_next_write = true;
    }
    pub fn identity(&self) -> &CapturedStoreIdentity {
        &self.identity
    }
    pub fn create_directory(&mut self, path: &VirtualPath) -> Result<(), StorageError> {
        if self.files.contains_key(path.lookup_key())
            || self.directories.contains_key(path.lookup_key())
        {
            return Err(StorageError::AlreadyExists);
        }
        self.require_parent(path)?;
        self.directories.insert(
            path.lookup_key().to_owned(),
            path.display_name().unwrap_or_default().to_owned(),
        );
        Ok(())
    }
    pub fn read_directory(&self, path: &VirtualPath) -> Result<Vec<String>, StorageError> {
        if !self.is_directory(path) {
            return Err(StorageError::NotFound);
        }
        let prefix = if path.lookup_key().is_empty() {
            String::new()
        } else {
            format!("{}/", path.lookup_key())
        };
        let mut entries = Vec::new();
        for (key, display) in &self.directories {
            if direct_child(key, &prefix) {
                entries.push(display.clone());
            }
        }
        for (key, entry) in &self.files {
            if !entry.delete_pending && direct_child(key, &prefix) {
                entries.push(entry.display.clone());
            }
        }
        entries.sort_by_key(|value| value.to_ascii_lowercase());
        Ok(entries)
    }
    pub fn create_or_open(
        &mut self,
        path: &VirtualPath,
        create: bool,
        allow_delete: bool,
    ) -> Result<FileHandle, StorageError> {
        let key = path.lookup_key().to_owned();
        if let Some(entry) = self.files.get(&key) {
            if entry.delete_pending {
                return Err(StorageError::DeletePending);
            }
        } else {
            if !create {
                return Err(StorageError::NotFound);
            }
            self.require_parent(path)?;
            let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let file_id =
                FileId::parse(format!("file-{id:020}")).map_err(|_| StorageError::IoFailure)?;
            self.files.insert(
                key.clone(),
                FileEntry {
                    file_id,
                    display: path.display_name().unwrap_or_default().to_owned(),
                    delete_pending: false,
                },
            );
        }
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        self.handles.insert(
            handle,
            HandleState {
                path_key: key,
                allow_delete,
            },
        );
        Ok(FileHandle(handle))
    }
    pub fn write_handle(
        &mut self,
        handle: FileHandle,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let file = self.handle_file(handle)?;
        self.write_at(&file, offset, bytes)
    }
    pub fn truncate_handle(
        &mut self,
        handle: FileHandle,
        length: usize,
    ) -> Result<(), StorageError> {
        let file = self.handle_file(handle)?;
        let mut data = self
            .staged
            .get(file.to_wire())
            .cloned()
            .or_else(|| self.read(&file).ok())
            .unwrap_or_default();
        data.resize(length, 0);
        self.write(&file, &data)
    }
    pub fn flush_handle(&mut self, handle: FileHandle) -> Result<(), StorageError> {
        let file = self.handle_file(handle)?;
        self.flush_file(&file).map(|_| ())
    }
    pub fn close_handle(&mut self, handle: FileHandle) -> Result<(), StorageError> {
        let state = self
            .handles
            .remove(&handle.0)
            .ok_or(StorageError::NotFound)?;
        if self
            .files
            .get(&state.path_key)
            .is_some_and(|entry| entry.delete_pending)
            && !self
                .handles
                .values()
                .any(|other| other.path_key == state.path_key)
        {
            self.files.remove(&state.path_key);
        }
        Ok(())
    }
    pub fn read_path(&self, path: &VirtualPath) -> Result<Vec<u8>, StorageError> {
        let entry = self
            .files
            .get(path.lookup_key())
            .ok_or(StorageError::NotFound)?;
        if entry.delete_pending {
            return Err(StorageError::NotFound);
        }
        self.read(&entry.file_id)
    }
    pub fn rename(
        &mut self,
        source: &VirtualPath,
        destination: &VirtualPath,
        replace: bool,
    ) -> Result<(), StorageError> {
        let source_key = source.lookup_key().to_owned();
        let destination_key = destination.lookup_key().to_owned();
        self.require_parent(destination)?;
        let source_entry = self
            .files
            .get(&source_key)
            .cloned()
            .ok_or(StorageError::NotFound)?;
        if source_entry.delete_pending {
            return Err(StorageError::DeletePending);
        } else if self.files.contains_key(&destination_key) {
            if !replace {
                return Err(StorageError::AlreadyExists);
            }
            self.delete(destination)?;
            if self.files.contains_key(&destination_key) {
                return Err(StorageError::SharingViolation);
            }
        }
        let mut moved = self
            .files
            .remove(&source_key)
            .ok_or(StorageError::NotFound)?;
        moved.display = destination.display_name().unwrap_or_default().to_owned();
        self.files.insert(destination_key.clone(), moved);
        for state in self.handles.values_mut() {
            if state.path_key == source_key {
                state.path_key = destination_key.clone();
            }
        }
        Ok(())
    }
    pub fn delete(&mut self, path: &VirtualPath) -> Result<(), StorageError> {
        let key = path.lookup_key();
        let entry = self.files.get_mut(key).ok_or(StorageError::NotFound)?;
        if self
            .handles
            .values()
            .any(|handle| handle.path_key == key && !handle.allow_delete)
        {
            return Err(StorageError::SharingViolation);
        } else if self.handles.values().any(|handle| handle.path_key == key) {
            entry.delete_pending = true;
        } else {
            self.files.remove(key);
        }
        Ok(())
    }
    pub fn tamper_selected_record_for_test(
        &mut self,
        file: &FileId,
        field: &str,
    ) -> Result<(), StorageError> {
        let path = self.file_dir(file).join("selected.commit");
        let mut record = self.read_record(&path)?;
        match field {
            "store" => record.store_id = "other-store".into(),
            "file" => record.file_id = "other-file".into(),
            "generation" => record.generation += 1,
            "chunk" => record.chunk_index += 1,
            "length" => record.plaintext_length += 1,
            "version" => record.format_version += 1,
            "tag" => {
                let byte = record
                    .ciphertext
                    .last_mut()
                    .ok_or(StorageError::IntegrityFailure)?;
                *byte ^= 1;
            }
            _ => return Err(StorageError::IntegrityFailure),
        }
        self.write_record(&path, &record)
    }
    fn seal(
        &mut self,
        cipher: &RecordCipher,
        nonces: &mut NonceTracker,
        file: &FileId,
        aad: RecordAad,
        plaintext: &[u8],
    ) -> Result<EncryptedRecordV1, StorageError> {
        let record = EncryptedRecordV1::seal(cipher, aad, plaintext, nonces)?;
        if self.forced_duplicate.contains(file.to_wire()) {
            return Err(StorageError::IntegrityFailure);
        }
        Ok(record)
    }
    fn aad(
        &self,
        file: &FileId,
        generation: u64,
        kind: RecordKind,
        index: u64,
        plaintext_length: usize,
    ) -> RecordAad {
        RecordAad {
            format_version: FORMAT_VERSION_V1,
            store_id: self.identity.store_id().to_wire().to_owned(),
            file_id: file.to_wire().to_owned(),
            generation,
            record_kind: kind,
            chunk_index: index,
            plaintext_length: plaintext_length as u64,
        }
    }
    fn ensure_identity(
        &self,
        record: &EncryptedRecordV1,
        file: &FileId,
        kind: RecordKind,
        index: u64,
    ) -> Result<(), StorageError> {
        if record.format_version != FORMAT_VERSION_V1
            || record.store_id != self.identity.store_id().to_wire()
            || record.file_id != file.to_wire()
            || record.record_kind != kind
            || record.chunk_index != index
        {
            return Err(StorageError::IntegrityFailure);
        }
        Ok(())
    }
    fn write_record(&self, path: &Path, record: &EncryptedRecordV1) -> Result<(), StorageError> {
        let bytes = record.encode()?;
        let mut output = File::create(path).map_err(map_io)?;
        output.write_all(&bytes).map_err(map_io)?;
        output.sync_all().map_err(map_io)
    }
    fn read_record(&self, path: &Path) -> Result<EncryptedRecordV1, StorageError> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    StorageError::NotFound
                } else {
                    map_io(error)
                }
            })?
            .read_to_end(&mut bytes)
            .map_err(map_io)?;
        EncryptedRecordV1::decode(&bytes)
    }
    fn flush_directory_marker(&self, directory: &Path) -> Result<(), StorageError> {
        let mut marker = File::create(directory.join(".directory-flush")).map_err(map_io)?;
        marker.write_all(b"v1").map_err(map_io)?;
        marker.sync_all().map_err(map_io)
    }
    fn file_dir(&self, file: &FileId) -> PathBuf {
        self.root
            .join("stores")
            .join(self.identity.store_id().to_wire())
            .join("files")
            .join(file.to_wire())
    }
    fn generation_dir(&self, file: &FileId, generation: u64) -> PathBuf {
        self.file_dir(file)
            .join("generations")
            .join(format!("g-{generation:020}"))
    }
    fn is_directory(&self, path: &VirtualPath) -> bool {
        path.lookup_key().is_empty() || self.directories.contains_key(path.lookup_key())
    }
    fn require_parent(&self, path: &VirtualPath) -> Result<(), StorageError> {
        match path.parent_key() {
            None => Ok(()),
            Some(parent) if self.directories.contains_key(&parent) => Ok(()),
            Some(_) => Err(StorageError::NotFound),
        }
    }
    fn handle_file(&self, handle: FileHandle) -> Result<FileId, StorageError> {
        let state = self.handles.get(&handle.0).ok_or(StorageError::NotFound)?;
        self.files
            .get(&state.path_key)
            .map(|entry| entry.file_id.clone())
            .ok_or(StorageError::NotFound)
    }
}

fn direct_child(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix)
        .is_some_and(|remainder| !remainder.is_empty() && !remainder.contains('/'))
}
fn map_io(error: std::io::Error) -> StorageError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::WriteZero | std::io::ErrorKind::StorageFull
    ) {
        StorageError::NoSpace
    } else {
        StorageError::IoFailure
    }
}
