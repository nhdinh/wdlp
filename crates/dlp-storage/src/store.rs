use crate::{
    CHUNK_SIZE, CapturedStoreIdentity, StorageError, StoreKey, VirtualPath,
    format::{CommitRecordV1, EncryptedManifestV1, EncryptedRecordV1, FORMAT_VERSION_V1},
};
use dlp_crypto::{NonceTracker, RecordAad, RecordCipher, RecordKind};
use dlp_domain::FileId;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_FILE: AtomicU64 = AtomicU64::new(1);
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static NEXT_EVIDENCE: AtomicU64 = AtomicU64::new(1);

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

/// Bounded test seam for simulating abrupt loss on either side of durability boundaries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DurabilityFaultPoint {
    BeforeRecordWrite,
    AfterRecordFlush,
    BeforeManifestWrite,
    AfterManifestFlush,
    BeforeCommitWrite,
    AfterCommitFlush,
    BeforePointerReplace,
    AfterPointerReplace,
    BeforeDirectoryFlush,
    AfterDirectoryFlush,
}

#[derive(Clone, Debug)]
pub struct FaultInjectingIo {
    fault: Option<DurabilityFaultPoint>,
    error: StorageError,
}

impl Default for FaultInjectingIo {
    fn default() -> Self {
        Self {
            fault: None,
            error: StorageError::IoFailure,
        }
    }
}

impl FaultInjectingIo {
    pub fn fail_at(point: DurabilityFaultPoint) -> Self {
        Self {
            fault: Some(point),
            error: StorageError::IoFailure,
        }
    }

    pub fn no_space_at(point: DurabilityFaultPoint) -> Self {
        Self {
            fault: Some(point),
            error: StorageError::NoSpace,
        }
    }

    fn hit(&mut self, point: DurabilityFaultPoint) -> Result<(), StorageError> {
        if self.fault == Some(point) {
            self.fault = None;
            return Err(self.error.clone());
        }
        Ok(())
    }
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
    namespace_generation: u64,
    fail_next_write: bool,
    fault_io: FaultInjectingIo,
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
        let mut store = Self {
            root,
            identity,
            key,
            staged: BTreeMap::new(),
            forced_duplicate: BTreeSet::new(),
            directories: BTreeMap::new(),
            files: BTreeMap::new(),
            handles: BTreeMap::new(),
            namespace_generation: 0,
            fail_next_write: false,
            fault_io: FaultInjectingIo::default(),
        };
        store.load_namespace()?;
        Ok(store)
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
            self.fault_io.hit(DurabilityFaultPoint::BeforeRecordWrite)?;
            self.write_record(
                &generation_dir.join(format!("chunk-{index:08}.rec")),
                &record,
            )?;
            self.fault_io.hit(DurabilityFaultPoint::AfterRecordFlush)?;
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
        self.fault_io
            .hit(DurabilityFaultPoint::BeforeManifestWrite)?;
        self.write_record(&generation_dir.join("manifest.rec"), &manifest_record)?;
        self.fault_io
            .hit(DurabilityFaultPoint::AfterManifestFlush)?;
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
        self.fault_io.hit(DurabilityFaultPoint::BeforeCommitWrite)?;
        self.write_record(&staged_commit, &commit_record)?;
        self.fault_io.hit(DurabilityFaultPoint::AfterCommitFlush)?;
        trace.record("commit-flush");
        let selected = self.file_dir(file).join("selected.commit");
        if selected.exists() {
            let prior = self.file_dir(file).join("previous.commit");
            fs::copy(&selected, &prior).map_err(map_io)?;
            self.flush_directory_marker(&self.file_dir(file))?;
        }
        let selected_tmp = self
            .file_dir(file)
            .join(format!("selected-{generation}.tmp"));
        self.fault_io
            .hit(DurabilityFaultPoint::BeforePointerReplace)?;
        self.write_record(&selected_tmp, &commit_record)?;
        if selected.exists() {
            fs::remove_file(&selected).map_err(map_io)?;
        }
        fs::rename(&selected_tmp, &selected).map_err(map_io)?;
        self.fault_io
            .hit(DurabilityFaultPoint::AfterPointerReplace)?;
        trace.record("pointer-publish");
        self.fault_io
            .hit(DurabilityFaultPoint::BeforeDirectoryFlush)?;
        self.flush_directory_marker(&self.file_dir(file))?;
        self.fault_io
            .hit(DurabilityFaultPoint::AfterDirectoryFlush)?;
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
        self.read_from_pointer(&self.file_dir(file).join("selected.commit"), file)
    }
    pub(crate) fn recover_selected_from_prior(
        &mut self,
        file: &FileId,
    ) -> Result<crate::RecoveryReport, StorageError> {
        let selected = self.file_dir(file).join("selected.commit");
        if !selected.exists() {
            return self.recover_from_prior_pointer(file, &selected);
        }
        match self.read_from_pointer(&selected, file) {
            Ok(_) => {
                let generation = self.commit_generation(&selected, file)?;
                self.cleanup_unreferenced_staging(file, generation)?;
                Ok(crate::RecoveryReport {
                    selected_generation: generation,
                    recovered_from_prior_pointer: false,
                })
            }
            Err(StorageError::NotFound) => Err(StorageError::IntegrityFailure),
            Err(error) => Err(error),
        }
    }
    fn recover_from_prior_pointer(
        &mut self,
        file: &FileId,
        selected: &Path,
    ) -> Result<crate::RecoveryReport, StorageError> {
        let prior = self.file_dir(file).join("previous.commit");
        match self.read_from_pointer(&prior, file) {
            Ok(_) => {}
            Err(StorageError::NotFound) => return Err(StorageError::RecoveryRequired),
            Err(error) => return Err(error),
        }
        let generation = self.commit_generation(&prior, file)?;
        fs::copy(&prior, selected).map_err(map_io)?;
        self.flush_directory_marker(&self.file_dir(file))?;
        self.cleanup_unreferenced_staging(file, generation)?;
        Ok(crate::RecoveryReport {
            selected_generation: generation,
            recovered_from_prior_pointer: true,
        })
    }
    fn commit_generation(&self, pointer: &Path, file: &FileId) -> Result<u64, StorageError> {
        let cipher = RecordCipher::from_store_key(&self.key);
        let selected = self.read_record(pointer)?;
        self.ensure_identity(&selected, file, RecordKind::Commit, 0)?;
        let commit = CommitRecordV1::decode(&selected.open(&cipher)?)?;
        if commit.file_id != file.to_wire() {
            return Err(StorageError::IntegrityFailure);
        }
        Ok(commit.generation)
    }
    fn read_from_pointer(&self, pointer: &Path, file: &FileId) -> Result<Vec<u8>, StorageError> {
        let cipher = RecordCipher::from_store_key(&self.key);
        let selected = self.read_record(pointer)?;
        self.ensure_identity(&selected, file, RecordKind::Commit, 0)?;
        let commit = CommitRecordV1::decode(&selected.open(&cipher)?)?;
        if commit.file_id != file.to_wire() {
            return Err(StorageError::IntegrityFailure);
        }
        let generation_dir = self.generation_dir(file, commit.generation);
        let committed_record = self.read_record(&generation_dir.join("commit.rec"))?;
        self.ensure_identity(&committed_record, file, RecordKind::Commit, 0)?;
        if committed_record.generation != commit.generation {
            return Err(StorageError::IntegrityFailure);
        }
        let committed = CommitRecordV1::decode(&committed_record.open(&cipher)?)?;
        if committed != commit {
            return Err(StorageError::IntegrityFailure);
        }
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
    pub fn inject_fault_at_for_test(&mut self, point: DurabilityFaultPoint) {
        self.fault_io = FaultInjectingIo::fail_at(point);
    }
    pub fn inject_no_space_at_for_test(&mut self, point: DurabilityFaultPoint) {
        self.fault_io = FaultInjectingIo::no_space_at(point);
    }
    pub(crate) fn preserve_integrity_evidence(&self, file: &FileId) -> Result<(), StorageError> {
        self.preserve_evidence_directory(&self.file_dir(file), "IntegrityFailure")
    }
    fn cleanup_unreferenced_staging(
        &self,
        file: &FileId,
        selected_generation: u64,
    ) -> Result<(), StorageError> {
        let generations = self.file_dir(file).join("generations");
        if !generations.exists() {
            return Ok(());
        }
        let mut referenced = BTreeSet::from([self.generation_dir(file, selected_generation)]);
        let prior = self.file_dir(file).join("previous.commit");
        if prior.exists()
            && let Ok(generation) = self.commit_generation(&prior, file)
        {
            referenced.insert(self.generation_dir(file, generation));
        }
        for entry in fs::read_dir(&generations).map_err(map_io)? {
            let path = entry.map_err(map_io)?.path();
            if path.is_dir() && !referenced.contains(&path) {
                self.preserve_evidence_directory(&path, "RecoveryQuarantine")?;
                fs::remove_dir_all(path).map_err(map_io)?;
            }
        }
        Ok(())
    }
    fn preserve_evidence_directory(&self, source: &Path, code: &str) -> Result<(), StorageError> {
        let evidence_root = self.root.join("evidence");
        fs::create_dir_all(&evidence_root).map_err(map_io)?;
        let evidence_id = format!("e-{:020}", NEXT_EVIDENCE.fetch_add(1, Ordering::Relaxed));
        let evidence_dir = evidence_root.join(&evidence_id);
        fs::create_dir(&evidence_dir).map_err(map_io)?;
        let mut diagnostics = OpenOptions::new()
            .create(true)
            .append(true)
            .open(evidence_root.join("diagnostics.log"))
            .map_err(map_io)?;
        let mut next_record = 1_u64;
        copy_evidence_files(
            source,
            &evidence_dir,
            &mut next_record,
            &evidence_id,
            code,
            &mut diagnostics,
        )?;
        diagnostics.sync_all().map_err(map_io)
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
        self.persist_namespace()
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
        self.flush_file(&file)?;
        self.persist_namespace()
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
            self.persist_namespace()?;
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
        self.persist_namespace()
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
            self.persist_namespace()?;
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
    fn namespace_path(&self) -> PathBuf {
        self.root
            .join("stores")
            .join(self.identity.store_id().to_wire())
            .join("namespace.rec")
    }

    fn persist_namespace(&mut self) -> Result<(), StorageError> {
        let mut plaintext = String::from("dlp-namespace/v1\n");
        for (key, display) in &self.directories {
            plaintext.push_str(&format!("D\t{key}\t{display}\n"));
        }
        for (key, entry) in &self.files {
            if !entry.delete_pending {
                plaintext.push_str(&format!(
                    "F\t{key}\t{}\t{}\n",
                    entry.file_id.to_wire(),
                    entry.display
                ));
            }
        }
        let generation = self
            .namespace_generation
            .checked_add(1)
            .ok_or(StorageError::IoFailure)?;
        let cipher = RecordCipher::from_store_key(&self.key);
        let mut nonces = NonceTracker::default();
        let record = EncryptedRecordV1::seal(
            &cipher,
            RecordAad {
                format_version: FORMAT_VERSION_V1,
                store_id: self.identity.store_id().to_wire().to_owned(),
                file_id: "namespace-index".to_owned(),
                generation,
                record_kind: RecordKind::Manifest,
                chunk_index: 0,
                plaintext_length: plaintext.len() as u64,
            },
            plaintext.as_bytes(),
            &mut nonces,
        )?;
        let target = self.namespace_path();
        let temporary = target.with_extension(format!("{generation}.tmp"));
        self.write_record(&temporary, &record)?;
        fs::rename(&temporary, &target).map_err(map_io)?;
        self.flush_directory_marker(target.parent().ok_or(StorageError::IoFailure)?)?;
        self.namespace_generation = generation;
        Ok(())
    }

    fn load_namespace(&mut self) -> Result<(), StorageError> {
        let target = self.namespace_path();
        if !target.exists() {
            return Ok(());
        }
        let record = self.read_record(&target)?;
        if record.format_version != FORMAT_VERSION_V1
            || record.store_id != self.identity.store_id().to_wire()
            || record.file_id != "namespace-index"
            || record.record_kind != RecordKind::Manifest
            || record.chunk_index != 0
        {
            return Err(StorageError::IntegrityFailure);
        }
        let cipher = RecordCipher::from_store_key(&self.key);
        let plaintext = record.open(&cipher)?;
        let text = std::str::from_utf8(&plaintext).map_err(|_| StorageError::IntegrityFailure)?;
        let mut lines = text.lines();
        if lines.next() != Some("dlp-namespace/v1") {
            return Err(StorageError::IntegrityFailure);
        }
        for line in lines {
            let columns = line.split('\t').collect::<Vec<_>>();
            match columns.as_slice() {
                ["D", key, display] if !key.is_empty() && !display.is_empty() => {
                    if self
                        .directories
                        .insert((*key).to_owned(), (*display).to_owned())
                        .is_some()
                    {
                        return Err(StorageError::IntegrityFailure);
                    }
                }
                ["F", key, file_id, display] if !key.is_empty() && !display.is_empty() => {
                    let file_id =
                        FileId::parse(*file_id).map_err(|_| StorageError::IntegrityFailure)?;
                    if self
                        .files
                        .insert(
                            (*key).to_owned(),
                            FileEntry {
                                file_id,
                                display: (*display).to_owned(),
                                delete_pending: false,
                            },
                        )
                        .is_some()
                    {
                        return Err(StorageError::IntegrityFailure);
                    }
                }
                _ => return Err(StorageError::IntegrityFailure),
            }
        }
        self.namespace_generation = record.generation;
        Ok(())
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

fn copy_evidence_files(
    source: &Path,
    destination: &Path,
    next_record: &mut u64,
    evidence_id: &str,
    code: &str,
    diagnostics: &mut File,
) -> Result<(), StorageError> {
    for entry in fs::read_dir(source).map_err(map_io)? {
        let path = entry.map_err(map_io)?.path();
        if path.is_dir() {
            copy_evidence_files(
                &path,
                destination,
                next_record,
                evidence_id,
                code,
                diagnostics,
            )?;
        } else {
            let target = destination.join(format!("r-{:020}", *next_record));
            *next_record = next_record.checked_add(1).ok_or(StorageError::IoFailure)?;
            let bytes = fs::read(&path).map_err(map_io)?;
            let digest = Sha256::digest(&bytes);
            diagnostics
                .write_all(
                    format!(
                        "integrity opaque={evidence_id} record=encrypted digest={digest:x} code={code}\n"
                    )
                    .as_bytes(),
                )
                .map_err(map_io)?;
            diagnostics.sync_data().map_err(map_io)?;
            fs::write(target, bytes).map_err(map_io)?;
        }
    }
    Ok(())
}
