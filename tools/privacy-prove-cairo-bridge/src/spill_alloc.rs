//! A global allocator that routes large allocations into unlinked, file-backed
//! `MAP_SHARED` mappings ("spill files") instead of anonymous heap memory.
//!
//! Why: on Darwin (macOS and iOS), anonymous dirty pages count against the
//! process's `phys_footprint` — the ledger iOS jetsam enforces — while
//! file-backed pages are "external" and evictable: the pager writes them back
//! and reclaims them under pressure. The prover's dominant allocations (LDE
//! evaluation columns, Merkle hash layers, witness/value buffers) are written
//! once and then scanned sequentially or read sparsely, which pages cleanly.
//! Backing them with spill files keeps the *footprint* (and on a phone, the
//! jetsam-relevant working set) bounded by the actively-touched pages instead
//! of the total allocated bytes.
//!
//! Mechanics: allocations of at least `SPILL_THRESHOLD` bytes (and alignment
//! at most one page) are served by `open(mkstemp) → unlink → ftruncate →
//! mmap(MAP_SHARED) → close(fd)`. The file is anonymous-on-disk from birth
//! (unlinked), so nothing leaks even on a crash; `munmap` on dealloc releases
//! both memory and disk. The routing decision is a pure function of `Layout`,
//! so alloc/dealloc agree without any side table. The alloc path makes no
//! Rust allocations (fixed stack buffers + libc only) to avoid recursion.
//!
//! Opt-in: spilling activates only when `$ZKMSG_SPILL_DIR` is set (on iOS the
//! app sets it to its tmp directory; on a desktop relay it is usually unset —
//! pure-RAM proving is ~30% faster when memory is plentiful).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI8, AtomicUsize, Ordering};

/// Live spilled bytes and mapping count, for diagnosing VM ceilings.
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_MAPS: AtomicUsize = AtomicUsize::new(0);

/// Peak live spill, readable from the host app for reporting.
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Returns the peak concurrent spilled bytes observed so far.
#[unsafe(no_mangle)]
pub extern "C" fn zkmsg_peak_spill_bytes() -> u64 {
    PEAK_BYTES.load(Ordering::Relaxed) as u64
}

/// Allocations at or above this size are spilled. 4 MiB captures every LDE
/// column (8–64 MiB), Merkle layer and value-context buffer while leaving
/// ordinary data structures on the system allocator.
const SPILL_THRESHOLD: usize = 4 << 20;

/// Conservative lower bound on the page size; real page size is queried at
/// runtime for mmap length rounding. Only used to reject over-aligned
/// requests (none exist in practice — SIMD wants 64 bytes).
const MAX_SUPPORTED_ALIGN: usize = 4096;

pub struct SpillAlloc;

/// -1 = uninitialized, 0 = disabled, 1 = enabled.
static ENABLED: AtomicI8 = AtomicI8::new(-1);

fn spill_enabled() -> bool {
    match ENABLED.load(Ordering::Relaxed) {
        1 => true,
        0 => false,
        _ => {
            // getenv is allocator-safe (no malloc).
            let enabled =
                unsafe { !libc::getenv(c"ZKMSG_SPILL_DIR".as_ptr()).is_null() };
            ENABLED.store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
            enabled
        }
    }
}

fn use_spill(layout: &Layout) -> bool {
    layout.size() >= SPILL_THRESHOLD
        && layout.align() <= MAX_SUPPORTED_ALIGN
        && spill_enabled()
}

fn page_ceil(size: usize) -> usize {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    (size + page - 1) & !(page - 1)
}

/// Builds the mkstemp template into `buf` without allocating. Returns false if
/// the directory path is too long.
fn build_template(buf: &mut [u8; libc::PATH_MAX as usize]) -> bool {
    let dir = unsafe { libc::getenv(c"ZKMSG_SPILL_DIR".as_ptr()) };
    if dir.is_null() {
        return false;
    }
    let mut n = 0usize;
    unsafe {
        while *dir.add(n) != 0 && n < buf.len() - 32 {
            buf[n] = *dir.add(n) as u8;
            n += 1;
        }
    }
    if n == 0 || n >= buf.len() - 32 {
        return false;
    }
    if buf[n - 1] == b'/' {
        n -= 1;
    }
    for &b in b"/zkmsg-spill-XXXXXX\0" {
        buf[n] = b;
        n += 1;
    }
    true
}

/// Allocator-safe diagnostic: formats "zkmsg spill fail <stage> size=<n>
/// errno=<e>" into a stack buffer and writes it to stderr. Must not allocate
/// (it runs inside the allocator), so no formatting machinery is used.
fn report_failure(stage: &str, size: usize, err: i32) {
    struct Buf {
        bytes: [u8; 128],
        len: usize,
    }
    impl Buf {
        fn push(&mut self, bytes: &[u8]) {
            for &b in bytes {
                if self.len < self.bytes.len() {
                    self.bytes[self.len] = b;
                    self.len += 1;
                }
            }
        }
        fn push_num(&mut self, mut v: u64) {
            let mut digits = [0u8; 20];
            let mut d = 0;
            if v == 0 {
                digits[0] = b'0';
                d = 1;
            }
            while v > 0 {
                digits[d] = b'0' + (v % 10) as u8;
                v /= 10;
                d += 1;
            }
            while d > 0 {
                d -= 1;
                let byte = digits[d];
                self.push(&[byte]);
            }
        }
    }

    let mut buf = Buf { bytes: [0u8; 128], len: 0 };
    buf.push(b"zkmsg spill fail ");
    buf.push(stage.as_bytes());
    buf.push(b" size=");
    buf.push_num(size as u64);
    buf.push(b" errno=");
    buf.push_num(err as u64);
    buf.push(b" live_mb=");
    buf.push_num((LIVE_BYTES.load(Ordering::Relaxed) / 1_048_576) as u64);
    buf.push(b" maps=");
    buf.push_num(LIVE_MAPS.load(Ordering::Relaxed) as u64);
    buf.push(b"\n");
    unsafe {
        libc::write(2, buf.bytes.as_ptr() as *const libc::c_void, buf.len);
    }
}

fn spill_mmap(size: usize) -> *mut u8 {
    let mut template = [0u8; libc::PATH_MAX as usize];
    if !build_template(&mut template) {
        return std::ptr::null_mut();
    }
    unsafe {
        let fd = libc::mkstemp(template.as_mut_ptr() as *mut libc::c_char);
        if fd < 0 {
            report_failure("mkstemp", size, *libc::__error());
            return std::ptr::null_mut();
        }
        // Anonymous on disk from birth: the name disappears immediately, the
        // file lives as long as the mapping.
        libc::unlink(template.as_ptr() as *const libc::c_char);
        let len = page_ceil(size);
        if libc::ftruncate(fd, len as libc::off_t) != 0 {
            report_failure("ftruncate", len, *libc::__error());
            libc::close(fd);
            return std::ptr::null_mut();
        }
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        libc::close(fd);
        if ptr == libc::MAP_FAILED {
            report_failure("mmap", len, *libc::__error());
            return std::ptr::null_mut();
        }
        let live = LIVE_BYTES.fetch_add(len, Ordering::Relaxed) + len;
        LIVE_MAPS.fetch_add(1, Ordering::Relaxed);
        PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
        ptr as *mut u8
    }
}

unsafe impl GlobalAlloc for SpillAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if use_spill(&layout) {
            let ptr = spill_mmap(layout.size());
            if !ptr.is_null() {
                return ptr;
            }
            // Routing is a pure function of Layout so alloc/dealloc always
            // agree; a spill failure (disk full, bad dir) therefore aborts
            // instead of silently mixing allocators — on a phone the
            // alternative is an anonymous-memory OOM kill anyway.
            unsafe { libc::abort() };
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if use_spill(&layout) {
            // Fresh file pages are zero-filled by definition.
            return unsafe { self.alloc(layout) };
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if use_spill(&layout) {
            let len = page_ceil(layout.size());
            unsafe { libc::munmap(ptr as *mut libc::c_void, len) };
            LIVE_BYTES.fetch_sub(len, Ordering::Relaxed);
            LIVE_MAPS.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}
