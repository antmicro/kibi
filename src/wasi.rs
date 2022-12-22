//! # sys (WASI)
//!
//! WASI-specific structs and functions. Will be imported as `sys` on WASI systems.

pub use crate::xdg::*;
use crate::Error;

use std::fs::File;
use std::io::{self, Read};
use std::mem;
use std::os::wasi::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::Mutex;

use sscanf::scanf;

extern crate wasi as wasi_snapshot;

pub struct TermMode {}

const STDIN: RawFd = 0x0;

const TTY_TOKEN: u64 = 1;
const RESIZE_TOKEN: u64 = 2;

struct InternalEventSource {
    events: [wasi_snapshot::Event; 2],
    tty_input: File,
    event_src: File,
    resize_occurred: bool,
}

impl InternalEventSource {
    pub fn wait_for_event(&mut self) -> Result<bool, Error> {
        // returns true if stdin has data to read
        let mut is_data_to_read = false;

        let subs = vec![
            wasi::Subscription {
                userdata: TTY_TOKEN,
                u: wasi::SubscriptionU {
                    tag: wasi::EVENTTYPE_FD_READ.raw(),
                    u: wasi::SubscriptionUU {
                        fd_read: wasi::SubscriptionFdReadwrite {
                            file_descriptor: self.tty_input.as_raw_fd() as u32
                        }
                    }
                }
            },
            wasi::Subscription {
                userdata: RESIZE_TOKEN,
                u: wasi::SubscriptionU {
                    tag: wasi::EVENTTYPE_FD_READ.raw(),
                    u: wasi::SubscriptionUU {
                        fd_read: wasi::SubscriptionFdReadwrite {
                            file_descriptor: self.event_src.as_raw_fd() as u32
                        }
                    }
                }
            },
        ];

        // subscribe and wait
        let result = unsafe {
            wasi::poll_oneoff(
                subs.as_ptr(),
                self.events.as_mut_ptr(),
                subs.len()
            )
        };

        let events_count = match result {
            Ok(n) => n,
            Err(e) => {
                return Err(Error::Io(io::Error::from_raw_os_error(e.raw() as i32)));
            }
        };

        for event in self.events[0..events_count].iter() {
            let errno = event.error.raw();
            if errno > 0 {
                return Err(Error::Io(io::Error::from_raw_os_error(errno as i32)));
            }
        }

        for event in self.events[0..events_count].iter() {
            match (event.userdata, event.type_) {
                (TTY_TOKEN, wasi::EVENTTYPE_FD_READ) => {
                    let to_read = event.fd_readwrite.nbytes as usize;
                    is_data_to_read = to_read > 0;
                },
                (RESIZE_TOKEN, wasi::EVENTTYPE_FD_READ) => {
                    let to_read = event.fd_readwrite.nbytes as usize;
                    let mut read_buff: [u8; wasi_ext_lib::WASI_EVENTS_MASK_SIZE] = [
                        0u8; wasi_ext_lib::WASI_EVENTS_MASK_SIZE
                    ];

                    if let Err(e) = self.event_src.read(&mut read_buff[0..to_read]) {
                        return Err(Error::Io(e));
                    };

                    let events = read_buff[0] as wasi_ext_lib::WasiEvents;

                    if events & wasi_ext_lib::WASI_EVENT_WINCH != 0 {
                        self.resize_occurred = true;
                    }
                },
                _ => unreachable!(),
            }
        }

        Ok(is_data_to_read)
    }
}

impl Default for InternalEventSource {
    fn default() -> Self {
        let input_fd = STDIN;
        let fd_stats = unsafe {
            wasi::fd_fdstat_get(input_fd as u32).expect(
                "Cannot obtain stdin metadata!"
            )
        };

        // In the wash stdin is char-device with read right
        // Crossterm crate won't panic even if we return Err here
        if fd_stats.fs_filetype != wasi::FILETYPE_CHARACTER_DEVICE ||
            (fd_stats.fs_rights_base & wasi::RIGHTS_FD_READ) == 0 {
            panic!("Polling from fd={} not possible!", input_fd);
        }

        // Obtain hterm event source
        let event_source_fd = {
            wasi_ext_lib::event_source_fd(
                wasi_ext_lib::WASI_EVENT_WINCH
            ).expect(
                "Cannot obtain EvenSource file descriptor!"
            )
        };

        InternalEventSource {
            events: unsafe { mem::zeroed() },
            tty_input: unsafe { File::from_raw_fd(input_fd) },
            event_src: unsafe { File::from_raw_fd(event_source_fd) },
            resize_occurred: false,
        }
    }
}

static INTERNAL_EVENT_READER: Mutex<Option<InternalEventSource>> = Mutex::new(None);

/// Return the current window size as (rows, columns).
/// By returning an error we cause kibi to fall back to another method of getting the window size
pub fn get_window_size() -> Result<(usize, usize), Error> {
    let hterm_screen = match wasi_ext_lib::hterm("screenSize", None) {
        Ok(s) => s,
        Err(e) => return Err(Error::Io(io::Error::from_raw_os_error(e)))
    };
    let value = hterm_screen.unwrap();
    let size = match scanf!(value, "[hterm.Size: {}, {}]", u16, u16) {
        Ok(size) => size,
        Err(_) => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "Cannot obtain terminal window size with hterm custom syscall"
            )));
        }
    };
    Ok((size.1 as usize, size.0 as usize))
}

/// Register a signal handler that sets a global variable when the window size changes. On WASI
/// platforms, this does nothing.
#[allow(clippy::unnecessary_wraps)] // Result required on other platforms
pub fn register_winsize_change_signal_handler() -> Result<(), Error> {
    INTERNAL_EVENT_READER.lock().expect(
        "Cannot lock internal event source object!"
    ).get_or_insert_with(InternalEventSource::default);
    Ok(())
}

/// Check if the windows size has changed since the last call to this function. On WASI platforms,
/// this always return false.
pub fn has_window_size_changed() -> bool {
    let mut guard = INTERNAL_EVENT_READER.lock().expect(
        "Cannot lock internal event source object!"
    );

    let result;
    if let Some(reader) = &mut *guard {
        result = reader.resize_occurred;
        reader.resize_occurred = false;
    } else {
        panic!("Internal event source object not initialized!");
    }

    result
}

/// Set the terminal mode. On WASI platforms, this does nothing.
#[allow(clippy::unnecessary_wraps)] // Result required on other platforms
pub fn set_term_mode(_term: &TermMode) -> Result<(), Error> { Ok(()) }

// Opening the file /dev/tty is effectively the same as `raw_mode`
#[allow(clippy::unnecessary_wraps)] // Result required on other platforms
pub fn enable_raw_mode() -> Result<TermMode, Error> { Ok(TermMode {}) }

pub fn stdin() -> std::io::Result<std::io::Stdin> { Ok(std::io::stdin()) }

pub fn path(filename: &str) -> std::path::PathBuf {
    // If the filename is absolute then it starts with a forward slash and we
    // can just open the file however if it lacks a forwrad slash then its
    // relative to the current working directory. As WASI does not have an ABI
    // for current directory we are using the PWD environment variable as a
    // defacto standard
    if filename.starts_with('/') {
        std::path::PathBuf::from(filename)
    } else {
        std::env::current_dir().unwrap_or_else(|_| "/".into()).join(filename)
    }
}

pub fn wait_for_event() -> Result<bool, Error> {
    // returns true if stdin data occurred
    let mut guard = INTERNAL_EVENT_READER.lock().expect(
        "Cannot lock internal event source object!"
    );

    let reader = if let Some(reader) = &mut *guard {
        reader
    } else {
        panic!("Internal event source object not initialized!");
    };

    reader.wait_for_event()
}
