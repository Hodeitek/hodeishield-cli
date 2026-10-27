// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Keeps the standard handles of the process out of a browser started by `login` (Windows only).
//!
//! Windows starts a child with every inheritable handle of the parent. When the output of
//! `hodeishield` goes into a pipe, the write end of that pipe is such a handle: a browser that
//! inherits it keeps the pipe open after `hodeishield` exits, and whatever reads the pipe waits
//! for the browser to exit. Clearing the inherit flag on the standard handles before the browser
//! starts avoids that. The handles are not restored: `login` starts no other process after the
//! browser, and the flag only matters to a child.
//!
//! This is the only module of the workspace that allows `unsafe` code: the Win32 calls below have
//! no safe counterpart in the standard library.

#![allow(unsafe_code)]

use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

/// Clears the inherit flag on standard input, output and error. Failures are ignored: a missing
/// or non-inheritable handle needs nothing, and the browser still opens.
pub fn clear_std_handle_inheritance() {
    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: `GetStdHandle` has no preconditions; it returns a handle or a sentinel.
        let handle = unsafe { GetStdHandle(id) };
        clear_inheritance(handle);
    }
}

fn clear_inheritance(handle: HANDLE) {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return;
    }
    // SAFETY: the handle is not null or invalid; a handle that is closed or of the wrong kind
    // makes the call fail, and the failure is ignored.
    let _ = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, GetHandleInformation};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    fn inheritable_pipe() -> (HANDLE, HANDLE) {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("small"),
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let (mut read, mut write) = (null_mut(), null_mut());
        // SAFETY: both out-pointers and the attributes live for the call.
        let created = unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) };
        assert_ne!(created, 0, "CreatePipe failed");
        (read, write)
    }

    fn inherits(handle: HANDLE) -> bool {
        let mut flags = 0;
        // SAFETY: `handle` is open and `flags` lives for the call.
        let ok = unsafe { GetHandleInformation(handle, &mut flags) };
        assert_ne!(ok, 0, "GetHandleInformation failed");
        flags & HANDLE_FLAG_INHERIT != 0
    }

    #[test]
    fn clearing_removes_the_inherit_flag_from_a_pipe_handle() {
        let (read, write) = inheritable_pipe();
        assert!(inherits(write), "the pipe starts inheritable");

        clear_inheritance(write);

        assert!(!inherits(write));
        assert!(inherits(read), "only the handle given is changed");
        // SAFETY: both handles are open and owned here.
        unsafe {
            CloseHandle(read);
            CloseHandle(write);
        }
    }

    #[test]
    fn null_and_invalid_handles_are_skipped() {
        clear_inheritance(null_mut());
        clear_inheritance(INVALID_HANDLE_VALUE);
    }

    #[test]
    fn clearing_the_standard_handles_does_not_panic() {
        clear_std_handle_inheritance();
    }
}
