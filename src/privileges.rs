/// Administrator privilege check for Windows.
///
/// Returns `true` if the current process is running with elevated (Administrator)
/// privileges, `false` otherwise.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length: u32 = 0;
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size,
            &mut return_length,
        );

        let _ = windows::Win32::Foundation::CloseHandle(token);

        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// On non-Windows platforms this always returns `false`.
#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

/// Asserts administrator privileges, returning an error if not elevated.
pub fn require_elevation() -> anyhow::Result<()> {
    if !is_elevated() {
        anyhow::bail!(
            "This tool must be run as Administrator. \
             Please re-launch from an elevated command prompt."
        );
    }
    Ok(())
}
