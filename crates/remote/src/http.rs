//! WebDAV's HTTP transport over WinHTTP: Windows' certificate store and proxy settings apply,
//! and no TLS stack is bundled. Blocking; background threads only.
//!
//! Redirects are followed by Arke itself, not by WinHTTP: WinHTTP drops custom headers such as
//! `Authorization` and `Depth` when a 301/302/307 changes host, and it can change PROPFIND to
//! GET. Doing the hops here keeps the method and headers intact.

use std::io::{Read, Seek, SeekFrom, Write};

use windows::Win32::Networking::WinHttp::{
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID, SECURITY_FLAG_IGNORE_CERT_DATE_INVALID,
    SECURITY_FLAG_IGNORE_UNKNOWN_CA, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_ADDREQ_FLAG_ADD, WINHTTP_FLAG_SECURE,
    WINHTTP_OPEN_REQUEST_FLAGS, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_OPTION_SECURITY_FLAGS, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_LOCATION, WINHTTP_QUERY_STATUS_CODE, WinHttpAddRequestHeaders,
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WinHttpSetTimeouts, WinHttpWriteData,
};
use windows::core::PCWSTR;

use crate::dav::{Body, Progress, Request, Transport};
use crate::error::{RemoteError, RemoteResult};

/// WinHTTP handle, closed on drop.
struct Handle(*mut core::ffi::c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: returned by WinHttpOpen/Connect/OpenRequest and not yet closed.
            let _ = unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `https://host:port/path` -> (secure, host, port, path).
fn split(url: &str) -> Option<(bool, String, u16, &str)> {
    let (secure, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else {
        (false, url.strip_prefix("http://")?)
    };
    let (authority, path) = rest.find('/').map_or((rest, "/"), |at| rest.split_at(at));
    let default = if secure { 443 } else { 80 };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, tail) = v6.split_once(']')?;
        (host, tail.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = port.map_or(Some(default), |p| p.parse().ok())?;
    Some((secure, host.to_owned(), port, path))
}

/// Resolves a `Location` header against the URL that produced it.
fn absolute_url(base: &str, location: &str) -> Option<String> {
    let location = location.trim();
    if location.starts_with("http://") || location.starts_with("https://") {
        return Some(location.to_owned());
    }
    let (scheme, rest) = base.split_once("://")?;
    let authority = rest.split('/').next()?;
    let root = format!("{scheme}://{authority}");
    if let Some(path) = location.strip_prefix('/') {
        return Some(format!("{root}/{path}"));
    }
    let folder = base.rsplit_once('/').map_or(base, |(head, _)| head);
    Some(format!("{folder}/{location}"))
}

/// WinHTTP error -> what the user should hear.
fn describe(err: &windows::core::Error, host: &str) -> RemoteError {
    // HRESULT_FROM_WIN32: facility 7, code in the low word.
    let hr = err.code().0 as u32;
    let code = if (hr >> 16) & 0x1fff == 7 {
        hr & 0xffff
    } else {
        hr
    };
    match code {
        12007 => RemoteError::NoSuchHost(host.to_owned()),
        12029 => RemoteError::Unreachable(host.to_owned()),
        12002 => RemoteError::Timeout,
        12030 | 12031 | 12017 => RemoteError::Lost,
        12037 | 12038 | 12044 | 12045 | 12057 | 12169 | 12175 => RemoteError::Certificate,
        _ => RemoteError::Server(err.message()),
    }
}

/// Sends a request body of unknown length in chunks, reporting the progress as it goes.
fn send_stream(
    req: *mut core::ffi::c_void,
    reader: &mut dyn Read,
    len: u64,
    progress: Progress<'_>,
    fail: &impl Fn(windows::core::Error) -> RemoteError,
) -> RemoteResult<()> {
    let total = u32::try_from(len).map_err(|_too_big| {
        RemoteError::Server("files over 4 GB can't be uploaded over WebDAV".into())
    })?;
    // SAFETY: `req` is a valid request handle and `total` is the length the server expects.
    unsafe { WinHttpSendRequest(req, None, None, 0, total, 0) }.map_err(fail)?;
    let mut buf = vec![0u8; CHUNK];
    let mut sent = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut written = 0u32;
        // SAFETY: `buf` is a live allocation of `n` bytes and `written` is a writable u32
        // pointer; the call only reads from `buf`.
        unsafe {
            WinHttpWriteData(
                req,
                Some(buf.as_ptr().cast()),
                u32::try_from(n).unwrap_or(u32::MAX),
                &raw mut written,
            )
        }
        .map_err(fail)?;
        sent += n as u64;
        if !progress(sent) {
            return Err(RemoteError::Cancelled);
        }
    }
    Ok(())
}

/// Reads a NUL-terminated string header.
unsafe fn query_string(req: *mut core::ffi::c_void, info: u32) -> Option<String> {
    let mut needed = 0u32;
    // SAFETY: `req` is a valid request handle and `needed` is a writable u32 pointer; the
    // call only asks for the buffer size, so a null buffer is expected here.
    let _ = unsafe {
        WinHttpQueryHeaders(
            req,
            info,
            PCWSTR::null(),
            None,
            &raw mut needed,
            std::ptr::null_mut(),
        )
    };
    if needed < 2 {
        return None;
    }
    let mut buf = vec![0u16; needed as usize / 2 + 1];
    let mut len = needed;
    // SAFETY: `buf` is a live allocation of at least `needed` bytes and `len` is a writable
    // u32 pointer; the buffer is only read after the call reports how much it wrote.
    unsafe {
        WinHttpQueryHeaders(
            req,
            info,
            PCWSTR::null(),
            Some(buf.as_mut_ptr().cast()),
            &raw mut len,
            std::ptr::null_mut(),
        )
    }
    .ok()?;
    Some(String::from_utf16_lossy(&buf[..len as usize / 2]))
}

/// HTTP over WinHTTP, one session for the app's lifetime.
pub struct WinHttp {
    session: Handle,
}

// SAFETY: a WinHTTP session handle may be used from any thread (each request gets its own
// connect and request handles).
unsafe impl Send for WinHttp {}
// SAFETY: as above; the session handle is only read after creation.
unsafe impl Sync for WinHttp {}

/// Chunk size for uploads and downloads.
const CHUNK: usize = 256 * 1024;
/// Redirects are bounded so a loop cannot hang a background thread.
const MAX_REDIRECTS: usize = 5;

impl WinHttp {
    /// Opens the session (no network access yet).
    pub fn new() -> RemoteResult<Self> {
        let agent = wide("Arke");
        // WinHTTP reads proxy settings from WinINET, not HTTP_PROXY. Honour the environment
        // too so the same build works behind a proxy configured for other tools.
        let proxy = ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"]
            .into_iter()
            .find_map(|name| std::env::var(name).ok())
            .map(|value| {
                value
                    .trim()
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .trim_end_matches('/')
                    .to_owned()
            });
        let proxy_w = proxy.as_ref().map(|p| wide(p));
        let (access, proxy_ptr) = if let Some(p) = proxy_w.as_ref() {
            (WINHTTP_ACCESS_TYPE_NAMED_PROXY, PCWSTR(p.as_ptr()))
        } else {
            (WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, PCWSTR::null())
        };
        let bypass = "localhost 127.0.0.1".to_owned();
        let bypass_w = wide(&bypass);
        // SAFETY: agent, proxy and bypass are NUL-terminated and outlive the call.
        let session = Handle(unsafe {
            WinHttpOpen(
                PCWSTR(agent.as_ptr()),
                access,
                proxy_ptr,
                if bypass.is_empty() {
                    PCWSTR::null()
                } else {
                    PCWSTR(bypass_w.as_ptr())
                },
                0,
            )
        });
        if session.0.is_null() {
            return Err(RemoteError::Server(
                windows::core::Error::from_thread().message(),
            ));
        }
        // Resolve 10 s, connect 10 s, send and receive 30 s each.
        // SAFETY: session is a valid handle.
        let _ = unsafe { WinHttpSetTimeouts(session.0, 10_000, 10_000, 30_000, 30_000) };
        Ok(Self { session })
    }

    /// Sends one hop and returns its status, `Location` and the URL WinHTTP actually used.
    fn send_once(
        &self,
        request: &mut Request<'_>,
        out: &mut dyn Write,
        progress: &mut Progress<'_>,
    ) -> RemoteResult<(u16, Option<String>, String)> {
        let (secure, host, port, path) = split(&request.url)
            .ok_or_else(|| RemoteError::Server(format!("bad URL {}", request.url)))?;
        let fail = |e: windows::core::Error| describe(&e, &host);
        let host_w = wide(&host);
        let path_w = wide(path);
        let method_w = wide(request.method);
        // SAFETY: all strings are NUL-terminated and outlive the calls; handles are owned by
        // Handle and closed in reverse creation order; buffers passed to WinHTTP are valid
        // for each call.
        unsafe {
            let connect = Handle(WinHttpConnect(
                self.session.0,
                PCWSTR(host_w.as_ptr()),
                port,
                0,
            ));
            if connect.0.is_null() {
                return Err(fail(windows::core::Error::from_thread()));
            }
            let flags = if secure {
                WINHTTP_FLAG_SECURE
            } else {
                WINHTTP_OPEN_REQUEST_FLAGS(0)
            };
            let req = Handle(WinHttpOpenRequest(
                connect.0,
                PCWSTR(method_w.as_ptr()),
                PCWSTR(path_w.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                std::ptr::null(),
                flags,
            ));
            if req.0.is_null() {
                return Err(fail(windows::core::Error::from_thread()));
            }
            // Arke follows redirects itself to keep the WebDAV method and headers.
            let policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER.to_ne_bytes();
            WinHttpSetOption(Some(req.0), WINHTTP_OPTION_REDIRECT_POLICY, Some(&policy))
                .map_err(fail)?;
            if request.ignore_cert_errors {
                let flags = (SECURITY_FLAG_IGNORE_UNKNOWN_CA
                    | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                    | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)
                    .to_ne_bytes();
                WinHttpSetOption(Some(req.0), WINHTTP_OPTION_SECURITY_FLAGS, Some(&flags))
                    .map_err(fail)?;
            }
            for (name, value) in &request.headers {
                let line: Vec<u16> = format!("{name}: {value}").encode_utf16().collect();
                WinHttpAddRequestHeaders(req.0, &line, WINHTTP_ADDREQ_FLAG_ADD).map_err(fail)?;
            }
            match &mut request.body {
                Body::Empty => WinHttpSendRequest(req.0, None, None, 0, 0, 0).map_err(fail)?,
                Body::Bytes(bytes) => {
                    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
                    WinHttpSendRequest(req.0, None, Some(bytes.as_ptr().cast()), len, len, 0)
                        .map_err(fail)?;
                }
                Body::Stream { reader, len } => {
                    send_stream(req.0, reader, *len, *progress, &fail)?;
                }
            }
            WinHttpReceiveResponse(req.0, std::ptr::null_mut()).map_err(fail)?;
            let location = query_string(req.0, WINHTTP_QUERY_LOCATION);
            let mut status = 0u32;
            let mut size = u32::try_from(size_of::<u32>()).unwrap_or(4);
            WinHttpQueryHeaders(
                req.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                PCWSTR::null(),
                Some((&raw mut status).cast()),
                &raw mut size,
                std::ptr::null_mut(),
            )
            .map_err(fail)?;
            let status = u16::try_from(status).unwrap_or(0);
            // Error and redirect bodies are HTML pages: not worth reading.
            if !(200..300).contains(&status) {
                return Ok((status, location, request.url.clone()));
            }
            let mut buf = vec![0u8; CHUNK];
            let mut done = 0u64;
            loop {
                let mut read = 0u32;
                WinHttpReadData(
                    req.0,
                    buf.as_mut_ptr().cast(),
                    u32::try_from(buf.len()).unwrap_or(u32::MAX),
                    &raw mut read,
                )
                .map_err(fail)?;
                if read == 0 {
                    break;
                }
                out.write_all(&buf[..read as usize])?;
                done += u64::from(read);
                if !progress(done) {
                    return Err(RemoteError::Cancelled);
                }
            }
            Ok((status, None, request.url.clone()))
        }
    }

    /// Sends a request, following 301/302/303/307/308 with the same method and headers.
    fn send_following(
        &self,
        mut request: Request<'_>,
        out: &mut dyn Write,
        mut progress: Progress<'_>,
    ) -> RemoteResult<(u16, String)> {
        for hop in 0..=MAX_REDIRECTS {
            let current = request.url.clone();
            let (status, location, _) = self.send_once(&mut request, out, &mut progress)?;
            let is_redirect = matches!(status, 301 | 302 | 303 | 307 | 308);
            let Some(location) = location else {
                return Ok((status, current));
            };
            if !is_redirect || hop == MAX_REDIRECTS {
                return Ok((status, current));
            }
            let next = absolute_url(&current, &location)
                .ok_or_else(|| RemoteError::Server(format!("bad redirect target {location}")))?;
            // Never send Basic credentials from an https origin down to plain http without
            // an explicit allowance.
            if current.starts_with("https://")
                && next.starts_with("http://")
                && !request.allow_insecure
            {
                request
                    .headers
                    .retain(|(name, _)| !name.eq_ignore_ascii_case("authorization"));
            }
            // A PUT body must be sent again at the new location.
            if let Body::Stream { reader, .. } = &mut request.body {
                reader.seek(SeekFrom::Start(0))?;
            }
            request.url = next;
        }
        Err(RemoteError::Server("too many redirects".into()))
    }
}

impl Transport for WinHttp {
    /// Arke (#381): follow redirects and return the URL the WebDAV place ended up at.
    fn resolve(&self, url: &str) -> RemoteResult<Option<String>> {
        let request = Request {
            method: "PROPFIND",
            url: url.to_owned(),
            headers: vec![("Depth", "0".into())],
            body: Body::Empty,
            allow_insecure: true,
            ignore_cert_errors: true,
        };
        let (_, final_url) = self.send_following(request, &mut std::io::sink(), &mut |_| true)?;
        Ok((final_url != url).then_some(final_url))
    }

    fn send(
        &self,
        request: Request<'_>,
        out: &mut dyn Write,
        progress: Progress<'_>,
    ) -> RemoteResult<u16> {
        let (status, _) = self.send_following(request, out, progress)?;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_urls() {
        assert_eq!(
            split("https://h/a%20b/"),
            Some((true, "h".into(), 443, "/a%20b/"))
        );
        assert_eq!(
            split("http://127.0.0.1:8080"),
            Some((false, "127.0.0.1".into(), 8080, "/"))
        );
        assert_eq!(
            split("http://[::1]:81/x"),
            Some((false, "::1".into(), 81, "/x"))
        );
        assert_eq!(split("ftp://h/"), None);
    }

    #[test]
    fn follows_307_and_keeps_webdav_headers() {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for expect_depth in [false, true] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut headers = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                    headers.push_str(&line);
                }
                let response = if expect_depth && headers.to_ascii_lowercase().contains("depth: 0")
                {
                    "HTTP/1.1 207 Multi-Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else if !expect_depth {
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let http = WinHttp::new().unwrap();
        let request = Request {
            method: "PROPFIND",
            url: format!("http://{addr}/start"),
            headers: vec![("Depth", "0".into())],
            body: Body::Empty,
            allow_insecure: true,
            ignore_cert_errors: true,
        };
        let (status, final_url) = http
            .send_following(request, &mut std::io::sink(), &mut |_| true)
            .unwrap();
        assert_eq!(status, 207);
        assert!(final_url.ends_with("/final"));
        server.join().unwrap();
    }

    #[test]
    fn follows_301_without_changing_webdav_method() {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for expect_propfind in [false, true] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                }
                let ok = expect_propfind && request_line.starts_with("PROPFIND ");
                let response = if !expect_propfind {
                    "HTTP/1.1 301 Moved Permanently\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else if ok {
                    "HTTP/1.1 207 Multi-Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let http = WinHttp::new().unwrap();
        let request = Request {
            method: "PROPFIND",
            url: format!("http://{addr}/old"),
            headers: Vec::new(),
            body: Body::Empty,
            allow_insecure: true,
            ignore_cert_errors: true,
        };
        let (status, final_url) = http
            .send_following(request, &mut std::io::sink(), &mut |_| true)
            .unwrap();
        assert_eq!(status, 207);
        assert!(final_url.ends_with("/moved"));
        server.join().unwrap();
    }

    /// Live check against the reporter's server: `ARKE_TEST_DAV_URL=http://djwp.148368.xyz/dav`.
    #[test]
    #[ignore = "needs a live WebDAV server that redirects"]
    fn resolves_a_live_redirect() {
        let Ok(url) = std::env::var("ARKE_TEST_DAV_URL") else {
            return;
        };
        let http = WinHttp::new().unwrap();
        let final_url = http.resolve(&url).unwrap();
        assert!(final_url.is_some(), "server did not redirect");
        println!("final URL: {}", final_url.unwrap());
    }

    /// Live check with a self-signed HTTPS server: `ARKE_TEST_HTTPS_URL=https://localhost:8443/dav`.
    #[test]
    #[ignore = "needs a local HTTPS server with an untrusted certificate"]
    fn untrusted_certificate_toggle() {
        let Ok(url) = std::env::var("ARKE_TEST_HTTPS_URL") else {
            return;
        };
        let http = WinHttp::new().unwrap();
        let request = |ignore: bool| Request {
            method: "PROPFIND",
            url: url.clone(),
            headers: vec![("Depth", "0".into())],
            body: Body::Empty,
            allow_insecure: true,
            ignore_cert_errors: ignore,
        };
        assert!(
            http.send_following(request(false), &mut std::io::sink(), &mut |_| true)
                .is_err(),
            "an untrusted certificate must be rejected by default"
        );
        let (status, _) = http
            .send_following(request(true), &mut std::io::sink(), &mut |_| true)
            .unwrap();
        assert_eq!(status, 207);
    }

    #[test]
    fn resolves_redirect_locations() {
        assert_eq!(
            absolute_url("http://a/dav", "http://b:8080/x").as_deref(),
            Some("http://b:8080/x")
        );
        assert_eq!(
            absolute_url("http://a:81/dav/folder", "/next").as_deref(),
            Some("http://a:81/next")
        );
        assert_eq!(
            absolute_url("http://a/dav/folder", "child").as_deref(),
            Some("http://a/dav/child")
        );
    }
}
