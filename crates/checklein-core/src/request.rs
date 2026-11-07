//! Read-only view of an incoming HTTP request, independent of any host framework.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestView {
    pub method: String,
    /// `https` or `http`, lowercase.
    pub scheme: String,
    /// Host and optional non-default port, lowercase.
    pub authority: String,
    /// Path component, always starting with `/`.
    pub path: String,
    /// Query string without the leading `?`.
    pub query: Option<String>,
    headers: Vec<(String, String)>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestParseError {
    #[error("empty request")]
    Empty,
    #[error("malformed request line")]
    RequestLine,
    #[error("malformed header line: {0}")]
    Header(String),
    #[error("missing Host header")]
    MissingHost,
}

impl RequestView {
    /// Builds a view. `target` is the path with an optional `?query`.
    pub fn new(method: &str, scheme: &str, authority: &str, target: &str) -> Self {
        let scheme = scheme.to_ascii_lowercase();
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (target.to_string(), None),
        };
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path
        };
        RequestView {
            method: method.to_string(),
            authority: normalize_authority(&scheme, authority),
            scheme,
            path,
            query,
            headers: Vec::new(),
        }
    }

    /// Adds a header. Names are stored lowercase; order is preserved.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.push_header(name, value);
        self
    }

    pub fn push_header(&mut self, name: &str, value: &str) {
        self.headers
            .push((name.to_ascii_lowercase(), value.to_string()));
    }

    /// Removes every header with this name (used to strip spoofable `Checklein-*` headers).
    pub fn remove_header(&mut self, name: &str) {
        let name = name.to_ascii_lowercase();
        self.headers.retain(|(n, _)| *n != name);
    }

    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn has_header(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.headers.iter().any(|(n, _)| *n == name)
    }

    /// The field value as RFC 9421 §2.1 defines it: each value trimmed, then joined with `", "`.
    pub fn header(&self, name: &str) -> Option<String> {
        let name = name.to_ascii_lowercase();
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.trim())
            .collect();
        if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        }
    }

    /// `path?query`, as RFC 9421 `@request-target`.
    pub fn request_target(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{}", self.path, q),
            None => self.path.clone(),
        }
    }

    pub fn target_uri(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme,
            self.authority,
            self.request_target()
        )
    }

    /// Parses an HTTP/1.1 request head (body ignored). Used by the CLI and test vectors.
    pub fn parse_http1(raw: &str, scheme: &str) -> Result<Self, RequestParseError> {
        let mut lines = raw.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
        let first = lines
            .next()
            .filter(|l| !l.trim().is_empty())
            .ok_or(RequestParseError::Empty)?;
        let mut parts = first.split_whitespace();
        let (method, target) = match (parts.next(), parts.next()) {
            (Some(m), Some(t)) => (m, t),
            _ => return Err(RequestParseError::RequestLine),
        };
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| RequestParseError::Header(line.to_string()))?;
            if name.is_empty() || name.contains(char::is_whitespace) {
                return Err(RequestParseError::Header(line.to_string()));
            }
            headers.push((name.to_string(), value.trim().to_string()));
        }
        let host = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .ok_or(RequestParseError::MissingHost)?;
        let mut view = RequestView::new(method, scheme, &host, target);
        for (n, v) in headers {
            view.push_header(&n, &v);
        }
        Ok(view)
    }
}

fn normalize_authority(scheme: &str, authority: &str) -> String {
    let a = authority.trim().to_ascii_lowercase();
    let default_port = match scheme {
        "https" => Some(":443"),
        "http" => Some(":80"),
        _ => None,
    };
    match default_port {
        Some(p) if a.ends_with(p) => a[..a.len() - p.len()].to_string(),
        _ => a,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http1_and_combines_fields() {
        let raw =
            "GET /a?b=1 HTTP/1.1\r\nHost: Example.COM:443\r\nX-A: one \r\nx-a: two\r\n\r\nbody";
        let r = RequestView::parse_http1(raw, "https").unwrap();
        assert_eq!(r.authority, "example.com");
        assert_eq!(r.path, "/a");
        assert_eq!(r.query.as_deref(), Some("b=1"));
        assert_eq!(r.header("X-A").as_deref(), Some("one, two"));
        assert_eq!(r.target_uri(), "https://example.com/a?b=1");
    }

    #[test]
    fn rejects_missing_host() {
        assert_eq!(
            RequestView::parse_http1("GET / HTTP/1.1\r\n\r\n", "https"),
            Err(RequestParseError::MissingHost)
        );
    }
}
