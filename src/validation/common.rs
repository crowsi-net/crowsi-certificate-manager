pub fn valid_id(value: &str) -> bool {
    (8..=256).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

/// Accepts only the canonical, case-stable target syntax used for fence keys.
pub fn valid_canonical_resource_id(value: &str) -> bool {
    valid_id(value)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
        && value.split('/').all(|segment| {
            segment
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub fn valid_key_version(value: &str) -> bool {
    (8..=160).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

pub fn valid_encoded(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
        })
}

pub fn valid_service_uri(value: &str) -> bool {
    uri_path(value, "service://")
}

pub fn valid_https_uri(value: &str) -> bool {
    uri_path(value, "https://")
}

pub fn valid_authority_uri(value: &str) -> bool {
    uri_path(value, "authority://")
}

pub fn valid_scopes(scopes: &[String], max: usize) -> bool {
    !scopes.is_empty()
        && scopes.len() <= max
        && scopes.windows(2).all(|pair| pair[0] < pair[1])
        && scopes.iter().all(|scope| valid_id(scope))
}

pub fn valid_spiffe_id(value: &str) -> bool {
    uri_path(value, "spiffe://")
}

pub fn valid_spiffe_prefix(value: &str) -> bool {
    value.strip_suffix('/').is_some_and(valid_spiffe_id)
}

fn uri_path(value: &str, prefix: &str) -> bool {
    if value.len() > 2_048 {
        return false;
    }
    let Some(value) = value.strip_prefix(prefix) else {
        return false;
    };
    let Some((authority, path)) = value.split_once('/') else {
        return false;
    };
    let segments = path.split('/').collect::<Vec<_>>();
    valid_authority(authority)
        && !segments.is_empty()
        && segments.len() <= 32
        && segments.into_iter().all(valid_segment)
}

fn valid_authority(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::{valid_canonical_resource_id, valid_https_uri, valid_service_uri, valid_spiffe_id};

    #[test]
    fn uri_rejects_too_many_segments() {
        let path = vec!["segment"; 33].join("/");
        assert!(!valid_spiffe_id(&format!("spiffe://example.test/{path}")));
    }

    #[test]
    fn uri_rejects_total_length_over_limit() {
        let path = vec!["a".repeat(128); 16].join("/");
        assert!(!valid_service_uri(&format!(
            "service://example.test/{path}"
        )));
    }

    #[test]
    fn uri_accepts_bounded_lowercase_paths() {
        assert!(valid_https_uri(
            "https://ihat.online/pa/certificate-lifecycle"
        ));
    }

    #[test]
    fn canonical_resource_rejects_case_aliases_and_dot_segments() {
        assert!(valid_canonical_resource_id(
            "resource.certificate/nerp-worker"
        ));
        assert!(!valid_canonical_resource_id(
            "resource.certificate/NERP-worker"
        ));
        assert!(!valid_canonical_resource_id("resource/../nerp-worker"));
    }
}
