// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, redacted command-line capture for OCSF process records.
//!
//! Capture is opt-in and off by default. When enabled, launch records may
//! include `process.cmd_line`. Redaction is a denylist of secret-looking
//! flag names and URL userinfo; a positional secret is not detected.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum number of argv slots (program plus arguments) written to `cmd_line`.
pub const MAX_CMD_LINE_ARGS: usize = 64;

/// Maximum number of Unicode characters written to `cmd_line`.
pub const MAX_CMD_LINE_CHARS: usize = 4096;

/// Suffix appended when argv is cut by [`MAX_CMD_LINE_ARGS`] or [`MAX_CMD_LINE_CHARS`].
pub const CMD_LINE_TRUNCATION_MARKER: &str = " ...";

/// Replacement for a denylisted flag value.
pub const REDACTED_ARG: &str = "<redacted>";

/// Long-flag names (without leading dashes) whose values are redacted.
///
/// Matching is case-insensitive. `--api-key` and `--api_key` are both listed
/// because either form appears in practice. This list is a denylist. It does
/// not catch positional secrets, values passed through a file flag, or
/// secrets encoded into paths.
pub const SENSITIVE_CMD_LINE_FLAGS: &[&str] =
    &["password", "token", "api-key", "api_key", "secret"];

/// Process-wide handle for `ocsf_cmd_line_enabled`.
///
/// Set once during sandbox start; the contained [`AtomicBool`] is updated by
/// the settings poll loop. Uninitialized reads treat capture as disabled.
pub static CMD_LINE_CAPTURE_ENABLED: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Return whether command-line capture is currently enabled.
///
/// Returns `false` when the flag has not been initialized.
#[must_use]
pub fn cmd_line_capture_enabled() -> bool {
    CMD_LINE_CAPTURE_ENABLED
        .get()
        .is_some_and(|flag| flag.load(Ordering::Relaxed))
}

/// Build a bounded, redacted command line from `program` and `args`.
///
/// Arguments are joined with spaces. Values that contain whitespace are
/// double-quoted. Control characters are escaped. Sensitive flag values and
/// URL userinfo are replaced. The result is capped at [`MAX_CMD_LINE_ARGS`]
/// slots and [`MAX_CMD_LINE_CHARS`] characters.
#[must_use]
pub fn sanitize_cmd_line<S: AsRef<str>>(program: &str, args: &[S]) -> String {
    let mut tokens = Vec::with_capacity(args.len() + 1);
    tokens.push(program);
    for arg in args {
        tokens.push(arg.as_ref());
    }

    let (rendered, hit_arg_limit) = render_argv(&tokens);
    let mut joined = join_quoted(&rendered);
    if hit_arg_limit {
        joined.push_str(CMD_LINE_TRUNCATION_MARKER);
    }
    truncate_cmd_line(&joined)
}

/// Escape a `cmd_line` value for the shorthand `[cmd:...]` field.
///
/// A raw newline would split the log line; a raw `]` would close the field
/// and let the remainder look like additional shorthand context.
#[must_use]
pub fn escape_shorthand_cmd_line(cmd: &str) -> String {
    let mut out = String::with_capacity(cmd.len());
    for c in cmd.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ']' => out.push_str("\\]"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let code = u32::from(c);
                let _ = write!(out, "\\u{{{code:x}}}");
            }
            c => out.push(c),
        }
    }
    out
}

fn render_argv(tokens: &[&str]) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if out.len() >= MAX_CMD_LINE_ARGS {
            return (out, true);
        }
        let token = tokens[i];
        if let Some(flag) = long_flag_prefix(token)
            && is_sensitive_flag_name(flag_name(flag))
        {
            if let Some((flag_part, _)) = token.split_once('=') {
                out.push(format!("{flag_part}={REDACTED_ARG}"));
                i += 1;
                continue;
            }
            out.push(token.to_string());
            i += 1;
            if i < tokens.len() && out.len() < MAX_CMD_LINE_ARGS {
                out.push(REDACTED_ARG.to_string());
                i += 1;
            }
            continue;
        }
        out.push(redact_url_userinfo(token));
        i += 1;
    }
    (out, false)
}

fn long_flag_prefix(token: &str) -> Option<&str> {
    let rest = token.strip_prefix("--")?;
    if rest.is_empty() {
        return None;
    }
    Some(token)
}

fn flag_name(flag: &str) -> &str {
    let rest = flag.strip_prefix("--").unwrap_or(flag);
    rest.split_once('=').map_or(rest, |(name, _)| name)
}

fn is_sensitive_flag_name(name: &str) -> bool {
    SENSITIVE_CMD_LINE_FLAGS
        .iter()
        .any(|flag| name.eq_ignore_ascii_case(flag))
}

fn redact_url_userinfo(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(scheme_end) = remaining.find("://") {
        output.push_str(&remaining[..scheme_end + 3]);
        remaining = &remaining[scheme_end + 3..];
        let auth_end = remaining.find(['/', '?', '#']).unwrap_or(remaining.len());
        let authority = &remaining[..auth_end];
        if let Some(at) = authority.rfind('@') {
            output.push_str("REDACTED");
            output.push_str(&authority[at..]);
        } else {
            output.push_str(authority);
        }
        remaining = &remaining[auth_end..];
    }
    output.push_str(remaining);
    output
}

fn join_quoted(args: &[String]) -> String {
    args.iter()
        .map(|arg| quote_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_arg(arg: &str) -> String {
    let escaped = escape_controls(arg);
    let needs_quotes = escaped.is_empty() || escaped.chars().any(|c| c.is_whitespace() || c == '"');
    if !needs_quotes {
        return escaped;
    }
    let mut quoted = String::from('"');
    for c in escaped.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

fn escape_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let code = u32::from(c);
                let _ = write!(out, "\\u{{{code:x}}}");
            }
            c => out.push(c),
        }
    }
    out
}

fn truncate_cmd_line(s: &str) -> String {
    let marker_len = CMD_LINE_TRUNCATION_MARKER.chars().count();
    if s.chars().count() <= MAX_CMD_LINE_CHARS {
        return s.to_string();
    }
    let keep = MAX_CMD_LINE_CHARS.saturating_sub(marker_len);
    let mut out: String = s.chars().take(keep).collect();
    out.push_str(CMD_LINE_TRUNCATION_MARKER);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_includes_non_path_argument() {
        let cmd = sanitize_cmd_line("curl", &["https://github.com/zen"]);
        assert_eq!(cmd, "curl https://github.com/zen");
        assert!(cmd.contains("https://github.com/zen"));
        assert!(!cmd.starts_with('/'));
    }

    #[test]
    fn sanitize_quotes_whitespace_arguments() {
        let cmd = sanitize_cmd_line("python3", &["/app/main.py", "file with space.txt"]);
        assert_eq!(cmd, r#"python3 /app/main.py "file with space.txt""#);
    }

    #[test]
    fn sanitize_redacts_password_token_api_key_and_secret() {
        let cmd = sanitize_cmd_line(
            "tool",
            &[
                "--password",
                "hunter2",
                "--token=abcd",
                "--api-key",
                "k",
                "--secret=shh",
                "https://github.com",
            ],
        );
        assert_eq!(
            cmd,
            "tool --password <redacted> --token=<redacted> --api-key <redacted> --secret=<redacted> https://github.com"
        );
        assert!(!cmd.contains("hunter2"));
        assert!(!cmd.contains("abcd"));
        assert!(!cmd.contains("--api-key k"));
        assert!(!cmd.contains("shh"));
    }

    #[test]
    fn sanitize_redacts_sensitive_flags_case_insensitively() {
        let cmd = sanitize_cmd_line("tool", &["--Password", "x", "--TOKEN=y"]);
        assert_eq!(cmd, "tool --Password <redacted> --TOKEN=<redacted>");
        assert!(!cmd.contains('x'));
        assert!(!cmd.contains('y'));
    }

    #[test]
    fn sanitize_does_not_treat_password_file_as_sensitive() {
        let cmd = sanitize_cmd_line("tool", &["--password-file", "/tmp/pw"]);
        assert_eq!(cmd, "tool --password-file /tmp/pw");
    }

    #[test]
    fn sanitize_redacts_url_userinfo() {
        let cmd = sanitize_cmd_line("curl", &["https://user:s3cret@api.example.com/v1?x=1"]);
        assert_eq!(cmd, "curl https://REDACTED@api.example.com/v1?x=1");
        assert!(!cmd.contains("s3cret"));
        assert!(!cmd.contains("user:"));
    }

    #[test]
    fn sanitize_redacts_url_userinfo_inside_equals_flag() {
        let cmd = sanitize_cmd_line("tool", &["--url=http://alice:pw@host/path"]);
        assert_eq!(cmd, "tool --url=http://REDACTED@host/path");
        assert!(!cmd.contains("alice"));
        assert!(!cmd.contains("pw@"));
    }

    #[test]
    fn sanitize_leaves_urls_without_userinfo() {
        let cmd = sanitize_cmd_line("curl", &["https://api.example.com/v1"]);
        assert_eq!(cmd, "curl https://api.example.com/v1");
    }

    #[test]
    fn sanitize_truncates_at_argument_bound() {
        let args: Vec<String> = (0..MAX_CMD_LINE_ARGS).map(|i| format!("arg{i}")).collect();
        let cmd = sanitize_cmd_line("prog", &args);
        assert!(cmd.ends_with(CMD_LINE_TRUNCATION_MARKER));
        assert!(!cmd.contains(&format!("arg{}", MAX_CMD_LINE_ARGS - 1)));
        assert!(cmd.contains("arg0"));
        let slots = cmd
            .trim_end_matches(CMD_LINE_TRUNCATION_MARKER)
            .split(' ')
            .count();
        assert_eq!(slots, MAX_CMD_LINE_ARGS);
    }

    #[test]
    fn sanitize_truncates_at_character_bound() {
        let long = "a".repeat(MAX_CMD_LINE_CHARS + 50);
        let cmd = sanitize_cmd_line("p", &[long.as_str()]);
        assert!(cmd.ends_with(CMD_LINE_TRUNCATION_MARKER));
        assert_eq!(cmd.chars().count(), MAX_CMD_LINE_CHARS);
        assert!(cmd.starts_with("p "));
    }

    #[test]
    fn sanitize_escapes_control_characters() {
        let cmd = sanitize_cmd_line("echo", &["hello\nworld"]);
        assert_eq!(cmd, r"echo hello\nworld");
        assert!(!cmd.contains('\n'));
    }

    #[test]
    fn cmd_line_capture_defaults_to_disabled_when_uninitialized() {
        if CMD_LINE_CAPTURE_ENABLED.get().is_none() {
            assert!(!cmd_line_capture_enabled());
        }
    }

    #[test]
    fn escape_shorthand_cmd_line_neutralizes_bracket_and_newline() {
        let escaped = escape_shorthand_cmd_line("echo foo]bar\nbaz");
        assert_eq!(escaped, r"echo foo\]bar\nbaz");
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\r'));
    }

    #[test]
    fn sensitive_flag_list_covers_documented_names() {
        for name in ["password", "token", "api-key", "secret"] {
            assert!(
                SENSITIVE_CMD_LINE_FLAGS
                    .iter()
                    .any(|flag| flag.eq_ignore_ascii_case(name)),
                "missing denylist entry {name}"
            );
        }
    }
}
