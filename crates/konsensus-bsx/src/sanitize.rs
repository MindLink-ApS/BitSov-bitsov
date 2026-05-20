//! BSX content sanitization.
//!
//! Strips raw HTML tags from text content fields and validates that
//! inline markdown links use the `bitsov://` scheme exclusively.
//! This module enforces the sovereignty guarantee: peers cannot inject
//! arbitrary HTML or link to external resources.

use crate::model::{BsxBlock, BsxPage};

/// Strip HTML tags from a string, preserving the text content between them.
///
/// This is a simple state-machine stripper — it removes anything between
/// `<` and `>` inclusive. It does not attempt to parse HTML; it simply
/// ensures no raw markup survives into the renderer.
///
/// # Examples
///
/// ```
/// # use konsensus_bsx::sanitize::strip_html_tags;
/// assert_eq!(strip_html_tags("hello <b>world</b>"), "hello world");
/// assert_eq!(strip_html_tags("<script>alert('xss')</script>"), "alert('xss')");
/// assert_eq!(strip_html_tags("no tags here"), "no tags here");
/// ```
pub fn strip_html_tags(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut inside_tag = false;

    for c in input.chars() {
        match c {
            '<' => inside_tag = true,
            '>' if inside_tag => inside_tag = false,
            _ if !inside_tag => result.push(c),
            _ => {}
        }
    }

    result
}

/// Sanitize all text content fields in a BSX document by stripping HTML tags.
///
/// This modifies the document in place, removing any raw HTML from fields
/// that support inline markdown: text blocks, headings, quotes, list items,
/// card content, callout content, and feed entry titles/summaries.
pub fn sanitize_document(doc: &mut BsxPage) {
    // Sanitize metadata text fields.
    doc.meta.title = strip_html_tags(&doc.meta.title);
    if let Some(ref mut desc) = doc.meta.description {
        *desc = strip_html_tags(desc);
    }

    sanitize_blocks(&mut doc.blocks);
}

fn sanitize_blocks(blocks: &mut [BsxBlock]) {
    for block in blocks.iter_mut() {
        sanitize_block(block);
    }
}

fn sanitize_block(block: &mut BsxBlock) {
    match block {
        BsxBlock::Text { content } => {
            *content = strip_html_tags(content);
        }
        BsxBlock::Heading { text, .. } => {
            *text = strip_html_tags(text);
        }
        BsxBlock::Quote {
            content,
            attribution,
        } => {
            *content = strip_html_tags(content);
            if let Some(ref mut attr) = attribution {
                *attr = strip_html_tags(attr);
            }
        }
        BsxBlock::List { items, .. } => {
            for item in items.iter_mut() {
                *item = strip_html_tags(item);
            }
        }
        BsxBlock::Card { title, content } => {
            if let Some(ref mut t) = title {
                *t = strip_html_tags(t);
            }
            *content = strip_html_tags(content);
        }
        BsxBlock::Callout { content, .. } => {
            *content = strip_html_tags(content);
        }
        BsxBlock::Feed { entries } => {
            for entry in entries.iter_mut() {
                entry.title = strip_html_tags(&entry.title);
                if let Some(ref mut summary) = entry.summary {
                    *summary = strip_html_tags(summary);
                }
            }
        }
        BsxBlock::Grid { items, .. } => {
            sanitize_blocks(items);
        }
        // Code blocks preserve content verbatim (code is not markdown).
        // Image/Audio/Video/Table/Divider/Form/Embed have no markdown text.
        BsxBlock::Code { .. }
        | BsxBlock::Image { .. }
        | BsxBlock::Table { .. }
        | BsxBlock::Divider {}
        | BsxBlock::Form { .. }
        | BsxBlock::Embed { .. }
        | BsxBlock::Audio { .. }
        | BsxBlock::Video { .. } => {}
    }
}

/// Extract all markdown link URLs from text.
///
/// Finds `[text](url)` patterns and returns the URLs. This is intentionally
/// simple — it matches the same limited markdown that the renderer supports.
pub fn extract_markdown_links(text: &str) -> Vec<&str> {
    let mut links = Vec::new();
    let mut rest = text;

    while let Some(bracket_open) = rest.find('[') {
        let after_open = &rest[bracket_open + 1..];
        if let Some(bracket_close) = after_open.find(']') {
            let after_close = &after_open[bracket_close + 1..];
            if after_close.starts_with('(') {
                if let Some(paren_close) = after_close.find(')') {
                    let url = &after_close[1..paren_close];
                    links.push(url);
                    rest = &after_close[paren_close + 1..];
                    continue;
                }
            }
        }
        // No valid link found at this position, advance past the bracket.
        rest = &rest[bracket_open + 1..];
    }

    links
}

/// Check whether a URL uses the allowed `bitsov://` scheme.
///
/// Returns `true` for `bitsov://` URLs and relative paths (no scheme).
/// Returns `false` for `http://`, `https://`, `javascript:`, `data:`, etc.
pub fn is_allowed_link(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return true;
    }

    // Relative paths (no scheme) are allowed — they resolve within the mesh.
    // A scheme is present if we find ":" before any "/" or "?".
    if let Some(colon_pos) = trimmed.find(':') {
        // Check that everything before the colon is alphabetic (a valid scheme).
        let scheme_candidate = &trimmed[..colon_pos];
        if scheme_candidate
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c == '+' || c == '-' || c == '.')
            && !scheme_candidate.is_empty()
        {
            // It looks like a scheme — only allow bitsov://
            return scheme_candidate.eq_ignore_ascii_case("bitsov");
        }
    }

    // No scheme detected — treat as relative path (allowed).
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    // --- strip_html_tags ---

    #[test]
    fn strip_simple_tags() {
        assert_eq!(strip_html_tags("hello <b>world</b>"), "hello world");
    }

    #[test]
    fn strip_script_tag() {
        assert_eq!(
            strip_html_tags("<script>alert('xss')</script>"),
            "alert('xss')"
        );
    }

    #[test]
    fn strip_self_closing_tag() {
        assert_eq!(strip_html_tags("line<br/>break"), "linebreak");
    }

    #[test]
    fn strip_tag_with_attributes() {
        assert_eq!(
            strip_html_tags("<a href=\"http://evil.com\">click</a>"),
            "click"
        );
    }

    #[test]
    fn no_tags_unchanged() {
        assert_eq!(strip_html_tags("plain text"), "plain text");
    }

    #[test]
    fn empty_string() {
        assert_eq!(strip_html_tags(""), "");
    }

    #[test]
    fn preserves_angle_brackets_in_text() {
        // Unmatched > is kept (it's not inside a tag).
        assert_eq!(strip_html_tags("5 > 3"), "5 > 3");
    }

    #[test]
    fn nested_tags_stripped() {
        assert_eq!(
            strip_html_tags("<div><p>nested</p></div>"),
            "nested"
        );
    }

    #[test]
    fn markdown_preserved() {
        assert_eq!(
            strip_html_tags("**bold** and *italic*"),
            "**bold** and *italic*"
        );
    }

    // --- extract_markdown_links ---

    #[test]
    fn extract_single_link() {
        let links = extract_markdown_links("click [here](bitsov://node/page)");
        assert_eq!(links, vec!["bitsov://node/page"]);
    }

    #[test]
    fn extract_multiple_links() {
        let links =
            extract_markdown_links("[a](bitsov://x) and [b](bitsov://y)");
        assert_eq!(links, vec!["bitsov://x", "bitsov://y"]);
    }

    #[test]
    fn extract_no_links() {
        let links = extract_markdown_links("no links here");
        assert!(links.is_empty());
    }

    #[test]
    fn extract_link_with_path() {
        let links = extract_markdown_links("[page](bitsov://abc123/docs/intro)");
        assert_eq!(links, vec!["bitsov://abc123/docs/intro"]);
    }

    #[test]
    fn extract_ignores_malformed() {
        let links = extract_markdown_links("[no close paren](http://evil.com");
        assert!(links.is_empty());
    }

    // --- is_allowed_link ---

    #[test]
    fn bitsov_scheme_allowed() {
        assert!(is_allowed_link("bitsov://node123/page"));
        assert!(is_allowed_link("bitsov://abc/docs/intro"));
    }

    #[test]
    fn relative_path_allowed() {
        assert!(is_allowed_link("/about"));
        assert!(is_allowed_link("/blog/post-1"));
        assert!(is_allowed_link("page"));
    }

    #[test]
    fn http_rejected() {
        assert!(!is_allowed_link("http://evil.com"));
        assert!(!is_allowed_link("https://evil.com"));
    }

    #[test]
    fn javascript_rejected() {
        assert!(!is_allowed_link("javascript:alert(1)"));
    }

    #[test]
    fn data_rejected() {
        assert!(!is_allowed_link("data:text/html,<h1>hi</h1>"));
    }

    #[test]
    fn ftp_rejected() {
        assert!(!is_allowed_link("ftp://files.example.com"));
    }

    #[test]
    fn empty_allowed() {
        assert!(is_allowed_link(""));
        assert!(is_allowed_link("  "));
    }

    // --- sanitize_document ---

    fn minimal_doc() -> BsxPage {
        BsxPage {
            meta: BsxMeta {
                title: "Test".into(),
                author_pubkey: None,
                payment: None,
                description: None,
                created_at: None,
                updated_at: None,
            },
            style_hints: None,
            resources: vec![],
            blocks: vec![],
        }
    }

    #[test]
    fn sanitize_strips_html_from_text_block() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Text {
            content: "hello <b>world</b>".into(),
        }];
        sanitize_document(&mut doc);
        match &doc.blocks[0] {
            BsxBlock::Text { content } => assert_eq!(content, "hello world"),
            _ => panic!("expected text block"),
        }
    }

    #[test]
    fn sanitize_strips_html_from_heading() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Heading {
            level: 1,
            text: "<em>Title</em>".into(),
        }];
        sanitize_document(&mut doc);
        match &doc.blocks[0] {
            BsxBlock::Heading { text, .. } => assert_eq!(text, "Title"),
            _ => panic!("expected heading block"),
        }
    }

    #[test]
    fn sanitize_strips_html_from_list_items() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::List {
            ordered: false,
            items: vec!["<b>bold</b> item".into(), "normal".into()],
        }];
        sanitize_document(&mut doc);
        match &doc.blocks[0] {
            BsxBlock::List { items, .. } => {
                assert_eq!(items[0], "bold item");
                assert_eq!(items[1], "normal");
            }
            _ => panic!("expected list block"),
        }
    }

    #[test]
    fn sanitize_preserves_code_blocks() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Code {
            content: "<div>html code</div>".into(),
            language: Some("html".into()),
        }];
        sanitize_document(&mut doc);
        match &doc.blocks[0] {
            BsxBlock::Code { content, .. } => {
                assert_eq!(content, "<div>html code</div>");
            }
            _ => panic!("expected code block"),
        }
    }

    #[test]
    fn sanitize_strips_html_from_title() {
        let mut doc = minimal_doc();
        doc.meta.title = "<script>xss</script>Title".into();
        sanitize_document(&mut doc);
        assert_eq!(doc.meta.title, "xssTitle");
    }

    #[test]
    fn sanitize_strips_html_in_grid_children() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Grid {
            columns: 2,
            items: vec![BsxBlock::Text {
                content: "<img src=x>safe text".into(),
            }],
        }];
        sanitize_document(&mut doc);
        match &doc.blocks[0] {
            BsxBlock::Grid { items, .. } => match &items[0] {
                BsxBlock::Text { content } => assert_eq!(content, "safe text"),
                _ => panic!("expected text block"),
            },
            _ => panic!("expected grid block"),
        }
    }

    #[test]
    fn sanitize_strips_html_from_quote() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Quote {
            content: "<i>wise words</i>".into(),
            attribution: Some("<b>Author</b>".into()),
        }];
        sanitize_document(&mut doc);
        match &doc.blocks[0] {
            BsxBlock::Quote {
                content,
                attribution,
            } => {
                assert_eq!(content, "wise words");
                assert_eq!(attribution.as_deref(), Some("Author"));
            }
            _ => panic!("expected quote block"),
        }
    }

    #[test]
    fn sanitize_strips_html_from_callout() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Callout {
            variant: CalloutVariant::Warning,
            content: "<b>Warning!</b> Be careful".into(),
        }];
        sanitize_document(&mut doc);
        match &doc.blocks[0] {
            BsxBlock::Callout { content, .. } => {
                assert_eq!(content, "Warning! Be careful");
            }
            _ => panic!("expected callout block"),
        }
    }

    #[test]
    fn sanitize_strips_html_from_feed_entries() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Feed {
            entries: vec![FeedEntry {
                title: "<b>Post</b>".into(),
                path: "/blog/1".into(),
                summary: Some("<i>Summary</i>".into()),
                date: None,
            }],
        }];
        sanitize_document(&mut doc);
        match &doc.blocks[0] {
            BsxBlock::Feed { entries } => {
                assert_eq!(entries[0].title, "Post");
                assert_eq!(entries[0].summary.as_deref(), Some("Summary"));
            }
            _ => panic!("expected feed block"),
        }
    }
}
