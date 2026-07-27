//! BSX to HTML renderer.
//!
//! Transforms a validated [`BsxPage`] into safe HTML. The output uses
//! only semantic HTML elements and class names — styling is applied by the
//! local node's CSS, not by the document author. This is the core
//! sovereignty guarantee: the peer provides content, your node provides
//! presentation.
//!
//! **Security guarantees:**
//! - All text content is HTML-escaped (no XSS)
//! - No inline styles, no JavaScript, no external URLs
//! - Resources referenced by `konsensus://` protocol URLs only
//! - Form actions point to local node endpoints only

use crate::model::{BsxBlock, BsxPage, CalloutVariant, FontPreference, FormFieldType};

/// Render a BSX document to an HTML string.
///
/// The output is a complete HTML fragment (not a full page with `<html>`/`<head>`).
/// The caller wraps this in whatever page chrome is appropriate (title bar,
/// sidebar, status bar, etc.).
///
/// Resource hashes are turned into `konsensus://resource/{hash}` URLs for
/// the custom protocol handler to resolve.
pub fn render_to_html(doc: &BsxPage) -> String {
    let mut html = String::with_capacity(4096);

    // Root wrapper with optional data attributes for style hints.
    html.push_str("<article class=\"bsx-document\"");
    if let Some(ref hints) = doc.style_hints {
        if let Some(ref color) = hints.accent_color {
            html.push_str(" data-accent=\"");
            html.push_str(&escape_attr(color));
            html.push('"');
        }
        if let Some(ref font) = hints.font_preference {
            let class = match font {
                FontPreference::SansSerif => "sans-serif",
                FontPreference::Serif => "serif",
                FontPreference::Monospace => "monospace",
            };
            html.push_str(" data-font=\"");
            html.push_str(class);
            html.push('"');
        }
    }
    html.push('>');

    // Document title
    html.push_str("<header class=\"bsx-header\"><h1 class=\"bsx-title\">");
    html.push_str(&escape_html(&doc.meta.title));
    html.push_str("</h1>");

    // Payment notice
    if let Some(ref payment) = doc.meta.payment {
        html.push_str("<div class=\"bsx-payment-notice\">");
        html.push_str(&escape_html(&format!("{}⚡ sats", payment.amount_sats)));
        html.push_str("</div>");
    }

    html.push_str("</header>");

    // Render blocks
    for block in &doc.blocks {
        render_block(&mut html, block);
    }

    html.push_str("</article>");
    html
}

fn render_block(html: &mut String, block: &BsxBlock) {
    match block {
        BsxBlock::Text { content } => {
            html.push_str("<p class=\"bsx-text\">");
            html.push_str(&render_inline_markdown(content));
            html.push_str("</p>");
        }
        BsxBlock::Heading { level, text } => {
            let tag = match level {
                1 => "h1",
                2 => "h2",
                3 => "h3",
                4 => "h4",
                5 => "h5",
                _ => "h6",
            };
            html.push('<');
            html.push_str(tag);
            html.push_str(" class=\"bsx-heading\">");
            html.push_str(&escape_html(text));
            html.push_str("</");
            html.push_str(tag);
            html.push('>');
        }
        BsxBlock::Image {
            resource_hash,
            caption,
            alt,
        } => {
            html.push_str("<figure class=\"bsx-image\">");
            html.push_str("<img src=\"konsensus://resource/");
            html.push_str(&escape_attr(resource_hash));
            html.push_str("\" alt=\"");
            html.push_str(&escape_attr(alt.as_deref().unwrap_or("")));
            html.push_str("\" loading=\"lazy\">");
            if let Some(cap) = caption {
                html.push_str("<figcaption>");
                html.push_str(&escape_html(cap));
                html.push_str("</figcaption>");
            }
            html.push_str("</figure>");
        }
        BsxBlock::Code { content, language } => {
            html.push_str("<pre class=\"bsx-code\"><code");
            if let Some(lang) = language {
                html.push_str(" class=\"language-");
                html.push_str(&escape_attr(lang));
                html.push('"');
            }
            html.push('>');
            html.push_str(&escape_html(content));
            html.push_str("</code></pre>");
        }
        BsxBlock::Table {
            caption,
            headers,
            rows,
        } => {
            html.push_str("<table class=\"bsx-table\">");
            if let Some(cap) = caption {
                html.push_str("<caption>");
                html.push_str(&escape_html(cap));
                html.push_str("</caption>");
            }
            html.push_str("<thead><tr>");
            for header in headers {
                html.push_str("<th>");
                html.push_str(&escape_html(header));
                html.push_str("</th>");
            }
            html.push_str("</tr></thead><tbody>");
            for row in rows {
                html.push_str("<tr>");
                for cell in row {
                    html.push_str("<td>");
                    html.push_str(&escape_html(cell));
                    html.push_str("</td>");
                }
                html.push_str("</tr>");
            }
            html.push_str("</tbody></table>");
        }
        BsxBlock::Divider {} => {
            html.push_str("<hr class=\"bsx-divider\">");
        }
        BsxBlock::Quote {
            content,
            attribution,
        } => {
            html.push_str("<blockquote class=\"bsx-quote\"><p>");
            html.push_str(&render_inline_markdown(content));
            html.push_str("</p>");
            if let Some(attr) = attribution {
                html.push_str("<footer>— ");
                html.push_str(&escape_html(attr));
                html.push_str("</footer>");
            }
            html.push_str("</blockquote>");
        }
        BsxBlock::List { ordered, items } => {
            let tag = if *ordered { "ol" } else { "ul" };
            html.push('<');
            html.push_str(tag);
            html.push_str(" class=\"bsx-list\">");
            for item in items {
                html.push_str("<li>");
                html.push_str(&render_inline_markdown(item));
                html.push_str("</li>");
            }
            html.push_str("</");
            html.push_str(tag);
            html.push('>');
        }
        BsxBlock::Card { title, content } => {
            html.push_str("<div class=\"bsx-card\">");
            if let Some(t) = title {
                html.push_str("<h3 class=\"bsx-card-title\">");
                html.push_str(&escape_html(t));
                html.push_str("</h3>");
            }
            html.push_str("<div class=\"bsx-card-body\">");
            html.push_str(&render_inline_markdown(content));
            html.push_str("</div></div>");
        }
        BsxBlock::Form {
            fields,
            submit_label,
            payment_amount,
        } => {
            html.push_str("<form class=\"bsx-form\" method=\"post\" action=\"konsensus://form/submit\">");
            for field in fields {
                html.push_str("<div class=\"bsx-form-field\">");
                html.push_str("<label>");
                html.push_str(&escape_html(&field.label));
                html.push_str("</label>");
                match &field.field_type {
                    FormFieldType::Text | FormFieldType::Email | FormFieldType::Number => {
                        let input_type = match &field.field_type {
                            FormFieldType::Email => "email",
                            FormFieldType::Number => "number",
                            _ => "text",
                        };
                        html.push_str("<input type=\"");
                        html.push_str(input_type);
                        html.push_str("\" name=\"");
                        html.push_str(&escape_attr(&field.name));
                        html.push('"');
                        if let Some(ref ph) = field.placeholder {
                            html.push_str(" placeholder=\"");
                            html.push_str(&escape_attr(ph));
                            html.push('"');
                        }
                        if field.required {
                            html.push_str(" required");
                        }
                        html.push('>');
                    }
                    FormFieldType::Textarea => {
                        html.push_str("<textarea name=\"");
                        html.push_str(&escape_attr(&field.name));
                        html.push('"');
                        if let Some(ref ph) = field.placeholder {
                            html.push_str(" placeholder=\"");
                            html.push_str(&escape_attr(ph));
                            html.push('"');
                        }
                        if field.required {
                            html.push_str(" required");
                        }
                        html.push_str("></textarea>");
                    }
                    FormFieldType::Select { options } => {
                        html.push_str("<select name=\"");
                        html.push_str(&escape_attr(&field.name));
                        html.push_str("\">");
                        for opt in options {
                            html.push_str("<option value=\"");
                            html.push_str(&escape_attr(opt));
                            html.push_str("\">");
                            html.push_str(&escape_html(opt));
                            html.push_str("</option>");
                        }
                        html.push_str("</select>");
                    }
                    FormFieldType::Checkbox => {
                        html.push_str("<input type=\"checkbox\" name=\"");
                        html.push_str(&escape_attr(&field.name));
                        html.push('"');
                        if field.required {
                            html.push_str(" required");
                        }
                        html.push('>');
                    }
                }
                html.push_str("</div>");
            }
            html.push_str("<button type=\"submit\" class=\"bsx-form-submit\">");
            html.push_str(&escape_html(submit_label));
            if *payment_amount > 0 {
                html.push_str(" (");
                html.push_str(&payment_amount.to_string());
                html.push_str("⚡)");
            }
            html.push_str("</button></form>");
        }
        BsxBlock::Embed {
            source_pubkey,
            path,
        } => {
            html.push_str("<div class=\"bsx-embed\" data-source=\"");
            html.push_str(&escape_attr(source_pubkey));
            html.push_str("\" data-path=\"");
            html.push_str(&escape_attr(path));
            html.push_str("\"><p class=\"bsx-embed-placeholder\">Embedded content from ");
            html.push_str(&escape_html(&source_pubkey[..8.min(source_pubkey.len())]));
            html.push_str("...</p></div>");
        }
        BsxBlock::Audio {
            resource_hash,
            title,
        } => {
            html.push_str("<div class=\"bsx-audio\">");
            if let Some(t) = title {
                html.push_str("<p class=\"bsx-audio-title\">");
                html.push_str(&escape_html(t));
                html.push_str("</p>");
            }
            html.push_str("<audio controls src=\"konsensus://resource/");
            html.push_str(&escape_attr(resource_hash));
            html.push_str("\"></audio></div>");
        }
        BsxBlock::Video {
            resource_hash,
            caption,
        } => {
            html.push_str("<div class=\"bsx-video\">");
            html.push_str("<video controls src=\"konsensus://resource/");
            html.push_str(&escape_attr(resource_hash));
            html.push_str("\"></video>");
            if let Some(cap) = caption {
                html.push_str("<p class=\"bsx-video-caption\">");
                html.push_str(&escape_html(cap));
                html.push_str("</p>");
            }
            html.push_str("</div>");
        }
        BsxBlock::Grid { columns, items } => {
            html.push_str("<div class=\"bsx-grid\" data-columns=\"");
            html.push_str(&columns.to_string());
            html.push_str("\">");
            for item in items {
                html.push_str("<div class=\"bsx-grid-item\">");
                render_block(html, item);
                html.push_str("</div>");
            }
            html.push_str("</div>");
        }
        BsxBlock::Callout { variant, content } => {
            let variant_class = match variant {
                CalloutVariant::Info => "info",
                CalloutVariant::Warning => "warning",
                CalloutVariant::Error => "error",
                CalloutVariant::Success => "success",
            };
            html.push_str("<div class=\"bsx-callout bsx-callout-");
            html.push_str(variant_class);
            html.push_str("\">");
            html.push_str(&render_inline_markdown(content));
            html.push_str("</div>");
        }
        BsxBlock::Feed { entries } => {
            html.push_str("<div class=\"bsx-feed\">");
            for entry in entries {
                html.push_str("<a class=\"bsx-feed-entry\" href=\"konsensus://page");
                html.push_str(&escape_attr(&entry.path));
                html.push_str("\">");
                html.push_str("<h3>");
                html.push_str(&escape_html(&entry.title));
                html.push_str("</h3>");
                if let Some(ref date) = entry.date {
                    html.push_str("<time>");
                    html.push_str(&escape_html(date));
                    html.push_str("</time>");
                }
                if let Some(ref summary) = entry.summary {
                    html.push_str("<p>");
                    html.push_str(&escape_html(summary));
                    html.push_str("</p>");
                }
                html.push_str("</a>");
            }
            html.push_str("</div>");
        }
    }
}

/// Render limited inline markdown: **bold**, *italic*, `code`, [link](url).
///
/// Only supports these four constructs. All text is HTML-escaped first,
/// then patterns are applied. This is safe because we escape before
/// transforming, so user content cannot inject HTML.
fn render_inline_markdown(text: &str) -> String {
    let escaped = escape_html(text);

    // Bold: **text**
    let result = apply_inline_pattern(&escaped, "**", "<strong>", "</strong>");
    // Italic: *text* (but not inside **)
    let result = apply_single_star_italic(&result);
    // Inline code: `text`
    apply_inline_pattern(&result, "`", "<code>", "</code>")
}

/// Apply a symmetric delimiter pattern (like ** or `).
fn apply_inline_pattern(input: &str, delim: &str, open_tag: &str, close_tag: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut rest = input;
    let mut inside = false;

    while let Some(pos) = rest.find(delim) {
        result.push_str(&rest[..pos]);
        if inside {
            result.push_str(close_tag);
        } else {
            result.push_str(open_tag);
        }
        inside = !inside;
        rest = &rest[pos + delim.len()..];
    }
    result.push_str(rest);

    // If we have an unclosed delimiter, it was a false positive — remove the open tag.
    if inside {
        result = result.replacen(open_tag, delim, 1);
    }

    result
}

/// Apply single-star italic, being careful not to match inside <strong> tags
/// (which were already inserted by the bold pass).
fn apply_single_star_italic(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut inside_italic = false;

    while let Some(c) = chars.next() {
        if c == '*' {
            // Check if this is a standalone * (not part of **)
            if chars.peek() == Some(&'*') {
                // This is **, pass through both
                result.push('*');
                result.push('*');
                chars.next();
                continue;
            }
            if inside_italic {
                result.push_str("</em>");
            } else {
                result.push_str("<em>");
            }
            inside_italic = !inside_italic;
        } else {
            result.push(c);
        }
    }

    // Unclosed italic — revert
    if inside_italic {
        result = result.replacen("<em>", "*", 1);
    }

    result
}

/// Escape HTML special characters.
fn escape_html(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(c),
        }
    }
    result
}

/// Escape for use in HTML attribute values.
fn escape_attr(s: &str) -> String {
    escape_html(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn minimal_doc() -> BsxPage {
        BsxPage {
            meta: BsxMeta {
                title: "Test Page".into(),
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
    fn render_empty_document() {
        let doc = minimal_doc();
        let html = render_to_html(&doc);
        assert!(html.contains("<article class=\"bsx-document\">"));
        assert!(html.contains("<h1 class=\"bsx-title\">Test Page</h1>"));
        assert!(html.contains("</article>"));
    }

    #[test]
    fn render_text_block() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Text {
            content: "Hello **world**".into(),
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("<p class=\"bsx-text\">Hello <strong>world</strong></p>"));
    }

    #[test]
    fn render_heading_levels() {
        let mut doc = minimal_doc();
        doc.blocks = vec![
            BsxBlock::Heading { level: 1, text: "H1".into() },
            BsxBlock::Heading { level: 3, text: "H3".into() },
        ];
        let html = render_to_html(&doc);
        assert!(html.contains("<h1 class=\"bsx-heading\">H1</h1>"));
        assert!(html.contains("<h3 class=\"bsx-heading\">H3</h3>"));
    }

    #[test]
    fn render_image() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Image {
            resource_hash: "blake3:abc".into(),
            caption: Some("A photo".into()),
            alt: Some("Alt text".into()),
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("src=\"konsensus://resource/blake3:abc\""));
        assert!(html.contains("alt=\"Alt text\""));
        assert!(html.contains("<figcaption>A photo</figcaption>"));
    }

    #[test]
    fn render_code_block() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Code {
            content: "fn main() {}".into(),
            language: Some("rust".into()),
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("class=\"language-rust\""));
        assert!(html.contains("fn main() {}"));
    }

    #[test]
    fn render_table() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Table {
            caption: Some("Data".into()),
            headers: vec!["A".into(), "B".into()],
            rows: vec![vec!["1".into(), "2".into()]],
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("<caption>Data</caption>"));
        assert!(html.contains("<th>A</th>"));
        assert!(html.contains("<td>1</td>"));
    }

    #[test]
    fn render_divider() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Divider {}];
        let html = render_to_html(&doc);
        assert!(html.contains("<hr class=\"bsx-divider\">"));
    }

    #[test]
    fn render_quote_with_attribution() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Quote {
            content: "Be sovereign".into(),
            attribution: Some("Satoshi".into()),
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("<blockquote class=\"bsx-quote\">"));
        assert!(html.contains("Be sovereign"));
        assert!(html.contains("— Satoshi"));
    }

    #[test]
    fn render_ordered_list() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::List {
            ordered: true,
            items: vec!["one".into(), "two".into()],
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("<ol class=\"bsx-list\">"));
        assert!(html.contains("<li>one</li>"));
    }

    #[test]
    fn render_unordered_list() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::List {
            ordered: false,
            items: vec!["a".into()],
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("<ul class=\"bsx-list\">"));
    }

    #[test]
    fn render_card() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Card {
            title: Some("Info".into()),
            content: "Card body".into(),
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("<div class=\"bsx-card\">"));
        assert!(html.contains("Info"));
        assert!(html.contains("Card body"));
    }

    #[test]
    fn render_form_with_payment() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Form {
            fields: vec![FormField {
                name: "email".into(),
                label: "Email".into(),
                field_type: FormFieldType::Email,
                required: true,
                placeholder: Some("you@example.com".into()),
            }],
            submit_label: "Send".into(),
            payment_amount: 25,
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("type=\"email\""));
        assert!(html.contains("required"));
        assert!(html.contains("placeholder=\"you@example.com\""));
        assert!(html.contains("Send (25⚡)"));
    }

    #[test]
    fn render_callout_variants() {
        let mut doc = minimal_doc();
        doc.blocks = vec![
            BsxBlock::Callout { variant: CalloutVariant::Warning, content: "Watch out".into() },
            BsxBlock::Callout { variant: CalloutVariant::Success, content: "Done".into() },
        ];
        let html = render_to_html(&doc);
        assert!(html.contains("bsx-callout-warning"));
        assert!(html.contains("bsx-callout-success"));
    }

    #[test]
    fn render_grid() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Grid {
            columns: 2,
            items: vec![
                BsxBlock::Text { content: "col1".into() },
                BsxBlock::Text { content: "col2".into() },
            ],
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("data-columns=\"2\""));
        assert!(html.contains("bsx-grid-item"));
    }

    #[test]
    fn render_feed() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Feed {
            entries: vec![FeedEntry {
                title: "Post 1".into(),
                path: "/blog/1".into(),
                summary: Some("A summary".into()),
                date: Some("2026-04-01".into()),
            }],
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("konsensus://page/blog/1"));
        assert!(html.contains("Post 1"));
        assert!(html.contains("A summary"));
    }

    #[test]
    fn render_payment_notice() {
        let mut doc = minimal_doc();
        doc.meta.payment = Some(PaymentMeta { amount_sats: 100 });
        let html = render_to_html(&doc);
        assert!(html.contains("bsx-payment-notice"));
        assert!(html.contains("100"));
    }

    #[test]
    fn html_escaping_prevents_xss() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Text {
            content: "<script>alert('xss')</script>".into(),
        }];
        let html = render_to_html(&doc);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn inline_markdown_bold() {
        assert_eq!(
            render_inline_markdown("hello **world**"),
            "hello <strong>world</strong>"
        );
    }

    #[test]
    fn inline_markdown_italic() {
        assert_eq!(
            render_inline_markdown("hello *world*"),
            "hello <em>world</em>"
        );
    }

    #[test]
    fn inline_markdown_code() {
        assert_eq!(
            render_inline_markdown("use `println!`"),
            "use <code>println!</code>"
        );
    }

    #[test]
    fn inline_markdown_unclosed_bold() {
        // Unclosed ** should be left as-is
        assert_eq!(
            render_inline_markdown("hello **world"),
            "hello **world"
        );
    }

    #[test]
    fn style_hints_as_data_attributes() {
        let mut doc = minimal_doc();
        doc.style_hints = Some(StyleHints {
            accent_color: Some("#336699".into()),
            font_preference: Some(FontPreference::Serif),
            theme: None,
        });
        let html = render_to_html(&doc);
        assert!(html.contains("data-accent=\"#336699\""));
        assert!(html.contains("data-font=\"serif\""));
    }

    #[test]
    fn render_audio_video() {
        let mut doc = minimal_doc();
        doc.blocks = vec![
            BsxBlock::Audio {
                resource_hash: "blake3:audio1".into(),
                title: Some("Song".into()),
            },
            BsxBlock::Video {
                resource_hash: "blake3:video1".into(),
                caption: Some("Clip".into()),
            },
        ];
        let html = render_to_html(&doc);
        assert!(html.contains("<audio controls"));
        assert!(html.contains("konsensus://resource/blake3:audio1"));
        assert!(html.contains("<video controls"));
        assert!(html.contains("konsensus://resource/blake3:video1"));
    }

    #[test]
    fn render_select_field() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Form {
            fields: vec![FormField {
                name: "color".into(),
                label: "Color".into(),
                field_type: FormFieldType::Select {
                    options: vec!["Red".into(), "Blue".into()],
                },
                required: false,
                placeholder: None,
            }],
            submit_label: "Pick".into(),
            payment_amount: 0,
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("<select"));
        assert!(html.contains("<option value=\"Red\">Red</option>"));
        assert!(html.contains("<option value=\"Blue\">Blue</option>"));
    }

    #[test]
    fn render_checkbox_field() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Form {
            fields: vec![FormField {
                name: "agree".into(),
                label: "I agree".into(),
                field_type: FormFieldType::Checkbox,
                required: true,
                placeholder: None,
            }],
            submit_label: "Submit".into(),
            payment_amount: 0,
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("type=\"checkbox\""));
        assert!(html.contains("required"));
    }

    #[test]
    fn render_embed() {
        let mut doc = minimal_doc();
        let source_pubkey = "demo-source-pubkey";
        doc.blocks = vec![BsxBlock::Embed {
            source_pubkey: source_pubkey.into(),
            path: "/about".into(),
        }];
        let html = render_to_html(&doc);
        assert!(html.contains("bsx-embed"));
        assert!(html.contains("data-source=\"demo-source-pubkey\""));
        assert!(html.contains("demo-sou..."));
    }
}
