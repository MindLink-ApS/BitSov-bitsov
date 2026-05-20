/**
 * Shared markdown rendering utilities.
 * Used by BrowserView (sovereign browser) and MyContent (editor preview).
 *
 * Security: No remote image loading (Principle 4), no script execution.
 * Only data: URIs allowed for images.
 */

/** Escape HTML entities. */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Render inline markdown: bold, italic, code, links, images, strikethrough. */
export function renderInline(text: string): string {
  let s = escapeHtml(text);

  // Images: ![alt](src)
  s = s.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, (_m, alt: string, src: string) => {
    // Only allow data: URIs (base64 inline) — no remote loading (Principle 4)
    if (src.startsWith("data:")) {
      return `<img src="${src}" alt="${alt}" class="browser-inline-img" />`;
    }
    return `<span class="browser-img-blocked" title="Remote images blocked (Principle 4)">[image: ${alt}]</span>`;
  });

  // Links: [text](url) — detect konsensus:// for internal navigation
  s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, text: string, href: string) => {
    if (href.startsWith("konsensus://") || href.startsWith("/")) {
      return `<a href="${href}" class="browser-internal-link" data-internal="true">${text}</a>`;
    }
    return `<a href="${href}" target="_blank" rel="noopener noreferrer" class="browser-external-link">${text}</a>`;
  });

  // Bold+italic
  s = s.replace(/\*\*\*(.+?)\*\*\*/g, "<strong><em>$1</em></strong>");
  // Bold
  s = s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  // Italic
  s = s.replace(/\*(.+?)\*/g, "<em>$1</em>");
  // Strikethrough
  s = s.replace(/~~(.+?)~~/g, "<del>$1</del>");
  // Inline code (must come after link processing)
  s = s.replace(/`([^`]+)`/g, "<code>$1</code>");

  return s;
}

/** Parse table cells from a row like "| a | b | c |". */
function parseCells(row: string): string[] {
  const trimmed = row.trim();
  const stripped = trimmed.startsWith("|") ? trimmed.slice(1) : trimmed;
  const end = stripped.endsWith("|") ? stripped.slice(0, -1) : stripped;
  return end.split("|");
}

/** Check if a line starts a block element. */
function isBlockStart(line: string): boolean {
  if (line.startsWith("```")) return true;
  if (/^#{1,6}\s/.test(line)) return true;
  if (/^(---|\*\*\*|___)$/.test(line.trim())) return true;
  if (line.startsWith("> ")) return true;
  if (/^[\s]*[-*+]\s/.test(line)) return true;
  if (/^\d+\.\s/.test(line)) return true;
  return false;
}

/** Parse markdown string into sanitized HTML — block-level parser. */
export function renderMarkdown(md: string): string {
  const lines = md.split("\n");
  const out: string[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        codeLines.push(escapeHtml(lines[i]));
        i++;
      }
      i++; // skip closing ```
      const langAttr = lang ? ` class="language-${escapeHtml(lang)}"` : "";
      out.push(`<pre><code${langAttr}>${codeLines.join("\n")}</code></pre>`);
      continue;
    }

    // Headings
    const headingMatch = line.match(/^(#{1,6})\s+(.+)$/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      out.push(`<h${level}>${renderInline(headingMatch[2])}</h${level}>`);
      i++;
      continue;
    }

    // Horizontal rule
    if (/^(---|\*\*\*|___)$/.test(line.trim())) {
      out.push("<hr />");
      i++;
      continue;
    }

    // Table (GFM style)
    if (line.includes("|") && i + 1 < lines.length && /^\|?\s*[-:]+[-| :]*$/.test(lines[i + 1])) {
      const rows: string[] = [];
      const headerCells = parseCells(line);
      const alignRow = parseCells(lines[i + 1]);
      const aligns = alignRow.map((c) => {
        const t = c.trim();
        if (t.startsWith(":") && t.endsWith(":")) return "center";
        if (t.endsWith(":")) return "right";
        return "left";
      });

      rows.push("<thead><tr>");
      headerCells.forEach((cell, ci) => {
        const align = aligns[ci] || "left";
        rows.push(`<th style="text-align:${align}">${renderInline(cell.trim())}</th>`);
      });
      rows.push("</tr></thead>");

      i += 2;
      rows.push("<tbody>");
      while (i < lines.length && lines[i].includes("|")) {
        const cells = parseCells(lines[i]);
        rows.push("<tr>");
        cells.forEach((cell, ci) => {
          const align = aligns[ci] || "left";
          rows.push(`<td style="text-align:${align}">${renderInline(cell.trim())}</td>`);
        });
        rows.push("</tr>");
        i++;
      }
      rows.push("</tbody>");
      out.push(`<table>${rows.join("")}</table>`);
      continue;
    }

    // Blockquote
    if (line.startsWith("> ") || line === ">") {
      const bqLines: string[] = [];
      while (i < lines.length && (lines[i].startsWith("> ") || lines[i] === ">")) {
        bqLines.push(lines[i].replace(/^>\s?/, ""));
        i++;
      }
      out.push(`<blockquote>${renderMarkdown(bqLines.join("\n"))}</blockquote>`);
      continue;
    }

    // Unordered list
    if (/^[\s]*[-*+]\s/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^[\s]*[-*+]\s/.test(lines[i])) {
        const content = lines[i].replace(/^[\s]*[-*+]\s/, "");
        if (content.startsWith("[ ] ")) {
          items.push(`<li><input type="checkbox" disabled /> ${renderInline(content.slice(4))}</li>`);
        } else if (content.startsWith("[x] ") || content.startsWith("[X] ")) {
          items.push(`<li><input type="checkbox" checked disabled /> ${renderInline(content.slice(4))}</li>`);
        } else {
          items.push(`<li>${renderInline(content)}</li>`);
        }
        i++;
      }
      out.push(`<ul>${items.join("")}</ul>`);
      continue;
    }

    // Ordered list
    if (/^\d+\.\s/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        items.push(`<li>${renderInline(lines[i].replace(/^\d+\.\s/, ""))}</li>`);
        i++;
      }
      out.push(`<ol>${items.join("")}</ol>`);
      continue;
    }

    // Empty line
    if (line.trim() === "") {
      i++;
      continue;
    }

    // Paragraph — collect consecutive non-empty lines
    const paraLines: string[] = [];
    while (i < lines.length && lines[i].trim() !== "" && !isBlockStart(lines[i])) {
      paraLines.push(lines[i]);
      i++;
    }
    if (paraLines.length > 0) {
      out.push(`<p>${paraLines.map(renderInline).join("<br />")}</p>`);
    }
  }

  return out.join("\n");
}
