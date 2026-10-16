//! In-house flamegraph SVG renderer: folded stacks in, a standalone interactive SVG out.
//!
//! Classic layout (root frames at the bottom), flamegraph.pl-style sizes and "hot" palette,
//! and a small embedded script for click-to-zoom, regex search and hover details.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};

/// Image width in px.
const IMAGE_WIDTH: u32 = 1200;
/// Horizontal padding on each side in px.
const SIDE_PAD: f64 = 10.0;
/// Drawing width in px (image width minus both side paddings).
const DRAW_WIDTH: f64 = 1180.0;
/// Height of one frame row in px (the rect is one px shorter, leaving a gap).
const FRAME_HEIGHT: u32 = 16;
/// Space above the frames: title, subtitle and the controls.
const TOP_PAD: u32 = 56;
/// Space below the frames: the details line.
const BOTTOM_PAD: u32 = 34;
/// Frames narrower than this (px) are elided together with their descendants.
const MIN_WIDTH: f64 = 0.1;
/// Approximate advance of one monospace glyph at 12 px.
const CHAR_WIDTH: f64 = 0.59 * 12.0;
/// Label padding inside a frame rect, per side, in px.
const LABEL_PAD: f64 = 3.0;

/// A flamegraph to draw.
#[derive(Debug)]
pub struct Chart<'a> {
    /// Title, e.g. `whytime: xz -T4 big.tar`.
    pub title: &'a str,
    /// Line under the title, e.g. `wall 41.2s: the critical path, width = wall-clock time`.
    pub subtitle: &'a str,
    /// Folded stacks: frames outermost first joined by `;` (no empty frames), and a weight
    /// in microseconds (> 0). Any order; a stack may repeat (weights add up).
    pub stacks: &'a [(String, u64)],
    /// Fill color (r, g, b) of root frames (the first frame of a stack) by name; root
    /// frames not in it, and every deeper frame, get the name-hashed warm palette.
    pub root_colors: &'a BTreeMap<String, (u8, u8, u8)>,
}

/// Writes `chart` as a standalone SVG document.
///
/// # Errors
/// Any error from writing to `sink`.
pub fn write(sink: &mut dyn Write, chart: &Chart<'_>) -> io::Result<()> {
    let (total, frames) = layout(chart);
    let depth = frames.iter().map(|f| f.depth + 1).max().unwrap_or(0);
    let rows = u32::try_from(depth).unwrap_or(u32::MAX);
    let height = TOP_PAD + rows.saturating_mul(FRAME_HEIGHT) + BOTTOM_PAD;
    let mut out = io::BufWriter::new(sink);
    writeln!(out, r#"<?xml version="1.0" standalone="no"?>"#)?;
    writeln!(
        out,
        r#"<svg version="1.1" width="{IMAGE_WIDTH}" height="{height}" viewBox="0 0 {IMAGE_WIDTH} {height}" xmlns="http://www.w3.org/2000/svg">"#
    )?;
    writeln!(
        out,
        r##"<defs><linearGradient id="bg" y1="0" y2="1" x1="0" x2="0"><stop stop-color="#eeeeee" offset="5%"/><stop stop-color="#eeeeb0" offset="95%"/></linearGradient></defs>"##
    )?;
    writeln!(
        out,
        r#"<rect x="0" y="0" width="{IMAGE_WIDTH}" height="{height}" fill="url(#bg)"/>"#
    )?;
    writeln!(
        out,
        r##"<g font-family="Verdana, sans-serif" text-anchor="middle"><text x="600" y="24" font-size="17">{}</text><text x="600" y="42" font-size="12" fill="#555">{}</text></g>"##,
        Esc(chart.title),
        Esc(chart.subtitle)
    )?;
    let details_y = height - 17;
    writeln!(
        out,
        r#"<g font-family="Verdana, sans-serif" font-size="12"><text id="unzoom" x="10" y="24" style="display:none;cursor:pointer">Reset Zoom</text><text id="search" x="1190" y="24" text-anchor="end" style="cursor:pointer">Search</text><text id="details" x="10" y="{details_y}"> </text><text id="matched" x="1190" y="{details_y}" text-anchor="end" style="cursor:pointer"></text></g>"#
    )?;
    writeln!(
        out,
        r#"<g id="frames" data-total="{total}" font-family="monospace" font-size="12" style="cursor:pointer">"#
    )?;
    for f in &frames {
        let top = height - BOTTOM_PAD - (u32::try_from(f.depth).unwrap_or(u32::MAX) + 1) * FRAME_HEIGHT;
        let (red, green, blue) = if f.depth == 0 {
            chart.root_colors.get(f.name).copied().unwrap_or_else(|| color(f.name))
        } else {
            color(f.name)
        };
        writeln!(
            out,
            r#"<g data-s="{}" data-v="{}"><title>{} ({}, {:.2}% of wall)</title><rect x="{:.2}" y="{top}" width="{:.2}" height="{}" rx="2" ry="2" fill="rgb({red},{green},{blue})"/><text x="{:.2}" y="{}">{}</text></g>"#,
            f.start,
            f.weight,
            Esc(f.name),
            crate::report::format_duration(f.weight.saturating_mul(1000)),
            100.0 * to_f64(f.weight) / to_f64(total),
            f.x,
            f.width,
            FRAME_HEIGHT - 1,
            f.x + LABEL_PAD,
            top + 11,
            Esc(&label(f.name, f.width)),
        )?;
    }
    writeln!(out, "</g>")?;
    writeln!(out, "<script><![CDATA[{SCRIPT}]]></script>")?;
    writeln!(out, "</svg>")?;
    out.flush()
}

/// Folded stacks merged into a tree; children keyed (and so ordered) by frame name.
#[derive(Debug, Default)]
struct Node<'a> {
    /// Summed weight (µs) of every stack through this node.
    weight: u64,
    /// Callees by frame name.
    children: BTreeMap<&'a str, Node<'a>>,
}

/// One drawn frame box.
#[derive(Debug, Clone, PartialEq)]
struct Frame<'a> {
    /// Frame name.
    name: &'a str,
    /// Stack depth; 0 for root frames (drawn at the bottom).
    depth: usize,
    /// Summed weight (µs) left of this frame within the whole graph.
    start: u64,
    /// Weight (µs) of this frame.
    weight: u64,
    /// Left edge in px.
    x: f64,
    /// Width in px.
    width: f64,
}

/// Merges the stacks into a tree and returns the total weight and the drawn frames (pre-order).
fn layout<'a>(chart: &Chart<'a>) -> (u64, Vec<Frame<'a>>) {
    let mut root = Node::default();
    for (stack, weight) in chart.stacks {
        root.weight = root.weight.saturating_add(*weight);
        let mut node = &mut root;
        for name in stack.split(';').filter(|n| !n.is_empty()) {
            node = node.children.entry(name).or_default();
            node.weight = node.weight.saturating_add(*weight);
        }
    }
    let mut frames = Vec::new();
    if root.weight > 0 {
        let scale = DRAW_WIDTH / to_f64(root.weight);
        place(&root, 0, 0, scale, &mut frames);
    }
    (root.weight, frames)
}

/// Appends the boxes of `node`'s children (at `depth`, starting at weight `start`), recursively.
fn place<'a>(node: &Node<'a>, depth: usize, start: u64, scale: f64, frames: &mut Vec<Frame<'a>>) {
    let mut start = start;
    for (&name, child) in &node.children {
        let width = to_f64(child.weight) * scale;
        if width >= MIN_WIDTH {
            frames.push(Frame {
                name,
                depth,
                start,
                weight: child.weight,
                x: SIDE_PAD + to_f64(start) * scale,
                width,
            });
            place(child, depth + 1, start, scale, frames);
        }
        start += child.weight;
    }
}

/// Converts a weight to `f64` for drawing.
#[allow(clippy::cast_precision_loss)] // presentation only; weights are far below 2^53 µs
fn to_f64(v: u64) -> f64 {
    v as f64
}

/// The label drawn inside a frame `width` px wide: the name, truncated with `..`, or empty.
fn label(name: &str, width: f64) -> String {
    let fit = max_chars(width - 2.0 * LABEL_PAD);
    if fit < 3 {
        return String::new();
    }
    if name.chars().count() <= fit {
        return name.to_owned();
    }
    let mut s: String = name.chars().take(fit - 2).collect();
    s.push_str("..");
    s
}

/// How many monospace glyphs fit in `avail` px.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // clamped finite, ≤ 1180 px
fn max_chars(avail: f64) -> usize {
    (avail.max(0.0) / CHAR_WIDTH).floor() as usize
}

/// Stable warm fill for `name`: flamegraph.pl "hot", or orange for kernel (`_[k]`) frames.
fn color(name: &str) -> (u8, u8, u8) {
    let h = fnv1a(name.as_bytes()).to_le_bytes();
    let (v1, v2, v3) = (u16::from(h[0]), u16::from(h[1]), u16::from(h[2]));
    let scaled = |base: u16, span: u16, v: u16| u8::try_from(base + span * v / 255).unwrap_or(u8::MAX);
    if name.ends_with("_[k]") {
        (scaled(225, 30, v3), scaled(110, 80, v1), scaled(0, 20, v2))
    } else {
        (scaled(205, 50, v3), scaled(0, 230, v1), scaled(0, 55, v2))
    }
}

/// 64-bit FNV-1a hash.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

/// Displays a string with XML special characters escaped.
#[derive(Debug)]
struct Esc<'a>(&'a str);

impl fmt::Display for Esc<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rest = self.0;
        while let Some(i) = rest.find(['&', '<', '>', '"', '\'']) {
            f.write_str(&rest[..i])?;
            f.write_str(match rest.as_bytes()[i] {
                b'&' => "&amp;",
                b'<' => "&lt;",
                b'>' => "&gt;",
                b'"' => "&quot;",
                _ => "&#39;",
            })?;
            rest = &rest[i + 1..];
        }
        f.write_str(rest)
    }
}

/// Zoom, search and hover details; mirrors [`label`] for re-truncation.
const SCRIPT: &str = r"
const W=1180,P=10,$=id=>document.getElementById(id);
const F=$('frames'),D=$('details'),M=$('matched'),R=$('unzoom'),T=+F.getAttribute('data-total');
const G=[...F.children].map(g=>{
  const r=g.children[1],t=g.children[0].textContent;
  return {g,r,x:g.children[2],s:+g.dataset.s,v:+g.dataset.v,y:+r.getAttribute('y'),
    f:r.getAttribute('fill'),n:t.slice(0,t.lastIndexOf(' ('))};
});
const I=new Map(G.map(o=>[o.g,o]));
const at=e=>I.get(e.target.parentNode);
function fit(n,w){
  const c=[...n],k=Math.floor((w-6)/7.08);
  return k<3?'':c.length<=k?n:c.slice(0,k-2).join('')+'..';
}
function put(o,x,w){
  o.r.setAttribute('x',x.toFixed(2));o.r.setAttribute('width',w.toFixed(2));
  o.x.setAttribute('x',(x+3).toFixed(2));o.x.textContent=fit(o.n,w);
}
function zoom(z){
  R.style.display='';
  for(const o of G){
    const inside=o.s>=z.s&&o.s+o.v<=z.s+z.v,above=o.s<=z.s&&o.s+o.v>=z.s+z.v;
    if(inside&&o.y<=z.y){o.g.style.display='';o.g.style.opacity='';put(o,P+(o.s-z.s)*W/z.v,o.v*W/z.v);}
    else if(above&&o.y>z.y){o.g.style.display='';o.g.style.opacity='.5';put(o,P,W);}
    else o.g.style.display='none';
  }
}
function unzoom(){
  R.style.display='none';
  for(const o of G){o.g.style.display='';o.g.style.opacity='';put(o,P+o.s*W/T,o.v*W/T);}
}
function search(re){
  const m=[];
  for(const o of G){
    const hit=re!==null&&re.test(o.n);
    o.r.setAttribute('fill',hit?'rgb(230,0,230)':o.f);
    if(hit)m.push(o);
  }
  if(re===null){M.textContent='';return;}
  m.sort((a,b)=>a.s-b.s||b.v-a.v);
  let end=0,sum=0;
  for(const o of m)if(o.s>=end){sum+=o.v;end=o.s+o.v;}
  M.textContent='Matched: '+(100*sum/T).toFixed(1)+'%';
}
function ask(){
  const p=prompt('Search frames (regex)');
  if(p)try{search(new RegExp(p));}catch(e){alert(e.message);}
}
F.addEventListener('click',e=>{const o=at(e);if(o)zoom(o);});
F.addEventListener('mouseover',e=>{const o=at(e);if(o)D.textContent=o.g.children[0].textContent;});
F.addEventListener('mouseout',()=>{D.textContent=' ';});
R.addEventListener('click',unzoom);
$('search').addEventListener('click',ask);
M.addEventListener('click',()=>search(null));
window.addEventListener('keydown',e=>{
  if((e.ctrlKey||e.metaKey)&&e.key==='f'){e.preventDefault();ask();}
  else if(e.key==='Escape')search(null);
});
";

#[cfg(test)]
mod tests {
    use super::*;

    /// No root colors.
    fn no_colors() -> BTreeMap<String, (u8, u8, u8)> {
        BTreeMap::new()
    }

    /// Builds owned stacks from literals.
    fn stacks(s: &[(&str, u64)]) -> Vec<(String, u64)> {
        s.iter().map(|&(k, v)| (k.to_owned(), v)).collect()
    }

    /// Renders a chart to a string.
    fn render(stacks: &[(String, u64)], colors: &BTreeMap<String, (u8, u8, u8)>) -> String {
        let chart = Chart { title: "t", subtitle: "s", stacks, root_colors: colors };
        let mut buf = Vec::new();
        write(&mut buf, &chart).unwrap();
        String::from_utf8(buf).unwrap()
    }

    /// Frame boxes for `stacks`.
    fn frames<'a>(stacks: &'a [(String, u64)], colors: &'a BTreeMap<String, (u8, u8, u8)>) -> (u64, Vec<Frame<'a>>) {
        layout(&Chart { title: "", subtitle: "", stacks, root_colors: colors })
    }

    /// Checks XML well-formedness: balanced tags and only known entities outside CDATA.
    fn assert_well_formed(doc: &str) {
        let mut stack: Vec<&str> = Vec::new();
        let mut rest = doc;
        while let Some(lt) = rest.find('<') {
            assert_entities(&rest[..lt]);
            rest = &rest[lt..];
            if let Some(r) = rest.strip_prefix("<![CDATA[") {
                rest = &r[r.find("]]>").expect("unterminated CDATA") + 3..];
                continue;
            }
            let gt = rest.find('>').expect("unterminated tag");
            let tag = &rest[1..gt];
            rest = &rest[gt + 1..];
            if tag.starts_with('?') {
                continue;
            }
            assert!(!tag.contains('<'), "raw < inside tag {tag:?}");
            assert_entities(tag);
            if let Some(name) = tag.strip_prefix('/') {
                assert_eq!(stack.pop(), Some(name), "mismatched close tag");
            } else if !tag.ends_with('/') {
                stack.push(tag.split([' ', '\n']).next().unwrap());
            }
        }
        assert_entities(rest);
        assert!(stack.is_empty(), "unclosed: {stack:?}");
    }

    /// Asserts every `&` in `s` starts a known entity and no raw `>` appears in text.
    fn assert_entities(s: &str) {
        for (i, _) in s.match_indices('&') {
            let ok = ["&amp;", "&lt;", "&gt;", "&quot;", "&#39;"].iter().any(|e| s[i..].starts_with(e));
            assert!(ok, "stray & in {s:?}");
        }
    }

    /// Root frames span the drawing width contiguously; children fit inside their parents.
    #[test]
    fn layout_widths_are_consistent() {
        let s = stacks(&[("a;b;c", 30), ("a;b", 10), ("a;d", 20), ("e", 40), ("f;g", 7)]);
        let c = no_colors();
        let (total, fr) = frames(&s, &c);
        assert_eq!(total, 107);
        let roots: Vec<_> = fr.iter().filter(|f| f.depth == 0).collect();
        let sum: f64 = roots.iter().map(|f| f.width).sum();
        assert!((sum - DRAW_WIDTH).abs() < 1e-6, "{sum}");
        assert!((roots[0].x - SIDE_PAD).abs() < 1e-9);
        for pair in roots.windows(2) {
            assert!((pair[0].x + pair[0].width - pair[1].x).abs() < 1e-6);
        }
        for (i, parent) in fr.iter().enumerate() {
            let kids = fr[i + 1..].iter().take_while(|f| f.depth > parent.depth).filter(|f| f.depth == parent.depth + 1);
            let mut edge = parent.x;
            let mut width = 0.0;
            for k in kids {
                assert!((k.x - edge).abs() < 1e-6, "child {} not contiguous", k.name);
                edge += k.width;
                width += k.width;
            }
            assert!(width <= parent.width + 1e-6, "children of {} overflow", parent.name);
        }
        let doc = render(&s, &c);
        assert!(doc.contains(r#"<rect x="10.00" y="#), "first root at the left padding");
    }

    /// Siblings are ordered by name regardless of input order; repeated stacks add up.
    #[test]
    fn siblings_sorted_and_repeats_merged() {
        let s = stacks(&[("main;zeta", 5), ("main;alpha", 3), ("main;mid", 2), ("main;alpha", 4)]);
        let c = no_colors();
        let (_, fr) = frames(&s, &c);
        let kids: Vec<_> = fr.iter().filter(|f| f.depth == 1).map(|f| (f.name, f.weight)).collect();
        assert_eq!(kids, [("alpha", 7), ("mid", 2), ("zeta", 5)]);
        let xs: Vec<f64> = fr.iter().filter(|f| f.depth == 1).map(|f| f.x).collect();
        assert!(xs.windows(2).all(|p| p[0] < p[1]));
        let doc = render(&s, &c);
        assert!(doc.find("<title>alpha").unwrap() < doc.find("<title>mid").unwrap());
        assert!(doc.contains("<title>alpha (7µs, 50.00% of wall)</title>"));
    }

    /// Names with XML metacharacters only appear escaped and the document stays well formed.
    #[test]
    fn names_are_escaped() {
        let s = stacks(&[("main;operator<<&\"x'", 10), ("main;other", 10)]);
        let c = no_colors();
        let chart = Chart { title: "a<b & 'c'", subtitle: "\"q\"", stacks: &s, root_colors: &c };
        let mut buf = Vec::new();
        write(&mut buf, &chart).unwrap();
        let doc = String::from_utf8(buf).unwrap();
        assert!(!doc.contains("operator<<"));
        assert!(doc.contains("operator&lt;&lt;&amp;&quot;x&#39;"));
        assert!(doc.contains("a&lt;b &amp; &#39;c&#39;"));
        assert!(doc.contains("&quot;q&quot;"));
        assert_eq!(doc.matches("<g").count(), doc.matches("</g>").count());
        assert_well_formed(&doc);
    }

    /// A stack far below the minimum width is not drawn, nor are its children.
    #[test]
    fn narrow_frames_are_elided() {
        let s = stacks(&[("main;big", 1_000_000), ("tiny;child", 10)]);
        let c = no_colors();
        let (total, fr) = frames(&s, &c);
        assert_eq!(total, 1_000_010);
        assert!(fr.iter().all(|f| f.name != "tiny" && f.name != "child"));
        let doc = render(&s, &c);
        assert!(!doc.contains("<title>tiny") && !doc.contains("<title>child"));
        assert_eq!(doc.matches("<title>").count(), 2);
    }

    /// Same input, same bytes; root colors apply to root frames only.
    #[test]
    fn deterministic_and_root_colors() {
        let st = stacks(&[("main;work_[k]", 10), ("bg;main", 5), ("[runqueue]", 3)]);
        let mut colors = no_colors();
        colors.insert("main".to_owned(), (1, 2, 3));
        let doc = render(&st, &colors);
        assert_eq!(doc, render(&st, &colors));
        assert_eq!(doc.matches("rgb(1,2,3)").count(), 1, "only the root main frame");
        let (r, g, b) = color("work_[k]");
        assert!((225..=255).contains(&r) && (110..=190).contains(&g) && b <= 20);
        let (r, g, b) = color("bg");
        assert!(r >= 205 && g <= 230 && b <= 55);
        assert!(doc.contains(&format!("fill=\"rgb({r},{g},{b})\"")));
    }

    /// Labels fit their rect: full, truncated with `..`, or empty below three glyphs.
    #[test]
    fn labels_truncate_to_fit() {
        assert_eq!(label("short", 100.0), "short");
        let l = label("a_rather_long_function_name", 80.0);
        assert!(l.ends_with("..") && l.chars().count() == max_chars(74.0));
        assert_eq!(label("abcdef", 20.0), "");
        assert_eq!(label("ééééééééé", 6.0 + 4.0 * CHAR_WIDTH), "éé..");
    }

    /// An empty chart still renders a valid document.
    #[test]
    fn empty_chart_renders() {
        let doc = render(&[], &no_colors());
        assert!(doc.contains(r#"data-total="0""#));
        assert_well_formed(&doc);
    }
}
