//! Hostnames for network peers, from what the traced programs' resolvers told them.
//!
//! The kernel side copies what tracked threads receive from resolver sockets (DNS servers on
//! port 53, over UDP or TCP, and systemd-resolved's varlink socket), plus the requests they
//! send to resolved, into [`DnsRecord`]s. [`Hosts`] parses them (DNS answers: question, CNAME
//! chain, A/AAAA records; varlink: the `ResolveHostname` request's name and the reply's
//! addresses) into the most recent name per address. It makes no lookup of its own (no
//! reverse DNS, no `/etc/hosts`), so a replayed trace names peers exactly as the live run did.
//!
//! Payloads are cut at `DNS_BYTES` and come from untrusted programs: every parser takes what
//! it can from a truncated message and rejects malformed ones, never panicking.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use whytime_abi::{DNS_TCP, DNS_UDP, DNS_VARLINK, DnsRecord};

/// The resolver method whose request names the host and whose reply lists its addresses.
const RESOLVE_HOSTNAME: &str = "io.systemd.Resolve.ResolveHostname";
/// DNS record type A (IPv4 address).
const TYPE_A: u16 = 1;
/// DNS record type CNAME (alias).
const TYPE_CNAME: u16 = 5;
/// DNS record type AAAA (IPv6 address).
const TYPE_AAAA: u16 = 28;
/// DNS question type ANY.
const TYPE_ANY: u16 = 255;
/// Longest name kept (RFC 1035: 255 bytes on the wire, 253 as text).
const MAX_NAME: usize = 253;
/// Labels plus compression pointers followed while reading one name.
const MAX_NAME_STEPS: usize = 128;
/// CNAMEs followed from a question.
const MAX_ALIASES: usize = 16;
/// JSON nesting accepted.
const MAX_DEPTH: usize = 32;

/// Address → name, from the resolver traffic of the traced tree.
#[derive(Debug, Default)]
pub struct Hosts {
    /// The latest name each address was the answer for.
    names: HashMap<IpAddr, Arc<str>>,
    /// Per resolver connection, `(tgid, socket inode)`.
    conns: HashMap<(u32, u64), Conn>,
}

/// What a resolver connection carried so far.
#[derive(Debug, Default)]
struct Conn {
    /// TCP: the last read was just the 2-byte length, so the next one is the message.
    body_next: bool,
    /// varlink: the name of the pending `ResolveHostname` request.
    asked: Option<Arc<str>>,
}

impl Hosts {
    /// Learns from one captured payload.
    pub fn ingest(&mut self, r: &DnsRecord) {
        let len = usize::try_from(r.len).map_or(0, |n| n.min(r.data.len()));
        let data = &r.data[..len];
        let conn = (r.hdr.tgid, r.ino);
        match u32::from(r.transport) {
            DNS_UDP if r.sent == 0 => self.answer(data),
            DNS_TCP if r.sent == 0 => {
                let state = self.conns.entry(conn).or_default();
                if r.total == 2 && len == 2 {
                    state.body_next = true;
                    return;
                }
                let message = if std::mem::take(&mut state.body_next) {
                    data
                } else {
                    data.get(2..).unwrap_or_default()
                };
                self.answer(message);
            }
            DNS_VARLINK => {
                for message in data.split(|&b| b == 0).filter(|m| !m.is_empty()) {
                    self.varlink(conn, r.sent != 0, message);
                }
            }
            _ => {}
        }
    }

    /// The name `ip` was last resolved from.
    pub fn name(&self, ip: IpAddr) -> Option<&Arc<str>> {
        self.names.get(&ip)
    }

    /// Learns from one DNS message (an answer, else nothing).
    fn answer(&mut self, message: &[u8]) {
        if let Some((name, addrs)) = dns_answer(message) {
            self.learn(&name, addrs);
        }
    }

    /// Learns from one varlink message on connection `conn`: a `ResolveHostname` request
    /// (`sent`) names the host of the reply that follows it.
    fn varlink(&mut self, conn: (u32, u64), sent: bool, message: &[u8]) {
        let Some(json) = Json::parse(message) else {
            return;
        };
        let state = self.conns.entry(conn).or_default();
        if sent {
            if json.get("method").and_then(Json::as_str) == Some(RESOLVE_HOSTNAME) {
                state.asked = json
                    .get("parameters")
                    .and_then(|p| p.get("name"))
                    .and_then(Json::as_str)
                    .and_then(hostname);
            }
            return;
        }
        let Some(params) = json.get("parameters") else {
            return;
        };
        let addrs = varlink_addresses(params);
        if addrs.is_empty() {
            return;
        }
        // The name the program asked for; the reply's is the canonical one, after CNAMEs.
        let name = state.asked.take().or_else(|| {
            params
                .get("name")
                .and_then(Json::as_str)
                .and_then(hostname)
        });
        if let Some(name) = name {
            self.learn(&name, addrs);
        }
    }

    /// `addrs` now resolve to `name`.
    fn learn(&mut self, name: &Arc<str>, addrs: impl IntoIterator<Item = IpAddr>) {
        for ip in addrs {
            self.names.insert(ip.to_canonical(), Arc::clone(name));
        }
    }
}

/// A DNS response's question name and the addresses its answer section gives for it,
/// directly or through a CNAME chain; `None` for queries, errors, other questions and
/// malformed messages. A truncated answer section yields its complete records.
fn dns_answer(msg: &[u8]) -> Option<(Arc<str>, Vec<IpAddr>)> {
    let be16 = |at: usize| Some(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]));
    let flags = be16(2)?;
    let (response, opcode, rcode) = (flags & 0x8000 != 0, (flags >> 11) & 0xf, flags & 0xf);
    if !response || opcode != 0 || rcode != 0 || be16(4)? != 1 {
        return None;
    }
    let answers = be16(6)?;
    let mut at = 12;
    let question = read_name(msg, &mut at)?;
    if !matches!(be16(at)?, TYPE_A | TYPE_AAAA | TYPE_ANY) {
        return None;
    }
    at += 4;
    let mut aliases = vec![question.to_ascii_lowercase()];
    let mut cnames = Vec::new();
    let mut addrs = Vec::new();
    for _ in 0..answers {
        let Some(owner) = read_name(msg, &mut at) else {
            break;
        };
        let (Some(rtype), Some(rdlen)) = (be16(at), be16(at + 8)) else {
            break;
        };
        let start = at + 10;
        let end = start + usize::from(rdlen);
        let Some(rdata) = msg.get(start..end) else {
            break;
        };
        let owner = owner.to_ascii_lowercase();
        match rtype {
            TYPE_A => {
                if let Ok(octets) = <[u8; 4]>::try_from(rdata) {
                    addrs.push((owner, IpAddr::V4(Ipv4Addr::from(octets))));
                }
            }
            TYPE_AAAA => {
                if let Ok(octets) = <[u8; 16]>::try_from(rdata) {
                    addrs.push((owner, IpAddr::V6(Ipv6Addr::from(octets))));
                }
            }
            TYPE_CNAME => {
                let mut target_at = start;
                if let Some(target) = read_name(msg, &mut target_at) {
                    cnames.push((owner, target.to_ascii_lowercase()));
                }
            }
            _ => {}
        }
        at = end;
    }
    // Records may come in any order: grow the alias set until it stops changing.
    while aliases.len() <= MAX_ALIASES {
        let next = cnames
            .iter()
            .find(|(owner, target)| aliases.contains(owner) && !aliases.contains(target));
        match next {
            Some((_, target)) => aliases.push(target.clone()),
            None => break,
        }
    }
    let addrs: Vec<IpAddr> = addrs
        .into_iter()
        .filter(|(owner, _)| aliases.contains(owner))
        .map(|(_, ip)| ip)
        .collect();
    (!addrs.is_empty()).then(|| (Arc::from(question), addrs))
}

/// Reads the domain name at `*at` (labels, possibly ending in a compression pointer) and
/// moves `*at` past it. `None` when it is truncated, loops, is the root, or has bytes that
/// are not printable ASCII.
fn read_name(msg: &[u8], at: &mut usize) -> Option<String> {
    let mut name = String::new();
    let mut pos = *at;
    let mut jumped = false;
    for _ in 0..MAX_NAME_STEPS {
        let len = *msg.get(pos)?;
        match len >> 6 {
            0 if len == 0 => {
                if !jumped {
                    *at = pos + 1;
                }
                return (!name.is_empty()).then_some(name);
            }
            0 => {
                let label = msg.get(pos + 1..pos + 1 + usize::from(len))?;
                if !label.iter().all(|&b| b.is_ascii_graphic() && b != b'.') {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|&b| char::from(b)));
                if name.len() > MAX_NAME {
                    return None;
                }
                pos += 1 + usize::from(len);
            }
            3 => {
                let low = *msg.get(pos + 1)?;
                if !jumped {
                    *at = pos + 2;
                    jumped = true;
                }
                pos = usize::from(u16::from_be_bytes([len & 0x3f, low]));
            }
            _ => return None,
        }
    }
    None
}

/// `parameters.addresses[]` of a `ResolveHostname` reply: `{"family": 2|10, "address":
/// [bytes]}` entries; malformed entries are skipped.
fn varlink_addresses(params: &Json) -> Vec<IpAddr> {
    let Some(Json::Arr(entries)) = params.get("addresses") else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let Some(Json::Arr(bytes)) = entry.get("address") else {
                return None;
            };
            let bytes: Vec<u8> = bytes
                .iter()
                .map(|b| b.as_u8())
                .collect::<Option<_>>()?;
            match (entry.get("family")?.as_u8()?, bytes.len()) {
                (2, 4) => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))),
                (10, 16) => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?))),
                _ => None,
            }
        })
        .collect()
}

/// `name` as a hostname to show: printable ASCII, at most [`MAX_NAME`] bytes, without the
/// trailing dot of a fully qualified name.
fn hostname(name: &str) -> Option<Arc<str>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME
        && name.bytes().all(|b| b.is_ascii_graphic());
    valid.then(|| Arc::from(name))
}

/// A JSON value, parsed leniently: input that ends early closes every open array and object,
/// dropping the unfinished member, because captured payloads are cut at `DNS_BYTES`.
#[derive(Clone, Debug, PartialEq)]
enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Num(f64),
    /// A string, unescaped.
    Str(String),
    /// An array.
    Arr(Vec<Json>),
    /// An object's members in order.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Parses the value at the start of `text` (trailing bytes are ignored); `None` on a
    /// syntax error, or when the input ends inside a top-level scalar.
    fn parse(text: &[u8]) -> Option<Self> {
        Parser {
            text,
            at: 0,
            ended: false,
        }
        .value(0)
    }

    /// Member `key` of an object.
    fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The text of a string.
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// An integer in 0..=255.
    fn as_u8(&self) -> Option<u8> {
        match *self {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Self::Num(n) if n.fract() == 0.0 && (0.0..=255.0).contains(&n) => Some(n as u8),
            _ => None,
        }
    }
}

/// Recursive-descent state for [`Json::parse`].
struct Parser<'a> {
    /// The whole input.
    text: &'a [u8],
    /// Offset of the next byte.
    at: usize,
    /// The input ended inside a value.
    ended: bool,
}

impl Parser<'_> {
    /// The next non-whitespace byte, not consumed; sets `ended` at the end of input.
    fn peek(&mut self) -> Option<u8> {
        while let Some(&b) = self.text.get(self.at) {
            if !matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                return Some(b);
            }
            self.at += 1;
        }
        self.ended = true;
        None
    }

    /// The value at the cursor, nested `depth` deep.
    fn value(&mut self, depth: usize) -> Option<Json> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.peek()? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(Json::Str),
            b't' => self.word("true", Json::Bool(true)),
            b'f' => self.word("false", Json::Bool(false)),
            b'n' => self.word("null", Json::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    /// An object (cursor on `{`).
    fn object(&mut self, depth: usize) -> Option<Json> {
        self.at += 1;
        let mut members = Vec::new();
        loop {
            match self.peek() {
                None => return Some(Json::Obj(members)),
                Some(b'}') => {
                    self.at += 1;
                    return Some(Json::Obj(members));
                }
                Some(b',') if !members.is_empty() => self.at += 1,
                Some(_) if members.is_empty() => {}
                Some(_) => return None,
            }
            let member = self.member(depth);
            match member {
                Some(member) => members.push(member),
                None if self.ended => return Some(Json::Obj(members)),
                None => return None,
            }
        }
    }

    /// `"key": value` inside an object.
    fn member(&mut self, depth: usize) -> Option<(String, Json)> {
        if self.peek()? != b'"' {
            return None;
        }
        let key = self.string()?;
        if self.peek()? != b':' {
            return None;
        }
        self.at += 1;
        Some((key, self.value(depth + 1)?))
    }

    /// An array (cursor on `[`).
    fn array(&mut self, depth: usize) -> Option<Json> {
        self.at += 1;
        let mut items = Vec::new();
        loop {
            match self.peek() {
                None => return Some(Json::Arr(items)),
                Some(b']') => {
                    self.at += 1;
                    return Some(Json::Arr(items));
                }
                Some(b',') if !items.is_empty() => self.at += 1,
                Some(_) if items.is_empty() => {}
                Some(_) => return None,
            }
            match self.value(depth + 1) {
                Some(item) => items.push(item),
                None if self.ended => return Some(Json::Arr(items)),
                None => return None,
            }
        }
    }

    /// The literal `word` (cursor on its first byte) as `value`.
    fn word(&mut self, word: &str, value: Json) -> Option<Json> {
        let rest = &self.text[self.at..];
        if rest.starts_with(word.as_bytes()) {
            self.at += word.len();
            Some(value)
        } else {
            self.ended = word.as_bytes().starts_with(rest);
            None
        }
    }

    /// A number; one that reaches the end of input may be cut short, so it is dropped.
    fn number(&mut self) -> Option<Json> {
        let start = self.at;
        while self
            .text
            .get(self.at)
            .is_some_and(|b| matches!(b, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
        {
            self.at += 1;
        }
        if self.at == self.text.len() {
            self.ended = true;
            return None;
        }
        let digits = std::str::from_utf8(&self.text[start..self.at]).ok()?;
        digits.parse().ok().map(Json::Num)
    }

    /// A string (cursor on its opening quote), unescaped.
    fn string(&mut self) -> Option<String> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let Some(&b) = self.text.get(self.at) else {
                self.ended = true;
                return None;
            };
            self.at += 1;
            match b {
                b'"' => return Some(out),
                b'\\' => {
                    let Some(&escape) = self.text.get(self.at) else {
                        self.ended = true;
                        return None;
                    };
                    self.at += 1;
                    out.push(match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.unicode_escape()?,
                        _ => return None,
                    });
                }
                0..0x20 => return None,
                0x20..0x80 => out.push(char::from(b)),
                _ => {
                    // A multi-byte UTF-8 sequence: copy it whole.
                    let start = self.at - 1;
                    let width = match b {
                        0xc0..0xe0 => 2,
                        0xe0..0xf0 => 3,
                        0xf0..0xf8 => 4,
                        _ => return None,
                    };
                    let Some(bytes) = self.text.get(start..start + width) else {
                        self.ended = true;
                        return None;
                    };
                    out.push_str(std::str::from_utf8(bytes).ok()?);
                    self.at = start + width;
                }
            }
        }
    }

    /// The character of a `\uXXXX` escape (after the `u`), joining surrogate pairs; lone
    /// surrogates become U+FFFD.
    fn unicode_escape(&mut self) -> Option<char> {
        let high = self.hex4()?;
        if !(0xd800..0xdc00).contains(&high) {
            return Some(char::from_u32(high).unwrap_or(char::REPLACEMENT_CHARACTER));
        }
        if !self.text[self.at..].starts_with(b"\\u") {
            return Some(char::REPLACEMENT_CHARACTER);
        }
        self.at += 2;
        let low = self.hex4()?;
        if !(0xdc00..0xe000).contains(&low) {
            return Some(char::REPLACEMENT_CHARACTER);
        }
        char::from_u32(0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00))
    }

    /// Four hex digits.
    fn hex4(&mut self) -> Option<u32> {
        let Some(digits) = self.text.get(self.at..self.at + 4) else {
            self.ended = true;
            return None;
        };
        let value = u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?;
        self.at += 4;
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::dns;

    /// A DNS response for `question` (type A) with `answers` already encoded.
    fn response(id: u16, question: &[u8], answers: &[Vec<u8>]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&0x8180_u16.to_be_bytes());
        msg.extend_from_slice(&1_u16.to_be_bytes());
        msg.extend_from_slice(&u16::try_from(answers.len()).unwrap().to_be_bytes());
        msg.extend_from_slice(&[0, 0, 0, 0]);
        msg.extend_from_slice(question);
        msg.extend_from_slice(&[0, 1, 0, 1]);
        for answer in answers {
            msg.extend_from_slice(answer);
        }
        msg
    }

    /// `name` in wire format.
    fn name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// A resource record: `owner` (already encoded), type, class IN, TTL 60, `rdata`.
    fn rr(owner: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = owner.to_vec();
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    /// A pointer to the question name, which always sits at offset 12.
    const QUESTION: [u8; 2] = [0xc0, 12];

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_answer_names_its_addresses_after_the_question_through_cnames() {
        // www.example.com CNAME edge.cdn.net, whose A and AAAA records come before the alias;
        // later records name edge.cdn.net through a pointer to the first answer's owner.
        let target = name("edge.cdn.net");
        let cdn_at = 12 + name("www.example.com").len() + 4;
        let mut answers = vec![rr(&target, TYPE_A, &[93, 184, 215, 14])];
        let pointer = [0xc0, u8::try_from(cdn_at).unwrap()];
        let mut v6 = [0_u8; 16];
        v6[0] = 0x26;
        v6[1] = 0x06;
        v6[15] = 1;
        answers.push(rr(&pointer, TYPE_AAAA, &v6));
        answers.push(rr(&QUESTION, TYPE_CNAME, &pointer));
        // An unrelated record is not the question's.
        answers.push(rr(&name("other.org"), TYPE_A, &[10, 0, 0, 1]));
        let msg = response(7, &name("www.example.com"), &answers);
        let (question, addrs) = dns_answer(&msg).expect("an answer");
        assert_eq!(&*question, "www.example.com");
        assert_eq!(addrs, vec![ip("93.184.215.14"), ip("2606::1")]);
    }

    #[test]
    fn queries_errors_and_other_questions_are_not_answers() {
        let a = rr(&QUESTION, TYPE_A, &[1, 2, 3, 4]);
        let mut query = response(1, &name("a.test"), std::slice::from_ref(&a));
        query[2] &= 0x7f;
        assert_eq!(dns_answer(&query), None);
        let mut nxdomain = response(1, &name("a.test"), std::slice::from_ref(&a));
        nxdomain[3] |= 3;
        assert_eq!(dns_answer(&nxdomain), None);
        let mut mx = response(1, &name("a.test"), &[a]);
        let qtype = 12 + name("a.test").len();
        mx[qtype + 1] = 15;
        assert_eq!(dns_answer(&mx), None);
    }

    #[test]
    fn truncated_and_damaged_messages_never_panic_and_keep_complete_records() {
        let answers = [
            rr(&QUESTION, TYPE_A, &[10, 0, 0, 1]),
            rr(&QUESTION, TYPE_A, &[10, 0, 0, 2]),
        ];
        let msg = response(9, &name("slow.whytime.test"), &answers);
        let second = msg.len() - answers[1].len();
        for len in 0..=msg.len() {
            let got = dns_answer(&msg[..len]);
            let want: &[&str] = match len {
                _ if len == msg.len() => &["10.0.0.1", "10.0.0.2"],
                _ if len >= second => &["10.0.0.1"],
                _ => &[],
            };
            let want: Vec<IpAddr> = want.iter().map(|s| ip(s)).collect();
            assert_eq!(got.map(|(_, a)| a).unwrap_or_default(), want, "cut at {len}");
        }
        // Every single-byte corruption of every prefix parses or fails cleanly.
        for at in 0..msg.len() {
            for byte in [0x00, 0x3f, 0x40, 0xc0, 0xff] {
                let mut bad = msg.clone();
                bad[at] = byte;
                for len in [at + 1, bad.len()] {
                    let _ = dns_answer(&bad[..len]);
                }
            }
        }
    }

    #[test]
    fn compression_loops_and_unprintable_names_are_rejected() {
        let mut at = 0;
        assert_eq!(read_name(&[0xc0, 0], &mut at), None);
        let mut at = 0;
        assert_eq!(read_name(&[3, b'a', 0, b'b', 0], &mut at), None);
        let mut at = 0;
        assert_eq!(read_name(&[0], &mut at), None);
        let mut at = 3;
        let msg = [1, b'x', 0, 0xc0, 0];
        assert_eq!(read_name(&msg, &mut at).as_deref(), Some("x"));
        assert_eq!(at, 5, "a pointer ends the name in place");
    }

    const REQUEST: &[u8] = b"{\"method\":\"io.systemd.Resolve.ResolveHostname\",\"parameters\":{\"name\":\"example.com\",\"flags\":0,\"ifindex\":0}}\0";
    const REPLY: &[u8] = b"{\"parameters\":{\"addresses\":[{\"ifindex\":2,\"family\":10,\"address\":[38,6,71,0,0,16,0,0,0,0,0,0,172,66,147,243]},{\"ifindex\":2,\"family\":2,\"address\":[172,66,147,243]}],\"name\":\"canonical.example.net\",\"flags\":8388609}}\0";

    #[test]
    fn a_varlink_reply_names_its_addresses_after_the_request() {
        let mut hosts = Hosts::default();
        hosts.ingest(&dns(10, 20, DNS_VARLINK, true, REQUEST));
        hosts.ingest(&dns(10, 20, DNS_VARLINK, false, REPLY));
        let name = |s: &str| hosts.name(ip(s)).map(|n| n.to_string());
        assert_eq!(name("172.66.147.243").as_deref(), Some("example.com"));
        assert_eq!(name("2606:4700:10::ac42:93f3").as_deref(), Some("example.com"));
        // Without a request on that connection, the reply's canonical name.
        let mut hosts = Hosts::default();
        hosts.ingest(&dns(10, 21, DNS_VARLINK, false, REPLY));
        assert_eq!(
            hosts.name(ip("172.66.147.243")).map(|n| n.to_string()).as_deref(),
            Some("canonical.example.net")
        );
    }

    #[test]
    fn a_varlink_reply_cut_short_keeps_its_complete_addresses() {
        for len in 0..REPLY.len() {
            let mut hosts = Hosts::default();
            hosts.ingest(&dns(1, 2, DNS_VARLINK, true, REQUEST));
            hosts.ingest(&dns(1, 2, DNS_VARLINK, false, &REPLY[..len]));
            let v6 = hosts.name(ip("2606:4700:10::ac42:93f3")).is_some();
            let v4 = hosts.name(ip("172.66.147.243")).is_some();
            // An entry counts once its address array is closed: both end in `243]`.
            let closed = REPLY[..len].windows(4).filter(|w| w == b"243]").count();
            assert_eq!((v6, v4), (closed >= 1, closed >= 2), "cut at {len}");
        }
    }

    #[test]
    fn tcp_answers_follow_their_length_prefix_read_with_or_without_it() {
        let msg = response(3, &name("db.internal"), &[rr(&QUESTION, TYPE_A, &[10, 1, 2, 3])]);
        let mut framed = u16::try_from(msg.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        // One read with the prefix.
        let mut hosts = Hosts::default();
        hosts.ingest(&dns(5, 6, DNS_TCP, false, &framed));
        assert!(hosts.name(ip("10.1.2.3")).is_some());
        // glibc reads the 2-byte length, then the message.
        let mut hosts = Hosts::default();
        hosts.ingest(&dns(5, 6, DNS_TCP, false, &framed[..2]));
        hosts.ingest(&dns(5, 6, DNS_TCP, false, &msg));
        assert_eq!(hosts.name(ip("10.1.2.3")).map(|n| n.to_string()).as_deref(), Some("db.internal"));
    }

    #[test]
    fn the_latest_answer_for_an_address_wins() {
        let mut hosts = Hosts::default();
        for host in ["a.test", "b.test"] {
            let msg = response(1, &name(host), &[rr(&QUESTION, TYPE_A, &[192, 0, 2, 1])]);
            hosts.ingest(&dns(1, 1, DNS_UDP, false, &msg));
        }
        assert_eq!(hosts.name(ip("192.0.2.1")).map(|n| n.to_string()).as_deref(), Some("b.test"));
        // Sent DNS messages (queries) teach nothing.
        let msg = response(1, &name("c.test"), &[rr(&QUESTION, TYPE_A, &[192, 0, 2, 1])]);
        hosts.ingest(&dns(1, 1, DNS_UDP, true, &msg));
        assert_eq!(hosts.name(ip("192.0.2.1")).map(|n| n.to_string()).as_deref(), Some("b.test"));
    }

    #[test]
    fn lenient_json_closes_containers_at_the_end_of_input_only() {
        assert_eq!(
            Json::parse(b"{\"a\":[1,2,{\"b\":\"x\\u00e9\\ud83d\\ude00\"}],\"c\":true} trailing"),
            Some(Json::Obj(vec![
                (
                    "a".into(),
                    Json::Arr(vec![
                        Json::Num(1.0),
                        Json::Num(2.0),
                        Json::Obj(vec![("b".into(), Json::Str("xé😀".into()))])
                    ])
                ),
                ("c".into(), Json::Bool(true)),
            ]))
        );
        // Cut inside a number, a string, a literal: the unfinished member is dropped.
        assert_eq!(
            Json::parse(b"{\"a\":[1,23"),
            Some(Json::Obj(vec![("a".into(), Json::Arr(vec![Json::Num(1.0)]))]))
        );
        assert_eq!(Json::parse(b"{\"a\":1,\"b\":\"te"), Json::parse(b"{\"a\":1}"));
        assert_eq!(Json::parse(b"{\"a\":1,\"b\":tr"), Json::parse(b"{\"a\":1}"));
        // Syntax errors are errors.
        for bad in [&b"{\"a\" 1}"[..], b"{\"a\":1 \"b\":2}", b"[1,,2]", b"{\"a\":nul}", b"x"] {
            assert_eq!(Json::parse(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        // Deep nesting stops at the limit instead of overflowing the stack.
        assert_eq!(Json::parse(&[b'['; 10_000]), None);
        // Every prefix of a reply parses without panicking.
        for len in 0..REPLY.len() {
            let _ = Json::parse(&REPLY[..len]);
        }
    }
}
