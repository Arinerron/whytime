//! Per-CPU variable layout from the kernel's BTF, for the BPF side's interrupt-context test.
//!
//! On x86-64 the preempt count (which says hardirq/softirq/NMI) is the per-CPU variable
//! `__preempt_count` (`pcpu_hot.preempt_count` on 6.2–6.14). BPF could address it as a
//! `__ksym`, which aya cannot load. Every CPU's copy of the static per-CPU variables has the
//! same layout, and BPF can reach the current CPU's `runqueues`, so user space hands it the
//! distance between the two: the difference of their offsets in the `.data..percpu` DATASEC
//! of `/sys/kernel/btf/vmlinux`.

const BTF_MAGIC: u16 = 0xeb9f;
const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_ENUM64: u32 = 19;

/// Address of `__preempt_count` minus address of `runqueues` on any CPU, from raw BTF;
/// `None` when the BTF lacks either.
pub fn preempt_count_from_rq(btf: &[u8]) -> Option<i64> {
    let btf = Btf::parse(btf)?;
    let percpu = btf.datasec(".data..percpu")?;
    let var = |name: &str| percpu.iter().find(|var| var.name == name);
    let rq = var("runqueues")?.offset;
    let count = match var("__preempt_count") {
        Some(count) => count.offset,
        None => {
            let hot = var("pcpu_hot")?;
            hot.offset + btf.member_offset(hot.type_id, "preempt_count")?
        }
    };
    Some(i64::from(count) - i64::from(rq))
}

/// One type of a BTF blob.
struct Type {
    kind: u32,
    name_off: u32,
    info: u32,
    /// `size` or `type`, by kind.
    size_or_type: u32,
    /// Offset of the kind-specific data following the common header.
    extra: usize,
}

/// A variable in a DATASEC.
struct SecVar<'a> {
    name: &'a str,
    /// The variable's type.
    type_id: u32,
    /// Byte offset in the section.
    offset: u32,
}

/// The type and string sections of a native-endian BTF blob.
struct Btf<'a> {
    data: &'a [u8],
    strings: &'a [u8],
    /// Index `id - 1`.
    types: Vec<Type>,
}

impl<'a> Btf<'a> {
    fn parse(blob: &'a [u8]) -> Option<Self> {
        let u32_at = |at: usize| read_u32(blob, at);
        if u16::from_ne_bytes(blob.get(..2)?.try_into().ok()?) != BTF_MAGIC {
            return None;
        }
        let hdr_len = usize::try_from(u32_at(4)?).ok()?;
        let field = |at| u32_at(at).and_then(|v| usize::try_from(v).ok());
        let (type_off, type_len) = (field(8)?, field(12)?);
        let (str_off, str_len) = (field(16)?, field(20)?);
        let data = blob.get(hdr_len + type_off..hdr_len + type_off + type_len)?;
        let strings = blob.get(hdr_len + str_off..hdr_len + str_off + str_len)?;
        let mut types = Vec::new();
        let mut at = 0;
        while at < data.len() {
            let info = read_u32(data, at + 4)?;
            let kind = (info >> 24) & 0x1f;
            let vlen = usize::try_from(info & 0xffff).ok()?;
            let extra = match kind {
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => vlen * 12,
                KIND_ENUM | KIND_FUNC_PROTO => vlen * 8,
                // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG.
                2 | 7..=12 | 16 | 18 => 0,
                _ => return None,
            };
            types.push(Type {
                kind,
                name_off: read_u32(data, at)?,
                info,
                size_or_type: read_u32(data, at + 8)?,
                extra: at + 12,
            });
            at += 12 + extra;
        }
        Some(Self {
            data,
            strings,
            types,
        })
    }

    fn get(&self, id: u32) -> Option<&Type> {
        self.types.get(usize::try_from(id).ok()?.checked_sub(1)?)
    }

    fn name(&self, name_off: u32) -> Option<&'a str> {
        let rest = self.strings.get(usize::try_from(name_off).ok()?..)?;
        let len = rest.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&rest[..len]).ok()
    }

    /// `(type, offset, size)` triples following type `t`.
    fn triples(&self, t: &Type) -> impl Iterator<Item = Option<(u32, u32, u32)>> + '_ {
        let at = t.extra;
        (0..t.info & 0xffff).map(move |i| {
            let base = at + usize::try_from(i).ok()? * 12;
            Some((
                read_u32(self.data, base)?,
                read_u32(self.data, base + 4)?,
                read_u32(self.data, base + 8)?,
            ))
        })
    }

    /// The variables of the DATASEC named `name`.
    fn datasec(&self, name: &str) -> Option<Vec<SecVar<'a>>> {
        let sec = self
            .types
            .iter()
            .find(|t| t.kind == KIND_DATASEC && self.name(t.name_off) == Some(name))?;
        self.triples(sec)
            .map(|entry| {
                let (type_id, offset, _size) = entry?;
                let var = self.get(type_id)?;
                Some(SecVar {
                    name: self.name(var.name_off)?,
                    type_id: var.size_or_type,
                    offset,
                })
            })
            .collect()
    }

    /// Byte offset of member `name` in struct/union `id`, looking through anonymous
    /// struct/union members.
    fn member_offset(&self, id: u32, name: &str) -> Option<u32> {
        let t = self.get(id)?;
        if !matches!(t.kind, KIND_STRUCT | KIND_UNION) {
            return None;
        }
        let bitfields = t.info & (1 << 31) != 0;
        self.triples(t).find_map(|member| {
            // Members are (name_off, type, offset in bits).
            let (name_off, type_id, bits) = member?;
            let bits = if bitfields { bits & 0xff_ffff } else { bits };
            let here = bits / 8;
            match self.name(name_off)? {
                "" => Some(here + self.member_offset(type_id, name)?),
                found if found == name => Some(here),
                _ => None,
            }
        })
    }
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assembles a native-endian BTF blob.
    #[derive(Default)]
    struct Builder {
        data: Vec<u8>,
        strings: Vec<u8>,
        types: u32,
    }

    impl Builder {
        /// Offset of `s` in the string section (0 for "").
        fn str(&mut self, s: &str) -> u32 {
            if self.strings.is_empty() {
                self.strings.push(0);
            }
            if s.is_empty() {
                return 0;
            }
            let at = u32::try_from(self.strings.len()).unwrap();
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            at
        }

        /// Appends a type; returns its id.
        fn ty(&mut self, name: &str, kind: u32, vlen: u32, size: u32, extra: &[u32]) -> u32 {
            let name = self.str(name);
            for word in [name, kind << 24 | vlen, size].iter().chain(extra) {
                self.data.extend_from_slice(&word.to_ne_bytes());
            }
            self.types += 1;
            self.types
        }

        fn finish(self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&BTF_MAGIC.to_ne_bytes());
            out.extend_from_slice(&[1, 0]);
            let data_len = u32::try_from(self.data.len()).unwrap();
            let str_len = u32::try_from(self.strings.len()).unwrap();
            for word in [24, 0, data_len, data_len, str_len] {
                out.extend_from_slice(&word.to_ne_bytes());
            }
            out.extend_from_slice(&self.data);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    #[test]
    fn distance_from_runqueues_to_the_standalone_preempt_count() {
        let mut b = Builder::default();
        let int = b.ty("int", KIND_INT, 0, 4, &[32]);
        let rq = b.ty("runqueues", KIND_VAR, 0, int, &[1]);
        let count = b.ty("__preempt_count", KIND_VAR, 0, int, &[1]);
        b.ty(".data..percpu", KIND_DATASEC, 2, 4096, &[rq, 3000, 64, count, 48, 4]);
        assert_eq!(preempt_count_from_rq(&b.finish()), Some(48 - 3000));
    }

    #[test]
    fn pcpu_hot_preempt_count_is_found_through_anonymous_members() {
        // struct pcpu_hot { union { struct { void *current_task; int preempt_count; };
        // u8 pad[64]; }; } at offset 128, runqueues at 1024.
        let mut b = Builder::default();
        let int = b.ty("int", KIND_INT, 0, 4, &[32]);
        let (current, count) = (b.str("current_task"), b.str("preempt_count"));
        let inner = b.ty("", KIND_STRUCT, 2, 12, &[current, int, 0, count, int, 64]);
        let union = b.ty("", KIND_UNION, 1, 64, &[0, inner, 0]);
        let hot = b.ty("pcpu_hot", KIND_STRUCT, 1, 64, &[0, union, 0]);
        let rq = b.ty("runqueues", KIND_VAR, 0, int, &[1]);
        let hot_var = b.ty("pcpu_hot", KIND_VAR, 0, hot, &[1]);
        b.ty(".data..percpu", KIND_DATASEC, 2, 4096, &[rq, 1024, 64, hot_var, 128, 64]);
        assert_eq!(preempt_count_from_rq(&b.finish()), Some(128 + 8 - 1024));
    }

    #[test]
    fn missing_variables_or_garbage_give_none() {
        let mut b = Builder::default();
        let int = b.ty("int", KIND_INT, 0, 4, &[32]);
        let rq = b.ty("runqueues", KIND_VAR, 0, int, &[1]);
        b.ty(".data..percpu", KIND_DATASEC, 1, 4096, &[rq, 3000, 64]);
        assert_eq!(preempt_count_from_rq(&b.finish()), None);
        assert_eq!(preempt_count_from_rq(b"not btf at all, definitely not"), None);
    }
}
