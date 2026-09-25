use super::{Elf, invalid};
use crate::{Error, model::*};
use ::elf::{
    abi,
    endian::EndianParse,
    file::Class,
    note::{Note, NoteIterator},
};
use std::collections::BTreeSet;

pub(super) fn parse(elf: &Elf<'_>, architecture: Architecture) -> Result<CpuRequirement, Error> {
    let mut ranges = BTreeSet::new();
    let mut buffers = Vec::new();
    if let Some(headers) = elf.section_headers() {
        for h in headers.iter().filter(|h| h.sh_type == abi::SHT_NOTE) {
            if ranges.insert((h.sh_offset, h.sh_size)) {
                buffers.push((elf.section_data(&h)?.0, h.sh_addralign));
            }
        }
    }
    if let Some(headers) = elf.segments() {
        for h in headers
            .iter()
            .filter(|h| matches!(h.p_type, abi::PT_NOTE | abi::PT_GNU_PROPERTY))
        {
            if ranges.insert((h.p_offset, h.p_filesz)) {
                buffers.push((elf.segment_data(&h)?, h.p_align));
            }
        }
    }
    let endian = elf.ehdr.endianness;
    let mut mask = 0;
    for (data, alignment) in buffers {
        // A section may impose no/minimal address alignment while its note
        // records still use the usual four-byte framing (e.g. vendor notes).
        let alignment = match alignment {
            0 | 1 | 2 | 4 => 4,
            8 => 8,
            _ => return Err(invalid("unsupported ELF note alignment")),
        };
        let mut offset = 0;
        while offset < data.len() {
            // Validate framing because NoteIterator suppresses malformed-note errors.
            let start = offset;
            let namesz = endian.parse_u32_at(&mut offset, data)? as usize;
            let descsz = endian.parse_u32_at(&mut offset, data)? as usize;
            let _kind = endian.parse_u32_at(&mut offset, data)?;
            offset = aligned_end(offset, namesz, alignment)?;
            offset = aligned_end(offset, descsz, alignment)?;
            let framed = data
                .get(start..offset)
                .ok_or_else(|| invalid("truncated ELF note"))?;
            let note = NoteIterator::new(endian, elf.ehdr.class, alignment, framed)
                .next()
                .ok_or_else(|| invalid("malformed ELF note"))?;
            if let Note::Unknown(note) = note
                && note.name == b"GNU\0"
                && note.n_type == abi::NT_GNU_PROPERTY_TYPE_0
            {
                let property_align = match elf.ehdr.class {
                    Class::ELF32 => 4,
                    Class::ELF64 => 8,
                };
                let mut p = 0;
                while p < note.desc.len() {
                    let kind = endian.parse_u32_at(&mut p, note.desc)?;
                    let size = endian.parse_u32_at(&mut p, note.desc)? as usize;
                    let end = p
                        .checked_add(size)
                        .ok_or_else(|| invalid("GNU property size overflow"))?;
                    let property = note
                        .desc
                        .get(p..end)
                        .ok_or_else(|| invalid("truncated GNU property"))?;
                    // NEEDED is a requirement; USED is deliberately not treated as one.
                    if kind == 0xc0008002 && architecture == Architecture::X86_64 {
                        if size != 4 {
                            return Err(invalid("invalid GNU x86 ISA property size"));
                        }
                        mask |= endian.parse_u32_at(&mut 0, property)?;
                    }
                    p = aligned_end(p, size, property_align)?;
                    if p > note.desc.len() {
                        return Err(invalid("truncated GNU property padding"));
                    }
                }
            }
        }
    }
    Ok(CpuRequirement {
        x86_64_isa: if mask & 8 != 0 {
            Some(X86Isa::V4)
        } else if mask & 4 != 0 {
            Some(X86Isa::V3)
        } else if mask & 2 != 0 {
            Some(X86Isa::V2)
        } else if mask & 1 != 0 {
            Some(X86Isa::Baseline)
        } else {
            None
        },
        unknown_isa_bits: mask & !15,
    })
}

fn aligned_end(offset: usize, size: usize, alignment: usize) -> Result<usize, Error> {
    offset
        .checked_add(size)
        .and_then(|n| n.checked_add(alignment - 1))
        .map(|n| n & !(alignment - 1))
        .ok_or_else(|| invalid("ELF note size overflow"))
}
