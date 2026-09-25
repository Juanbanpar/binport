use super::{Elf, invalid};
use crate::Error;
use ::elf::{
    abi,
    dynamic::{Dyn, DynamicTable},
    parse::ParseAt,
    string_table::StringTable,
};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Dynamic<'a> {
    pub needed: Vec<String>,
    pub rpath: Vec<String>,
    pub runpath: Vec<String>,
    pub soname: Option<String>,
    pub pie: bool,
    pub tags: BTreeMap<i64, u64>,
    pub strings: Option<StringTable<'a>>,
}

/// Resolve a virtual address only through file-backed PT_LOAD bytes.
pub(super) fn at_vaddr<'a>(elf: &Elf<'a>, address: u64, size: u64) -> Result<&'a [u8], Error> {
    if let Some(headers) = elf.segments() {
        for h in headers.iter().filter(|h| h.p_type == abi::PT_LOAD) {
            if let Some(offset) = address.checked_sub(h.p_vaddr)
                && offset <= h.p_filesz
                && size <= h.p_filesz - offset
            {
                let bytes = elf.segment_data(&h)?;
                return bytes
                    .get(
                        usize::try_from(offset).map_err(|_| invalid("offset overflow"))?
                            ..usize::try_from(offset + size)
                                .map_err(|_| invalid("size overflow"))?,
                    )
                    .ok_or_else(|| invalid("dynamic address outside segment"));
            }
        }
    }
    Err(invalid(
        "dynamic address is not in a file-backed PT_LOAD segment",
    ))
}

pub(super) fn parse<'a>(elf: &Elf<'a>) -> Result<Dynamic<'a>, Error> {
    let mut result = Dynamic::default();
    // Prefer the loader's view, PT_DYNAMIC, over optional section headers.
    let segment = elf
        .segments()
        .and_then(|h| h.iter().find(|h| h.p_type == abi::PT_DYNAMIC));
    let section = elf
        .section_headers()
        .and_then(|h| h.iter().find(|h| h.sh_type == abi::SHT_DYNAMIC));
    let bytes = if let Some(h) = segment {
        elf.segment_data(&h)?
    } else if let Some(h) = section {
        elf.section_data(&h)?.0
    } else {
        return Ok(result);
    };
    if bytes.len() % Dyn::size_for(elf.ehdr.class) != 0 {
        return Err(invalid("truncated dynamic table"));
    }
    let table = DynamicTable::new(elf.ehdr.endianness, elf.ehdr.class, bytes);
    let mut string_tags = Vec::new();
    let mut terminated = false;
    for i in 0..table.len() {
        let entry = table.get(i)?;
        if entry.d_tag == abi::DT_NULL {
            terminated = true;
            break;
        }
        if matches!(
            entry.d_tag,
            abi::DT_NEEDED | abi::DT_RPATH | abi::DT_RUNPATH | abi::DT_SONAME
        ) {
            string_tags.push((entry.d_tag, entry.d_val()));
        }
        // Only index singleton tags used by this analysis. Other tags can be
        // repeatable (e.g. DT_AUXILIARY) and are not uniqueness constraints.
        if matches!(
            entry.d_tag,
            abi::DT_STRTAB
                | abi::DT_STRSZ
                | abi::DT_SYMTAB
                | abi::DT_SYMENT
                | abi::DT_VERSYM
                | abi::DT_VERNEED
                | abi::DT_VERNEEDNUM
                | abi::DT_FLAGS_1
                | abi::DT_SONAME
                | abi::DT_RPATH
                | abi::DT_RUNPATH
        ) && let Some(old) = result.tags.insert(entry.d_tag, entry.d_val())
            && old != entry.d_val()
        {
            return Err(invalid("conflicting duplicate dynamic tags"));
        }
    }
    if !terminated {
        return Err(invalid("dynamic table has no DT_NULL terminator"));
    }
    result.pie = result
        .tags
        .get(&abi::DT_FLAGS_1)
        .is_some_and(|f| f & abi::DF_1_PIE as u64 != 0);
    if let (Some(&address), Some(&size)) = (
        result.tags.get(&abi::DT_STRTAB),
        result.tags.get(&abi::DT_STRSZ),
    ) {
        result.strings = Some(StringTable::new(at_vaddr(elf, address, size)?));
    } else if !string_tags.is_empty() {
        return Err(invalid("dynamic strings need DT_STRTAB and DT_STRSZ"));
    }
    for (tag, offset) in string_tags {
        let value = result
            .strings
            .as_ref()
            .ok_or_else(|| invalid("missing dynamic strings"))?
            .get(usize::try_from(offset).map_err(|_| invalid("string offset overflow"))?)?;
        match tag {
            abi::DT_NEEDED => result.needed.push(value.into()),
            abi::DT_SONAME => result.soname = Some(value.into()),
            abi::DT_RPATH => result.rpath = value.split(':').map(str::to_owned).collect(),
            abi::DT_RUNPATH => result.runpath = value.split(':').map(str::to_owned).collect(),
            _ => {}
        }
    }
    Ok(result)
}
