//! MD5 (RFC 1321), only for verifying imported legacy hashes; aws-lc-rs offers no MD5.

const SHIFT: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let mut m = [0u32; 16];
    for (w, bytes) in m.iter_mut().zip(block.as_chunks::<4>().0) {
        *w = u32::from_le_bytes(*bytes);
    }
    let [mut va, mut vb, mut vc, mut vd] = *state;
    for (step, (shift, konst)) in SHIFT.iter().zip(K.iter()).enumerate() {
        let (mix, idx) = match step / 16 {
            0 => ((vb & vc) | (!vb & vd), step),
            1 => ((vd & vb) | (!vd & vc), step.wrapping_mul(5).wrapping_add(1)),
            2 => (vb ^ vc ^ vd, step.wrapping_mul(3).wrapping_add(5)),
            _ => (vc ^ (vb | !vd), step.wrapping_mul(7)),
        };
        let word = m.get(idx & 15).copied().unwrap_or(0);
        let rotated = va
            .wrapping_add(mix)
            .wrapping_add(*konst)
            .wrapping_add(word)
            .rotate_left(*shift);
        va = vd;
        vd = vc;
        vc = vb;
        vb = vb.wrapping_add(rotated);
    }
    state[0] = state[0].wrapping_add(va);
    state[1] = state[1].wrapping_add(vb);
    state[2] = state[2].wrapping_add(vc);
    state[3] = state[3].wrapping_add(vd);
}

/// The MD5 digest of the concatenation of `parts`.
pub(super) fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut message: Vec<u8> = parts.concat();
    let bits = u64::try_from(message.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bits.to_le_bytes());
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    for block in message.as_chunks::<64>().0 {
        compress(&mut state, block);
    }
    zeroize::Zeroize::zeroize(&mut message);
    let mut out = [0u8; 16];
    for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(state.iter()) {
        *o = w.to_le_bytes();
    }
    out
}
