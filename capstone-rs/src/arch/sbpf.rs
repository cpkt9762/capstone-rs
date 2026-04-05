use core::convert::From;
use core::{cmp, fmt, slice};

pub use capstone_sys::sbpf_insn as SbpfInsn;
pub use capstone_sys::sbpf_insn_group as SbpfInsnGroup;
pub use capstone_sys::sbpf_reg as SbpfReg;
use capstone_sys::{cs_sbpf, cs_sbpf_op, sbpf_op_mem, sbpf_op_type};

pub use crate::arch::arch_builder::sbpf::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};

pub struct SbpfInsnDetail<'a>(pub(crate) &'a cs_sbpf);

impl_PartialEq_repr_fields!(SbpfInsnDetail<'a> [ 'a ];
    operands
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SbpfOperand {
    Reg(RegId),
    Imm(i64),
    Mem(SbpfOpMem),
    Off(i32),
    Invalid,
}

impl Default for SbpfOperand {
    fn default() -> Self {
        SbpfOperand::Invalid
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SbpfOpMem(pub(crate) sbpf_op_mem);

impl SbpfOpMem {
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    pub fn disp(&self) -> i32 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(SbpfOpMem;
    base, disp
);

impl cmp::Eq for SbpfOpMem {}

impl From<&cs_sbpf_op> for SbpfOperand {
    fn from(insn: &cs_sbpf_op) -> SbpfOperand {
        match insn.type_ {
            sbpf_op_type::SBPF_OP_INVALID => SbpfOperand::Invalid,
            sbpf_op_type::SBPF_OP_REG => {
                SbpfOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            sbpf_op_type::SBPF_OP_IMM => SbpfOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            sbpf_op_type::SBPF_OP_OFF => SbpfOperand::Off(unsafe { insn.__bindgen_anon_1.off }),
            sbpf_op_type::SBPF_OP_MEM => {
                SbpfOperand::Mem(SbpfOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
        }
    }
}

def_arch_details_struct!(
    InsnDetail = SbpfInsnDetail;
    Operand = SbpfOperand;
    OperandIterator = SbpfOperandIterator;
    OperandIteratorLife = SbpfOperandIterator<'a>;
    [ pub struct SbpfOperandIterator<'a>(slice::Iter<'a, cs_sbpf_op>); ]
    cs_arch_op = cs_sbpf_op;
    cs_arch = cs_sbpf;
);
