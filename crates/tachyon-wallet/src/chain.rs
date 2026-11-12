//! Validated, replayable public chain inputs, shared with the OSS through
//! `oss-core`. No wallet secrets enter this module.

pub use oss_core::{
    TachyonBlock as Block, anchor, anchor_hex, bytes32,
    chain::{validate, validate_checkpoint, validate_thin},
    max_polynomial_members,
};
