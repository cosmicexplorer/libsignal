//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Contains helper methods.

pub mod unwrap {
    pub fn no_encoding_error(result: Result<(), prost::EncodeError>) {
        // prost documents the only possible encoding error is if there is insufficient
        // space, which is not a problem when it is allowed to encode into a Vec.
        result.expect("No encoding error")
    }

    pub fn no_hmac_varkey_error<E: std::fmt::Debug>(
        result: Result<hmac::Hmac<sha2::Sha256>, E>,
    ) -> hmac::Hmac<sha2::Sha256> {
        result.expect("HMAC-SHA256 should accept any size key")
    }
}
