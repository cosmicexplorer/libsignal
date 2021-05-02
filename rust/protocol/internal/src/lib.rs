//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]
#![deny(unsafe_code)]
#![no_std]

//! This crate allows us to have a separate rustdoc project for internal APIs.
//!
//! `rustdoc` already [allows great control over presentation] of our *public* API. However, the
//! addition of [doctests] ensures that no matter what the API is, the examples will remain up to
//! date. With this feedback loop established, `rustdoc` therefore also becomes an invaluable tool
//! for documenting internals.
//!
//! [allows great control over presentation]: https://doc.rust-lang.org/rustdoc/the-doc-attribute.html
//! [doctests]: https://doc.rust-lang.org/rustdoc/documentation-tests.html

#[cfg(doc)]
use constant_time_ops::constant_time_cmp;
/// Implements [constant_time_cmp] in terms of other constant-time comparison methods.
///
/// These helper methods have a clear contract, which we restate as working code in doctests.
pub mod constant_time_ops {
    #[cfg(doc)]
    use core::cmp::Ord;
    use core::cmp::Ordering;

    /// Determine whether the most significant bit in a byte is on.
    ///
    /// This method upholds the following relationship over all of its inputs:
    /// ```
    /// # use rand::Rng;
    /// # use internal::constant_time_ops::expand_top_bit;
    /// # let mut rng = rand::rngs::OsRng;
    /// # for _ in 1..320 {
    /// #     let a: u8 = rng.gen();
    /// assert!(
    ///     if a >> 7 == 1 {
    ///         expand_top_bit(a) == 0xFF
    ///     } else {
    ///         expand_top_bit(a) == 0
    ///     }
    /// );
    /// # }
    /// ```
    ///
    pub fn expand_top_bit(a: u8) -> u8 {
        0u8.wrapping_sub(a >> 7)
    }

    /// Determine whether a byte is zero.
    ///
    /// This method upholds the following relationship over all of its inputs:
    /// ```
    /// # use rand::Rng;
    /// # use internal::constant_time_ops::ct_is_zero;
    /// # let mut rng = rand::rngs::OsRng;
    /// # for _ in 1..320 {
    /// #     let a: u8 = rng.gen();
    /// assert!(
    ///     if a == 0 {
    ///         ct_is_zero(a) == 0xFF
    ///     } else {
    ///         ct_is_zero(a) == 0
    ///     }
    /// );
    /// # }
    /// ```
    ///
    /// To confirm the specific case of zero:
    /// ```
    /// # use internal::constant_time_ops::ct_is_zero;
    /// assert!(ct_is_zero(0) == 0xFF);
    /// ```
    pub fn ct_is_zero(a: u8) -> u8 {
        expand_top_bit(!a & a.wrapping_sub(1))
    }

    /// Determine whether two bytes are equal.
    ///
    /// This method upholds the following relationship over all of its inputs:
    /// ```
    /// # use rand::Rng;
    /// # use internal::constant_time_ops::ct_is_eq;
    /// # let mut rng = rand::rngs::OsRng;
    /// # for _ in 1..320 {
    /// #     let (a, b): (u8, u8) = rng.gen();
    /// assert!(
    ///     if a == b {
    ///         ct_is_eq(a, b) == 0xFF
    ///     } else {
    ///         ct_is_eq(a, b) == 0
    ///     }
    /// );
    /// # }
    /// ```
    pub fn ct_is_eq(a: u8, b: u8) -> u8 {
        ct_is_zero(a ^ b)
    }

    /// Determine whether one byte is less than another.
    ///
    /// This method upholds the following relationship over all of its inputs:
    /// ```
    /// # use rand::Rng;
    /// # use internal::constant_time_ops::ct_is_lt;
    /// # let mut rng = rand::rngs::OsRng;
    /// # for _ in 1..320 {
    /// #     let (a, b): (u8, u8) = rng.gen();
    /// assert!(
    ///     if a < b {
    ///         ct_is_lt(a, b) == 0xFF
    ///     } else {
    ///         ct_is_lt(a, b) == 0
    ///     }
    /// );
    /// # }
    /// ```
    pub fn ct_is_lt(a: u8, b: u8) -> u8 {
        expand_top_bit(a ^ ((a ^ b) | ((a.wrapping_sub(b)) ^ a)))
    }

    /// Select among the bits from `a` and `b` given the `mask.`
    ///
    /// This method upholds the following relationship over all of its inputs:
    /// ```
    /// # use rand::Rng;
    /// # use internal::constant_time_ops::ct_select;
    /// # let mut rng = rand::rngs::OsRng;
    /// # for _ in 1..320 {
    /// #     let (mask_flag, a, b): (bool, u8, u8) = rng.gen();
    /// #     let mask: u8 = if mask_flag { 0xFF } else { 0 };
    /// assert!(mask == 0 || mask == 0xFF); // This is assumed as a prerequisite.
    /// assert!(
    ///     if mask == 0xFF {
    ///         ct_select(mask, a, b) == a
    ///     } else if mask == 0x00 {
    ///         ct_select(mask, a, b) == b
    ///     } else {
    ///         unreachable!()
    ///     }
    /// );
    /// # }
    /// ```
    pub fn ct_select(mask: u8, a: u8, b: u8) -> u8 {
        debug_assert!(mask == 0 || mask == 0xFF);
        b ^ (mask & (a ^ b))
    }

    /// Compare the byte slices `x` and `y` with an execution pattern that does not leak details
    /// about the value of the two keys as it performs comparisons.
    ///
    /// This method's output should completely align with [Ord::cmp]:
    /// ```
    /// # use internal::constant_time_ops::constant_time_cmp;
    /// # use rand::{Rng, distributions::Standard};
    /// # let mut rng = rand::rngs::OsRng;
    /// # for cur_len in 1..320 {
    /// let x: Vec<u8>;
    /// let y: Vec<u8>;
    /// # let x: Vec<u8> = rng.sample_iter(Standard).take(cur_len).collect();
    /// # let y: Vec<u8> = rng.sample_iter(Standard).take(cur_len).collect();
    /// assert!(x.len() == y.len()); // This method panics if `x` and `y` are different lengths.
    /// assert!(constant_time_cmp(&x, &y) == x.cmp(&y));
    /// assert!(constant_time_cmp(&y, &x) == y.cmp(&x));
    /// # }
    /// ```
    ///
    /// This is what that looks like for some small inputs:
    /// ```
    /// # use internal::constant_time_ops::constant_time_cmp;
    /// use std::cmp::Ordering;
    ///
    /// assert!(constant_time_cmp(&[1], &[1]) == Ordering::Equal);
    /// assert!(constant_time_cmp(&[1, 0], &[0, 1]) == Ordering::Greater);
    /// assert!(constant_time_cmp(&[0, 1], &[1, 0]) == Ordering::Less);
    /// assert!(constant_time_cmp(&[1], &[2]) == Ordering::Less);
    /// ```
    ///
    /// ### Avoiding Information Leakage
    /// The primary goal of this function is to not leak any additional information about the value
    /// of the two keys through side channels, say due to an early exit of the loop as in
    /// [Ord::cmp].
    ///
    /// ### Future Work
    /// If `x` and `y` were different lengths, this would leak information about their relative
    /// sizes, if we exited early when processing them. However, we currently avoid this by
    /// immediately panicking if the inputs are not the same size.
    ///
    /// In addition, by branching at the end, this method will leak the final comparison result,
    /// when the integer is translated to the [Ordering] enum. This seems unavoidable for now.
    ///
    /// TODO: To address the above shortcomings, it could be possible to instead have this function
    /// SHA-256 hash both inputs, then compare the resulting hashes in the usual non-const time
    /// way. We avoid modifying our approach at the moment since it is not clear if applications
    /// will rely on public key ordering being defined in some particular way or not.
    pub fn constant_time_cmp(x: &[u8], y: &[u8]) -> Ordering {
        debug_assert!(x.len() == y.len());
        let mut result: u8 = 0;

        for i in 0..x.len() {
            let a = x[x.len() - 1 - i];
            let b = y[x.len() - 1 - i];

            let is_eq = ct_is_eq(a, b);
            let is_lt = ct_is_lt(a, b);

            result = ct_select(is_eq, result, ct_select(is_lt, 1, 255));
        }

        debug_assert!(result == 0 || result == 1 || result == 255);

        if result == 0 {
            Ordering::Equal
        } else if result == 1 {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

/// Codifying common patterns in this codebase, attempting to add type safety by using
/// type parameters.
pub mod traits {
    /// Some messages have a signature to check. We use this interface to check that signature.
    ///
    /// The below example uses a very simple and insecure hashing scheme based purely on the size of
    /// the owned data:
    /// ```
    /// # use internal::traits::SignatureVerifiable;
    /// struct S(Box<[u8]>);
    ///
    /// impl SignatureVerifiable for S {
    ///     type Sig = usize;
    ///     type Error = ();   // This throws away any error information.
    ///     fn verify_signature(&self, signature: usize) -> Result<(), ()> {
    ///         // Just check that the *length* of the underlying data is correct.
    ///         if signature == self.0.len() { Ok(()) } else { Err(()) }
    ///     }
    /// }
    ///
    /// let s = S(Box::new([1, 2, 3, 4, 5]));
    ///
    /// assert!(s.verify_signature(4).is_err());
    /// assert!(s.verify_signature(5).is_ok());
    /// ```
    pub trait SignatureVerifiable {
        /// The information necessaru to *validate* some *signature* against a *message*.
        ///
        /// Usually the "message" struct would implement [SignatureVerifiable].
        type Sig;
        /// The type returned if the signature verification fails.
        ///
        /// All signature verification failures **must** return an [Err]!
        type Error;
        /// Verify whether a signature matches the message contents from `self`.
        fn verify_signature(&self, signature: Self::Sig) -> Result<(), Self::Error>;
    }
}
