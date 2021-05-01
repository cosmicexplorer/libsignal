//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Where to send a message to.

use std::fmt;

/// The type in memory for a *device*, which is separate from an *identity*.
///
/// Used in [ProtocolAddress].
pub type DeviceId = u32;

/// The target of a [crate::SignalMessage].
#[derive(Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct ProtocolAddress {
    name: String,
    device_id: DeviceId,
}

impl ProtocolAddress {
    /// Create a new instance.
    pub fn new(name: String, device_id: DeviceId) -> Self {
        ProtocolAddress { name, device_id }
    }

    /// A unique identifier for the target user.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// An identifier for the individual device to send to, as Signal does not send messages to all
    /// devices at a time.
    #[inline]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
}

impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.name, self.device_id)
    }
}
