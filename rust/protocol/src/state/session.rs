//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto;
use std::result::Result;

use prost::Message;
use subtle::ConstantTimeEq;

use crate::protocol::CIPHERTEXT_MESSAGE_CURRENT_VERSION;
use crate::ratchet::{
    ChainKey, HeaderEncryptedMessageKeys, MessageKeys, RatchetingMessageKeys, RootKey,
};
use crate::{IdentityKey, KeyPair, PrivateKey, PublicKey, SignalProtocolError, ViaProtobuf};

use crate::consts;
use crate::proto::storage;
use crate::state::{PreKeyId, SignedPreKeyId};

/// A distinct error type to keep from accidentally propagating deserialization errors.
#[derive(Debug)]
pub(crate) struct InvalidSessionError(&'static str);

impl std::fmt::Display for InvalidSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<InvalidSessionError> for SignalProtocolError {
    fn from(e: InvalidSessionError) -> Self {
        Self::InvalidSessionStructure(e.0)
    }
}

pub use chain::{
    ChainImpl, CommonChain, HeaderEncryptedMessageChain, ReceiverChain, ReceiverChainInstance,
    SenderChain, SenderChainInstance, StandardMessageChain,
};
mod chain {
    use crate::ratchet::{ChainKey, RatchetingMessageKeys};
    use crate::{PrivateKey, PublicKey, SignalProtocolError, ViaProtobuf};

    use std::fmt::Debug;

    pub trait CommonChain: ViaProtobuf + Clone {
        type Key: RatchetingMessageKeys;
        fn sender_ratchet_key(&self) -> &PublicKey;

        fn chain_key(&self) -> &ChainKey;
        fn set_chain_key(&mut self, key: ChainKey);

        fn message_keys(&self) -> &[Self::Key];
        fn push_new_message_key(&mut self, key: Self::Key);
        fn remove_message_key(&mut self, index: usize) -> Result<Self::Key, SignalProtocolError>;
        fn pop_message_key(&mut self) -> Result<Self::Key, SignalProtocolError> {
            self.remove_message_key(self.message_keys().len() - 1)
        }

        fn needs_pni_signature(&self) -> bool;
        fn set_needs_pni_signature(&mut self, needs_pni_signature: bool);
    }

    pub trait ChainImpl: CommonChain + Debug {
        fn sender_ratchet_key_private(&self) -> Option<&PrivateKey>;

        fn initialize(
            chain_key: ChainKey,
            sender: PublicKey,
            sender_private: Option<PrivateKey>,
        ) -> Self
        where
            Self: Sized;
    }

    pub use forwarding::{ReceiverChain, ReceiverChainInstance, SenderChain, SenderChainInstance};
    mod forwarding {
        use super::{ChainImpl, CommonChain};

        pub use receiver::{ReceiverChain, ReceiverChainInstance};
        pub use sender::{SenderChain, SenderChainInstance};

        mod receiver {
            use super::{ChainImpl, CommonChain};

            use crate::ratchet::ChainKey;
            use crate::{PublicKey, SignalProtocolError, ViaProtobuf};

            pub trait ReceiverChain: CommonChain {
                fn initialize_receiver_chain(chain_key: ChainKey, sender: PublicKey) -> Self
                where
                    Self: Sized;
            }

            #[derive(Clone, Debug)]
            pub struct ReceiverChainInstance<C: ChainImpl> {
                pub receiver_chain: C,
            }

            impl<C> ReceiverChain for ReceiverChainInstance<C>
            where
                C: ChainImpl,
            {
                fn initialize_receiver_chain(chain_key: ChainKey, sender: PublicKey) -> Self {
                    Self {
                        receiver_chain: <C as ChainImpl>::initialize(chain_key, sender, None),
                    }
                }
            }

            /// Forward to underlying [ChainImpl] instance.
            impl<C> ViaProtobuf for ReceiverChainInstance<C>
            where
                C: ChainImpl,
            {
                type Proto = <C as ViaProtobuf>::Proto;
                fn into_protobuf(&self) -> Self::Proto {
                    self.receiver_chain.into_protobuf()
                }
                fn from_protobuf(proto: &Self::Proto) -> Result<Self, SignalProtocolError>
                where
                    Self: Sized,
                {
                    Ok(Self {
                        receiver_chain: <C as ViaProtobuf>::from_protobuf(proto)?,
                    })
                }
            }

            /// Forward to underlying [ChainImpl] instance.
            impl<C> CommonChain for ReceiverChainInstance<C>
            where
                C: ChainImpl,
            {
                type Key = <C as CommonChain>::Key;
                #[inline]
                fn sender_ratchet_key(&self) -> &PublicKey {
                    self.receiver_chain.sender_ratchet_key()
                }
                #[inline]
                fn chain_key(&self) -> &ChainKey {
                    self.receiver_chain.chain_key()
                }
                #[inline]
                fn set_chain_key(&mut self, key: ChainKey) {
                    self.receiver_chain.set_chain_key(key);
                }
                #[inline]
                fn message_keys(&self) -> &[Self::Key] {
                    self.receiver_chain.message_keys()
                }
                #[inline]
                fn push_new_message_key(&mut self, key: Self::Key) {
                    self.receiver_chain.push_new_message_key(key);
                }
                #[inline]
                fn remove_message_key(
                    &mut self,
                    index: usize,
                ) -> Result<Self::Key, SignalProtocolError> {
                    self.receiver_chain.remove_message_key(index)
                }
                #[inline]
                fn needs_pni_signature(&self) -> bool {
                    self.receiver_chain.needs_pni_signature()
                }
                #[inline]
                fn set_needs_pni_signature(&mut self, needs_pni_signature: bool) {
                    self.receiver_chain
                        .set_needs_pni_signature(needs_pni_signature);
                }
            }
        }

        mod sender {
            use super::{ChainImpl, CommonChain};

            use crate::ratchet::ChainKey;
            use crate::{KeyPair, PrivateKey, PublicKey, SignalProtocolError, ViaProtobuf};

            pub trait SenderChain: CommonChain {
                fn sender_ratchet_key_private(&self) -> &PrivateKey;
                fn initialize_sender_chain(chain_key: ChainKey, sender: KeyPair) -> Self
                where
                    Self: Sized;
            }

            #[derive(Clone, Debug)]
            pub struct SenderChainInstance<C: ChainImpl> {
                pub sender_chain: C,
            }

            impl<C> SenderChain for SenderChainInstance<C>
            where
                C: ChainImpl,
            {
                fn sender_ratchet_key_private(&self) -> &PrivateKey {
                    self.sender_chain
                        .sender_ratchet_key_private()
                        .expect("A SenderChainInstance should always have a private key set!")
                }
                fn initialize_sender_chain(next_chain_key: ChainKey, sender: KeyPair) -> Self {
                    let KeyPair {
                        public_key,
                        private_key,
                    } = sender;
                    Self {
                        sender_chain: <C as ChainImpl>::initialize(
                            next_chain_key,
                            public_key,
                            Some(private_key),
                        ),
                    }
                }
            }

            /// Forward to underlying [ChainImpl] instance.
            impl<C> ViaProtobuf for SenderChainInstance<C>
            where
                C: ChainImpl,
            {
                type Proto = <C as ViaProtobuf>::Proto;
                fn into_protobuf(&self) -> Self::Proto {
                    self.sender_chain.into_protobuf()
                }
                fn from_protobuf(proto: &Self::Proto) -> Result<Self, SignalProtocolError>
                where
                    Self: Sized,
                {
                    Ok(Self {
                        sender_chain: <C as ViaProtobuf>::from_protobuf(proto)?,
                    })
                }
            }

            /// Forward to underlying [ChainImpl] instance.
            impl<C> CommonChain for SenderChainInstance<C>
            where
                C: ChainImpl,
            {
                type Key = <C as CommonChain>::Key;
                #[inline]
                fn sender_ratchet_key(&self) -> &PublicKey {
                    self.sender_chain.sender_ratchet_key()
                }
                #[inline]
                fn chain_key(&self) -> &ChainKey {
                    self.sender_chain.chain_key()
                }
                #[inline]
                fn set_chain_key(&mut self, key: ChainKey) {
                    self.sender_chain.set_chain_key(key);
                }
                #[inline]
                fn message_keys(&self) -> &[Self::Key] {
                    self.sender_chain.message_keys()
                }
                #[inline]
                fn push_new_message_key(&mut self, key: Self::Key) {
                    self.sender_chain.push_new_message_key(key);
                }
                #[inline]
                fn remove_message_key(
                    &mut self,
                    index: usize,
                ) -> Result<Self::Key, SignalProtocolError> {
                    self.sender_chain.remove_message_key(index)
                }
                #[inline]
                fn needs_pni_signature(&self) -> bool {
                    self.sender_chain.needs_pni_signature()
                }
                #[inline]
                fn set_needs_pni_signature(&mut self, needs_pni_signature: bool) {
                    self.sender_chain
                        .set_needs_pni_signature(needs_pni_signature);
                }
            }
        }
    }

    pub use chain_impl::{HeaderEncryptedMessageChain, StandardMessageChain};
    mod chain_impl {
        use super::{ChainImpl, CommonChain};

        pub use header_encrypted_chain::HeaderEncryptedMessageChain;
        pub use standard_chain::StandardMessageChain;

        mod standard_chain {
            use super::{ChainImpl, CommonChain};

            use crate::proto::storage;
            use crate::ratchet::{ChainKey, MessageKeys};
            use crate::{PrivateKey, PublicKey, SignalProtocolError, ViaProtobuf};

            #[derive(Clone, Debug)]
            pub struct StandardMessageChain {
                sender_ratchet_key: PublicKey,
                sender_ratchet_key_private: Option<PrivateKey>,
                chain_key: ChainKey,
                message_keys: Vec<MessageKeys>,
                needs_pni_signature: bool,
            }

            impl ViaProtobuf for StandardMessageChain {
                type Proto = storage::Chain;
                fn into_protobuf(&self) -> Self::Proto {
                    storage::Chain {
                        sender_ratchet_key: self.sender_ratchet_key().serialize().to_vec(),
                        sender_ratchet_key_private: self
                            .sender_ratchet_key_private()
                            .map(|k| k.serialize()),
                        chain_key: Some(self.chain_key().into_protobuf()),
                        message_keys: self
                            .message_keys
                            .iter()
                            .map(|k| k.into_protobuf())
                            .collect(),
                        needs_pni_signature: self.needs_pni_signature(),
                    }
                }
                fn from_protobuf(proto: &Self::Proto) -> Result<Self, SignalProtocolError>
                where
                    Self: Sized,
                {
                    let storage::Chain {
                        sender_ratchet_key,
                        sender_ratchet_key_private,
                        chain_key,
                        message_keys,
                        needs_pni_signature,
                    } = proto;
                    Ok(Self {
                        sender_ratchet_key: PublicKey::deserialize(sender_ratchet_key)?,
                        sender_ratchet_key_private: match sender_ratchet_key_private {
                            Some(k) => Some(PrivateKey::deserialize(k)?),
                            None => None,
                        },
                        chain_key: ChainKey::from_protobuf(
                            chain_key
                                .as_ref()
                                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
                        )?,
                        message_keys: message_keys
                            .into_iter()
                            .map(|k| <Self as CommonChain>::Key::from_protobuf(&k))
                            .collect::<Result<Vec<_>, SignalProtocolError>>()?,
                        needs_pni_signature: *needs_pni_signature,
                    })
                }
            }

            impl CommonChain for StandardMessageChain {
                type Key = MessageKeys;
                #[inline]
                fn sender_ratchet_key(&self) -> &PublicKey {
                    &self.sender_ratchet_key
                }
                #[inline]
                fn chain_key(&self) -> &ChainKey {
                    &self.chain_key
                }
                #[inline]
                fn set_chain_key(&mut self, key: ChainKey) {
                    self.chain_key = key;
                }
                #[inline]
                fn message_keys(&self) -> &[Self::Key] {
                    self.message_keys.as_ref()
                }
                #[inline]
                fn push_new_message_key(&mut self, key: Self::Key) {
                    self.message_keys.insert(0, key);
                }
                fn remove_message_key(
                    &mut self,
                    index: usize,
                ) -> Result<Self::Key, SignalProtocolError> {
                    if index >= self.message_keys.len() {
                        Err(SignalProtocolError::InvalidArgument(
                            format!(
                                "insufficient message keys available ({}) to remove the one at index {}",
                                self.message_keys.len(),
                                index
                            ),
                        ))
                    } else {
                        Ok(self.message_keys.remove(index))
                    }
                }
                #[inline]
                fn needs_pni_signature(&self) -> bool {
                    self.needs_pni_signature
                }
                #[inline]
                fn set_needs_pni_signature(&mut self, needs_pni_signature: bool) {
                    self.needs_pni_signature = needs_pni_signature;
                }
            }

            impl ChainImpl for StandardMessageChain {
                #[inline]
                fn sender_ratchet_key_private(&self) -> Option<&PrivateKey> {
                    self.sender_ratchet_key_private.as_ref()
                }

                fn initialize(
                    chain_key: ChainKey,
                    sender: PublicKey,
                    sender_private: Option<PrivateKey>,
                ) -> Self
                where
                    Self: Sized,
                {
                    Self {
                        sender_ratchet_key: sender,
                        sender_ratchet_key_private: sender_private,
                        chain_key,
                        message_keys: vec![],
                        needs_pni_signature: false,
                    }
                }
            }
        }

        mod header_encrypted_chain {
            use super::{ChainImpl, CommonChain};

            use crate::proto::storage;
            use crate::ratchet::{ChainKey, HeaderEncryptedMessageKeys};
            use crate::{PrivateKey, PublicKey, SignalProtocolError, ViaProtobuf};

            #[derive(Clone, Debug)]
            pub struct HeaderEncryptedMessageChain {
                sender_ratchet_key: PublicKey,
                sender_ratchet_key_private: Option<PrivateKey>,
                chain_key: ChainKey,
                message_keys: Vec<HeaderEncryptedMessageKeys>,
                needs_pni_signature: bool,
            }

            impl ViaProtobuf for HeaderEncryptedMessageChain {
                type Proto = storage::HeaderEncryptedChain;
                fn into_protobuf(&self) -> Self::Proto {
                    storage::HeaderEncryptedChain {
                        sender_ratchet_key: self.sender_ratchet_key().serialize().to_vec(),
                        sender_ratchet_key_private: self
                            .sender_ratchet_key_private()
                            .map(|k| k.serialize()),
                        chain_key: Some(self.chain_key().into_protobuf()),
                        message_keys: self
                            .message_keys
                            .iter()
                            .map(|k| k.into_protobuf())
                            .collect(),
                        needs_pni_signature: self.needs_pni_signature(),
                    }
                }
                fn from_protobuf(proto: &Self::Proto) -> Result<Self, SignalProtocolError>
                where
                    Self: Sized,
                {
                    let storage::HeaderEncryptedChain {
                        sender_ratchet_key,
                        sender_ratchet_key_private,
                        chain_key,
                        message_keys,
                        needs_pni_signature,
                    } = proto;
                    Ok(Self {
                        sender_ratchet_key: PublicKey::deserialize(sender_ratchet_key)?,
                        sender_ratchet_key_private: match sender_ratchet_key_private {
                            Some(k) => Some(PrivateKey::deserialize(k)?),
                            None => None,
                        },
                        chain_key: ChainKey::from_protobuf(
                            chain_key
                                .as_ref()
                                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
                        )?,
                        message_keys: message_keys
                            .into_iter()
                            .map(|k| <Self as CommonChain>::Key::from_protobuf(&k))
                            .collect::<Result<Vec<_>, SignalProtocolError>>()?,
                        needs_pni_signature: *needs_pni_signature,
                    })
                }
            }

            impl CommonChain for HeaderEncryptedMessageChain {
                type Key = HeaderEncryptedMessageKeys;
                #[inline]
                fn sender_ratchet_key(&self) -> &PublicKey {
                    &self.sender_ratchet_key
                }
                #[inline]
                fn chain_key(&self) -> &ChainKey {
                    &self.chain_key
                }
                #[inline]
                fn set_chain_key(&mut self, key: ChainKey) {
                    self.chain_key = key;
                }
                #[inline]
                fn message_keys(&self) -> &[Self::Key] {
                    self.message_keys.as_ref()
                }
                #[inline]
                fn push_new_message_key(&mut self, key: Self::Key) {
                    self.message_keys.insert(0, key);
                }
                fn remove_message_key(
                    &mut self,
                    index: usize,
                ) -> Result<Self::Key, SignalProtocolError> {
                    if index >= self.message_keys.len() {
                        Err(SignalProtocolError::InvalidArgument(
                            format!(
                                "insufficient message keys available ({}) to remove the one at index {}",
                                self.message_keys.len(),
                                index
                            ),
                        ))
                    } else {
                        Ok(self.message_keys.remove(index))
                    }
                }
                #[inline]
                fn needs_pni_signature(&self) -> bool {
                    self.needs_pni_signature
                }
                #[inline]
                fn set_needs_pni_signature(&mut self, needs_pni_signature: bool) {
                    self.needs_pni_signature = needs_pni_signature;
                }
            }

            impl ChainImpl for HeaderEncryptedMessageChain {
                #[inline]
                fn sender_ratchet_key_private(&self) -> Option<&PrivateKey> {
                    self.sender_ratchet_key_private.as_ref()
                }

                fn initialize(
                    chain_key: ChainKey,
                    sender: PublicKey,
                    sender_private: Option<PrivateKey>,
                ) -> Self
                where
                    Self: Sized,
                {
                    Self {
                        sender_ratchet_key: sender,
                        sender_ratchet_key_private: sender_private,
                        chain_key,
                        message_keys: vec![],
                        needs_pni_signature: false,
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UnacknowledgedPreKeyMessageItems {
    pre_key_id: Option<PreKeyId>,
    signed_pre_key_id: SignedPreKeyId,
    base_key: PublicKey,
}

impl UnacknowledgedPreKeyMessageItems {
    fn new(
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: SignedPreKeyId,
        base_key: PublicKey,
    ) -> Self {
        Self {
            pre_key_id,
            signed_pre_key_id,
            base_key,
        }
    }

    pub(crate) fn pre_key_id(&self) -> Option<PreKeyId> {
        self.pre_key_id
    }

    pub(crate) fn signed_pre_key_id(&self) -> SignedPreKeyId {
        self.signed_pre_key_id
    }

    pub(crate) fn base_key(&self) -> &PublicKey {
        &self.base_key
    }
}

pub trait SessionStructure: ViaProtobuf + Clone {
    type Key: RatchetingMessageKeys;
    type C: ChainImpl;
    type R: RecordStructure<S = Self>;

    fn session_version(&self) -> u32;

    fn local_identity_public(&self) -> &PublicKey;
    fn remote_identity_public(&self) -> &PublicKey;

    fn root_key(&self) -> &RootKey;
    fn set_root_key(&mut self, root_key: &RootKey);

    fn previous_counter(&self) -> u32;
    fn set_previous_counter(&mut self, ctr: u32);

    fn sender_chain(&self) -> &SenderChainInstance<Self::C>;
    fn set_sender_chain(&mut self, chain: SenderChainInstance<Self::C>);
    fn update_sender_chain_key(&mut self, key: ChainKey);
    fn update_sender_chain_needs_pni_signature(&mut self, needs_pni_signature: bool);

    fn receiver_chains(&self) -> &[ReceiverChainInstance<Self::C>];
    fn add_receiver_chain(&mut self, chain: ReceiverChainInstance<Self::C>);
    fn remove_receiver_chain(&mut self, index: usize) -> Result<(), SignalProtocolError>;
    fn update_receiver_chain(
        &mut self,
        chain: ReceiverChainInstance<Self::C>,
        index: usize,
    ) -> Result<(), SignalProtocolError>;

    fn pending_pre_key(&self) -> Option<&storage::PendingPreKey>;
    fn set_pending_pre_key(&mut self, key: storage::PendingPreKey);
    fn clear_pending_pre_key(&mut self);

    fn remote_registration_id(&self) -> u32;
    fn set_remote_registration_id(&mut self, registration_id: u32);

    fn local_registration_id(&self) -> u32;
    fn set_local_registration_id(&mut self, registration_id: u32);

    fn alice_base_key(&self) -> Option<&PublicKey>;
    fn set_alice_base_key(&mut self, key: &PublicKey);

    fn initialize(
        local_identity_public: PublicKey,
        remote_identity_public: PublicKey,
        root_key: RootKey,
        receiver: Option<(PublicKey, ChainKey)>,
        sender_identity: KeyPair,
        sender_chain_key: ChainKey,
    ) -> Self
    where
        Self: Sized;
}

#[derive(Clone, Debug)]
pub struct StandardSessionStructure {
    session_version: u32,
    local_identity_public: PublicKey,
    remote_identity_public: PublicKey,
    root_key: RootKey,
    previous_counter: u32,
    sender_chain: SenderChainInstance<StandardMessageChain>,
    receiver_chains: Vec<ReceiverChainInstance<StandardMessageChain>>,
    pending_pre_key: Option<storage::PendingPreKey>,
    remote_registration_id: u32,
    local_registration_id: u32,
    alice_base_key: Option<PublicKey>,
}

impl ViaProtobuf for StandardSessionStructure {
    type Proto = storage::SessionStructure;
    fn into_protobuf(&self) -> Self::Proto {
        storage::SessionStructure {
            session_version: self.session_version(),
            local_identity_public: self.local_identity_public.serialize().to_vec(),
            remote_identity_public: self.remote_identity_public.serialize().to_vec(),
            root_key: self.root_key().key().to_vec(),
            previous_counter: self.previous_counter(),
            sender_chain: Some(self.sender_chain().sender_chain.into_protobuf()),
            receiver_chains: self
                .receiver_chains
                .iter()
                .map(|c| c.receiver_chain.into_protobuf())
                .collect::<Vec<_>>(),
            pending_pre_key: self.pending_pre_key.clone(),
            remote_registration_id: self.remote_registration_id,
            local_registration_id: self.local_registration_id,
            alice_base_key: self
                .alice_base_key
                .expect("alice_base_key was None before serializing StandardSessionStructure")
                .serialize()
                .into_vec(),
        }
    }
    fn from_protobuf(proto: &Self::Proto) -> Result<Self, SignalProtocolError>
    where
        Self: Sized,
    {
        let storage::SessionStructure {
            session_version,
            local_identity_public,
            remote_identity_public,
            root_key,
            previous_counter,
            sender_chain,
            receiver_chains,
            pending_pre_key,
            remote_registration_id,
            local_registration_id,
            alice_base_key,
        } = proto;
        Ok(Self {
            session_version: *session_version,
            local_identity_public: PublicKey::deserialize(local_identity_public)?,
            remote_identity_public: PublicKey::deserialize(remote_identity_public)?,
            root_key: RootKey::new(
                root_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?,
            ),
            previous_counter: *previous_counter,
            sender_chain: SenderChainInstance {
                sender_chain: <Self as SessionStructure>::C::from_protobuf(
                    sender_chain
                        .as_ref()
                        .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
                )?,
            },
            receiver_chains: receiver_chains
                .iter()
                .map(|c| {
                    <Self as SessionStructure>::C::from_protobuf(&c)
                        .map(|c| ReceiverChainInstance { receiver_chain: c })
                })
                .collect::<Result<Vec<_>, SignalProtocolError>>()?,
            pending_pre_key: pending_pre_key.clone(),
            remote_registration_id: *remote_registration_id,
            local_registration_id: *local_registration_id,
            alice_base_key: Some(PublicKey::deserialize(alice_base_key)?),
        })
    }
}

impl SessionStructure for StandardSessionStructure {
    type Key = MessageKeys;
    type C = StandardMessageChain;
    type R = StandardRecordStructure;
    #[inline]
    fn session_version(&self) -> u32 {
        self.session_version
    }
    #[inline]
    fn local_identity_public(&self) -> &PublicKey {
        &self.local_identity_public
    }
    #[inline]
    fn remote_identity_public(&self) -> &PublicKey {
        &self.remote_identity_public
    }
    #[inline]
    fn root_key(&self) -> &RootKey {
        &self.root_key
    }
    #[inline]
    fn set_root_key(&mut self, root_key: &RootKey) {
        self.root_key = *root_key;
    }
    #[inline]
    fn previous_counter(&self) -> u32 {
        self.previous_counter
    }
    #[inline]
    fn set_previous_counter(&mut self, ctr: u32) {
        self.previous_counter = ctr;
    }
    #[inline]
    fn sender_chain(&self) -> &SenderChainInstance<Self::C> {
        &self.sender_chain
    }
    #[inline]
    fn set_sender_chain(&mut self, chain: SenderChainInstance<Self::C>) {
        self.sender_chain = chain;
    }
    #[inline]
    fn update_sender_chain_key(&mut self, key: ChainKey) {
        self.sender_chain.set_chain_key(key);
    }
    #[inline]
    fn update_sender_chain_needs_pni_signature(&mut self, needs_pni_signature: bool) {
        self.sender_chain
            .set_needs_pni_signature(needs_pni_signature);
    }
    #[inline]
    fn receiver_chains(&self) -> &[ReceiverChainInstance<Self::C>] {
        self.receiver_chains.as_ref()
    }
    #[inline]
    fn add_receiver_chain(&mut self, chain: ReceiverChainInstance<Self::C>) {
        self.receiver_chains.push(chain);
    }
    fn remove_receiver_chain(&mut self, index: usize) -> Result<(), SignalProtocolError> {
        if index >= self.receiver_chains.len() {
            Err(SignalProtocolError::InvalidArgument(format!(
                "insufficient receiver chains available ({}) to remove the one at index {}",
                self.receiver_chains.len(),
                index
            )))
        } else {
            self.receiver_chains.remove(index);
            Ok(())
        }
    }
    fn update_receiver_chain(
        &mut self,
        chain: ReceiverChainInstance<Self::C>,
        index: usize,
    ) -> Result<(), SignalProtocolError> {
        if index >= self.receiver_chains.len() {
            Err(SignalProtocolError::InvalidArgument(format!(
                "insufficient receiver chains available ({}) to update the one at index {}",
                self.receiver_chains.len(),
                index
            )))
        } else {
            self.receiver_chains[index] = chain;
            Ok(())
        }
    }
    #[inline]
    fn pending_pre_key(&self) -> Option<&storage::PendingPreKey> {
        self.pending_pre_key.as_ref()
    }
    #[inline]
    fn set_pending_pre_key(&mut self, key: storage::PendingPreKey) {
        self.pending_pre_key = Some(key);
    }
    /* TODO: consider making this panic if the pending pre-key doesn't exist? */
    #[inline]
    fn clear_pending_pre_key(&mut self) {
        self.pending_pre_key = None;
    }
    #[inline]
    fn remote_registration_id(&self) -> u32 {
        self.remote_registration_id
    }
    #[inline]
    fn set_remote_registration_id(&mut self, registration_id: u32) {
        self.remote_registration_id = registration_id;
    }
    #[inline]
    fn local_registration_id(&self) -> u32 {
        self.local_registration_id
    }
    #[inline]
    fn set_local_registration_id(&mut self, registration_id: u32) {
        self.local_registration_id = registration_id;
    }
    #[inline]
    fn alice_base_key(&self) -> Option<&PublicKey> {
        self.alice_base_key.as_ref()
    }
    #[inline]
    fn set_alice_base_key(&mut self, key: &PublicKey) {
        self.alice_base_key = Some(key.clone());
    }

    fn initialize(
        local_identity_public: PublicKey,
        remote_identity_public: PublicKey,
        root_key: RootKey,
        receiver: Option<(PublicKey, ChainKey)>,
        sender_identity: KeyPair,
        sender_chain_key: ChainKey,
    ) -> Self
    where
        Self: Sized,
    {
        let receiver_chain = receiver.map(|(pub_key, chain_key)| {
            ReceiverChainInstance::initialize_receiver_chain(chain_key, pub_key)
        });
        let sender_chain =
            SenderChainInstance::initialize_sender_chain(sender_chain_key, sender_identity);

        Self {
            session_version: CIPHERTEXT_MESSAGE_CURRENT_VERSION as u32,
            local_identity_public,
            remote_identity_public,
            root_key,
            previous_counter: 0,
            sender_chain,
            receiver_chains: match receiver_chain {
                Some(chain) => vec![chain],
                None => vec![],
            },
            pending_pre_key: None,
            remote_registration_id: 0,
            local_registration_id: 0,
            alice_base_key: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HeaderEncryptedSessionStructure {
    session_version: u32,
    local_identity_public: PublicKey,
    remote_identity_public: PublicKey,
    root_key: RootKey,
    previous_counter: u32,
    sender_chain: SenderChainInstance<HeaderEncryptedMessageChain>,
    receiver_chains: Vec<ReceiverChainInstance<HeaderEncryptedMessageChain>>,
    pending_pre_key: Option<storage::PendingPreKey>,
    remote_registration_id: u32,
    local_registration_id: u32,
    alice_base_key: Option<PublicKey>,
}

impl ViaProtobuf for HeaderEncryptedSessionStructure {
    type Proto = storage::HeaderEncryptedSessionStructure;
    fn into_protobuf(&self) -> Self::Proto {
        storage::HeaderEncryptedSessionStructure {
            session_version: self.session_version(),
            local_identity_public: self.local_identity_public.serialize().into_vec(),
            remote_identity_public: self.remote_identity_public.serialize().into_vec(),
            root_key: self.root_key().key().to_vec(),
            previous_counter: self.previous_counter(),
            sender_chain: Some(self.sender_chain().sender_chain.into_protobuf()),
            receiver_chains: self
                .receiver_chains
                .iter()
                .map(|c| c.receiver_chain.into_protobuf())
                .collect::<Vec<_>>(),
            pending_pre_key: self.pending_pre_key.clone(),
            remote_registration_id: self.remote_registration_id,
            local_registration_id: self.local_registration_id,
            alice_base_key: self
                .alice_base_key
                .expect(
                    "alice_base_key was None before serializing HeaderEncryptedSessionStructure",
                )
                .serialize()
                .into_vec(),
        }
    }
    fn from_protobuf(proto: &Self::Proto) -> Result<Self, SignalProtocolError>
    where
        Self: Sized,
    {
        let storage::HeaderEncryptedSessionStructure {
            session_version,
            local_identity_public,
            remote_identity_public,
            root_key,
            previous_counter,
            sender_chain,
            receiver_chains,
            pending_pre_key,
            remote_registration_id,
            local_registration_id,
            alice_base_key,
        } = proto;
        Ok(Self {
            session_version: *session_version,
            local_identity_public: PublicKey::deserialize(&local_identity_public)?,
            remote_identity_public: PublicKey::deserialize(&remote_identity_public)?,
            root_key: RootKey::new(
                root_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?,
            ),
            previous_counter: *previous_counter,
            sender_chain: SenderChainInstance {
                sender_chain: <Self as SessionStructure>::C::from_protobuf(
                    sender_chain
                        .as_ref()
                        .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
                )?,
            },
            receiver_chains: receiver_chains
                .into_iter()
                .map(|c| {
                    <Self as SessionStructure>::C::from_protobuf(&c)
                        .map(|c| ReceiverChainInstance { receiver_chain: c })
                })
                .collect::<Result<Vec<_>, SignalProtocolError>>()?,
            pending_pre_key: pending_pre_key.clone(),
            remote_registration_id: *remote_registration_id,
            local_registration_id: *local_registration_id,
            alice_base_key: Some(PublicKey::deserialize(alice_base_key)?),
        })
    }
}

impl SessionStructure for HeaderEncryptedSessionStructure {
    type Key = HeaderEncryptedMessageKeys;
    type C = HeaderEncryptedMessageChain;
    type R = HeaderEncryptedRecordStructure;
    #[inline]
    fn session_version(&self) -> u32 {
        self.session_version
    }
    #[inline]
    fn local_identity_public(&self) -> &PublicKey {
        &self.local_identity_public
    }
    #[inline]
    fn remote_identity_public(&self) -> &PublicKey {
        &self.remote_identity_public
    }
    #[inline]
    fn root_key(&self) -> &RootKey {
        &self.root_key
    }
    #[inline]
    fn set_root_key(&mut self, root_key: &RootKey) {
        self.root_key = *root_key;
    }
    #[inline]
    fn previous_counter(&self) -> u32 {
        self.previous_counter
    }
    #[inline]
    fn set_previous_counter(&mut self, ctr: u32) {
        self.previous_counter = ctr;
    }
    #[inline]
    fn sender_chain(&self) -> &SenderChainInstance<Self::C> {
        &self.sender_chain
    }
    #[inline]
    fn set_sender_chain(&mut self, chain: SenderChainInstance<Self::C>) {
        self.sender_chain = chain;
    }
    #[inline]
    fn update_sender_chain_key(&mut self, key: ChainKey) {
        self.sender_chain.set_chain_key(key);
    }
    #[inline]
    fn update_sender_chain_needs_pni_signature(&mut self, needs_pni_signature: bool) {
        self.sender_chain
            .set_needs_pni_signature(needs_pni_signature);
    }
    #[inline]
    fn receiver_chains(&self) -> &[ReceiverChainInstance<Self::C>] {
        self.receiver_chains.as_ref()
    }
    #[inline]
    fn add_receiver_chain(&mut self, chain: ReceiverChainInstance<Self::C>) {
        self.receiver_chains.push(chain);
    }
    fn remove_receiver_chain(&mut self, index: usize) -> Result<(), SignalProtocolError> {
        if index >= self.receiver_chains.len() {
            Err(SignalProtocolError::InvalidArgument(format!(
                "insufficient receiver chains available ({}) to remove the one at index {}",
                self.receiver_chains.len(),
                index
            )))
        } else {
            self.receiver_chains.remove(index);
            Ok(())
        }
    }
    fn update_receiver_chain(
        &mut self,
        chain: ReceiverChainInstance<Self::C>,
        index: usize,
    ) -> Result<(), SignalProtocolError> {
        if index >= self.receiver_chains.len() {
            Err(SignalProtocolError::InvalidArgument(format!(
                "insufficient receiver chains available ({}) to update the one at index {}",
                self.receiver_chains.len(),
                index
            )))
        } else {
            self.receiver_chains[index] = chain;
            Ok(())
        }
    }

    #[inline]
    fn pending_pre_key(&self) -> Option<&storage::PendingPreKey> {
        self.pending_pre_key.as_ref()
    }
    #[inline]
    fn set_pending_pre_key(&mut self, key: storage::PendingPreKey) {
        self.pending_pre_key = Some(key);
    }
    /* TODO: consider making this panic if the pending pre-key doesn't exist? */
    #[inline]
    fn clear_pending_pre_key(&mut self) {
        self.pending_pre_key = None;
    }
    #[inline]
    fn remote_registration_id(&self) -> u32 {
        self.remote_registration_id
    }
    #[inline]
    fn set_remote_registration_id(&mut self, registration_id: u32) {
        self.remote_registration_id = registration_id;
    }
    #[inline]
    fn local_registration_id(&self) -> u32 {
        self.local_registration_id
    }
    #[inline]
    fn set_local_registration_id(&mut self, registration_id: u32) {
        self.local_registration_id = registration_id;
    }
    #[inline]
    fn alice_base_key(&self) -> Option<&PublicKey> {
        self.alice_base_key.as_ref()
    }
    #[inline]
    fn set_alice_base_key(&mut self, key: &PublicKey) {
        self.alice_base_key = Some(key.clone());
    }

    fn initialize(
        local_identity_public: PublicKey,
        remote_identity_public: PublicKey,
        root_key: RootKey,
        receiver: Option<(PublicKey, ChainKey)>,
        sender_identity: KeyPair,
        sender_chain_key: ChainKey,
    ) -> Self
    where
        Self: Sized,
    {
        let receiver_chain = receiver.map(|(pub_key, chain_key)| {
            ReceiverChainInstance::initialize_receiver_chain(chain_key, pub_key)
        });
        let sender_chain =
            SenderChainInstance::initialize_sender_chain(sender_chain_key, sender_identity);

        Self {
            session_version: CIPHERTEXT_MESSAGE_CURRENT_VERSION as u32,
            local_identity_public,
            remote_identity_public,
            root_key,
            previous_counter: 0,
            sender_chain,
            receiver_chains: match receiver_chain {
                Some(chain) => vec![chain],
                None => vec![],
            },
            pending_pre_key: None,
            remote_registration_id: 0,
            local_registration_id: 0,
            alice_base_key: None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SessionState<S: SessionStructure> {
    session: S,
}

impl<S> SessionState<S>
where
    S: SessionStructure,
{
    pub(crate) fn new(session: S) -> Self {
        Self { session }
    }

    pub(crate) fn into_underlying_session(self) -> S {
        self.session
    }

    pub(crate) fn alice_base_key(&self) -> Result<&PublicKey, SignalProtocolError> {
        self.session
            .alice_base_key()
            .ok_or(SignalProtocolError::InvalidSessionStructure(
                "alice_base_key not yet initialized",
            ))
    }

    pub(crate) fn set_alice_base_key(&mut self, key: &PublicKey) {
        self.session.set_alice_base_key(key);
    }

    pub fn session_version(&self) -> u32 {
        match self.session.session_version() {
            0 => 2,
            v => v,
        }
    }

    pub(crate) fn remote_identity_key(&self) -> IdentityKey {
        IdentityKey::new(*self.session.remote_identity_public())
    }

    pub(crate) fn remote_identity_key_bytes(&self) -> Vec<u8> {
        self.remote_identity_key().serialize().to_vec()
    }

    pub(crate) fn local_identity_key(&self) -> IdentityKey {
        IdentityKey::new(*self.session.local_identity_public())
    }

    pub(crate) fn local_identity_key_bytes(&self) -> Vec<u8> {
        self.local_identity_key().serialize().to_vec()
    }

    pub(crate) fn session_with_self(&self) -> bool {
        // If we compared bytes directly it would be faster, but may miss non-canonical points.
        // It's unclear if supporting such points is desirable.
        self.remote_identity_key_bytes() == self.local_identity_key_bytes()
    }

    pub(crate) fn previous_counter(&self) -> u32 {
        self.session.previous_counter()
    }

    pub(crate) fn set_previous_counter(&mut self, ctr: u32) {
        self.session.set_previous_counter(ctr)
    }

    pub(crate) fn root_key(&self) -> RootKey {
        *self.session.root_key()
    }

    pub(crate) fn set_root_key(&mut self, root_key: &RootKey) {
        self.session.set_root_key(root_key)
    }

    pub(crate) fn sender_ratchet_key(&self) -> PublicKey {
        *self.session.sender_chain().sender_ratchet_key()
    }

    pub(crate) fn sender_ratchet_key_for_logging(&self) -> String {
        hex::encode(self.sender_ratchet_key().public_key_bytes())
    }

    pub(crate) fn sender_ratchet_private_key(&self) -> PrivateKey {
        *self.session.sender_chain().sender_ratchet_key_private()
    }

    pub(crate) fn all_receiver_chain_logging_info(&self) -> Vec<(Vec<u8>, u32)> {
        let mut results = vec![];
        for chain in self.session.receiver_chains().iter() {
            let sender_ratchet_public = chain.sender_ratchet_key().serialize().to_vec();
            let chain_key_idx = chain.chain_key().index();
            results.push((sender_ratchet_public, chain_key_idx))
        }
        results
    }

    pub(crate) fn get_receiver_chain(
        &self,
        sender: &PublicKey,
    ) -> Option<(ReceiverChainInstance<<S as SessionStructure>::C>, usize)> {
        let sender_bytes = sender.serialize();

        for (idx, chain) in self.session.receiver_chains().iter().enumerate() {
            // If we compared bytes directly it would be faster, but may miss non-canonical points.
            // It's unclear if supporting such points is desirable.
            let this_point = chain.sender_ratchet_key().serialize();

            if this_point == sender_bytes {
                return Some((chain.clone(), idx));
            }
        }

        None
    }

    pub(crate) fn get_receiver_chain_key(&self, sender: &PublicKey) -> Option<ChainKey> {
        self.get_receiver_chain(sender)
            .map(|(chain, _)| *chain.chain_key())
    }

    pub(crate) fn get_receiver_chain_key_bytes(&self, sender: &PublicKey) -> Option<Vec<u8>> {
        self.get_receiver_chain_key(sender)
            .map(|chain_key| chain_key.key()[..].into())
    }

    pub(crate) fn add_receiver_chain(&mut self, sender: &PublicKey, chain_key: &ChainKey) {
        let chain = ReceiverChainInstance::initialize_receiver_chain(*chain_key, *sender);

        self.session.add_receiver_chain(chain);

        if self.session.receiver_chains().len() > consts::MAX_RECEIVER_CHAINS {
            log::info!(
                "Trimming excessive receiver_chain for session with base key {}, chain count: {}",
                self.sender_ratchet_key_for_logging(),
                self.session.receiver_chains().len()
            );
            self.session
                .remove_receiver_chain(0)
                .expect("just checked that > 0 receiver chains were active");
        }
    }

    pub(crate) fn set_sender_chain(&mut self, sender: &KeyPair, next_chain_key: &ChainKey) {
        let new_chain = SenderChainInstance::initialize_sender_chain(*next_chain_key, *sender);
        self.session.set_sender_chain(new_chain);
    }

    pub(crate) fn get_sender_chain_key(&self) -> ChainKey {
        *self.session.sender_chain().chain_key()
    }

    pub(crate) fn get_sender_chain_key_bytes(&self) -> Vec<u8> {
        self.get_sender_chain_key().key().to_vec()
    }

    pub(crate) fn set_sender_chain_key(&mut self, next_chain_key: &ChainKey) {
        self.session.update_sender_chain_key(*next_chain_key);
    }

    pub(crate) fn get_message_keys(
        &mut self,
        sender: &PublicKey,
        counter: u32,
    ) -> Result<Option<<<S as SessionStructure>::C as CommonChain>::Key>, InvalidSessionError> {
        if let Some((mut chain, index)) = self.get_receiver_chain(sender) {
            let message_key_idx = chain
                .message_keys()
                .iter()
                .position(|m| m.counter() == counter);

            if let Some(position) = message_key_idx {
                let keys = chain.remove_message_key(position).expect("this index is from message_key_idx above, which is at most the index of keys in .message_keys()");
                // Update with the message key that we just removed.
                self.session
                    .update_receiver_chain(chain, index)
                    .expect("this index is from self.get_receiver_chain(sender) above");
                return Ok(Some(keys));
            }
        }

        Ok(None)
    }

    pub(crate) fn set_message_keys(
        &mut self,
        sender: &PublicKey,
        message_keys: &<<S as SessionStructure>::C as CommonChain>::Key,
    ) {
        let (mut updated_chain, index) = self
            .get_receiver_chain(sender)
            .expect("called set_message_keys for a non-existent chain");
        updated_chain.push_new_message_key(message_keys.clone());

        if updated_chain.message_keys().len() > consts::MAX_MESSAGE_KEYS {
            updated_chain
                .pop_message_key()
                .expect("just checked .message_keys() has at least 1 element");
        }

        self.session
            .update_receiver_chain(updated_chain, index)
            .expect("this index is from self.get_receiver_chain(sender) earlier");
    }

    pub(crate) fn set_receiver_chain_key(&mut self, sender: &PublicKey, chain_key: &ChainKey) {
        let (mut updated_chain, index) = self
            .get_receiver_chain(sender)
            .expect("called set_receiver_chain_key for a non-existent chain");
        updated_chain.set_chain_key(*chain_key);
        self.session
            .update_receiver_chain(updated_chain, index)
            .expect("this index is from self.get_receiver_chain(sender)");
    }

    pub(crate) fn set_unacknowledged_pre_key_message(
        &mut self,
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) {
        let pending = storage::PendingPreKey {
            pre_key_id: pre_key_id.unwrap_or(0),
            signed_pre_key_id: signed_pre_key_id as i32,
            base_key: base_key.serialize().to_vec(),
        };
        self.session.set_pending_pre_key(pending);
    }

    pub(crate) fn unacknowledged_pre_key_message_items(
        &self,
    ) -> Result<Option<UnacknowledgedPreKeyMessageItems>, InvalidSessionError> {
        if let Some(ref pending_pre_key) = self.session.pending_pre_key() {
            Ok(Some(UnacknowledgedPreKeyMessageItems::new(
                match pending_pre_key.pre_key_id {
                    0 => None,
                    v => Some(v),
                },
                pending_pre_key.signed_pre_key_id as SignedPreKeyId,
                PublicKey::deserialize(&pending_pre_key.base_key)
                    .map_err(|_| InvalidSessionError("invalid pending PreKey message base key"))?,
            )))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn clear_unacknowledged_pre_key_message(&mut self) {
        self.session.clear_pending_pre_key()
    }

    pub(crate) fn set_remote_registration_id(&mut self, registration_id: u32) {
        self.session.set_remote_registration_id(registration_id);
    }

    pub(crate) fn remote_registration_id(&self) -> u32 {
        self.session.remote_registration_id()
    }

    pub(crate) fn set_local_registration_id(&mut self, registration_id: u32) {
        self.session.set_local_registration_id(registration_id);
    }

    pub(crate) fn local_registration_id(&self) -> u32 {
        self.session.local_registration_id()
    }

    pub(crate) fn needs_pni_signature(&self) -> bool {
        self.session.sender_chain().needs_pni_signature()
    }

    pub(crate) fn set_needs_pni_signature(&mut self, needs_pni_signature: bool) {
        self.session
            .update_sender_chain_needs_pni_signature(needs_pni_signature);
    }
}

impl<S> From<S> for SessionState<S>
where
    S: SessionStructure,
{
    fn from(value: S) -> SessionState<S> {
        SessionState::new(value)
    }
}

pub trait RecordStructure: ViaProtobuf {
    type S: SessionStructure;
    fn current_session(&self) -> Option<&Self::S>;
    fn previous_sessions(&self) -> &[Self::S];
    fn initialize(current_session: Option<Self::S>, previous_sessions: Vec<Self::S>) -> Self
    where
        Self: Sized;
}

#[derive(Clone, Debug)]
pub struct StandardRecordStructure {
    current_session: Option<StandardSessionStructure>,
    previous_sessions: Vec<StandardSessionStructure>,
}

impl ViaProtobuf for StandardRecordStructure {
    type Proto = storage::RecordStructure;
    fn into_protobuf(&self) -> Self::Proto {
        let current_session = self.current_session.as_ref().map(|s| s.into_protobuf());
        let previous_sessions: Vec<Vec<u8>> = self
            .previous_sessions
            .iter()
            .map(|s| s.into_protobuf().encode_to_vec())
            .collect();
        storage::RecordStructure {
            current_session,
            previous_sessions,
        }
    }
    fn from_protobuf(proto: &Self::Proto) -> Result<Self, SignalProtocolError>
    where
        Self: Sized,
    {
        let current_session = proto
            .current_session
            .as_ref()
            .map(|s| <Self as RecordStructure>::S::from_protobuf(&s))
            .transpose()?;
        let previous_sessions: Vec<<Self as RecordStructure>::S> = proto
            .previous_sessions
            .iter()
            .map(|s| {
                <<Self as RecordStructure>::S as ViaProtobuf>::Proto::decode(s.as_ref())
                    .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)
                    .and_then(|s| <Self as RecordStructure>::S::from_protobuf(&s))
            })
            .collect::<Result<Vec<<Self as RecordStructure>::S>, SignalProtocolError>>()?;
        Ok(Self {
            current_session,
            previous_sessions,
        })
    }
}

impl RecordStructure for StandardRecordStructure {
    type S = StandardSessionStructure;
    #[inline]
    fn current_session(&self) -> Option<&Self::S> {
        self.current_session.as_ref()
    }
    #[inline]
    fn previous_sessions(&self) -> &[Self::S] {
        self.previous_sessions.as_ref()
    }
    fn initialize(current_session: Option<Self::S>, previous_sessions: Vec<Self::S>) -> Self
    where
        Self: Sized,
    {
        Self {
            current_session,
            previous_sessions,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HeaderEncryptedRecordStructure {
    current_session: Option<HeaderEncryptedSessionStructure>,
    previous_sessions: Vec<HeaderEncryptedSessionStructure>,
}

impl ViaProtobuf for HeaderEncryptedRecordStructure {
    type Proto = storage::HeaderEncryptedRecordStructure;
    fn into_protobuf(&self) -> Self::Proto {
        let current_session = self.current_session.as_ref().map(|s| s.into_protobuf());
        let previous_sessions: Vec<Vec<u8>> = self
            .previous_sessions
            .iter()
            .map(|s| s.into_protobuf().encode_to_vec())
            .collect();
        storage::HeaderEncryptedRecordStructure {
            current_session,
            previous_sessions,
        }
    }
    fn from_protobuf(proto: &Self::Proto) -> Result<Self, SignalProtocolError>
    where
        Self: Sized,
    {
        let current_session = proto
            .current_session
            .as_ref()
            .map(|s| <Self as RecordStructure>::S::from_protobuf(&s))
            .transpose()?;
        let previous_sessions: Vec<<Self as RecordStructure>::S> = proto
            .previous_sessions
            .iter()
            .map(|s| {
                <<Self as RecordStructure>::S as ViaProtobuf>::Proto::decode(s.as_ref())
                    .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)
                    .and_then(|s| <Self as RecordStructure>::S::from_protobuf(&s))
            })
            .collect::<Result<Vec<<Self as RecordStructure>::S>, SignalProtocolError>>()?;
        Ok(Self {
            current_session,
            previous_sessions,
        })
    }
}

impl RecordStructure for HeaderEncryptedRecordStructure {
    type S = HeaderEncryptedSessionStructure;
    #[inline]
    fn current_session(&self) -> Option<&Self::S> {
        self.current_session.as_ref()
    }
    #[inline]
    fn previous_sessions(&self) -> &[Self::S] {
        self.previous_sessions.as_ref()
    }
    fn initialize(current_session: Option<Self::S>, previous_sessions: Vec<Self::S>) -> Self
    where
        Self: Sized,
    {
        Self {
            current_session,
            previous_sessions,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionRecord<S: SessionStructure> {
    current_session: Option<SessionState<S>>,
    previous_sessions: Vec<SessionState<S>>,
}

impl<S> ViaProtobuf for SessionRecord<S>
where
    S: SessionStructure,
{
    type Proto = <S::R as ViaProtobuf>::Proto;
    fn into_protobuf(&self) -> Self::Proto {
        let Self {
            current_session,
            previous_sessions,
        } = self;
        let current_session_record = current_session.clone().map(|s| s.into_underlying_session());
        let previous_session_records = previous_sessions
            .iter()
            .cloned()
            .map(|s| s.into_underlying_session())
            .collect();
        let underlying_record_structure =
            <S::R as RecordStructure>::initialize(current_session_record, previous_session_records);
        underlying_record_structure.into_protobuf()
    }
    fn from_protobuf(proto: &Self::Proto) -> Result<Self, SignalProtocolError>
    where
        Self: Sized,
    {
        let underlying_record_structure = <S::R as ViaProtobuf>::from_protobuf(proto)?;
        let current_session: Option<SessionState<S>> = underlying_record_structure
            .current_session()
            .map(|s| SessionState::<S>::new(s.clone()));
        let previous_sessions: Vec<SessionState<S>> = underlying_record_structure
            .previous_sessions()
            .iter()
            .map(|s| SessionState::<S>::new(s.clone()))
            .collect();
        Ok(Self {
            current_session,
            previous_sessions,
        })
    }
}

impl<S> SessionRecord<S>
where
    S: SessionStructure,
{
    pub fn new_fresh() -> Self {
        Self {
            current_session: None,
            previous_sessions: Vec::new(),
        }
    }

    pub(crate) fn new(state: SessionState<S>) -> Self {
        Self {
            current_session: Some(state),
            previous_sessions: Vec::new(),
        }
    }

    pub(crate) fn has_session_state(
        &self,
        version: u32,
        alice_base_key: &[u8],
    ) -> Result<bool, InvalidSessionError> {
        if let Some(current_session) = &self.current_session {
            if current_session.session_version() == version
                && alice_base_key
                    .ct_eq(
                        current_session
                            .alice_base_key()
                            .map_err(|_| {
                                InvalidSessionError(
                                    "alice_base_key not initialized for current session",
                                )
                            })?
                            .serialize()
                            .as_ref(),
                    )
                    .into()
            {
                return Ok(true);
            }
        }

        for previous in self.previous_session_states().iter() {
            if previous.session_version() == version
                && alice_base_key
                    .ct_eq(
                        previous
                            .alice_base_key()
                            .map_err(|_| {
                                InvalidSessionError(
                                    "alice_base_key not initialized for previous session",
                                )
                            })?
                            .serialize()
                            .as_ref(),
                    )
                    .into()
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn has_current_session_state(&self) -> bool {
        self.current_session.is_some()
    }

    pub(crate) fn session_state(&self) -> Option<&SessionState<S>> {
        self.current_session.as_ref()
    }

    pub(crate) fn session_state_mut(&mut self) -> Option<&mut SessionState<S>> {
        self.current_session.as_mut()
    }

    pub(crate) fn set_session_state(&mut self, session: SessionState<S>) {
        self.current_session = Some(session);
    }

    pub(crate) fn previous_session_states(&self) -> &[SessionState<S>] {
        self.previous_sessions.as_ref()
    }

    pub(crate) fn promote_old_session(
        &mut self,
        old_session: usize,
        updated_session: SessionState<S>,
    ) {
        if old_session >= self.previous_sessions.len() {
            panic!(
                "tried to promote an old session that no longer exists (index {} out of range)",
                old_session,
            );
        }
        self.previous_sessions.remove(old_session);
        self.promote_state(updated_session)
    }

    pub(crate) fn promote_state(&mut self, new_state: SessionState<S>) {
        self.archive_current_state_inner();
        self.current_session = Some(new_state);
    }

    // A non-fallible version of archive_current_state.
    fn archive_current_state_inner(&mut self) {
        if let Some(current_session) = self.current_session.take() {
            if self.previous_sessions.len() >= consts::ARCHIVED_STATES_MAX_LENGTH {
                self.previous_sessions.pop();
            }
            self.previous_sessions.insert(0, current_session);
        } else {
            log::info!("Skipping archive, current session state is fresh",);
        }
    }

    pub fn archive_current_state(&mut self) -> Result<(), SignalProtocolError> {
        self.archive_current_state_inner();
        Ok(())
    }

    pub fn remote_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "remote_registration_id",
                    "No current session".into(),
                )
            })?
            .remote_registration_id())
    }

    pub fn local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "local_registration_id",
                    "No current session".into(),
                )
            })?
            .local_registration_id())
    }

    pub fn session_version(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState("session_version", "No current session".into())
            })?
            .session_version())
    }

    pub fn local_identity_key_bytes(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "local_identity_key_bytes",
                    "No current session".into(),
                )
            })?
            .local_identity_key_bytes())
    }

    pub fn remote_identity_key_bytes(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "remote_identity_key_bytes",
                    "No current session".into(),
                )
            })?
            .remote_identity_key_bytes())
    }

    /* TODO: remove this method!! it's used in the FFI though. */
    pub fn has_sender_chain(&self) -> bool {
        self.current_session.is_some()
    }

    pub fn needs_pni_signature(&self) -> Result<bool, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "needs_pni_signature",
                    "No current session".into(),
                )
            })?
            .needs_pni_signature())
    }

    pub fn set_needs_pni_signature(
        &mut self,
        needs_pni_signature: bool,
    ) -> Result<(), SignalProtocolError> {
        Ok(self
            .session_state_mut()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "set_needs_pni_signature",
                    "No current session".into(),
                )
            })?
            .set_needs_pni_signature(needs_pni_signature))
    }

    pub fn alice_base_key(&self) -> Result<&PublicKey, SignalProtocolError> {
        self.session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState("alice_base_key", "No current session".into())
            })?
            .alice_base_key()
    }

    pub fn get_receiver_chain_key(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<ChainKey>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "get_receiver_chain_key",
                    "No current session".into(),
                )
            })?
            .get_receiver_chain_key(sender))
    }

    pub fn get_receiver_chain_key_bytes(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<Vec<u8>>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "get_receiver_chain_key_bytes",
                    "No current session".into(),
                )
            })?
            .get_receiver_chain_key_bytes(sender))
    }

    pub fn get_sender_chain_key_bytes(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "get_sender_chain_key_bytes",
                    "No current session".into(),
                )
            })?
            .get_sender_chain_key_bytes())
    }

    pub fn current_ratchet_key_matches(&self, key: &PublicKey) -> bool {
        match &self.current_session {
            Some(session) => &session.sender_ratchet_key() == key,
            None => false,
        }
    }
}
