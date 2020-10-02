import SignalFfi
import Foundation

/*
 SignalFfiError *signal_process_prekey_bundle(PreKeyBundle *bundle,
                                             const ProtocolAddress *protocol_address,
                                             FfiSessionStoreStruct *session_store,
                                             FfiIdentityKeyStoreStruct *identity_key_store,
                                             void *ctx)

SignalFfiError *signal_encrypt_message(const unsigned char **result,
                                       size_t *result_len,
                                       const unsigned char *ptext,
                                       size_t ptext_len,
                                       const ProtocolAddress *protocol_address,
                                       FfiSessionStoreStruct *session_store,
                                       FfiIdentityKeyStoreStruct *identity_key_store,
                                       void *ctx)

SignalFfiError *signal_decrypt_message(const unsigned char **result,
                                       size_t *result_len,
                                       const SignalMessage *message,
                                       const ProtocolAddress *protocol_address,
                                       FfiSessionStoreStruct *session_store,
                                       FfiIdentityKeyStoreStruct *identity_key_store,
                                       void *ctx)

SignalFfiError *signal_decrypt_pre_key_message(const unsigned char **result,
                                               size_t *result_len,
                                               const PreKeySignalMessage *message,
                                               const ProtocolAddress *protocol_address,
                                               FfiSessionStoreStruct *session_store,
                                               FfiIdentityKeyStoreStruct *identity_key_store,
                                               FfiPreKeyStoreStruct *prekey_store,
                                               FfiSignedPreKeyStoreStruct *signed_prekey_store,
                                               void *ctx)

 */

func SignalEncrypt(message: [UInt8],
                   address: ProtocolAddress,
                   session_store: SessionStore,
                   identity_store: IdentityKeyStore,
                   ctx: UnsafeMutableRawPointer?) throws -> CiphertextMessage {
    return try withSessionStore(session_store) { ffi_session_store in
        try withIdentityKeyStore(identity_store) { ffi_identity_store in
            try invokeFnReturningCiphertextMessage {
                signal_encrypt_message($0, message, message.count, address.nativeHandle(), ffi_session_store, ffi_identity_store, ctx)
            }
        }
    }
}

func SignalDecrypt(message: SignalMessage,
                   address: ProtocolAddress,
                   session_store: SessionStore,
                   identity_store: IdentityKeyStore,
                   ctx: UnsafeMutableRawPointer?) throws -> [UInt8] {
    return try withSessionStore(session_store) { ffi_session_store in
        try withIdentityKeyStore(identity_store) { ffi_identity_store in
            try invokeFnReturningArray {
                signal_decrypt_message($0, $1, message.nativeHandle(), address.nativeHandle(), ffi_session_store, ffi_identity_store, ctx)
            }
        }
    }
}

func SignalDecryptPreKey(message: PreKeySignalMessage,
                         address: ProtocolAddress,
                         session_store: SessionStore,
                         identity_store: IdentityKeyStore,
                         pre_key_store: PreKeyStore,
                         signed_pre_key_store: SignedPreKeyStore,
                         ctx: UnsafeMutableRawPointer?) throws -> [UInt8] {
    return try withSessionStore(session_store) { ffi_session_store in
        try withIdentityKeyStore(identity_store) { ffi_identity_store in
            try withPreKeyStore(pre_key_store) { ffi_pre_key_store in
                try withSignedPreKeyStore(signed_pre_key_store) { ffi_signed_pre_key_store in
                    try invokeFnReturningArray {
                        signal_decrypt_pre_key_message($0, $1, message.nativeHandle(), address.nativeHandle(), ffi_session_store, ffi_identity_store, ffi_pre_key_store, ffi_signed_pre_key_store, ctx)
                    }
                }
            }
        }
    }
}

func ProcessPreKeyBundle(bundle: PreKeyBundle,
                         address: ProtocolAddress,
                         session_store: SessionStore,
                         identity_store: IdentityKeyStore,
                         ctx: UnsafeMutableRawPointer?) throws {
    return try withSessionStore(session_store) { ffi_session_store in
        try withIdentityKeyStore(identity_store) { ffi_identity_store in
            try CheckError(signal_process_prekey_bundle(bundle.nativeHandle(), address.nativeHandle(), ffi_session_store, ffi_identity_store, ctx))
        }
    }
}

func GroupEncrypt(group_id: SenderKeyName,
                  message: [UInt8],
                  store: SenderKeyStore,
                  ctx: UnsafeMutableRawPointer?) throws -> [UInt8] {
    return try withSenderKeyStore(store) { ffiStore in
        return try invokeFnReturningArray {
            signal_group_encrypt_message($0, $1, group_id.nativeHandle(), message, message.count, ffiStore, ctx)
        }
    }
}

func GroupDecrypt(group_id: SenderKeyName,
                  message: [UInt8],
                  store: SenderKeyStore,
                  ctx: UnsafeMutableRawPointer?) throws -> [UInt8] {
    return try withSenderKeyStore(store) { ffiStore in
        return try invokeFnReturningArray {
            signal_group_decrypt_message($0, $1, group_id.nativeHandle(), message, message.count, ffiStore, ctx)
        }
    }
}

func ProcessSenderKeyDistributionMessage(sender_name: SenderKeyName,
                                         msg: SenderKeyDistributionMessage,
                                         store: SenderKeyStore,
                                         ctx: UnsafeMutableRawPointer?) throws {
    try withSenderKeyStore(store) {
        try CheckError(signal_process_sender_key_distribution_message(sender_name.nativeHandle(),
                                                                      msg.nativeHandle(),
                                                                      $0, ctx))
    }
}
