/// The single error type thrown by every PGPKit capability.
public enum PGPError: Error, Sendable, Equatable {
    /// A key could not be parsed, is of the wrong kind, or is unusable.
    case invalidKey
    /// The passphrase does not unlock the private key.
    case invalidPassphrase
    /// An input was empty, malformed or out of the supported range.
    case invalidInput
    /// The message could not be decrypted with the given key.
    case decryptionFailed
    /// The signature does not match the data and public key.
    case signatureInvalid
    /// The engine failed to generate a key pair.
    case keyGenerationFailed
    /// An unclassified engine failure, carrying the underlying error code.
    case engine(code: Int)
}
