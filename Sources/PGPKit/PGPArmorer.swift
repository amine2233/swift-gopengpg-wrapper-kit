import Foundation

/// Converts PGP binary data to and from its ASCII-armored form.
public protocol PGPArmorer: Sendable {
    /// Wraps binary PGP data in an ASCII armor block.
    /// - Parameters:
    ///   - data: The binary message, signature or key.
    ///   - type: The kind of data being armored, which selects the armor header.
    /// - Returns: The armored text.
    /// - Throws: ``PGPError/invalidInput`` or ``PGPError/invalidKey`` when `data` does not match `type`.
    func armor(_ data: Data, as type: PGPArmorType) async throws -> String

    /// Removes the ASCII armor from a PGP block.
    ///
    /// The kind of block is detected from its header.
    /// - Parameter armored: The armored message, signature or key.
    /// - Returns: The binary data.
    /// - Throws: ``PGPError/invalidInput`` when the block is malformed or of an unsupported kind.
    func dearmor(_ armored: String) async throws -> Data
}
