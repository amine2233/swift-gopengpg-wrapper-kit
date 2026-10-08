import PGPKit

extension PGP {
    /// Builds a `PGP` backed by GopenPGP.
    ///
    /// Pass any capability to replace its GopenPGP implementation; omitted ones use the default.
    public static func gopenPGP(
        keys: (any PGPKeyManager)? = nil,
        cipher: (any PGPCipher)? = nil,
        signer: (any PGPSigner)? = nil,
        armorer: (any PGPArmorer)? = nil
    ) -> PGP {
        PGP(
            keys: keys ?? PGPKeyManagerGopenPGP(),
            cipher: cipher ?? PGPCipherGopenPGP(),
            signer: signer ?? PGPSignerGopenPGP(),
            armorer: armorer ?? PGPArmorerGopenPGP()
        )
    }
}
