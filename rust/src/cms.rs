use crate::certificate;
use crate::common;
use crate::csr;
use crate::name;

// IssuerAndSerialNumber ::= SEQUENCE {
//     issuer Name,
//     serialNumber CertificateSerialNumber }

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct IssuerAndSerialNumber<'a> {
    pub issuer: name::Name<'a>,
    pub serial_number: asn1::BigInt<'a>,
}

// https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
// SignerInfo ::= SEQUENCE {
//     version CMSVersion,
//     sid SignerIdentifier,
//     digestAlgorithm DigestAlgorithmIdentifier,
//     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//     signatureAlgorithm SignatureAlgorithmIdentifier,
//     signature SignatureValue,
//     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct SignerInfo<'a> {
    pub version: u8,
    // Of note, this is not exactly the standard here because we are not implementing
    // the SignerIdentifier CHOICE.
    pub issuer_and_serial_number: IssuerAndSerialNumber<'a>,
    pub digest_algorithm: common::AlgorithmIdentifier<'a>,
    #[implicit(0)]
    pub authenticated_attributes: Option<csr::Attributes<'a>>,

    pub digest_encryption_algorithm: common::AlgorithmIdentifier<'a>,
    pub encrypted_digest: &'a [u8],

    #[implicit(1)]
    pub unauthenticated_attributes: Option<csr::Attributes<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct SignedData<'a> {
    pub version: u8,
    pub digest_algorithms: asn1::SetOf<'a, common::AlgorithmIdentifier<'a>>,
    pub content_info: ContentInfo<'a>,
    #[implicit(0)]
    pub certificates: Option<asn1::SetOf<'a, certificate::CertificateChoices<'a>>>,

    // We don't ever supply any of these, so for now, don't fill out the fields.
    #[implicit(1)]
    pub crls: Option<asn1::Sequence<'a>>,

    pub signer_infos: asn1::SetOf<'a, SignerInfo<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct ContentInfo<'a> {
    pub content_type: asn1::ObjectIdentifier,

    #[explicit(0)]
    pub content: Option<&'a [u8]>,
}
