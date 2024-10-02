// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.
#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Eq, Clone)]
pub struct AttributeCertificateV2 {
    // TODO
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Eq, Clone)]
pub struct ExtendedCertificate<'a> {
    pub extended_certificate_info: ExtendedCertificateInfo<'a>,
    pub signature_algorithm: cryptography_x509::common::AlgorithmIdentifier<'a>,
    pub signature: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Eq, Clone)]
pub struct ExtendedCertificateInfo<'a> {
    pub version: u8,
    pub certificate: cryptography_x509::certificate::Certificate<'a>,
    pub attributes: asn1::SetOf<'a, cryptography_x509::common::AttributeTypeValue<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Eq, Clone)]
pub enum CertificateChoices<'a> {
    Certificate(cryptography_x509::certificate::Certificate<'a>),
    #[implicit(0)]
    ExtendedCertificate(asn1::Null), // Obsolete
    #[implicit(1)]
    AttributeCertificateV1(asn1::Null), // Obsolete
    #[implicit(2)]
    AttributeCertificateV2(AttributeCertificateV2),
    OtherCertificateFormat(asn1::Null), // TODO(dm)
}
