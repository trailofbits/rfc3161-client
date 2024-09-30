// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct GeneralNameStruct<'a> {
    pub name: cryptography_x509::name::GeneralName<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum GeneralNameWrapper<'a> {
    #[implicit(0)]
    General(GeneralNameStruct<'a>),
}
