//! [RFC 3161] definitions.
//!
//! [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161

use asn1::{SimpleAsn1Readable, SimpleAsn1Writable};

/// RFC 3161 2.4.1
///
/// ```asn1
/// MessageImprint ::= SEQUENCE  {
///   hashAlgorithm AlgorithmIdentifier,
///   hashedMessage OCTET STRING  }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write, Clone)]
pub struct MessageImprint<'a> {
    pub hash_algorithm: cryptography_x509::common::AlgorithmIdentifier<'a>,
    pub hashed_message: &'a [u8],
}

/// RFC 3161 2.4.1
///
/// ```asn1
/// TimeStampReq ::= SEQUENCE  {
///   version                  INTEGER  { v1(1) },
///   messageImprint           MessageImprint,
///     --a hash algorithm OID and the hash value of the data to be
///     --time-stamped
///   reqPolicy                TSAPolicyId                OPTIONAL,
///   nonce                    INTEGER                    OPTIONAL,
///   certReq                  BOOLEAN                    DEFAULT FALSE,
///   extensions               [0] IMPLICIT Extensions    OPTIONAL  }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct RawTimeStampReq<'a> {
    pub version: u8,

    pub message_imprint: MessageImprint<'a>,

    pub req_policy: Option<asn1::ObjectIdentifier>,

    pub nonce: Option<asn1::BigUint<'a>>,

    #[default(false)]
    pub cert_req: bool,

    pub extensions: Option<cryptography_x509::extensions::RawExtensions<'a>>,
}

//    PKIStatus ::= INTEGER {
//       granted                (0),
//       -- when the PKIStatus contains the value zero a TimeStampToken, as
//          requested, is present.
//       grantedWithMods        (1),
//        -- when the PKIStatus contains the value one a TimeStampToken,
//          with modifications, is present.
//       rejection              (2),
//       waiting                (3),
//       revocationWarning      (4),
//        -- this message contains a warning that a revocation is
//        -- imminent
//       revocationNotification (5)
//        -- notification that a revocation has occurred  }
// TODO(dm) = Implement me

/// RFC 3161 2.4.2
///
/// ```asn1
/// PKIStatusInfo ::= SEQUENCE {
///   status        PKIStatus,
///   statusString  PKIFreeText     OPTIONAL,
///   failInfo      PKIFailureInfo  OPTIONAL  }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct PKIStatusInfo<'a> {
    pub status: u8,
    pub status_string: Option<asn1::SequenceOf<'a, asn1::Utf8String<'a>>>,
    pub fail_info: Option<asn1::BitString<'a>>,
}

/// Inner type for [`Accuracy`]. This represents the basic structure,
/// but does not enforce the value range invariants on the `millis`
/// or `micros` fields.
#[derive(asn1::Asn1Read, asn1::Asn1Write, Copy, Clone)]
struct AccuracyInner<'a> {
    pub seconds: Option<asn1::BigUint<'a>>,
    #[implicit(0)]
    pub millis: Option<u16>,
    #[implicit(1)]
    pub micros: Option<u16>,
}

/// RFC 3161 2.4.2
///
/// ```asn1
/// Accuracy ::= SEQUENCE {
///   seconds        INTEGER              OPTIONAL,
///   millis     [0] INTEGER  (1..999)    OPTIONAL,
///   micros     [1] INTEGER  (1..999)    OPTIONAL  }
/// ```
#[derive(Copy, Clone)]
pub struct Accuracy<'a>(AccuracyInner<'a>);

impl<'a> Accuracy<'a> {
    pub fn seconds(&self) -> Option<asn1::BigUint<'a>> {
        self.0.seconds
    }

    pub fn millis(&self) -> Option<u16> {
        self.0.millis
    }

    pub fn micros(&self) -> Option<u16> {
        self.0.micros
    }
}

impl<'a> SimpleAsn1Readable<'a> for Accuracy<'a> {
    const TAG: asn1::Tag = <AccuracyInner as SimpleAsn1Readable<'a>>::TAG;

    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        let inner = AccuracyInner::parse_data(data)?;

        let valid_range = 1..=999;
        if !inner
            .millis
            .map_or(true, |millis| valid_range.contains(&millis))
        {
            return Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue));
        }

        if !inner
            .micros
            .map_or(true, |micros| valid_range.contains(&micros))
        {
            return Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue));
        }

        Ok(Self(inner))
    }
}

impl<'a> SimpleAsn1Writable for Accuracy<'a> {
    const TAG: asn1::Tag = <AccuracyInner as SimpleAsn1Writable>::TAG;

    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        self.0.write_data(dest)
    }
}

/// RFC 3161 2.4.2
///
/// ```asn1
/// TimeStampToken ::= ContentInfo
///   -- contentType is id-signedData ([CMS])
///   -- content is SignedData ([CMS])
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct TimeStampToken<'a> {
    pub _content_type: asn1::DefinedByMarker<asn1::ObjectIdentifier>,

    #[defined_by(_content_type)]
    pub content: Content<'a>,
}

pub const PKCS7_SIGNED_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 2);

/// RFC 3161 2.4.2
///
/// See RFC 5652 for the definition of `SignedData`.
#[derive(asn1::Asn1DefinedByWrite, asn1::Asn1DefinedByRead)]
pub enum Content<'a> {
    #[defined_by(PKCS7_SIGNED_DATA_OID)]
    SignedData(asn1::Explicit<Box<crate::cms::SignedData<'a>>, 0>),
}

// https://www.ietf.org/rfc/rfc3161.txt - Section 2.4.2
pub const TST_INFO_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 16, 1, 4);

impl<'a> crate::cms::ContentInfo<'a> {
    pub fn tst_info(&self) -> Result<TSTInfo<'a>, asn1::ParseError> {
        // Check if the content_type matches TST_INFO_OID
        if self.content_type != TST_INFO_OID {
            return Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue));
        }

        // Unwrap the content, return an error if it's None
        let content_bytes = self
            .content
            .ok_or_else(|| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))?;

        // Parse the content bytes into a TSTInfo instance
        let tst_info = asn1::parse_single::<TSTInfo>(content_bytes)?;

        // Return the parsed TSTInfo
        Ok(tst_info)
    }
}

/// RFC 3161 2.4.2
///
/// ```asn1
/// TSTInfo ::= SEQUENCE  {
///   version                      INTEGER  { v1(1) },
///   policy                       TSAPolicyId,
///   messageImprint               MessageImprint,
///     -- MUST have the same value as the similar field in
///     -- TimeStampReq
///   serialNumber                 INTEGER,
///    -- Time-Stamping users MUST be ready to accommodate integers
///    -- up to 160 bits.
///   genTime                      GeneralizedTime,
///   accuracy                     Accuracy                 OPTIONAL,
///   ordering                     BOOLEAN             DEFAULT FALSE,
///   nonce                        INTEGER                  OPTIONAL,
///     -- MUST be present if the similar field was present
///     -- in TimeStampReq.  In that case it MUST have the same value.
///   tsa                          [0] GeneralName          OPTIONAL,
///   extensions                   [1] IMPLICIT Extensions  OPTIONAL   }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct TSTInfo<'a> {
    pub version: u8,
    pub policy: Option<asn1::ObjectIdentifier>,
    pub message_imprint: MessageImprint<'a>,
    pub serial_number: asn1::BigInt<'a>,
    pub gen_time: asn1::GeneralizedTime,
    pub accuracy: Option<Accuracy<'a>>,
    #[default(false)]
    pub ordering: bool,
    pub nonce: Option<asn1::BigUint<'a>>,
    #[explicit(0)]
    pub tsa: Option<cryptography_x509::name::GeneralName<'a>>,
    #[implicit(1)]
    pub extensions: Option<cryptography_x509::extensions::RawExtensions<'a>>,
}

/// RFC 3161 2.4.2
///
/// ```asn1
/// TimeStampResp ::= SEQUENCE  {
///    status                  PKIStatusInfo,
///    timeStampToken          TimeStampToken     OPTIONAL  }
/// ```
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct RawTimeStampResp<'a> {
    pub status: PKIStatusInfo<'a>,
    pub time_stamp_token: Option<TimeStampToken<'a>>,
}

#[cfg(test)]
mod tests {
    use crate::cms;

    use super::*;

    #[test]
    fn test_parse_timestamp_request() {
        // See TESTING.md
        // openssl ts -query -data README.md -sha512 -cert -out file.tsq
        let enc_request = hex::decode("30640201013051300d060960864801650304020305000440c05812f7df5c643047235d400de272f03bd3d319f71f0c75c4b57948ccf2cdf85f8feb422dedcfa9ec26c102b08f778332ad9be18f759aebe93d64dcc65f49c3020900fce125b1e42c03110101ff")
                          .unwrap();
        let request = asn1::parse_single::<RawTimeStampReq>(&enc_request).unwrap();

        assert_eq!(request.version, 1);

        assert_eq!(
            request.message_imprint.hash_algorithm,
            cryptography_x509::common::AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: cryptography_x509::common::AlgorithmParameters::Sha512(Some(()))
            }
        );

        assert_eq!(
            request.message_imprint.hashed_message,
            &hex::decode("C05812F7DF5C643047235D400DE272F03BD3D319F71F0C75C4B57948CCF2CDF85F8FEB422DEDCFA9EC26C102B08F778332AD9BE18F759AEBE93D64DCC65F49C3").unwrap()
        );

        match request.req_policy {
            Some(request_policy) => {
                println!("request_policy  {}", request_policy.to_string());
            }
            None => {}
        }

        match request.nonce {
            Some(nonce_value) => {
                assert_eq!(
                    nonce_value.as_bytes(),
                    hex::decode("00fce125b1e42c0311").unwrap()
                )
            }
            None => {
                assert!(false, "Missing nonce.");
            }
        }

        assert_eq!(request.cert_req, true);
    }

    #[test]
    fn test_timestamp_fields() {
        let enc_response = hex::decode("3003020100").unwrap();
        let pki_status_info = asn1::parse_single::<PKIStatusInfo>(&enc_response).unwrap();
        assert_eq!(pki_status_info.status, 0);

        let enc_tst_info = hex::decode("3082019502010106042a0304013051300d060960864801650304020305000440c05812f7df5c643047235d400de272f03bd3d319f71f0c75c4b57948ccf2cdf85f8feb422dedcfa9ec26c102b08f778332ad9be18f759aebe93d64dcc65f49c30204035daf44180f32303234303932343132353733355a0101ff02080b7df056edda4995a0820111a482010d308201093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d54686973206365727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726e").unwrap(); //let enc_tst_info = hex::decode("3082019502010106042a0304013051300d060960864801650304020305000440c05812f7df5c643047235d400de272f03bd3d319f71f0c75c4b57948ccf2cdf85f8feb422dedcfa9ec26c102b08f778332ad9be18f759aebe93d64dcc65f49c30204035daf44180f32303234303932343132353733355a0101ff02080b7df056edda4995a0820111a482010d308201093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d54686973206365727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726e").unwrap();
        let tst_info = asn1::parse_single::<TSTInfo>(&enc_tst_info).unwrap();
        assert_eq!(tst_info.version, 1);

        let enc_general_name = hex::decode("a482010d308201093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d54686973206365727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726e").unwrap();
        asn1::parse_single::<cryptography_x509::name::GeneralName>(&enc_general_name).unwrap();

        let enc_content_info = hex::decode("308201ae060b2a864886f70d0109100104a082019d048201993082019502010106042a0304013051300d060960864801650304020305000440c05812f7df5c643047235d400de272f03bd3d319f71f0c75c4b57948ccf2cdf85f8feb422dedcfa9ec26c102b08f778332ad9be18f759aebe93d64dcc65f49c30204035daf44180f32303234303932343132353733355a0101ff02080b7df056edda4995a0820111a482010d308201093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d54686973206365727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726e").unwrap();
        asn1::parse_single::<cms::ContentInfo>(&enc_content_info).unwrap();
    }

    #[test]
    fn test_parse_timestamp_response() {
        let enc_response = hex::decode("3082157c30030201003082157306092a864886f70d010702a082156430821560020103310f300d06096086480165030402030500308201ae060b2a864886f70d0109100104a082019d048201993082019502010106042a0304013051300d060960864801650304020305000440c05812f7df5c643047235d400de272f03bd3d319f71f0c75c4b57948ccf2cdf85f8feb422dedcfa9ec26c102b08f778332ad9be18f759aebe93d64dcc65f49c30204035daf44180f32303234303932343132353733355a0101ff02080b7df056edda4995a0820111a482010d308201093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d54686973206365727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726ea0821008308207ff308205e7a003020102020900c1e986160da8e980300d06092a864886f70d01010d05003081953111300f060355040a130846726565205453413110300e060355040b1307526f6f74204341311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310f300d0603550408130642617965726e310b3009060355040613024445301e170d3136303331333031353231335a170d3431303330373031353231335a3081953111300f060355040a130846726565205453413110300e060355040b1307526f6f74204341311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310f300d0603550408130642617965726e310b300906035504061302444530820222300d06092a864886f70d01010105000382020f003082020a0282020100b6028e0e3032f11110d964cda94b9d0278e1942ae913aaa59907cda69793995bd9ac7e33bad9fe3704da1c01a98d21afe3f591a59d7067705167998f5016722e0ab462b21f439171d2cfcc4593f3735af794a5ab311f6c010c7898de33d75c4510ee76f4bd1d1498cf17d303f06a5dd9f796cc6ca9b657a56fe3ea4fefbe7ce6b6a18d3e35a30cee5ff170d1cf39a333d3fda8964d22db685b29e561be890f0aa845873b2e84ab26ab839ffe8fade9d23bb31e61d273cc9b880649185fabecfa0534600aba901b614e2e854582dea2226fc19cd7df52bed50d8777cd9988c053a3fc7dc3287a068a4ff12b713cd9803666e955385456ff38f80298cf6b93856e9224774a66cf1cdd11c2f8efd85203d7458b25664b13ed639cded4ff8113d6cc5353d2729473c3c307157c722aa5b5dd0bfb2d6c38b1b93749c881ec60026d08951b3824bd71bacbce473aebd636f0b918b4a2c8ff4694f07457af2d6f1cf82554d1770fd79ff5d314dcd104cddcabc94138056dfcf017e7eb8572fd52f70144f188da05f5823f58dd06297e7387bed2d772c13da8266601045fe412dd70986c0c987ba7344b9037387516d258e7885b51f8968b7f2601213bc4cb4c85f8ff0b84af6a988337cdfb81868f7ecf31dca6716d7ec2dd802c1672629e5c0052cb357dd29aafc43f615b3b1ff9d4e1ce08c71c73e1febb7dc56a33621329e9ed6c230203010001a382024e3082024a300c0603551d13040530030101ff300e0603551d0f0101ff0404030201c6301d0603551d0e04160414fa550d8c346651434cf7e7b3a76c95af7ae6a4973081ca0603551d230481c23081bf8014fa550d8c346651434cf7e7b3a76c95af7ae6a497a1819ba481983081953111300f060355040a130846726565205453413110300e060355040b1307526f6f74204341311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310f300d0603550408130642617965726e310b3009060355040613024445820900c1e986160da8e98030330603551d1f042c302a3028a026a0248622687474703a2f2f7777772e667265657473612e6f72672f726f6f745f63612e63726c3081cf0603551d200481c73081c43081c1060a2b0601040181f22401013081b2303306082b060105050702011627687474703a2f2f7777772e667265657473612e6f72672f667265657473615f6370732e68746d6c303206082b060105050702011626687474703a2f2f7777772e667265657473612e6f72672f667265657473615f6370732e706466304706082b06010505070202303b1a394672656554534120747275737465642074696d657374616d70696e6720536f6674776172652061732061205365727669636520285361615329303706082b06010505070101042b3029302706082b06010505073001861b687474703a2f2f7777772e667265657473612e6f72673a32353630300d06092a864886f70d01010d0500038202010068af7ebf938562ef4ceb3b580be2faf6cc35a26772962f3d95901fa5630c87d09198984ce8a06a33f8a9c282ed9f1cb11ac6c23e17108ee4efce6fb294de95c133262255725522ca61971d4a3b7f78250dfb8d4aeec0fb1959b164100520b9c10e64c62662e4ad4d0abae2298fc948fc4e99e8d9e6b8fdbe4404121ec7c1422eacb2c9d7328e07396e60b4f3bb803ad4a555c80fefb53f85e7764a0a9fb4afc399f4cd2f5fbf587105c6081cf3d05337b6bb7d1b010b749f4888c912f3696ba1b6902d77b7dfc046c04a0cc1ec4f8d185e2da55dfb7bc2a2036c6219246a4f99ddbb6f1f829398f3b803dc0ad90dcb59bef4c27c77404b99043b78271867991152c399f12cbfc4c625adc096355ae44e342100ec517a502e2f06f940b8d43599bbc1154f8ae761a0b0d555fb4a1391d4f3420af8dbf12f2d7ddb9d77dce1537804074af175e4f2d6d55b34b5d6f7dcbdd31730af56480d4c0cff143f9e83bc151866d0ba0f0bbdc47fe27864176bbd6c1ab85df325edf777889bc4471bf3fa73e56cc591e8b160cda7b0786a1ec04ac3b24fa2e28d5d19e5e48004d5e166a83c82ec6fd54fb385ebaf7133a85b52de46db5244e1c34ae8d36e712f9fce0d493d7d3edd586c6198e3ec3e6e96346f417ac9f221e0aff33a8f6a0b1ef4c023630b76adaa8d91433825ecc41c49a5b98b181c7da30e997ab954c73c2cd805afda9930820801308205e9a003020102020900c1e986160da8e982300d06092a864886f70d01010d05003081953111300f060355040a130846726565205453413110300e060355040b1307526f6f74204341311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310f300d0603550408130642617965726e310b3009060355040613024445301e170d3136303331333031353733395a170d3236303331313031353733395a308201093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d54686973206365727469666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726e30820222300d06092a864886f70d01010105000382020f003082020a0282020100b591048c4e486f34e9dc08627fc2375162236984b82cb130beff517cfc38f84bce5c65a874dab2621ae0bce7e33563e0ede934fd5f8823159f07848808227460c1ed88261706f4281334359dfbb81bd1353fc179610af1a8c8c865dc00ea23b3a89be6bd03ba85a9ec827d60565905e22d6a584ed1380ae150280cee397e98a012f380464007862443bc077cb95f421af31712d9683cdb6dffbaf3c8ba5ba566ae523d459d6177346d4d840e27886b7c01c5b890d78a2e27bba8dd2f9a2812e157d62f921c65962548069dcdb7d06de181de0e9570d66f87220ce28b628ab55906f3ee0c210f7051e8f4858af8b9a92d09e46af2d9cba5bfcfad168cdf604491a4b06603b114caf7031f065e7eeefa53c575f3490c059d2e32ddc76ac4d4c4c710683b97fd1be591bc61055186d88f9a0391b307b6f91ed954daa36f9acd6a1e14aa2e4adf17464b54db18dbb6ffe30080246547370436ce4e77bae5de6fe0f3f9d6e7ffbeb461e794e92fb0951f8aae61a412cce9b21074635c8be327ae1a0f6b4a646eb0f8463bc63bf845530435d19e802511ec9f66c3496952d8becb69b0aa4d4c41f60515fe7dcbb89319cdda59ba6aea4be3ceae718e6fcb6ccd7db9fc50bb15b12f3665b0aa307289c2e6dd4b111ce48ba2d9efdb5a6b9a506069334fb34f6fc7ae330f0b34208aac80df3266fdd90465876ba2cb898d9505315b6e7b0203010001a38201db308201d730090603551d1304023000301d0603551d0e041604146e760b7b4e4f9ce160ca6d2ce927a2a294b37737301f0603551d23041830168014fa550d8c346651434cf7e7b3a76c95af7ae6a497300b0603551d0f0404030206c030160603551d250101ff040c300a06082b06010505070308306306082b0601050507010104573055302a06082b06010505073002861e687474703a2f2f7777772e667265657473612e6f72672f7473612e637274302706082b06010505073001861b687474703a2f2f7777772e667265657473612e6f72673a3235363030370603551d1f0430302e302ca02aa0288626687474703a2f2f7777772e667265657473612e6f72672f63726c2f726f6f745f63612e63726c3081c60603551d200481be3081bb3081b80601003081b2303306082b060105050702011627687474703a2f2f7777772e667265657473612e6f72672f667265657473615f6370732e68746d6c303206082b060105050702011626687474703a2f2f7777772e667265657473612e6f72672f667265657473615f6370732e706466304706082b06010505070202303b1a394672656554534120747275737465642074696d657374616d70696e6720536f6674776172652061732061205365727669636520285361615329300d06092a864886f70d01010d05000382020100a5c944e2c6fac0a14d930a7fd0a0b172b41fc1483c3e957c68a2bcd9b9764f1a950161fd72472d41a5eed277786203b5422240fb3a26cde176087b6fb1011df4cc19e2571aa4a051109665e94c46f50bd2adee6ac4137e251b25a39dabda451515d8ff9e07209e8ec20b7874f7e1a0ede7c00937fe84a334f8b3265ced2d8ed9df61396583677feb382c1ee3b23e6ea5f05df30de7b9f89005d25266f612f39c8b4f6daba6d7bfbac19632b90637329f52a6f066a10e43eaa81f849a6c5fe3fe8b5ea23275f687f2052e502ea6c30762a668cce07871dd8e97e315bba929e25589977a0a312ce96c5106b1437c779f2b361b182888f3ee8a234374fa063e956192627f7c431073965d1260928eba009e803429ae324cf96f042354f37bca5afddc79f79346ab388bfc79f01dc9861254ea6cc129941076b83d20556f3be51326837f2876f7833b370e7c3d410523827d4f53400c72218d75229ff10c6f8893a9a3a1c0c42bb4c898c13df41c7f6573b4fc56515971a610a7b0d2857c8225a9fb204eaceca2e8971aa1af87886a2ae3c72fe0a0aae842980a77bef16b92115458090d982b5946603764e75a0ad3d11454b9986f678b9ab6afe8497033ae3abfd4eb43b7bc9dee68815949e6481582a82e785277f2282107efe390200e0508acb8ea82ea2505276f3c9da2a3d3b4ad38bbf8842bda36fc2448291f558dc02dd1e03182038a308203860201013081a33081953111300f060355040a130846726565205453413110300e060355040b1307526f6f74204341311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310f300d0603550408130642617965726e310b3009060355040613024445020900c1e986160da8e982300d06096086480165030402030500a081b8301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d010905310f170d3234303932343132353733355a302b060b2a864886f70d010910020c311c301a301830160414916da3d860ecca82e34bc59d1793e7e968875f14304f06092a864886f70d01090431420440e7a6993b6d6ad5f2c1ba9c6f55b934b28ef14dd13d4a671bc6fa073237af03f0d709a9452cd5ad73d54747b9f108a7e0f953828e4e0ccb3388921dcbd89c811e300d06092a864886f70d010101050004820200931f4415ac7eda8cab20a3168aaadea692e7cb5bc4a17ec90b0ebf400934c8e8111e8fee00c16f94870bcd745d0f7ef7a99b2e2b07e53a3b28c5fff42a19499c3b9c947d978d102193853aa7e493e58793f49fd4aceab66eb7cef1d245a88484613bf1c74e89ac71791c29bcde0a7a455563b699be88f266233e241f3c2bb7d205ee116b358d0e26fcdc34af027cd42663fe434a59f32a7c6c276b16f010cd0e02f6039240eb3e547e1431ea81f70621a7ae355d4515c74b96c52b78d8eab226720929a6f9b69bf2cefa43b9953b9ae4c38c25f7bbe169bba84daa12c3fd0730d1de74bcc55c07563d8332c07b94beaa4b43da67620993ac0b5762857c87a75e4a6f9cb6a65408f86c896ad03a8a85786df7176f18b8e8ffd76d39023b16691bd4c217e6d7b7139fc093aafc7b8584e553a8adef3e1ccfae2fce05c307a5e38e354f640642523095e6392e2d1f4524e6fe230534e3d819b6556604d5335b6722db67a7887abd48981d7d1678e80f39c3d7ceac08c35165acf28141b05f85551cd02bcc8575c0838803a7f5984c0e0f8cc14b8f1307a133013f2b1753fdded4c5cb185701899384a5c629fa4f289e85807ca55623e364e25aec25afbc26cc8f5fd19904d78016d7ebeebf77cba8d03512cf0b05a62c8562b4eba7b2b15d687513180c72d7f01303e9828c1e94776fcd25c2c3f231cd81e8a4d8c1f25c301023a7").unwrap();
        let response = asn1::parse_single::<RawTimeStampResp>(&enc_response).unwrap();

        assert_eq!(response.status.status, 0);

        let tst_info_content = response.time_stamp_token.unwrap().content;
        match tst_info_content {
            Content::SignedData(signed_data) => {
                let explicit_signed_data = signed_data.as_inner();
                assert_eq!(explicit_signed_data.version, 3);

                let tst_info = explicit_signed_data.content_info.tst_info().unwrap();

                assert_eq!(tst_info.version, 1);
                assert_eq!(
                    tst_info.nonce.expect("Nonce must be set").as_bytes(),
                    hex::decode("0B7DF056EDDA4995").unwrap()
                );
            }
        }
    }

    #[test]
    fn test_parse_accuracy() {
        let accuracy = AccuracyInner {
            seconds: None,
            // NOTE: `AccuracyInner` does not enforce range invariant.
            millis: Some(9999),
            micros: None,
        };

        let bytes = asn1::write_single(&accuracy).unwrap();
        assert_eq!(bytes, b"0\x04\x80\x02'\x0f");

        let enc = hex::decode("3004800201F4").unwrap();
        let response = asn1::parse_single::<Accuracy>(&enc).unwrap();
        assert_eq!(response.millis().unwrap(), 500);
    }

    #[test]
    fn test_parse_accuracy_bad_ranges() {
        for (millis, micros) in &[
            (Some(9999), None),
            (None, Some(9999)),
            (Some(0), Some(0)),
            (Some(1000), Some(0)),
        ] {
            let accuracy = AccuracyInner {
                seconds: None,
                millis: *millis,
                micros: *micros,
            };

            let enc = asn1::write_single(&accuracy).unwrap();

            assert!(asn1::parse_single::<Accuracy>(&enc).is_err());
        }
    }
}
