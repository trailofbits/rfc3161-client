pub mod oid;
use std::sync::Arc;

use pyo3::prelude::*;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone, Eq, Debug)]
pub struct AlgorithmIdentifier<'a> {
    pub oid: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(oid)]
    pub params: AlgorithmParameters<'a>,
}

// We restrict here to only HASH algorithms
#[derive(asn1::Asn1DefinedByRead, asn1::Asn1DefinedByWrite, PartialEq, Eq, Hash, Clone, Debug)]
pub enum AlgorithmParameters<'a> {
    #[defined_by(oid::SHA1_OID)]
    Sha1(Option<asn1::Null>),
    #[defined_by(oid::SHA224_OID)]
    Sha224(Option<asn1::Null>),
    #[defined_by(oid::SHA256_OID)]
    Sha256(Option<asn1::Null>),
    #[defined_by(oid::SHA384_OID)]
    Sha384(Option<asn1::Null>),
    #[defined_by(oid::SHA512_OID)]
    Sha512(Option<asn1::Null>),
    #[defined_by(oid::SHA3_224_OID)]
    Sha3_224(Option<asn1::Null>),
    #[defined_by(oid::SHA3_256_OID)]
    Sha3_256(Option<asn1::Null>),
    #[defined_by(oid::SHA3_384_OID)]
    Sha3_384(Option<asn1::Null>),
    #[defined_by(oid::SHA3_512_OID)]
    Sha3_512(Option<asn1::Null>),

    #[default]
    Other(asn1::ObjectIdentifier, Option<asn1::Tlv<'a>>),
}

//    MessageImprint ::= SEQUENCE  {
//         hashAlgorithm                AlgorithmIdentifier,
//         hashedMessage                OCTET STRING  }
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct MessageImprint<'a> {
    pub hash_algorithm: AlgorithmIdentifier<'a>,
    pub hashed_message: asn1::BitString<'a>,
}

// pub struct RawExtensions<'a> {
//     asn1::SequenceOf<'a, Extension<'a>>,
//     asn1::SequenceOfWriter<'a, Extension<'a>, Vec<Extension<'a>>>,
// }

// TSAPolicyId ::= OBJECT IDENTIFIER
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct TsaPolicyId {
    pub policy_id: asn1::ObjectIdentifier,
}

/// TimeStampReq ::= SEQUENCE  {
//    version                  INTEGER  { v1(1) },
//    messageImprint           MessageImprint,
//      --a hash algorithm OID and the hash value of the data to be
//      --time-stamped
//    reqPolicy                TSAPolicyId                OPTIONAL,
//    nonce                    INTEGER                    OPTIONAL,
//    certReq                  BOOLEAN                    DEFAULT FALSE,
//    extensions               [0] IMPLICIT Extensions    OPTIONAL  }
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct RawTimeStampReq<'a> {
    pub version: u8, // TODO(dm) Do we want to change this to an ENUM?

    pub message_imprint: MessageImprint<'a>,

    pub req_policy: Option<TsaPolicyId>,

    pub nonce: Option<asn1::BigUint<'a>>,

    // #[default(false)]
    pub cert_req: bool,
    // pub extensions: Option<extensions::RawExtensions<'a>>,
}

self_cell::self_cell!(
    struct OwnedTimeStamReq {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawTimeStampReq,
    }
);

#[pyo3::pyclass]
pub struct TimeStampReq {
    raw: Arc<OwnedTimeStamReq>,
}

#[pyo3::pymethods]
impl TimeStampReq {
    #[getter]
    fn version(&self) -> PyResult<u8> {
        Ok(self.raw.borrow_dependent().version)
    }
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

// PKIFailureInfo ::= BIT STRING {
//    badAlg               (0),
//      -- unrecognized or unsupported Algorithm Identifier
//    badRequest           (2),
//      -- transaction not permitted or supported
//    badDataFormat        (5),
//      -- the data submitted has the wrong format
//    timeNotAvailable    (14),
//      -- the TSA's time source is not available
//    unacceptedPolicy    (15),
//      -- the requested TSA policy is not supported by the TSA
//    unacceptedExtension (16),
//      -- the requested extension is not supported by the TSA
//     addInfoNotAvailable (17)
//       -- the additional information requested could not be understood
//       -- or is not available
//     systemFailure       (25)
//       -- the request cannot be handled due to system failure  }

//    PKIStatusInfo ::= SEQUENCE {
//       status        PKIStatus,
//       statusString  PKIFreeText     OPTIONAL,
//       failInfo      PKIFailureInfo  OPTIONAL  }
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct PKIStatusInfo<'a> {
    status: asn1::Enumerated, // TODO: This is not ENUMERATED in the standard but INTEGER
    status_string: Option<asn1::Utf8String<'a>>,
    fail_info: Option<asn1::BitString<'a>>, // TODO: Should replace this with an enum ?
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct ContentInfo<'a> {
    pub content_type: asn1::ObjectIdentifier,
    pub content: TSTInfo<'a>,
}

// asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 1);

//   Accuracy ::= SEQUENCE {
//          seconds        INTEGER              OPTIONAL,
//          millis     [0] INTEGER  (1..999)    OPTIONAL,
//          micros     [1] INTEGER  (1..999)    OPTIONAL  }
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct Accuracy<'a> {
    seconds: Option<asn1::BigUint<'a>>,
    millis: Option<u8>,
    micros: Option<u8>,
}
// TSTInfo ::= SEQUENCE  {
//     version                      INTEGER  { v1(1) },
//     policy                       TSAPolicyId,
//     messageImprint               MessageImprint,
//       -- MUST have the same value as the similar field in
//       -- TimeStampReq
//     serialNumber                 INTEGER,
//      -- Time-Stamping users MUST be ready to accommodate integers
//      -- up to 160 bits.
//     genTime                      GeneralizedTime,
//     accuracy                     Accuracy                 OPTIONAL,
//     ordering                     BOOLEAN             DEFAULT FALSE,
//     nonce                        INTEGER                  OPTIONAL,
//       -- MUST be present if the similar field was present
//       -- in TimeStampReq.  In that case it MUST have the same value.
//     tsa                          [0] GeneralName          OPTIONAL,
//     extensions                   [1] IMPLICIT Extensions  OPTIONAL   }
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct TSTInfo<'a> {
    pub version: u8,
    pub policy: TsaPolicyId,
    pub message_imprint: MessageImprint<'a>,
    pub serial_number: asn1::BigUint<'a>,
    pub gen_time: asn1::GeneralizedTime,
    pub accuracy: Option<Accuracy<'a>>,
    #[default(false)]
    pub ordering: bool,
    pub nonce: Option<asn1::BigUint<'a>>,
    //pub tsa: Option<GeneralName>,
    // pub extensions: Optional<Extensions>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct SignedData<'a> {
    pub version: u8,
    pub digest_algorithms: AlgorithmIdentifier<'a>,
    pub content_info: ContentInfo<'a>,
    // #[implicit(0)]
    // pub certificates: Option<asn1::SetOfWriter<'a, &'a certificate::Certificate<'a>>>,

    // We don't ever supply any of these, so for now, don't fill out the fields.
    #[implicit(1)]
    pub crls: Option<asn1::Sequence<'a>>,
    //pub signer_infos: asn1::SetOfWriter<'a, SignerInfo<'a>>,
}

//    TimeStampToken ::= ContentInfo
//      -- contentType is id-signedData ([CMS])
//      -- content is SignedData ([CMS])
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct TimeStampToken<'a> {
    content_type: asn1::ObjectIdentifier,
    pub content: SignedData<'a>,
}

//    TimeStampResp ::= SEQUENCE  {
//       status                  PKIStatusInfo,
//       timeStampToken          TimeStampToken     OPTIONAL  }
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct RawTimeStampResp<'a> {
    pub status: PKIStatusInfo<'a>,
    pub time_stamp_token: Option<TimeStampToken<'a>>,
}

self_cell::self_cell!(
    struct OwnedTimeStamResp {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawTimeStampResp,
    }
);

#[pyo3::pyclass]
pub struct TimeStampResp {
    raw: Arc<OwnedTimeStamResp>,
}

#[pyo3::pymethods]
impl TimeStampResp {}

#[pyo3::pyfunction]
#[pyo3(signature = (data))]
pub(crate) fn parse_timestamp_response(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
) -> PyResult<TimeStampResp> {
    let raw = OwnedTimeStamResp::try_new(data, |data| asn1::parse_single(data.as_bytes(py)))
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("ASN.1 parse error: {:?}", e))
        })?;

    Ok(TimeStampResp { raw: raw.into() })
}

#[pyo3::pyfunction]
#[pyo3(signature = (data))]
pub(crate) fn parse_timestamp_request(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
) -> PyResult<TimeStampReq> {
    let raw = OwnedTimeStamReq::try_new(data, |data| asn1::parse_single(data.as_bytes(py)))
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("ASN.1 parse error: {:?}", e))
        })?;

    Ok(TimeStampReq { raw: raw.into() })
}

/// A Python module implemented in Rust.
#[pymodule]
fn sigstore_tsp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TimeStampReq>()?;
    m.add_class::<TimeStampResp>()?;
    m.add_function(wrap_pyfunction!(parse_timestamp_response, m)?)?;
    m.add_function(wrap_pyfunction!(parse_timestamp_request, m)?)?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_test() {
        // See TESTING.md
        // openssl ts -query -data README.md -no_nonce -sha512 -cert -out file.tsq
        let enc_request = hex::decode("30590201013051300d060960864801650304020305000440c05812f7df5c643047235d400de272f03bd3d319f71f0c75c4b57948ccf2cdf85f8feb422dedcfa9ec26c102b08f778332ad9be18f759aebe93d64dcc65f49c30101ff")
                           .expect("Decoding failed");
        let request = asn1::parse_single::<RawTimeStampReq>(&enc_request).unwrap();

        assert_eq!(request.version, 1);
    }

    #[test]
    fn simple_test() {
        // 300d06096086480165030402030500
        let algo_identifier = asn1::write_single(&AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: AlgorithmParameters::Sha512(Some(()))
        });
        match algo_identifier {
            Ok(vec) => { println!("AlgorithmIdentifier {}", hex::encode(&vec)) },
            Err(_) => { todo!() }
        }

        let enc_test = hex::decode("300d06096086480165030402030500").expect("Decoding failed");
        let algo_identifier_round = asn1::parse_single::<AlgorithmIdentifier>(&enc_test).unwrap();


        let message_imprint = asn1::write_single(&MessageImprint {
            hash_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Sha512(Some(())),
            },
            hashed_message: asn1::BitString::new(&hex::decode("C05812F7DF5C643047235D400DE272F03BD3D319F71F0C75C4B57948CCF2CDF85F8FEB422DEDCFA9EC26C102B08F778332AD9BE18F759AEBE93D64DCC65F49C3").expect(""), 0).unwrap(),
        });
        match message_imprint {
            Ok(vec) => { println!("MessageImprint {}", hex::encode(&vec)) },
            Err(_) => { todo!() }
        }

    }
}