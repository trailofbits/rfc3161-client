pub mod name;
pub mod util;

use pyo3::{exceptions::PyValueError, prelude::*};
use sha2::Digest;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use tsp_asn1::cms::{SignedData as RawSignedData, SignerInfo as RawSignerInfo};
use tsp_asn1::tsp::{
    MessageImprint as RawMessageImprint, RawTimeStampReq, RawTimeStampResp, TSTInfo as RawTSTInfo,
    TimeStampToken,
};

self_cell::self_cell!(
    struct OwnedTimeStampReq {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawTimeStampReq,
    }
);

#[pyo3::pyclass(frozen, module = "rfc3161_client._rust")]
pub struct TimeStampReq {
    raw: OwnedTimeStampReq,
}

#[pyo3::pymethods]
impl TimeStampReq {
    #[getter]
    fn version(&self) -> PyResult<u8> {
        Ok(self.raw.borrow_dependent().version)
    }

    #[getter]
    fn nonce<'p>(&self, py: pyo3::Python<'p>) -> PyResult<Option<PyObject>> {
        match self.raw.borrow_dependent().nonce {
            Some(nonce) => {
                let py_nonce = crate::util::big_asn1_uint_to_py(py, nonce)?;
                Ok(Some(py_nonce.into_py(py)))
            }
            None => Ok(None),
        }
    }

    #[getter]
    fn policy<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<Option<PyObject>> {
        match &self.raw.borrow_dependent().req_policy {
            Some(req_policy) => {
                let py_oid = crate::util::oid_to_py_oid(py, &req_policy)?;
                Ok(Some(py_oid.into_py(py)))
            }
            None => Ok(None),
        }
    }

    #[getter]
    fn cert_req(&self) -> pyo3::PyResult<bool> {
        Ok(self.raw.borrow_dependent().cert_req)
    }

    #[getter]
    fn message_imprint(&self, py: pyo3::Python<'_>) -> PyResult<PyMessageImprint> {
        let message_imprint = asn1::write_single(&self.raw.borrow_dependent().message_imprint)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("Unable to serialize Message Imprint")
            })?;
        let full_bytes = self.raw.borrow_owner().as_bytes(py);

        if let Some(offset) = full_bytes
            .windows(message_imprint.len())
            .position(|window| window == message_imprint)
        {
            let slice = &full_bytes[offset..offset + message_imprint.len()];
            let new_owner = pyo3::types::PyBytes::new_bound(py, slice);
            Ok(PyMessageImprint {
                contents: OwnedMessageImprint::try_new(new_owner.as_unbound().clone_ref(py), |v| {
                    asn1::parse_single::<tsp_asn1::tsp::MessageImprint>(v.as_bytes(py))
                })
                .unwrap(),
            })
        } else {
            Err(pyo3::exceptions::PyValueError::new_err(
                "Could not find MessageImprint in the response",
            ))
        }
    }

    fn as_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> PyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let result = asn1::write_single(&self.raw.borrow_dependent());
        match result {
            Ok(request_bytes) => Ok(pyo3::types::PyBytes::new_bound(py, &request_bytes)),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{e}"))),
        }
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        let buffer = asn1::write_single(&self.raw.borrow_dependent()).unwrap();
        buffer.hash(&mut hasher);
        hasher.finish()
    }

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let version = self.version()?;
        let nonce_repr = match self.nonce(py)? {
            Some(n) => n.to_string(),
            None => "None".to_string(),
        };
        Ok(format!(
            "<TimestampRequest(version={version}, nonce={nonce_repr})>"
        ))
    }
}

self_cell::self_cell!(
    struct OwnedMessageImprint {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawMessageImprint,
    }
);

#[pyo3::pyclass(frozen, module = "rfc3161_client._rust")]
pub(crate) struct PyMessageImprint {
    pub contents: OwnedMessageImprint,
}

#[pyo3::pymethods]
impl PyMessageImprint {
    #[getter]
    fn hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let hash_algoritm = self.contents.borrow_dependent().hash_algorithm.oid();
        crate::util::oid_to_py_oid(py, hash_algoritm)
    }

    #[getter]
    fn message<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let message = self.contents.borrow_dependent().hashed_message;
        Ok(pyo3::types::PyBytes::new_bound(py, message))
    }
}

self_cell::self_cell!(
    struct OwnedTimeStampResp {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawTimeStampResp,
    }
);

#[pyo3::pyclass(frozen, module = "rfc3161_client._rust")]
pub struct TimeStampResp {
    raw: OwnedTimeStampResp,
}

#[pyo3::pymethods]
impl TimeStampResp {
    #[getter]
    fn status(&self) -> pyo3::PyResult<u8> {
        Ok(self.raw.borrow_dependent().status.status)
    }

    #[getter]
    fn status_string<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::types::PyList>> {
        let opt_status_strings = &self.raw.borrow_dependent().status.status_string;
        match opt_status_strings {
            Some(status_strings) => {
                let status_list = pyo3::types::PyList::empty_bound(py);
                for status_string in status_strings.clone() {
                    let _ = status_list
                        .append(pyo3::types::PyString::new_bound(py, status_string.as_str()));
                }
                Ok(status_list)
            }
            None => Ok(pyo3::types::PyList::empty_bound(py)),
        }
    }

    // TST INFO
    #[getter]
    fn tst_info(&self, py: pyo3::Python<'_>) -> PyResult<PyTSTInfo> {
        let tsp = match &self.raw.borrow_dependent().time_stamp_token {
            Some(TimeStampToken {
                _content_type,
                content: tsp_asn1::tsp::Content::SignedData(signed_data),
            }) => signed_data,
            None => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "Missing SignedData",
                ))
            }
        };

        let tst_info = tsp.as_inner().content_info.tst_info().map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Malformed TimestampToken: {}", e))
        })?;

        let tst_bytes = asn1::write_single(&tst_info)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Unable to serialize TSTInfo"))?;

        let full_bytes = self.raw.borrow_owner().as_bytes(py);
        if let Some(offset) = full_bytes
            .windows(tst_bytes.len())
            .position(|window| window == tst_bytes)
        {
            let tst_slice = &full_bytes[offset..offset + tst_bytes.len()];
            let new_owner = pyo3::types::PyBytes::new_bound(py, tst_slice);

            let py_tstinfo = PyTSTInfo {
                raw: OwnedTSTInfo::try_new(new_owner.as_unbound().clone_ref(py), |v| {
                    asn1::parse_single::<tsp_asn1::tsp::TSTInfo>(v.as_bytes(py))
                })
                .unwrap(),
            };
            Ok(py_tstinfo)
        } else {
            Err(pyo3::exceptions::PyValueError::new_err(
                "Could not find TSTInfo in the response",
            ))
        }
    }

    // Signed Data
    #[getter]
    fn signed_data(&self, py: pyo3::Python<'_>) -> PyResult<SignedData> {
        match &self.raw.borrow_dependent().time_stamp_token {
            Some(TimeStampToken {
                _content_type,
                content: tsp_asn1::tsp::Content::SignedData(signed_data),
            }) => {
                let signed_data_bytes =
                    asn1::write_single(&signed_data.as_inner()).map_err(|_| {
                        pyo3::exceptions::PyValueError::new_err("Unable to serialize SignedData")
                    })?;

                let full_bytes = self.raw.borrow_owner().as_bytes(py);
                if let Some(offset) = full_bytes
                    .windows(signed_data_bytes.len())
                    .position(|window| window == signed_data_bytes)
                {
                    let tst_slice = &full_bytes[offset..offset + signed_data_bytes.len()];
                    let new_owner = pyo3::types::PyBytes::new_bound(py, tst_slice);

                    let py_signed_data = SignedData {
                        raw: OwnedSignedData::try_new(new_owner.as_unbound().clone_ref(py), |v| {
                            asn1::parse_single::<tsp_asn1::cms::SignedData>(v.as_bytes(py))
                        })
                        .unwrap(),
                    };
                    Ok(py_signed_data)
                } else {
                    Err(pyo3::exceptions::PyValueError::new_err(
                        "Could not find SignedData in the response",
                    ))
                }
            }
            None => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "Missing SignedData",
                ))
            }
        }
    }

    // Timestamp Token (as_bytes)
    fn time_stamp_token<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> PyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let result = asn1::write_single(&self.raw.borrow_dependent().time_stamp_token);
        match result {
            Ok(request_bytes) => Ok(pyo3::types::PyBytes::new_bound(py, &request_bytes)),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{e}"))),
        }
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        let buffer = asn1::write_single(&self.raw.borrow_dependent()).unwrap();
        buffer.hash(&mut hasher);
        hasher.finish()
    }

    fn __repr__(&self) -> pyo3::PyResult<String> {
        let status = self.status()?;
        Ok(format!("<TimestampResponse(status={status}, ...)>"))
    }
}

self_cell::self_cell!(
    pub struct OwnedSignedData {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawSignedData,
    }
);

#[pyo3::pyclass(frozen, module = "rfc3161_client._rust")]
pub struct SignedData {
    pub raw: OwnedSignedData,
}

#[pyo3::pymethods]
impl SignedData {
    #[getter]
    fn version(&self) -> pyo3::PyResult<u8> {
        Ok(self.raw.borrow_dependent().version)
    }

    #[getter]
    fn digest_algorithms<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::types::PySet>> {
        let py_set = pyo3::types::PySet::empty_bound(py)?;
        for algorithm in self.raw.borrow_dependent().digest_algorithms.clone() {
            let py_oid = crate::util::oid_to_py_oid(py, algorithm.oid())?;
            py_set.add(py_oid)?;
        }

        Ok(py_set)
    }

    #[getter]
    fn certificates<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::types::PySet>> {
        let py_certs = pyo3::types::PySet::empty_bound(py)?;
        let certs = match self.raw.borrow_dependent().certificates.clone() {
            Some(certs) => certs,
            None => return Ok(py_certs),
        };

        for cert in certs {
            match cert {
                tsp_asn1::certificate::CertificateChoices::Certificate(cert) => {
                    let raw = asn1::write_single(&cert).unwrap().clone();
                    py_certs.add(pyo3::types::PyBytes::new_bound(py, &raw))?;
                }
                _ => return Err(PyValueError::new_err("Unknown certificate type")),
            }
        }
        Ok(py_certs)
    }

    #[getter]
    fn signer_infos<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::PyObject> {
        let py_set = pyo3::types::PySet::empty_bound(py)?;

        let full_bytes = self.raw.borrow_owner().as_bytes(py);
        for signer in self.raw.borrow_dependent().signer_infos.clone() {
            let signer_bytes = asn1::write_single(&signer).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("Unable to serialize SignerInfo")
            })?;

            if let Some(offset) = full_bytes
                .windows(signer_bytes.len())
                .position(|window| window == signer_bytes)
            {
                let slice = &full_bytes[offset..offset + signer_bytes.len()];
                let new_owner = pyo3::types::PyBytes::new_bound(py, slice);

                let py_signer_info = SignerInfo {
                    raw: OwnedSignerInfo::try_new(new_owner.as_unbound().clone_ref(py), |v| {
                        asn1::parse_single::<RawSignerInfo>(v.as_bytes(py))
                    })
                    .unwrap(),
                };
                py_set.add(py_signer_info.into_py(py))?;
            }
        }

        Ok(py_set.to_object(py))
    }
}

self_cell::self_cell!(
    pub struct OwnedSignerInfo {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawSignerInfo,
    }
);

#[pyo3::pyclass(frozen, module = "rfc3161_client._rust")]
pub struct SignerInfo {
    pub raw: OwnedSignerInfo,
}

#[pyo3::pymethods]
impl SignerInfo {
    #[getter]
    fn version(&self) -> pyo3::PyResult<u8> {
        Ok(self.raw.borrow_dependent().version)
    }
}

#[pyo3::pyclass(frozen, module = "rfc3161_client._rust")]
pub struct Accuracy {
    seconds: Option<u128>,
    millis: Option<u16>,
    micros: Option<u16>,
}

#[pymethods]
impl Accuracy {
    #[getter]
    fn seconds(&self) -> Option<u128> {
        self.seconds
    }

    #[getter]
    fn millis(&self) -> Option<u16> {
        self.millis
    }

    #[getter]
    fn micros(&self) -> Option<u16> {
        self.micros
    }
}

impl From<tsp_asn1::tsp::Accuracy<'_>> for Accuracy {
    fn from(acc: tsp_asn1::tsp::Accuracy<'_>) -> Self {
        Accuracy {
            seconds: acc.seconds().and_then(|s| {
                let bytes = s.as_bytes();
                if bytes.len() <= 16 {
                    let mut buffer = [0u8; 16];
                    buffer[16 - bytes.len()..].copy_from_slice(bytes);
                    Some(u128::from_be_bytes(buffer))
                } else {
                    None
                }
            }),
            millis: acc.millis(),
            micros: acc.micros(),
        }
    }
}

self_cell::self_cell!(
    pub struct OwnedTSTInfo {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawTSTInfo,
    }
);

#[pyo3::pyclass(frozen, module = "rfc3161_client._rust")]
pub struct PyTSTInfo {
    pub raw: OwnedTSTInfo,
}

#[pyo3::pymethods]
impl PyTSTInfo {
    #[getter]
    fn version(&self) -> PyResult<u8> {
        Ok(self.raw.borrow_dependent().version)
    }

    #[getter]
    fn policy<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<Option<PyObject>> {
        match &self.raw.borrow_dependent().policy {
            Some(req_policy) => {
                let py_oid = crate::util::oid_to_py_oid(py, &req_policy)?;
                Ok(Some(py_oid.into_py(py)))
            }
            None => Ok(None),
        }
    }

    #[getter]
    fn message_imprint(&self, py: pyo3::Python<'_>) -> PyResult<PyMessageImprint> {
        let message_imprint = asn1::write_single(&self.raw.borrow_dependent().message_imprint)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("Unable to serialize Message Imprint")
            })?;
        let full_bytes = self.raw.borrow_owner().as_bytes(py);

        if let Some(offset) = full_bytes
            .windows(message_imprint.len())
            .position(|window| window == message_imprint)
        {
            let slice = &full_bytes[offset..offset + message_imprint.len()];
            let new_owner = pyo3::types::PyBytes::new_bound(py, slice);
            Ok(PyMessageImprint {
                contents: OwnedMessageImprint::try_new(new_owner.as_unbound().clone_ref(py), |v| {
                    asn1::parse_single::<tsp_asn1::tsp::MessageImprint>(v.as_bytes(py))
                })
                .unwrap(),
            })
        } else {
            Err(pyo3::exceptions::PyValueError::new_err(
                "Could not find MessageImprint in the response",
            ))
        }
    }

    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let bytes = self.raw.borrow_dependent().serial_number.as_bytes();
        let py_serial = crate::util::big_byte_slice_to_py_int(py, bytes)?;
        Ok(py_serial)
    }

    #[getter]
    fn gen_time<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let gen_time = &self.raw.borrow_dependent().gen_time;
        crate::util::datetime_to_py_utc(py, gen_time.as_datetime())
    }

    #[getter]
    fn accuracy(&self) -> PyResult<Option<Accuracy>> {
        match self.raw.borrow_dependent().accuracy {
            Some(accuracy) => {
                let py_acc = Accuracy::from(accuracy);
                Ok(Some(py_acc))
            }
            None => Ok(None),
        }
    }

    #[getter]
    fn ordering(&self) -> bool {
        self.raw.borrow_dependent().ordering
    }

    #[getter]
    fn nonce<'p>(&self, py: Python<'p>) -> PyResult<Option<PyObject>> {
        match self.raw.borrow_dependent().nonce {
            Some(nonce) => {
                let py_nonce = crate::util::big_asn1_uint_to_py(py, nonce)?;
                Ok(Some(py_nonce.into_py(py)))
            }
            None => Ok(None),
        }
    }

    #[getter]
    fn name<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::PyObject> {
        let gn = &self.raw.borrow_dependent().tsa;
        match gn {
            Some(name) => match name {
                tsp_asn1::name::GeneralNameWrapper::General(gn_name) => {
                    let py_gn = match &gn_name.name {
                        cryptography_x509::name::GeneralName::OtherName(data) => {
                            let oid = crate::util::oid_to_py_oid(py, &data.type_id)?;
                            crate::util::OTHER_NAME
                                .get(py)?
                                .call1((oid, data.value.full_data()))?
                                .to_object(py)
                        }
                        cryptography_x509::name::GeneralName::DirectoryName(data) => {
                            let py_name = crate::name::parse_name(py, data.unwrap_read())?;
                            crate::util::DIRECTORY_NAME
                                .get(py)?
                                .call1((py_name,))?
                                .to_object(py)
                        }
                        _ => return Err(PyValueError::new_err("Unknown name format")),
                    };
                    Ok(py_gn)
                }
            },
            None => Err(pyo3::exceptions::PyValueError::new_err("No names found")),
        }
    }

    // Extensions
    // The extensions are not exposed because they are not needed.
    // If this change, or if you workflow requires them, please open an issue.

    fn as_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> PyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let result = asn1::write_single(&self.raw.borrow_dependent());
        match result {
            Ok(request_bytes) => Ok(pyo3::types::PyBytes::new_bound(py, &request_bytes)),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{e}"))),
        }
    }
}

#[pyo3::pyfunction]
#[pyo3(signature = (data))]
pub(crate) fn parse_timestamp_response(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
) -> PyResult<TimeStampResp> {
    let raw = OwnedTimeStampResp::try_new(data, |data| asn1::parse_single(data.as_bytes(py)))
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
    let raw = OwnedTimeStampReq::try_new(data, |data| asn1::parse_single(data.as_bytes(py)))
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("ASN.1 parse error: {:?}", e))
        })?;

    Ok(TimeStampReq { raw: raw.into() })
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, nonce, cert))]
pub(crate) fn create_timestamp_request(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
    nonce: bool,
    cert: bool,
) -> PyResult<TimeStampReq> {
    let data_bytes = data.as_bytes(py);
    let hash = sha2::Sha512::digest(data_bytes);

    let message_imprint = tsp_asn1::tsp::MessageImprint {
        hash_algorithm: cryptography_x509::common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: cryptography_x509::common::AlgorithmParameters::Sha512(Some(())),
        },
        hashed_message: hash.as_slice(),
    };

    let random_bytes = crate::util::generate_random_bytes_for_asn1_biguint();
    let nonce_asn1 = asn1::BigUint::new(&random_bytes);

    let timestamp_request = RawTimeStampReq {
        version: 1,
        message_imprint: message_imprint,
        nonce: if nonce { nonce_asn1 } else { None },
        req_policy: None,
        cert_req: cert,
        extensions: None,
    };

    let request_bytes = asn1::write_single(&timestamp_request)
        .map_err(|e| PyValueError::new_err(format!("Serialization error: {:?}", e)));
    let py_bytes = pyo3::types::PyBytes::new_bound(py, &request_bytes.unwrap()).unbind();

    let raw = OwnedTimeStampReq::try_new(py_bytes, |data| asn1::parse_single(data.as_bytes(py)))
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("ASN.1 parse error: {:?}", e))
        })?;

    Ok(TimeStampReq { raw: raw.into() })
}

#[pyo3::pyfunction]
#[pyo3(signature = (sig, certs))]
fn pkcs7_verify(
    py: pyo3::Python<'_>,
    sig: &[u8],
    certs: Vec<pyo3::Py<pyo3::types::PyBytes>>,
) -> pyo3::PyResult<()> {
    let p7 = openssl::pkcs7::Pkcs7::from_der(sig).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Unable to parse sig as pkcs7: {:?}", e))
    })?;

    let flags = openssl::pkcs7::Pkcs7Flags::empty();

    let store = {
        let mut b = openssl::x509::store::X509StoreBuilder::new().map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Unable to create store builder: {:?}",
                e
            ))
        })?;

        for cert in &certs {
            b.add_cert(openssl::x509::X509::from_der(&cert.as_bytes(py)).unwrap())
                .map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "Unable to add certificate: {:?}",
                        e
                    ))
                })?;
        }
        b.build()
    };
    let certs = openssl::stack::Stack::new().map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Unable to create certs stack: {:?}", e))
    })?;

    let signers = p7.signers(&certs, flags).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Unable to create signers: {:?}", e))
    })?;
    if signers.len() == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("No signers found"));
    }

    for signer in signers {
        let mut store_ctx = openssl::x509::X509StoreContext::new().map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Unable to create store context. {:?}",
                e
            ))
        })?;
        let is_valid = store_ctx
            .init(&store, &signer, &certs, |ctx| ctx.verify_cert())
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Unable to create verification context. {:?}",
                    e
                ))
            })?;

        if !is_valid {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Unable to verify certificate",
            ));
        }
    }

    Ok(())
}

/// A Python module implemented in Rust.
#[pyo3::pymodule]
mod rfc3161_client {
    use super::*;

    #[pyo3::pymodule]
    mod _rust {
        #[pymodule_export]
        use super::parse_timestamp_response;

        #[pymodule_export]
        use super::create_timestamp_request;

        #[pymodule_export]
        use super::parse_timestamp_request;

        #[pymodule_export]
        use super::{
            Accuracy, PyMessageImprint, PyTSTInfo, SignedData, SignerInfo, TimeStampReq,
            TimeStampResp,
        };

        #[pyo3::pymodule]
        mod verify {
            #[pymodule_export]
            use super::super::pkcs7_verify;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedTimeStampResp;
    use tsp_asn1::tsp::RawTimeStampResp;

    #[test]
    fn test() {
        pyo3::prepare_freethreaded_python();

        pyo3::Python::with_gil(|py| {
            let data = hex::decode("308202ec3003020100308202e306092a864886f70d010702a08202d4308202d0020103310d300b06096086480165030402013081d9060b2a864886f70d0109100104a081c90481c63081c302010106092b0601040183bf30023051300d0609608648016503040203050004409b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec04302143e2f3211f06695a6fb447d11dadf37b2228e8ca1180f32303234313030323039323135355a3003020101a034a4323030310e300c060355040a13056c6f63616c311e301c0603550403131554657374205453412054696d657374616d70696e67a000318201dc308201d802010130483030310e300c060355040a13056c6f63616c311e301c06035504031315546573742054534120496e7465726d656469617465021461ab8956727edad25ee3c2cd663d5ddd719071a0300b0609608648016503040201a0820126301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d010905310f170d3234313030323039323135355a302f06092a864886f70d0109043122042089719cf333d5226a661aeab5807edcf53ba01f85323dc0415ee981f6c78d21953081b8060b2a864886f70d010910022f3181a83081a53081a230819f300d060960864801650304020305000440c04d4b48148c29c5cbab7919d432f6b1ae33995426613b4f759631108ff7d1e9c95537fac1acf43e2813754630c29abe6a0e3b804701ef3e04d3a17a4624c910304c3034a4323030310e300c060355040a13056c6f63616c311e301c06035504031315546573742054534120496e7465726d656469617465021461ab8956727edad25ee3c2cd663d5ddd719071a0300a06082a8648ce3d0403020446304402205333cdad93a03d3b22ebc3e84c560e9271fbedef0f97babf71c973a5ce4bd98e022001baf6b000e63eafac813c6e73bd46619bd2a6ebb161ca4e20b5c09a13e118c1")
            .unwrap();

            let py_bytes = pyo3::types::PyBytes::new_bound(py, &data);

            // Does not work
            // let raw = OwnedTimeStampResp::try_new(py_bytes.into(), |v| {
            //     RawTimeStampResp::parse_data(v.as_bytes(py))
            // }).unwrap();

            // Works
            let raw = OwnedTimeStampResp::try_new(py_bytes.into(), |v| {
                asn1::parse_single::<RawTimeStampResp>(v.as_bytes(py))
            })
            .unwrap();

            assert_eq!(raw.borrow_dependent().status.status, 0);
        });
    }
}
