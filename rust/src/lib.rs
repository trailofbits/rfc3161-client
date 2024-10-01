pub mod oid;
pub mod util;

use std::sync::Arc;

use asn1::SimpleAsn1Readable;
use pyo3::{exceptions::PyValueError, prelude::*};
use rand::Rng;
use sha2::Digest;
use tsp_asn1::cms::SignedData as RawSignedData;
use tsp_asn1::tsp::{
    MessageImprint as RawMessageImprint, RawTimeStampReq, RawTimeStampResp, TSTInfo as RawTSTInfo,
};

self_cell::self_cell!(
    struct OwnedTimeStampReq {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawTimeStampReq,
    }
);

#[pyo3::pyclass]
pub struct TimeStampReq {
    raw: Arc<OwnedTimeStampReq>,
}

#[pyo3::pymethods]
impl TimeStampReq {
    #[getter]
    fn version(&self) -> PyResult<u8> {
        Ok(self.raw.borrow_dependent().version)
    }

    #[getter]
    fn nonce<'p>(&self, py: pyo3::Python<'p>) -> PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match self.raw.borrow_dependent().nonce {
            Some(nonce) => {
                let py_nonce = crate::util::big_asn1_uint_to_py(py, nonce)?;
                Ok(py_nonce)
            }
            None => todo!(),
        }
    }

    #[getter]
    fn policy<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match &self.raw.borrow_dependent().req_policy {
            Some(req_policy) => crate::util::oid_to_py_oid(py, &req_policy),
            None => todo!(),
        }
    }

    #[getter]
    fn cert_req(&self) -> pyo3::PyResult<bool> {
        Ok(self.raw.borrow_dependent().cert_req)
    }

    #[getter]
    fn message_imprint(&self, py: pyo3::Python<'_>) -> PyResult<PyMessageImprint> {
        Ok(PyMessageImprint {
            contents: OwnedMessageImprint::try_new(self.raw.borrow_owner().clone_ref(py), |v| {
                RawMessageImprint::parse_data(v.as_bytes(py))
            })
            .unwrap(),
        })
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
}

self_cell::self_cell!(
    struct OwnedMessageImprint {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawMessageImprint,
    }
);

#[pyo3::pyclass(frozen, module = "sigstore_tsp._rust")]
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

#[pyo3::pyclass]
pub struct TimeStampResp {
    raw: Arc<OwnedTimeStampResp>,
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
            None => {
                return Err(pyo3::exceptions::PyNotImplementedError::new_err(
                    "No status string is not yet implemented.",
                ))
            }
        }
    }

    // TST INFO
    #[getter]
    fn tst_info(&self) -> PyResult<PyTSTInfo> {
        let py_tstinfo = PyTSTInfo {
            raw: OwnedTSTInfo::try_new(Arc::clone(&self.raw), |v| {
                let timestamp_token = v.borrow_dependent().time_stamp_token.as_ref();
                match timestamp_token {
                    Some(content) => match &content.content {
                        tsp_asn1::tsp::Content::SignedData(signed_data) => {
                            let tst_info = signed_data.as_inner().content_info.tst_info().unwrap();
                            Ok::<_, PyErr>(tst_info)
                        }
                    },
                    None => Err(pyo3::exceptions::PyValueError::new_err("")),
                }
            })
            .unwrap(),
        };
        Ok(py_tstinfo)
    }

    // Signed Data
    fn signed_data(&self) -> PyResult<SignedData> {
        let py_signed_data = SignedData {
            raw: OwnedSignedData::try_new(Arc::clone(&self.raw), |v| {
                let timestamp_token = v.borrow_dependent().time_stamp_token.as_ref();
                match timestamp_token {
                    Some(content) => match &content.content {
                        tsp_asn1::tsp::Content::SignedData(signed_data) => {
                            let s = signed_data.as_inner();
                            Ok::<_, PyErr>(RawSignedData {
                                version: s.version,
                                digest_algorithms: s.digest_algorithms.clone(),
                                content_info: s.content_info.clone(),
                                certificates: s.certificates.clone(),
                                crls: None,
                                signer_infos: s.signer_infos.clone(),
                            })
                        }
                    },
                    None => Err(pyo3::exceptions::PyValueError::new_err(
                        "Missing Timestamp Content",
                    )),
                }
            })
            .unwrap(),
        };
        Ok(py_signed_data)
    }
}

self_cell::self_cell!(
    pub struct OwnedSignedData {
        owner: Arc<OwnedTimeStampResp>,
        #[covariant]
        dependent: RawSignedData,
    }
);

#[pyo3::pyclass(frozen, module = "sigstore_tsp._rust")]
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
                    let raw = asn1::write_single(&cert).expect("TODO").clone();
                    py_certs.add(pyo3::types::PyBytes::new_bound(py, &raw))?;
                }
                _ => {}
            }
        }
        Ok(py_certs)
    }

    // TODO(dm) Implement me
    // #[getter]
    // fn signer_infos() {

    // }
}

self_cell::self_cell!(
    pub struct OwnedTSTInfo {
        owner: Arc<OwnedTimeStampResp>,
        #[covariant]
        dependent: RawTSTInfo,
    }
);

#[pyo3::pyclass(frozen, module = "sigstore_tsp._rust")]
pub struct PyTSTInfo {
    pub raw: OwnedTSTInfo,
}

#[pyclass]
struct Accuracy {
    seconds: Option<u128>,
    millis: Option<u8>,
    micros: Option<u8>,
}

#[pymethods]
impl Accuracy {
    #[getter]
    fn seconds(&self) -> Option<u128> {
        self.seconds
    }

    #[getter]
    fn millis(&self) -> Option<u8> {
        self.millis
    }

    #[getter]
    fn micros(&self) -> Option<u8> {
        self.micros
    }
}

impl From<tsp_asn1::tsp::Accuracy<'_>> for Accuracy {
    fn from(acc: tsp_asn1::tsp::Accuracy<'_>) -> Self {
        Accuracy {
            seconds: acc
                .seconds
                .map(|s| u128::from_be_bytes(s.as_bytes().try_into().expect("TODO"))),
            millis: acc.millis,
            micros: acc.micros,
        }
    }
}

#[pyo3::pymethods]
impl PyTSTInfo {
    #[getter]
    fn version(&self) -> PyResult<u8> {
        Ok(self.raw.borrow_dependent().version)
    }

    #[getter]
    fn policy<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match &self.raw.borrow_dependent().policy {
            Some(req_policy) => crate::util::oid_to_py_oid(py, &req_policy),
            None => todo!(),
        }
    }

    // TODO(DM) Message Imprint
    // #[getter]
    // fn message_imprint(&self) -> PyResult<PyMessageImprint> {
    //     Ok(PyMessageImprint {
    //         contents: OwnedMessageImprint::try_new(self.raw.borrow_owner().clone(), |v| {
    //             Ok::<_, ()>(v.borrow_dependent().message_imprint.clone())
    //         })
    //         .unwrap(),
    //     })
    // }

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
    fn accuracy(&self) -> PyResult<Accuracy> {
        match self.raw.borrow_dependent().accuracy {
            Some(accuracy) => {
                let py_acc = Accuracy::from(accuracy);
                Ok(py_acc)
            }
            None => todo!(),
        }
    }

    #[getter]
    fn ordering(&self) -> bool {
        self.raw.borrow_dependent().ordering
    }

    #[getter]
    fn nonce<'p>(&self, py: Python<'p>) -> PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match self.raw.borrow_dependent().nonce {
            Some(nonce) => {
                let py_nonce = crate::util::big_asn1_uint_to_py(py, nonce)?;
                Ok(py_nonce)
            }
            None => todo!(),
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
                        _ => todo!(),
                    };
                    Ok(py_gn)
                }
            },
            None => todo!(),
        }
    }
    // TODO(dm) extensions: Extensions
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
#[pyo3(signature = (data))]
pub(crate) fn create_timestamp_request(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
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

    let mut rng = rand::thread_rng();
    let nonce: u64 = rng.gen();
    let nonce_bytes = nonce.to_be_bytes();

    let nonce_biguint = asn1::BigUint::new(&nonce_bytes);

    let timestamp_request = RawTimeStampReq {
        version: 1,
        message_imprint: message_imprint,
        nonce: nonce_biguint,
        req_policy: None,
        cert_req: false,
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

/// A Python module implemented in Rust.
#[pyo3::pymodule]
mod sigstore_tsp {
    use super::*;

    #[pyo3::pymodule]
    mod _rust {

        #[pymodule_export]
        use super::parse_timestamp_response;

        #[pymodule_export]
        use super::create_timestamp_request;

        #[pymodule_export]
        use super::parse_timestamp_request;
    }
}

#[cfg(test)]
mod tests {}
