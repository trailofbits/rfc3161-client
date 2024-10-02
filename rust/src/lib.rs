pub mod oid;
pub mod util;

use asn1::SimpleAsn1Readable;
use pyo3::{exceptions::PyValueError, prelude::*};
use rand::Rng;
use sha2::Digest;
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

#[pyo3::pyclass(frozen, module = "sigstore_tsp._rust")]
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
        Ok(PyMessageImprint {
            contents: OwnedMessageImprint::try_new(self.raw.borrow_owner().clone_ref(py), |v| {
                let req = asn1::parse_single::<RawTimeStampReq>(v.as_bytes(py)).map_err(|e| {
                    PyValueError::new_err(format!("invalid message imprint: {:?}", e))
                });
                match req {
                    Ok(res) => Ok(res.message_imprint),
                    Err(_) => Err(PyValueError::new_err("Unable to retrieve message imprint")),
                }
            })
            .map_err(|e| PyValueError::new_err(format!("invalid message imprint: {:?}", e)))?,
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

#[pyo3::pyclass(frozen, module = "sigstore_tsp._rust")]
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
        let py_tstinfo = PyTSTInfo {
            raw: OwnedTSTInfo::try_new(self.raw.borrow_owner().clone_ref(py), |v| {
                let rsp = asn1::parse_single::<RawTimeStampResp>(v.as_bytes(py))
                    .map_err(|e| PyValueError::new_err(format!("invalid TimeStampResp: {:?}", e)))
                    .unwrap();

                match rsp.time_stamp_token {
                    Some(TimeStampToken {
                        _content_type,
                        content: tsp_asn1::tsp::Content::SignedData(signed_data),
                    }) => signed_data
                        .as_inner()
                        .content_info
                        .tst_info()
                        .map_err(|_| PyValueError::new_err("invalid TSTInfo")),
                    None => Err(PyValueError::new_err("missing TimeStampToken")),
                }
            })
            .unwrap(),
        };
        Ok(py_tstinfo)
    }

    // Signed Data
    #[getter]
    fn signed_data(&self, py: pyo3::Python<'_>) -> PyResult<SignedData> {
        let py_signed_data = SignedData {
            raw: OwnedSignedData::try_new(self.raw.borrow_owner().clone_ref(py), |v| {
                let resp = asn1::parse_single::<RawTimeStampResp>(v.as_bytes(py))
                    .map_err(|e| PyValueError::new_err(format!("invalid TimeStampResp: {:?}", e)))
                    .unwrap();

                match resp.time_stamp_token {
                    Some(TimeStampToken {
                        _content_type,
                        content: tsp_asn1::tsp::Content::SignedData(signed_data),
                    }) => Ok(*signed_data.into_inner()),
                    None => Err(PyValueError::new_err("missing TimeStampToken")),
                }
            })
            .unwrap(),
        };
        Ok(py_signed_data)
    }
}

self_cell::self_cell!(
    pub struct OwnedSignedData {
        owner: pyo3::Py<pyo3::types::PyBytes>,
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
                _ => return Err(PyValueError::new_err("Unknown certificate type")),
            }
        }
        Ok(py_certs)
    }

    #[getter]
    fn signer_infos<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::PyObject> {
        let py_set = pyo3::types::PySet::empty_bound(py)?;

        let mut i = 0;
        for _ in self.raw.borrow_dependent().signer_infos.clone() {
            let py_signer_info = SignerInfo {
                raw: OwnedSignerInfo::try_new(self.raw.borrow_owner().clone_ref(py), |v| {
                    let resp = asn1::parse_single::<RawTimeStampResp>(v.as_bytes(py))
                        .map_err(|e| {
                            PyValueError::new_err(format!(
                                "invalid Signer Data: {:?}",
                                v.as_bytes(py)
                            ))
                        })
                        .unwrap();

                    match resp.time_stamp_token {
                        Some(TimeStampToken {
                            _content_type,
                            content: tsp_asn1::tsp::Content::SignedData(signed_data),
                        }) => {
                            let signer_info = signed_data.into_inner().signer_infos.nth(i).unwrap();
                            Ok(signer_info)
                        }
                        None => Err(PyValueError::new_err("missing TimeStampToken")),
                    }
                })
                .unwrap(),
            };
            py_set.add(py_signer_info.into_py(py))?;
            i = i + 1;
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

#[pyo3::pyclass(frozen, module = "sigstore_tsp._rust")]
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

self_cell::self_cell!(
    pub struct OwnedTSTInfo {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawTSTInfo,
    }
);

#[pyo3::pyclass(frozen, module = "sigstore_tsp._rust")]
pub struct PyTSTInfo {
    pub raw: OwnedTSTInfo,
}

#[pyo3::pyclass(frozen, module = "sigstore_tsp._rust")]
pub struct Accuracy {
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
        Ok(PyMessageImprint {
            contents: OwnedMessageImprint::try_new(self.raw.borrow_owner().clone_ref(py), |v| {
                RawMessageImprint::parse_data(v.as_bytes(py))
            })
            .map_err(|_| PyValueError::new_err("invalid message imprint"))?,
        })
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

        #[pymodule_export]
        use super::{
            Accuracy, PyMessageImprint, PyTSTInfo, SignedData, SignerInfo, TimeStampReq,
            TimeStampResp,
        };

        #[pymodule_export]
        use crate::oid::ObjectIdentifier;
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedTimeStampResp;
    use asn1::SimpleAsn1Readable;
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
