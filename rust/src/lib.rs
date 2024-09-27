pub mod certificate;
pub mod cms;
pub mod common;
pub mod crl;
pub mod csr;
pub mod extensions;
pub mod name;
pub mod oid;
pub mod tsp;

use pyo3::{exceptions::PyValueError, prelude::*};
use rand::Rng;
use sha2::Digest;
use tsp::{RawTimeStampReq, RawTimeStampResp};

self_cell::self_cell!(
    struct OwnedTimeStamReq {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawTimeStampReq,
    }
);

#[pyo3::pyclass]
pub struct TimeStampReq {
    raw: OwnedTimeStamReq,
}

pub(crate) fn big_asn1_uint_to_py<'p>(
    py: pyo3::Python<'p>,
    v: asn1::BigUint<'_>,
) -> PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let int_type = py.get_type_bound::<pyo3::types::PyLong>();
    Ok(int_type.call_method1(
        pyo3::intern!(py, "from_bytes"),
        (v.as_bytes(), pyo3::intern!(py, "big")),
    )?)
}

pub(crate) fn oid_to_py_oid<'p>(
    py: pyo3::Python<'p>,
    oid: &asn1::ObjectIdentifier,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    Ok(pyo3::Bound::new(py, ObjectIdentifier { oid: oid.clone() })?.into_any())
}

#[pyo3::pyclass(frozen, module = "sigstore_tsp._rust")]
pub(crate) struct ObjectIdentifier {
    pub(crate) oid: asn1::ObjectIdentifier,
}

#[pyo3::pymethods]
impl ObjectIdentifier {
    #[new]
    fn new(value: &str) -> PyResult<Self> {
        let oid = asn1::ObjectIdentifier::from_string(value)
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid value"))?;
        Ok(ObjectIdentifier { oid })
    }

    #[getter]
    fn dotted_string(&self) -> String {
        self.oid.to_string()
    }
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
                let py_nonce = big_asn1_uint_to_py(py, nonce)?;
                Ok(py_nonce)
            }
            None => todo!(),
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

    #[getter]
    fn policy<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match &self.raw.borrow_dependent().req_policy {
            Some(req_policy) => oid_to_py_oid(py, &req_policy),
            None => todo!(),
        }
    }
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
    raw: OwnedTimeStamResp,
}

impl TimeStampResp {
    fn get_tst_info(&self) -> pyo3::PyResult<tsp::TSTInfo<'_>> {
        let timestamp_token = self.raw.borrow_dependent().time_stamp_token.as_ref();
        match timestamp_token {
            Some(content) => match &content.content {
                tsp::Content::SignedData(signed_data) => {
                    let tst_info = signed_data.as_inner().content_info.tst_info().unwrap();
                    Ok(tst_info)
                }
            },
            None => Err(pyo3::exceptions::PyValueError::new_err("")),
        }
    }
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
    fn tst_info_version(&self) -> pyo3::PyResult<u8> {
        let tst_info = self.get_tst_info()?;
        Ok(tst_info.version)
    }

    #[getter]
    fn tst_info_nonce<'p>(&self, py: pyo3::Python<'p>) -> PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let tst_info = self.get_tst_info()?;
        match tst_info.nonce {
            Some(nonce) => {
                let py_nonce = big_asn1_uint_to_py(py, nonce)?;
                Ok(py_nonce)
            }
            None => todo!(),
        }
    }

    #[getter]
    fn tst_info_policy<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let tst_info = self.get_tst_info()?;
        match tst_info.policy {
            Some(policy_id) => oid_to_py_oid(py, &policy_id),
            None => todo!(),
        }
    }
}

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

#[pyo3::pyfunction]
#[pyo3(signature = (data))]
pub(crate) fn create_timestamp_request(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
) -> PyResult<TimeStampReq> {
    let data_bytes = data.as_bytes(py);
    let hash = sha2::Sha512::digest(data_bytes);

    let message_imprint = tsp::MessageImprint {
        hash_algorithm: common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::Sha512(Some(())),
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

    let raw = OwnedTimeStamReq::try_new(py_bytes, |data| asn1::parse_single(data.as_bytes(py)))
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

        use super::*;

        #[pymodule_export]
        use super::parse_timestamp_response;

        #[pymodule_export]
        use super::create_timestamp_request;

        #[pymodule_export]
        use super::parse_timestamp_request;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
