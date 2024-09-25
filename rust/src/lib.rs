pub mod certificate;
pub mod cms;
pub mod common;
pub mod crl;
pub mod csr;
pub mod extensions;
pub mod name;
pub mod oid;
pub mod tsp;

use pyo3::prelude::*;
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

#[pyo3::pymethods]
impl TimeStampReq {
    #[getter]
    fn version(&self) -> PyResult<u8> {
        Ok(self.raw.borrow_dependent().version)
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
}
