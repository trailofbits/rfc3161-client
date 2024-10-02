use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[pyo3::pyclass(frozen, module = "sigstore_tsp._rust")]
pub(crate) struct ObjectIdentifier {
    pub(crate) oid: asn1::ObjectIdentifier,
}

#[pyo3::pymethods]
impl ObjectIdentifier {
    #[new]
    fn new(value: &str) -> pyo3::PyResult<Self> {
        let oid = asn1::ObjectIdentifier::from_string(value)
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid value"))?;
        Ok(ObjectIdentifier { oid })
    }

    #[getter]
    fn dotted_string(&self) -> String {
        self.oid.to_string()
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, ObjectIdentifier>) -> bool {
        self.oid == other.oid
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.oid.hash(&mut hasher);
        hasher.finish()
    }
}
