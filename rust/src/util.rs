use pyo3::types::IntoPyDict;
use pyo3::types::PyAnyMethods;

pub struct LazyPyImport {
    module: &'static str,
    names: &'static [&'static str],
    value: pyo3::sync::GILOnceCell<pyo3::PyObject>,
}

impl LazyPyImport {
    pub const fn new(module: &'static str, names: &'static [&'static str]) -> LazyPyImport {
        LazyPyImport {
            module,
            names,
            value: pyo3::sync::GILOnceCell::new(),
        }
    }

    pub fn get<'p>(&'p self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let p = self.value.get_or_try_init(py, || {
            let mut obj = py.import_bound(self.module)?.into_any();
            for name in self.names {
                obj = obj.getattr(*name)?;
            }
            Ok::<_, pyo3::PyErr>(obj.unbind())
        })?;

        Ok(p.clone_ref(py).into_bound(py))
    }
}

pub fn big_byte_slice_to_py_int<'p>(
    py: pyo3::Python<'p>,
    v: &'_ [u8],
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let int_type = py.get_type_bound::<pyo3::types::PyLong>();
    let kwargs = [("signed", true)].into_py_dict_bound(py);
    int_type.call_method(pyo3::intern!(py, "from_bytes"), (v, "big"), Some(&kwargs))
}

pub(crate) fn big_asn1_uint_to_py<'p>(
    py: pyo3::Python<'p>,
    v: asn1::BigUint<'_>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
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
    Ok(pyo3::Bound::new(py, crate::oid::ObjectIdentifier { oid: oid.clone() })?.into_any())
}

pub static DATETIME_DATETIME: LazyPyImport = LazyPyImport::new("datetime", &["datetime"]);
pub static DATETIME_TIMEZONE_UTC: LazyPyImport =
    LazyPyImport::new("datetime", &["timezone", "utc"]);

pub(crate) fn datetime_to_py_utc<'p>(
    py: pyo3::Python<'p>,
    dt: &asn1::DateTime,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let timezone = types::DATETIME_TIMEZONE_UTC.get(py)?;
    types::DATETIME_DATETIME.get(py)?.call1((
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        0,
        timezone,
    ))
}

pub static OTHER_NAME: LazyPyImport = LazyPyImport::new("cryptography.x509", &["OtherName"]);
