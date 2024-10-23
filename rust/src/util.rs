use rand::Rng;

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

pub static OBJECT_IDENTIFIER: LazyPyImport =
    LazyPyImport::new("cryptography.x509.oid", &["ObjectIdentifier"]);

pub(crate) fn oid_to_py_oid<'p>(
    py: pyo3::Python<'p>,
    oid: &asn1::ObjectIdentifier,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    //Ok(pyo3::Bound::new(py, crate::oid::ObjectIdentifier { oid: oid.clone() })?.into_any())
    let oid_object = OBJECT_IDENTIFIER.get(py)?;
    oid_object.call1((oid.to_string(),))
}

pub static DATETIME_DATETIME: LazyPyImport = LazyPyImport::new("datetime", &["datetime"]);
pub static DATETIME_TIMEZONE_UTC: LazyPyImport =
    LazyPyImport::new("datetime", &["timezone", "utc"]);

pub(crate) fn datetime_to_py_utc<'p>(
    py: pyo3::Python<'p>,
    dt: &asn1::DateTime,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let timezone = DATETIME_TIMEZONE_UTC.get(py)?;
    DATETIME_DATETIME.get(py)?.call1((
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
pub static ASN1_TYPE_TO_ENUM: LazyPyImport =
    LazyPyImport::new("cryptography.x509.name", &["_ASN1_TYPE_TO_ENUM"]);
pub static NAME_ATTRIBUTE: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["NameAttribute"]);
pub static RELATIVE_DISTINGUISHED_NAME: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["RelativeDistinguishedName"]);
pub static NAME: LazyPyImport = LazyPyImport::new("cryptography.x509", &["Name"]);
pub static DIRECTORY_NAME: LazyPyImport =
    LazyPyImport::new("cryptography.x509", &["DirectoryName"]);

pub fn generate_random_bytes_for_asn1_biguint() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let nonce_random: u64 = rng.gen_range(0..u64::MAX);
    let nonce_bytes = nonce_random.to_be_bytes();

    // Remove leading 0
    let first_non_zero = nonce_bytes
        .iter()
        .position(|&x| x != 0)
        .unwrap_or(nonce_bytes.len() - 1);
    let result = &nonce_bytes[first_non_zero..];

    // Finally, verify that the encoding is minimal
    if result[0] & 0x80 == 0x80 {
        [&[0], &result[..]].concat()
    } else {
        result.to_vec()
    }
}

mod tests {
    use super::generate_random_bytes_for_asn1_biguint;

    #[test]
    fn test_generate_random_bytes_for_asn1_biguint() {
        for _ in 0..0xffff {
            let bytes = generate_random_bytes_for_asn1_biguint();
            asn1::BigUint::new(&bytes);
        }
    }
}
