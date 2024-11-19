use pyo3::types::IntoPyDict;
use pyo3::types::{PyAnyMethods, PyListMethods};

fn parse_name_attribute<'p>(
    py: pyo3::Python<'p>,
    attribute: cryptography_x509::common::AttributeTypeValue<'_>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let oid = crate::util::oid_to_py_oid(py, &attribute.type_id)?;
    let tag_val = attribute.value.tag().as_u8().ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(
            "Long-form tags are not supported in NameAttribute values",
        )
    })?;
    let py_tag = crate::util::ASN1_TYPE_TO_ENUM.get(py)?.get_item(tag_val)?;
    let py_data = match attribute.value.tag().as_u8() {
        // BitString tag value
        Some(3) => pyo3::types::PyBytes::new(py, attribute.value.data()).into_any(),
        // BMPString tag value
        Some(30) => {
            let py_bytes = pyo3::types::PyBytes::new(py, attribute.value.data());
            py_bytes.call_method1(pyo3::intern!(py, "decode"), ("utf_16_be",))?
        }
        // UniversalString
        Some(28) => {
            let py_bytes = pyo3::types::PyBytes::new(py, attribute.value.data());
            py_bytes.call_method1(pyo3::intern!(py, "decode"), ("utf_32_be",))?
        }
        _ => {
            let parsed = std::str::from_utf8(attribute.value.data())
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("Parsing error in ASN1"))?;
            pyo3::types::PyString::new(py, parsed).into_any()
        }
    };
    let kwargs = [(pyo3::intern!(py, "_validate"), false)].into_py_dict(py)?;
        //.map_err(|_| pyo3::exceptions::PyValueError::new_err("Unable to parse argument"))?;
    let o = crate::util::NAME_ATTRIBUTE.get(py)?;
    Ok(o.call((oid, py_data, py_tag), Some(&kwargs))?)
}

pub(crate) fn parse_rdn<'a>(
    py: pyo3::Python<'a>,
    rdn: &asn1::SetOf<'a, cryptography_x509::common::AttributeTypeValue<'a>>,
) -> pyo3::PyResult<pyo3::Bound<'a, pyo3::PyAny>> {
    let py_attrs = pyo3::types::PyList::empty(py);
    for attribute in rdn.clone() {
        let na = parse_name_attribute(py, attribute)?;
        py_attrs.append(na)?;
    }
    Ok(crate::util::RELATIVE_DISTINGUISHED_NAME
        .get(py)?
        .call1((py_attrs,))?)
}

pub(crate) fn parse_name<'p>(
    py: pyo3::Python<'p>,
    name: &cryptography_x509::name::NameReadable<'_>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let py_rdns = pyo3::types::PyList::empty(py);
    for rdn in name.clone() {
        let py_rdn = parse_rdn(py, &rdn)?;
        py_rdns.append(py_rdn)?;
    }
    Ok(crate::util::NAME.get(py)?.call1((py_rdns,))?)
}

pub(crate) fn parse_general_name(
    py: pyo3::Python<'_>,
    gn: &cryptography_x509::name::GeneralName<'_>,
) -> pyo3::PyResult<pyo3::PyObject> {
    let py_gn = match gn {
        cryptography_x509::name::GeneralName::OtherName(data) => {
            let oid = crate::util::oid_to_py_oid(py, &data.type_id)?;
            crate::util::OTHER_NAME
                .get(py)?
                .call1((oid, data.value.full_data()))?
                .into()
        }
        cryptography_x509::name::GeneralName::DirectoryName(data) => {
            let py_name = parse_name(py, data.unwrap_read())?;
            crate::util::DIRECTORY_NAME
                .get(py)?
                .call1((py_name,))?
                .into()
        }
        _ => return Err(pyo3::exceptions::PyValueError::new_err("Unknown name form")),
    };
    Ok(py_gn)
}
