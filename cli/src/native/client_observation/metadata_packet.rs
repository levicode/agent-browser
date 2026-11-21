//! Lossless dictionaries local to one isolated-realm reply. Occurrences keep
//! their exact coordinates and folded text. Only identical metadata is shared.
use super::*;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    templates: Vec<Value>,
    attributes: Vec<Value>,
    rows: Vec<WireRow>,
}

pub(super) type Shape = (usize, Option<usize>);

pub(super) struct Row {
    pub facts: Arc<Value>,
    pub shape: Option<Shape>,
    pub rect: Option<Rect>,
    pub folded: Option<Vec<Fold>>,
}

pub(super) enum Fold {
    Text {
        visible: bool,
        secure: bool,
        text: String,
    },
    Complete(Value),
}

impl Fold {
    /// The ordinary full-row shape for direct reads or their equivalence tests.
    pub(super) fn full(&self) -> std::borrow::Cow<'_, Value> {
        match self {
            Self::Complete(value) => std::borrow::Cow::Borrowed(value),
            Self::Text {
                visible,
                secure,
                text,
            } => std::borrow::Cow::Owned(json!({
                "author":{"nodeType":3,"visible":visible,"text":text},"attributes":{},"labels":[],
                "states":{"secure":secure,"hidden":false,"focused":false,"disabled":false},
                "safePublicNameFromContent":false,"redactName":secure,"inputPurpose":if *secure {"generic-secret"}else{"none"}
            })),
        }
    }
}

pub(super) fn plain(value: Value) -> Result<Row, ObservationError> {
    let rect = serde_json::from_value(value["rect"].clone())
        .map_err(|_| ObservationError::BackendFailure)?;
    let folded = value
        .get("__nativeFolded")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().cloned().map(Fold::Complete).collect());
    Ok(Row {
        facts: Arc::new(value),
        shape: None,
        rect,
        folded,
    })
}

pub(super) fn decode(encoded: &str, count: usize) -> Result<Vec<Row>, ObservationError> {
    let packet: Packet =
        serde_json::from_str(encoded).map_err(|_| ObservationError::BackendFailure)?;
    if packet.rows.len() != count {
        return Err(ObservationError::BackendFailure);
    }
    let mut facts = HashMap::<Shape, Arc<Value>>::new();
    packet
        .rows
        .into_iter()
        .map(|record| decode_row(record, &packet.templates, &packet.attributes, &mut facts))
        .collect()
}

/// Use the signed tag to decode coordinates and text directly. In particular,
/// a rectangle needs no temporary vector of four JSON numbers.
enum WireRow {
    Text(Fold),
    Entry {
        template: usize,
        attribute: Option<usize>,
        rect: Option<[f64; 4]>,
        children: Option<Vec<WireRow>>,
    },
}

impl<'de> Deserialize<'de> for WireRow {
    fn deserialize<D: serde::Deserializer<'de>>(source: D) -> Result<Self, D::Error> {
        use serde::de::{Error, IgnoredAny, SeqAccess, Visitor};
        struct Read;
        impl<'de> Visitor<'de> for Read {
            type Value = WireRow;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a metadata row")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut row: A) -> Result<WireRow, A::Error> {
                let invalid = || A::Error::custom("invalid metadata row");
                let tag = row.next_element::<i64>()?.ok_or_else(invalid)?;
                let decoded = if (-4..=-1).contains(&tag) {
                    let flags = -1 - tag;
                    let secure = flags & 2 != 0;
                    let visible = flags & 1 != 0;
                    let text = row.next_element::<String>()?.ok_or_else(invalid)?;
                    if secure && (visible || !text.is_empty()) {
                        return Err(invalid());
                    }
                    WireRow::Text(Fold::Text {
                        visible,
                        secure,
                        text,
                    })
                } else {
                    WireRow::Entry {
                        template: usize::try_from(tag).map_err(|_| invalid())?,
                        attribute: row.next_element::<Option<usize>>()?.flatten(),
                        rect: row.next_element::<Option<[f64; 4]>>()?.flatten(),
                        children: row.next_element::<Vec<WireRow>>()?,
                    }
                };
                if row.next_element::<IgnoredAny>()?.is_some() {
                    return Err(invalid());
                }
                Ok(decoded)
            }
        }
        source.deserialize_seq(Read)
    }
}

fn decode_row(
    record: WireRow,
    templates: &[Value],
    attributes: &[Value],
    cache: &mut HashMap<Shape, Arc<Value>>,
) -> Result<Row, ObservationError> {
    let (template, attribute, rect, children) = match record {
        WireRow::Text(text) => return plain(text.full().into_owned()),
        WireRow::Entry {
            template,
            attribute,
            rect,
            children,
        } => (template, attribute, rect, children),
    };
    let invalid = ObservationError::BackendFailure;
    let shape = (template, attribute);
    let facts = match cache.entry(shape) {
        std::collections::hash_map::Entry::Occupied(entry) => Arc::clone(entry.get()),
        std::collections::hash_map::Entry::Vacant(entry) => {
            let mut facts = templates
                .get(template)
                .and_then(Value::as_object)
                .ok_or(invalid.clone())?
                .clone();
            if let Some(id) = attribute {
                let attrs = attributes
                    .get(id)
                    .filter(|v| v.is_object())
                    .ok_or(invalid.clone())?;
                facts.insert("attributes".into(), attrs.clone());
            }
            Arc::clone(entry.insert(Arc::new(Value::Object(facts))))
        }
    };
    let rect = match rect {
        Some([x, y, width, height]) => Some(Rect {
            x,
            y,
            width,
            height,
        }),
        None => serde_json::from_value(facts["rect"].clone()).map_err(|_| invalid.clone())?,
    };
    let folded = if let Some(children) = children {
        Some(
            children
                .into_iter()
                .map(|child| match child {
                    WireRow::Text(text) => Ok(text),
                    WireRow::Entry {
                        children: Some(_), ..
                    } => Err(ObservationError::BackendFailure),
                    other => {
                        let row = decode_row(other, templates, attributes, cache)?;
                        let mut value = (*row.facts).clone();
                        if let Some(rect) = row.rect {
                            value["rect"] = json!(rect);
                        }
                        Ok(Fold::Complete(value))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
    } else {
        facts
            .get("__nativeFolded")
            .and_then(Value::as_array)
            .map(|rows| rows.iter().cloned().map(Fold::Complete).collect())
    };
    Ok(Row {
        facts,
        shape: Some(shape),
        rect,
        folded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_facts_share_only_metadata_not_coordinates_or_folded_text() {
        let encoded = json!({"templates":[{"author":{"nodeType":1},"states":{"checked":false}}],
            "attributes":[{"class":"sample"}],
            "rows":[[0,0,[1.25,2.5,3.75,4.0],[[-2,"one"]]],[0,0,[5.0,6.0,7.0,8.0],[[-3,""]]]]});
        let rows = decode(&encoded.to_string(), 2).unwrap();
        assert!(Arc::ptr_eq(&rows[0].facts, &rows[1].facts));
        assert_eq!(rows[0].facts["states"]["checked"], false);
        assert!(rows[0].facts["states"].get("disabled").is_none());
        assert_eq!(rows[0].rect.as_ref().unwrap().x, 1.25);
        assert_eq!(rows[1].rect.as_ref().unwrap().x, 5.0);
        assert!(
            matches!(&rows[0].folded.as_ref().unwrap()[0],Fold::Text{secure:false,visible:true,text} if text=="one")
        );
        assert!(
            matches!(&rows[1].folded.as_ref().unwrap()[0],Fold::Text{secure:true,visible:false,text} if text.is_empty())
        );
    }

    #[test]
    fn malformed_dictionaries_or_protected_text_do_not_publish_partial_rows() {
        for row in [
            json!([]),
            json!([1]),
            json!([0, 1]),
            json!([0, 0, [0, 1, 2]]),
            json!([0, 0, null, [[-3, "private"]]]),
            json!([0, 0, null, [[-4, ""]]]),
        ] {
            let packet = json!({"templates":[{}],"attributes":[{}],"rows":[row]}).to_string();
            assert!(matches!(
                decode(&packet, 1),
                Err(ObservationError::BackendFailure)
            ));
        }
    }
}
