#![cfg(feature = "ner")]

use hushid::{shield_text, Glossary, Ner, Session, Vault};

fn model() -> Ner {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("models/person.onnx");
    Ner::load(&path).expect("model")
}

#[test]
fn french_titles_keep_agreement_outside_the_token() {
    let ner = model();
    let feminine = "Mme Tremblay est arrivée.";
    let mut vault = Vault::new();
    let (out, audit) = hushid::shield_text_with(
        &mut vault,
        &Glossary::empty(),
        feminine,
        hushid::Operator::Token,
    )
    .unwrap();
    let _ = ner;
    // The default shield_text_with does not load the model. The session does.
    let mut session = Session::new(Glossary::empty()).with_ner(model());
    let index = session.shield_message(feminine).unwrap();
    let projection = &session.replay()[index].projection;
    assert_eq!(session.audits()[index].glossary, 1, "{projection}");
    assert!(projection.starts_with("Mme h1_glossary_"), "{projection}");
    assert!(projection.ends_with(" est arrivée."), "{projection}");
    assert!(!projection.contains("Tremblay"), "{projection}");
    assert_eq!(session.vault().restore_write(projection).unwrap(), feminine);

    let masculine = "M. Tremblay est arrivé.";
    let index = session.shield_message(masculine).unwrap();
    let projection = &session.replay()[index].projection;
    assert!(projection.starts_with("M. h1_glossary_"), "{projection}");
    assert!(projection.ends_with(" est arrivé."), "{projection}");
    assert!(!projection.contains("Tremblay"), "{projection}");

    let _ = (out, audit);
}

#[test]
fn english_titles_leave_the_rest_of_the_sentence() {
    let mut session = Session::new(Glossary::empty()).with_ner(model());
    for sentence in ["Mrs. Smith has arrived.", "Mr. Smith has arrived."] {
        let index = session.shield_message(sentence).unwrap();
        let projection = &session.replay()[index].projection;
        assert!(projection.contains(" h1_glossary_"), "{projection}");
        assert!(projection.contains(" has arrived."), "{projection}");
        assert!(!projection.contains("Smith"), "{projection}");
        assert_eq!(session.vault().restore_write(projection).unwrap(), sentence);
    }
}

#[test]
fn a_title_before_a_common_noun_stays() {
    let mut session = Session::new(Glossary::empty()).with_ner(model());
    let text = "Mme Table est arrivée.";
    let index = session.shield_message(text).unwrap();
    assert_eq!(session.replay()[index].projection, text);
}

#[test]
fn a_name_without_a_title_stays_when_the_glossary_is_empty() {
    let mut session = Session::new(Glossary::empty()).with_ner(model());
    let text = "Tremblay est arrivée.";
    let index = session.shield_message(text).unwrap();
    assert_eq!(session.replay()[index].projection, text);
    let _ = shield_text;
}
