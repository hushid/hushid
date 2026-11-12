use hushid::{shield_text, Glossary, Vault};

#[test]
fn a_french_title_stays_when_the_name_model_is_not_built() {
    let text = "Mme Tremblay est arrivée.";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &Glossary::empty(), text).unwrap();
    assert_eq!(out, text);
    assert_eq!(audit.glossary, 0);
}
