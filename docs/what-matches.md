# What matches

A detector runs on the text you pass in. A value with no recognized shape is left unchanged. That includes a city, a diagnosis, an account number with no recognized shape, a person who is not in the loaded glossary, and text inside an image or a PDF.

A cue has to sit within 40 characters of the value, unless the row below says the shape is enough on its own.

| Kind | Matches | Stays as written |
|---|---|---|
| Email | `ada@example.com` | A word with no `@` |
| Phone | A number with separators, such as `415-555-0134`. A real `+44` number includes the plus. | The same digits with no separator. A `+` that only marks an added diff line. |
| Payment card | A grouped number that passes the check digit, such as `4111-1111-1111-1111`. The groups may be split by a space, a dot, a hyphen, a comma, or a slash. | A number that fails the check digit. A 13 to 19 digit run with no separator, unless a word such as `card` or `visa` is nearby. |
| SIN | Nine digits, or three groups of three, that pass the check digit and sit next to a cue such as `social insurance` or `numéro d'assurance sociale`. | The same digits with no cue, or a number that fails the check digit. A slash is not a separator. |
| RAMQ | Four letters and eight digits in the published layout, such as `BOUF 9451 1419`. A hyphen between the groups is the same number. The month is 01 through 12 or 51 through 62. The day is 01 through 31. | A month or a day outside that range. These checks do not ask whether the number was issued. |
| Postal code | A Canadian postal code next to `postal code`, `code postal`, or a street address in the same 40-character window. | A bare `A1A 1A1`. |
| Address | A civic number and a street type, such as `123 rue Saint-Denis`. | A city name on its own. |
| Birth date | A real calendar date within 40 characters of a cue such as `date of birth`, `DOB`, `née le`, or `born`. `born` counts only inside the same sentence. | A date with no cue. A day that month does not have. |
| Name | A spelling in the glossary the host loaded, including that spelling with the accents removed. | A person who is not in that list. A different accent does not match. `Glossary::empty()` matches no names. The file `glossary/popular-names.txt` is not loaded on its own. A UTF-8 BOM at the start of a line is ignored. |
| Secret | A recognized secret shape. The replacement is `h1_secret`, and the value is not stored. | A secret shape this crate does not recognize. |

The optional `ner` feature is off unless the host turns it on. `shield_text` does not use it.
