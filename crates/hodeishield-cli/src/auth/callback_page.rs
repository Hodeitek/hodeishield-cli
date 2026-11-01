// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The pages the loopback listener shows in the browser at the end of a sign-in.
//!
//! Every page is self-contained: one inline stylesheet that follows the system light or dark
//! preference, an inline SVG mark, no script, no font and no other request. The Content Security
//! Policy allows nothing but that stylesheet, by hash. The text comes from fixed tables, in the
//! language of the `Accept-Language` header (English when none matches); nothing from the request
//! is ever written into a page.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

/// What happened, which decides the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    /// The sign-in completed.
    Success,
    /// The user did not grant access in the browser.
    Denied,
    /// The response could not be used (no code, wrong or missing issuer).
    Failed,
    /// The response belongs to another sign-in than the one the CLI started.
    Mismatch,
    /// Any other path on the loopback address.
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Es,
    De,
    Fr,
    It,
    Eu,
}

impl Lang {
    const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Es => "es",
            Self::De => "de",
            Self::Fr => "fr",
            Self::It => "it",
            Self::Eu => "eu",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        let primary = tag.split('-').next()?.to_ascii_lowercase();
        Some(match primary.as_str() {
            "en" => Self::En,
            "es" => Self::Es,
            "de" => Self::De,
            "fr" => Self::Fr,
            "it" => Self::It,
            "eu" => Self::Eu,
            _ => return None,
        })
    }

    /// The best supported language of an `Accept-Language` value: the highest `q`, the first listed
    /// among equals. English when none is supported or the value is malformed.
    pub fn negotiate(header: Option<&str>) -> Self {
        let mut best: Option<(u32, Self)> = None;
        for item in header.unwrap_or("").split(',').take(32) {
            let mut parts = item.split(';');
            let tag = parts.next().unwrap_or("").trim();
            let weight = parts
                .find_map(|p| p.trim().strip_prefix("q="))
                .map_or(Some(1000), parse_weight);
            let (Some(weight), Some(lang)) = (weight, Self::from_tag(tag)) else {
                continue;
            };
            if weight > 0 && best.is_none_or(|(w, _)| weight > w) {
                best = Some((weight, lang));
            }
        }
        best.map_or(Self::En, |(_, lang)| lang)
    }
}

/// A `q` value in thousandths (`0.8` is 800); `None` when it is not a number from 0 to 1.
fn parse_weight(text: &str) -> Option<u32> {
    let value: f32 = text.trim().parse().ok()?;
    (0.0..=1.0)
        .contains(&value)
        .then(|| (value * 1000.0).round() as u32)
}

struct Text {
    title: &'static str,
    body: &'static str,
    /// What to do next; the command is shown apart, in the page.
    next: &'static str,
}

const fn t(title: &'static str, body: &'static str, next: &'static str) -> Text {
    Text { title, body, next }
}

#[allow(clippy::too_many_lines)]
fn text(page: Page, lang: Lang) -> Text {
    use Lang::{De, En, Es, Eu, Fr, It};
    match (page, lang) {
        (Page::Success, En) => t(
            "You are signed in",
            "The CLI is now signed in to HodeiShield.",
            "You can close this window and return to the terminal.",
        ),
        (Page::Success, Es) => t(
            "Sesión iniciada",
            "La CLI ya ha iniciado sesión en HodeiShield.",
            "Puedes cerrar esta ventana y volver al terminal.",
        ),
        (Page::Success, De) => t(
            "Anmeldung abgeschlossen",
            "Die CLI ist jetzt bei HodeiShield angemeldet.",
            "Sie können dieses Fenster schließen und zum Terminal zurückkehren.",
        ),
        (Page::Success, Fr) => t(
            "Connexion réussie",
            "La CLI est maintenant connectée à HodeiShield.",
            "Vous pouvez fermer cette fenêtre et revenir au terminal.",
        ),
        (Page::Success, It) => t(
            "Accesso eseguito",
            "La CLI ha effettuato l'accesso a HodeiShield.",
            "Puoi chiudere questa finestra e tornare al terminale.",
        ),
        (Page::Success, Eu) => t(
            "Saioa hasi da",
            "CLIa HodeiShield-en saioa hasi du.",
            "Leiho hau itxi eta terminalera itzul zaitezke.",
        ),
        (Page::Denied, En) => t(
            "Sign-in cancelled",
            "Access was not granted, so the CLI is not signed in.",
            "You can close this window. To try again, run:",
        ),
        (Page::Denied, Es) => t(
            "Inicio de sesión cancelado",
            "No se concedió el acceso, así que la CLI no ha iniciado sesión.",
            "Puedes cerrar esta ventana. Para volver a intentarlo, ejecuta:",
        ),
        (Page::Denied, De) => t(
            "Anmeldung abgebrochen",
            "Der Zugriff wurde nicht erteilt, die CLI ist daher nicht angemeldet.",
            "Sie können dieses Fenster schließen. Für einen neuen Versuch führen Sie aus:",
        ),
        (Page::Denied, Fr) => t(
            "Connexion annulée",
            "L'accès n'a pas été accordé, la CLI n'est donc pas connectée.",
            "Vous pouvez fermer cette fenêtre. Pour réessayer, exécutez :",
        ),
        (Page::Denied, It) => t(
            "Accesso annullato",
            "L'accesso non è stato concesso, quindi la CLI non ha effettuato l'accesso.",
            "Puoi chiudere questa finestra. Per riprovare, esegui:",
        ),
        (Page::Denied, Eu) => t(
            "Saioa hasteko eskaera bertan behera utzi da",
            "Sarbidea ez da eman, beraz CLIa ez da saioa hasi.",
            "Leiho hau itxi dezakezu. Berriro saiatzeko, exekutatu:",
        ),
        (Page::Failed, En) => t(
            "Sign-in did not complete",
            "The response from the sign-in could not be used.",
            "You can close this window. To try again, run:",
        ),
        (Page::Failed, Es) => t(
            "El inicio de sesión no se completó",
            "No se pudo usar la respuesta del inicio de sesión.",
            "Puedes cerrar esta ventana. Para volver a intentarlo, ejecuta:",
        ),
        (Page::Failed, De) => t(
            "Anmeldung nicht abgeschlossen",
            "Die Antwort der Anmeldung konnte nicht verwendet werden.",
            "Sie können dieses Fenster schließen. Für einen neuen Versuch führen Sie aus:",
        ),
        (Page::Failed, Fr) => t(
            "La connexion n'a pas abouti",
            "La réponse de la connexion n'a pas pu être utilisée.",
            "Vous pouvez fermer cette fenêtre. Pour réessayer, exécutez :",
        ),
        (Page::Failed, It) => t(
            "Accesso non completato",
            "La risposta dell'accesso non ha potuto essere utilizzata.",
            "Puoi chiudere questa finestra. Per riprovare, esegui:",
        ),
        (Page::Failed, Eu) => t(
            "Saioa hastea ez da osatu",
            "Saioa hasteko erantzuna ezin izan da erabili.",
            "Leiho hau itxi dezakezu. Berriro saiatzeko, exekutatu:",
        ),
        (Page::Mismatch, En) => t(
            "This is not the current sign-in",
            "This page belongs to an earlier or different sign-in than the one the CLI started.",
            "Close this window. If you are not signed in yet, run:",
        ),
        (Page::Mismatch, Es) => t(
            "No es el inicio de sesión actual",
            "Esta página pertenece a un inicio de sesión anterior o distinto del que inició la CLI.",
            "Cierra esta ventana. Si aún no has iniciado sesión, ejecuta:",
        ),
        (Page::Mismatch, De) => t(
            "Nicht die aktuelle Anmeldung",
            "Diese Seite gehört zu einer früheren oder anderen Anmeldung als der, die die CLI gestartet hat.",
            "Schließen Sie dieses Fenster. Falls Sie noch nicht angemeldet sind, führen Sie aus:",
        ),
        (Page::Mismatch, Fr) => t(
            "Ce n'est pas la connexion en cours",
            "Cette page correspond à une connexion antérieure ou différente de celle lancée par la CLI.",
            "Fermez cette fenêtre. Si vous n'êtes pas encore connecté, exécutez :",
        ),
        (Page::Mismatch, It) => t(
            "Non è l'accesso in corso",
            "Questa pagina appartiene a un accesso precedente o diverso da quello avviato dalla CLI.",
            "Chiudi questa finestra. Se non hai ancora effettuato l'accesso, esegui:",
        ),
        (Page::Mismatch, Eu) => t(
            "Hau ez da uneko saio-hasiera",
            "Orri hau CLIak hasitakoaren aurreko edo beste saio-hasiera batena da.",
            "Itxi leiho hau. Oraindik saioa hasi ez baduzu, exekutatu:",
        ),
        (Page::NotFound, En) => t(
            "Page not found",
            "Nothing is served at this address.",
            "You can close this window.",
        ),
        (Page::NotFound, Es) => t(
            "Página no encontrada",
            "No hay nada en esta dirección.",
            "Puedes cerrar esta ventana.",
        ),
        (Page::NotFound, De) => t(
            "Seite nicht gefunden",
            "Unter dieser Adresse wird nichts angeboten.",
            "Sie können dieses Fenster schließen.",
        ),
        (Page::NotFound, Fr) => t(
            "Page introuvable",
            "Rien n'est servi à cette adresse.",
            "Vous pouvez fermer cette fenêtre.",
        ),
        (Page::NotFound, It) => t(
            "Pagina non trovata",
            "Non c'è nulla a questo indirizzo.",
            "Puoi chiudere questa finestra.",
        ),
        (Page::NotFound, Eu) => t(
            "Ez da orria aurkitu",
            "Ez dago ezer helbide honetan.",
            "Leiho hau itxi dezakezu.",
        ),
    }
}

/// The one stylesheet, shared by every page. Colours follow the product's dark navy and violet,
/// with a light variant of enough contrast for text (at least 4.5:1).
const STYLE: &str = "\
:root{color-scheme:light dark;--bg:#f8fafc;--card:#fff;--fg:#0f172a;--muted:#475569;\
--line:#cbd5e1;--accent:#5b3fd6;--ok:#15803d;--bad:#b91c1c;--code:#eef2f7}\
@media (prefers-color-scheme:dark){:root{--bg:#0e1220;--card:#141b2e;--fg:#e8edf8;\
--muted:#a9b4cc;--line:#1e2d45;--accent:#a791fa;--ok:#4ade80;--bad:#f87171;--code:#0e1220}}\
*{box-sizing:border-box}\
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1rem;\
background:var(--bg);color:var(--fg);\
font:16px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}\
main{width:100%;max-width:28rem;background:var(--card);border:1px solid var(--line);\
border-radius:.75rem;padding:2rem 1.5rem;text-align:center}\
.mark{width:2.5rem;height:2.5rem;color:var(--accent)}\
.state{width:2rem;height:2rem;margin:1.25rem auto 0}\
.ok{color:var(--ok)}.bad{color:var(--bad)}.neutral{color:var(--muted)}\
h1{margin:.75rem 0 .5rem;font-size:1.375rem;line-height:1.25;text-wrap:balance}\
p{margin:0 0 .75rem;color:var(--muted);text-wrap:pretty}\
p.lead{color:var(--fg)}\
code{display:inline-block;padding:.25rem .625rem;border:1px solid var(--line);\
border-radius:.375rem;background:var(--code);color:var(--fg);\
font:.9375rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}\
footer{margin-top:1.25rem;font-size:.8125rem;color:var(--muted)}";

const MARK: &str = "<svg class=\"mark\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" \
stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\" \
focusable=\"false\"><path d=\"M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6z\"/></svg>";

/// The status icon: a tick for success, a cross for a failure, a dash for the rest.
fn state_icon(page: Page) -> &'static str {
    match page {
        Page::Success => {
            "<svg class=\"state ok\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" \
             stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\" \
             focusable=\"false\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"m8 12.5 3 3 5-6\"/></svg>"
        }
        Page::Denied | Page::Failed | Page::Mismatch => {
            "<svg class=\"state bad\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" \
             stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\" \
             focusable=\"false\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"m9 9 6 6m0-6-6 6\"/></svg>"
        }
        Page::NotFound => {
            "<svg class=\"state neutral\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" \
             stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\" \
             focusable=\"false\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8.5 12h7\"/></svg>"
        }
    }
}

/// Whether the page tells the user to run `login` again.
const fn offers_login(page: Page) -> bool {
    matches!(page, Page::Denied | Page::Failed | Page::Mismatch)
}

/// The HTTP status of a page.
pub const fn status(page: Page) -> &'static str {
    match page {
        Page::Success | Page::Denied => "200 OK",
        Page::Failed | Page::Mismatch => "400 Bad Request",
        Page::NotFound => "404 Not Found",
    }
}

/// The Content Security Policy: nothing is allowed but the page's own stylesheet, by hash.
pub fn content_security_policy() -> String {
    let hash = STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
    format!(
        "default-src 'none'; style-src 'sha256-{hash}'; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'"
    )
}

/// The HTML of a page in a language.
pub fn render(page: Page, lang: Lang) -> String {
    let Text { title, body, next } = text(page, lang);
    let command = if offers_login(page) {
        "<p><code>hodeishield login</code></p>"
    } else {
        ""
    };
    format!(
        "<!doctype html><html lang=\"{code}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light dark\">\
         <title>{title} - HodeiShield</title><style>{STYLE}</style></head>\
         <body><main>{MARK}{icon}<h1>{title}</h1><p class=\"lead\">{body}</p><p>{next}</p>{command}\
         <footer>HodeiShield CLI</footer></main></body></html>",
        code = lang.code(),
        icon = state_icon(page),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGES: [Page; 5] = [
        Page::Success,
        Page::Denied,
        Page::Failed,
        Page::Mismatch,
        Page::NotFound,
    ];
    const LANGS: [Lang; 6] = [Lang::En, Lang::Es, Lang::De, Lang::Fr, Lang::It, Lang::Eu];

    #[test]
    fn the_language_follows_accept_language_with_english_as_the_fallback() {
        let pick = |h: Option<&str>| Lang::negotiate(h);
        assert_eq!(pick(None), Lang::En);
        assert_eq!(pick(Some("")), Lang::En);
        assert_eq!(pick(Some("ja, zh;q=0.8")), Lang::En);
        assert_eq!(pick(Some("es-ES,es;q=0.9,en;q=0.8")), Lang::Es);
        assert_eq!(pick(Some("de-AT")), Lang::De);
        assert_eq!(pick(Some("en;q=0.5, fr;q=0.9")), Lang::Fr);
        assert_eq!(pick(Some("EU")), Lang::Eu);
        assert_eq!(pick(Some("it;q=0, fr;q=0.1")), Lang::Fr);
        assert_eq!(pick(Some("es;q=abc, de")), Lang::De);
        assert_eq!(pick(Some(";;;,,,q=")), Lang::En);
    }

    #[test]
    fn every_page_in_every_language_is_complete_and_accessible() {
        for page in PAGES {
            for lang in LANGS {
                let html = render(page, lang);
                assert!(html.starts_with("<!doctype html>"), "{page:?} {lang:?}");
                assert!(
                    html.contains(&format!("<html lang=\"{}\">", lang.code())),
                    "{page:?} {lang:?}"
                );
                assert_eq!(html.matches("<h1>").count(), 1, "{page:?} {lang:?}");
                assert_eq!(html.matches("<main>").count(), 1);
                assert!(html.contains("prefers-color-scheme:dark"));
                assert!(html.contains("name=\"viewport\""));
                assert_eq!(html.matches("<style>").count(), 1);
                assert_eq!(
                    html.contains("hodeishield login"),
                    offers_login(page),
                    "{page:?} {lang:?}"
                );
            }
        }
    }

    #[test]
    fn the_pages_differ_by_language() {
        for page in PAGES {
            let all: Vec<_> = LANGS.iter().map(|l| render(page, *l)).collect();
            for (i, a) in all.iter().enumerate() {
                for b in &all[i + 1..] {
                    assert_ne!(a, b, "{page:?}");
                }
            }
        }
        assert!(render(Page::Success, Lang::En).contains("close this window"));
        assert!(render(Page::Success, Lang::Es).contains("cerrar esta ventana"));
    }

    #[test]
    fn a_page_loads_nothing_from_the_network_and_runs_no_script() {
        for page in PAGES {
            for lang in LANGS {
                let html = render(page, lang);
                for forbidden in [
                    "<script", "<link", "<img", "<iframe", "src=", "href=", "@import", "url(",
                    "http://", "https://", " onclick", " onload",
                ] {
                    assert!(
                        !html.contains(forbidden),
                        "{forbidden} in {page:?} {lang:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_policy_allows_only_the_stylesheet_by_hash() {
        let csp = content_security_policy();
        assert!(
            csp.starts_with("default-src 'none'; style-src 'sha256-"),
            "{csp}"
        );
        assert!(!csp.contains("unsafe"), "{csp}");
        assert!(!csp.contains("script-src"), "{csp}");
        let hash = STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
        assert!(csp.contains(&hash));
    }

    #[test]
    fn statuses_match_the_outcome() {
        assert_eq!(status(Page::Success), "200 OK");
        assert_eq!(status(Page::Denied), "200 OK");
        assert_eq!(status(Page::Failed), "400 Bad Request");
        assert_eq!(status(Page::Mismatch), "400 Bad Request");
        assert_eq!(status(Page::NotFound), "404 Not Found");
    }
}
