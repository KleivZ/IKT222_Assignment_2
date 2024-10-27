## IKT222 Assignment 2: Blogg med XSS-sårbarhet

Dette repository inneholder en enkel blogg-applikasjon utviklet for IKT222 Software Security ved NTNU. Applikasjonen er designet for å demonstrere en bevisst Cross-Site Scripting (XSS) sårbarhet, og illustrerer dermed viktige sikkerhetsprinsipper i webapplikasjoner.

### Funksjonalitet

  * Hjemmeside med blogginnlegg og kommentarfelt.
  * Om meg-side.
  * Kontakt-side med kontaktskjema.
  * Styling med Bootstrap for et responsivt og moderne design.
  * XSS-sårbarhet i kommentarfeltet (for demonstrasjonsformål).
  * Bruk av Jinja2 templates for effektiv kodeorganisering.
  * Docker-basert deployment for enkel kjøring og distribusjon.

### Teknologier

  * **Backend:** Flask (Python web framework)
  * **Frontend:** HTML, CSS, JavaScript
  * **Templating:** Jinja2
  * **Containerization:** Docker

### Kjøring

1.  **Forutsetninger:**

      * Installer Docker Desktop: [https://www.docker.com/products/docker-desktop/](https://www.google.com/url?sa=E&source=gmail&q=https://www.google.com/url?sa=E%26source=gmail%26q=https://www.google.com/url?sa=E%26source=gmail%26q=https://www.google.com/url?sa=E%26source=gmail%26q=https://www.docker.com/products/docker-desktop/)

2.  **Last ned Docker-imaget:**

    ```bash
    docker pull ghcr.io/kleivz/blogg:latest
    ```

3.  **Kjør applikasjonen:**

    ```bash
    docker run -p 5000:5000 ghcr.io/kleivz/blogg:latest
    ```

4.  **Åpne i nettleseren:**  `http://localhost:5000`

### XSS-sårbarhet

En XSS-sårbarhet er bevisst introdusert i kommentarfeltet på  `index.html`.  Dette er implementert ved å bruke  `{{ comment | safe }}`  for å gjengi kommentarer, som eksplisitt instruerer Jinja2  *ikke*  å escape HTML-koden.

**Sikkerhetsrisiko:**

Denne sårbarheten  åpner  for  potensielle  XSS-angrep,  hvor  en  angriper  kan  injisere  ondsinnet  JavaScript-kode  som  kjøres  i  nettleseren  til  andre  brukere.  Dette  kan  føre  til  alvorlige  konsekvenser,  som  tyveri  av  informasjonskapsler,  kapring  av  økter  eller  manipulering  av  sidens  innhold.

**Eksempel på ondsinnet kode:**

```javascript
<script>alert('XSS!')</script>
```

### Sikkerhetsanbefalinger

I  en  produksjonsklar  webapplikasjon  er  det  essensielt  å  implementere  følgende  sikkerhetstiltak  for  å  forhindre  XSS-angrep:

  * **Escaping:**  Bruk  Jinja2's  `escape`-funksjon  (eller  tilsvarende  i  andre  templating-språk)  til  å  escape  HTML-spesialtegn  i  brukerinput.
  * **Inputvalidering:**  Valider  brukerinput  både  på  klient-  og  serversiden  for  å  sikre  at  den  ikke  inneholder  ulovlige  tegn  eller  strukturer.
  * **Content  Security  Policy  (CSP):**  Implementer  CSP-regler  for  å  begrense  hvilke  skript  som  kan  kjøres  på  siden.

### Bidra

Hvis du finner feil eller har forslag til forbedringer, er du velkommen til å opprette en issue eller pull request på GitHub.
