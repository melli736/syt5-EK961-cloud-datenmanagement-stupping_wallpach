# EK961 Middleware Engineering "Cloud-Datenmanagement"
**Autor:** Stuppnig 5DHIT, Wallpach 5BHIT
## Einführung
Diese Übung zeigt die Anwendung von verteilten Webservices an einer simplen Anforderung.

**Ziele:**
Das Ziel dieser Übung ist eine Webanbindung zur Benutzeranmeldung umzusetzen. Dabei soll sich ein Benutzer registrieren und am System anmelden können.
Die Kommunikation zwischen Client und Service soll mit Hilfe einer REST Schnittstelle umgesetzt werden.


## Sicherheitsüberlegungen
Bei der Entwicklung einer REST-Schnittstelle ist es wichtig, häufige Angriffsvektoren zu berücksichtigen, um die Sicherheit zu gewährleisten. Zu den gängigsten Angriffsvektoren gehören:

### 1. **SQL-Injection**  
   Angreifer versuchen, schadhafter SQL-Code in Eingabefelder einzufügen, um unberechtigt auf die Datenbank zuzugreifen. Dies kann durch unsichere API-Endpunkte oder Datenbankabfragen passieren.

### 2. **Cross-Site Scripting (XSS)**  
   Schadcode wird in die API-Daten eingefügt, der dann im Browser des Benutzers ausgeführt wird, um Informationen zu stehlen oder die Benutzerinteraktionen zu manipulieren.
<div style="page-break-after: always;"></div>

### 3. **Cross-Site Request Forgery (CSRF)**  
   Ein Angreifer kann eine unautorisierte Anfrage an eine API senden, während ein eingeloggter Benutzer aktiv ist, und somit dessen Rechte missbrauchen.

### 4. **Man-in-the-Middle (MITM) Angriffe**  
   Bei unsicherer Übertragung können Angreifer Daten während der Übertragung abfangen und manipulieren.

### 5. **Brute-Force-Angriffe**  
   Angreifer versuchen, durch Ausprobieren vieler Passwörter oder Authentifizierungstoken Zugriff zu erhalten.

### 6. **Insecure Deserialization**  
   Wenn Objekte oder Daten auf unsichere Weise deserialisiert werden, können Angreifer das System manipulieren, um schadhafter Code ausgeführt zu bekommen.

### Trennung von Registrierung, Login und Datenhaltung:
Es ist eine gute Praxis, die **Funktionalität der Registrierung und des Logins** von der **Datenhaltung** zu trennen und zu sichern, um die Sicherheit und Wartbarkeit zu erhöhen. Dies kann folgendermaßen erfolgen:

- **Token-basierte Authentifizierung**: Verwenden Sie JWT (JSON Web Token) oder OAuth2 zur Authentifizierung und Autorisierung anstelle von Sessions. Dies stellt sicher, dass keine sensiblen Anmeldedaten auf dem Server gespeichert werden.
- **Datenhaltung**: Benutzerdaten (wie Passwörter) sollten niemals im Klartext gespeichert werden. Stattdessen sollte ein sicherer Hashing-Algorithmus wie bcrypt verwendet werden.
- **Separate Authentifizierungsservices**: Authentifizierung und Datenverwaltung (z.B. Benutzerinformationen) können in getrennten Microservices abgewickelt werden. 
- **Role-based Access Control (RBAC)**: Stellen Sie sicher, dass nur berechtigte Benutzer auf bestimmte Daten zugreifen können. Dies kann durch die Implementierung von Zugriffsrichtlinien und Rollen geschehen.

### Absicherung der Eingabe und Übermittlung:
Die Sicherstellung der Sicherheit der Eingabedaten und ihrer Übermittlung ist entscheidend. Hier sind einige Best Practices:

1. **Input Validation und Sanitization**: Alle Eingaben müssen validiert und bereinigt werden, um Angriffe wie SQL-Injection und XSS zu verhindern. (Spezifische Validatoren für jede Eingabe, z.B. für E-Mails, Telefonnummern, Passwörter etc.)
2. **Verwendung von HTTPS**: Verschlüsseln der gesamten Kommunikation zwischen Client und Server durch HTTPS (SSL/TLS), um MITM-Angriffe zu verhindern.
3. **CSRF-Schutz**: Verwendung von CSRF-Tokens, um sicherzustellen, dass nur legitime Anfragen vom Benutzer kommen.
4. **Rate Limiting und Captchas**: Mechanismen wie Rate Limiting einsetzen, um Brute-Force-Angriffe zu verhindern, und Captchas bei der Registrierung und dem Login verwenden, um automatisierte Angriffe zu blockieren.
5. **Secure Cookies**: `HttpOnly` und `Secure` Flags für Authentifizierungs-Cookies verwenden, um sicherzustellen, dass sie nicht von JavaScript ausgelesen werden können und nur über HTTPS übertragen werden.
6. **HSTS (HTTP Strict Transport Security)**: HSTS aktivieren, um sicherzustellen, dass die Kommunikation nur über HTTPS erfolgt.

### Verbreitete Services zur Absicherung:
- **OAuth 2.0 und OpenID Connect**: bieten eine sichere und skalierbare Lösung für die Authentifizierung und Autorisierung.
- **JWT (JSON Web Tokens)**: ermöglicht verschlüsselte Übertragung von Benutzerdaten, ideal für API-basierte Authentifizierung.
- **Rate Limiting mit Redis oder API-Gateways**: Tools wie Redis oder API-Gateways (z.B. Kong, Apigee) können Rate Limiting umzusetzen, (Brute-Force-Angriffe verhindern)
- **ReCaptcha von Google**: kann zum Schutz gegen Bots und automatisierte Angriffe eingesetzt werden.
- **Cloudflare**: schützt gegen DDoS-Angriffe und kann als WAF (Web Application Firewall) fungieren.

<div style="page-break-after: always;"></div>

# Umgesetzte Sicherheitsmaßnahmen und Tests

## 1. Sicherheitsmaßnahmen

### 1.1 JWT-Token zur Authentifizierung
**JSON Web Tokens (JWT)** wurden für eine sichere Authentifizierung zwischen dem Client und dem Service eingesetzt. JWT-Token enthalten Informationen über den Benutzer in einem verschlüsselten Format und werden bei jeder Anfrage an geschützte Endpunkte verwendet.

- **Vorteile**:
  - Stateless: Server muss keine Sitzungsinformationen speichern
  - Skalierbar: super für verteilte Systeme
  - Sicherheit: Token können mit einer Ablaufzeit versehen werden, um Missbrauch zu minimieren

- **Sicherheitsmaßnahmen im Umgang mit JWT:**
  - Token werden mit einem sicheren, geheimen Schlüssel signiert.
  - Ablaufzeiten ("Expiration Time") wurden definiert, um zu verhindern, dass abgelaufene Token verwendet werden
  - Token werden ausschließlich über sichere Verbindungen (HTTPS) übertragen.

### 1.2 Schutz vor SQL-Injection
Um SQL-Injection-Angriffe zu verhindern, wurde das Framework **FastAPI** in Kombination mit **SQLAlchemy** verwendet.

- **Mechanismen:**
  - SQLAlchemy generiert sicher parameterisierte SQL-Abfragen, wodurch schadhafter Code in Eingaben keinen Einfluss auf die Datenbankstruktur hat.
  - FastAPI prüft eingehende Daten automatisch und minimiert so das Risiko, dass unsichere Eingaben weitergeleitet werden.

### 1.3 Sicheres Hashing von Passwörtern
Für die Speicherung von Passwörtern wurde Hashing mit **Salt und Pepper** umgesetzt:

- **Hashing**: Passwörter werden vor der Speicherung mit einem Hashing-Algorithmus verschlüsselt.

- **Salt** (ein zufälliger Wert) wird zu jedem Passwort hinzugefügt, um sicherzustellen, dass selbst identische Passwörter unterschiedliche Hash-Werte haben.

- **Pepper**:Ein geheimer, serverseitiger Schlüssel (Pepper) wird zusätzlich zu jedem Passwort hinzugefügt, was eine weitere Sicherheitsschicht bietet.

- **Vorteile**:
  - Schutz gegen Rainbow-Table-Angriffe.
  - Erhöhte Sicherheit, selbst wenn ein Angreifer Zugriff auf die Datenbank erhält. 
  - Dadurch können selbst bei einem Sicherheitsvorfall (z. B. einem Datenleck) keine Passwörter im Klartext gestohlen werden, was das Risiko eines Missbrauchs reduziert.

### 1.4 **HTTPS (Hypertext Transfer Protocol Secure):**
   - **Warum wichtig:** HTTPS stellt sicher, dass die Kommunikation zwischen dem Client (z. B. einem Webbrowser) und dem Server verschlüsselt wird. Dadurch wird verhindert, dass Angreifer sensible Informationen (wie Benutzernamen, Passwörter und andere persönliche Daten) abfangen können, während sie über das Netzwerk übertragen werden. Ohne HTTPS könnten Daten im Klartext über das Netzwerk gesendet werden, was besonders bei der Anmeldung oder Registrierung ein Sicherheitsrisiko darstellt.
   
  
### 1.5 **Cross-Origin Resource Sharing (CORS) limitieren:**
   - **Warum wichtig:** CORS ist eine Sicherheitsmaßnahme, die es einer Webanwendung verhindert, auf Ressourcen von einer anderen Domain zuzugreifen, wenn dies nicht explizit erlaubt ist. Durch das Limitieren von CORS wird kontrolliert, welche Domains auf die REST-API zugreifen können. Das verhindert Cross-Site Request Forgery (CSRF)-Angriffe, bei denen ein Angreifer eine Anfrage von einer anderen Website ausstellt, um schadhafte Operationen im Kontext des Benutzers durchzuführen. Eine sorgfältige CORS-Konfiguration stellt sicher, dass nur vertrauenswürdige Domains auf die API zugreifen dürfen.
   
### 1.6 **Fehlermeldungen bei falschen Anmeldeinformationen (keine genaue Fehlerbeschreibung):**
   - **Warum wichtig:** Wenn ein Angreifer die genaue Ursache für eine fehlerhafte Anmeldung erfährt, könnte er gezielt weitere Versuche unternehmen. Wenn beispielsweise die Fehlermeldung zwischen „falscher Benutzername“ und „falsches Passwort“ unterscheidet, kann ein Angreifer gezielt den richtigen Benutzernamen ermitteln und nur noch das Passwort erraten. Das Verbergen dieser Details (z. B. durch eine allgemeine Fehlermeldung wie „Benutzername oder Passwort ist falsch“) verhindert, dass ein Angreifer zusätzliche Informationen über den Fehler erhält, und erschwert einen Brute-Force-Angriff.
   
### 1.7 **Rate Limiting gegen Brute-Force-Angriffe:**
   - **Warum wichtig:** Bei Brute-Force-Angriffen versucht ein Angreifer, durch systematisches Ausprobieren von Kombinationen (Benutzername und Passwort) Zugang zu einem Konto zu erhalten. Durch das Implementieren von Rate Limiting wird die Anzahl der Anmeldeversuche für einen bestimmten Zeitraum begrenzt. Das erschwert es Angreifern, automatisierte Tools zu verwenden, um mit einer großen Anzahl von Versuchen Passwörter zu erraten. Dies schützt vor solchen Angriffen und trägt dazu bei, dass die Anwendung sicherer bleibt.


## 2. Tests zur Validierung der Implementierung
Um die Funktionalitäten und Sicherheitsmaßnahmen zu testen, wurden Tests mit der **pytest**-Bibliothek durchgeführt. 

### 2.1 Einrichtung der Testumgebung
1. Installation der pytest-Bibliothek:
   ```bash
   pip install pytest
   ```

2. Ausführung der Tests:
   ```bash
   pytest
   ```
   Alle Tests werden im Root-Verzeichnis des Projekts ausgeführt.

<div style="page-break-after: always;"></div>

### 2.2 Durchgeführte Tests
Die Tests decken die Kernfunktionen der Anwendung ab:

#### 2.2.1 POST /register
- **Ziel:** Validierung der Registrierung neuer Benutzer.
- **Testfälle:**
  1. **Erfolgreiche Registrierung:**
      - Eingabe korrekter Daten 
      - Erwartetes Ergebnis: Statuscode 201 (Created) und korrekte Rückgabe der Benutzerinformationen.
  2. **Fehlgeschlagene Registrierung:**
      - Eingabe ungültiger Daten (z. B. fehlendes Passwort).
      - Erwartetes Ergebnis: Statuscode 400 (Bad Request) und Fehlermeldung.

#### 2.2.2 POST /login
- **Ziel:** Überprüfung der Anmeldung mit korrekten und falschen Anmeldedaten.
- **Testfälle:**
  1. **Erfolgreiche Anmeldung:**
      - Eingabe korrekter Anmeldedaten.
      - Erwartetes Ergebnis: Statuscode 200 (OK) und Rückgabe eines gültigen JWT-Tokens.
  2. **Fehlgeschlagene Anmeldung:**
      - Eingabe ungültiger Anmeldedaten (z. B. falsches Passwort).
      - Erwartetes Ergebnis: Statuscode 401 (Unauthorized) und Fehlermeldung.

<div style="page-break-after: always;"></div>

#### 2.2.3 GET /me
- **Ziel:** Überprüfung, ob der JWT-Token korrekt funktioniert und Zugriff auf geschützte Endpunkte ermöglicht.
- **Testfälle:**
  1. **Erfolgreiche Anfrage:**
      - Gültiger JWT-Token wird bereitgestellt.
      - Erwartetes Ergebnis: Statuscode 200 (OK) und Rückgabe der Benutzerinformationen.
  2. **Fehlgeschlagene Anfrage:**
      - Kein oder ein ungültiger JWT-Token wird bereitgestellt.
      - Erwartetes Ergebnis: Statuscode 401 (Unauthorized) und Fehlermeldung.

### 2.3 Ergebnisse der Tests
Alle oben beschriebenen Testfälle wurden durchgeführt. Die Ergebnisse zeigen, dass:

1. Die Registrierung und Anmeldung korrekt funktionieren.
2. JWT-Token wie erwartet generiert und validiert werden.
3. Fehlerhafte Anfragen (z. B. falsche Anmeldedaten) korrekt behandelt werden.



