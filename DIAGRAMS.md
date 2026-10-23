# Systemdiagrammer: 64-bit ABAC/ACL AuthSystem i Go

Dette dokumentet inneholder en komplett og ryddig samling av tekniske diagrammer for prosjektet [`ABAC-ACL-AuthSystemInGo-main`](file:///C:/dev/ABAC-ACL-AuthSystemInGo-main/ABAC-ACL-AuthSystemInGo-main). Diagrammene er utformet med **Mermaid** og dekker datamodell (ER), use cases, prosess- og evalueringsflyt, sekvenser, systemarkitektur og tilstander.

---

## Innholdsfortegnelse
1. [Oversikt over systemet](#1-oversikt-over-systemet)
2. [ER-diagram (Entity-Relationship & Datamodell)](#2-er-diagram-entity-relationship--datamodell)
3. [64-bit Bitmask & Minnelayout Diagram](#3-64-bit-bitmask--minnelayout-diagram)
4. [Use Case-diagram](#4-use-case-diagram)
5. [Flytdiagrammer (Flowcharts)](#5-flytdiagrammer-flowcharts)
   - [Flyt 1: Evaluering av tilgang (Evaluator Engine)](#flyt-1-kjerneevaluering-av-tilgang-evaluator-engine)
   - [Flyt 2: Webgrensesnitt og Kontekst-simulering](#flyt-2-webgrensesnitt-innlogging-og-kontekst-simulering)
   - [Flyt 3: ACL Encode (Bygging av 64-bit heltall)](#flyt-3-acl-encode-bygging-av-64-bit-heltall)
6. [Sekvensdiagrammer](#6-sekvensdiagrammer)
   - [Sekvens 1: Innlogging og dynamisk tilgangssjekk i Web UI](#sekvens-1-innlogging-og-dynamisk-tilgangssjekk-i-web-ui)
   - [Sekvens 2: Ekstern Batch-sjekk over REST API](#sekvens-2-ekstern-batch-sjekk-over-rest-api)
7. [Systemarkitektur & Komponentdiagram](#7-systemarkitektur--komponentdiagram)
8. [Tilstandsdiagram (State Diagram)](#8-tilstandsdiagram-state-diagram)

---

## 1. Oversikt over systemet

Systemet kombinerer to autorisasjonsmodeller:
- **ACL (Access Control List)** komprimert til et **64-bit heltall (`uint64`)** fordelt på 4 par `(Gi, Ci)`.
- **ABAC (Attribute-Based Access Control)** der kontekst $C_i$ (tid, lokasjon, nettverk, 2FA, enhetsstatus) kreves oppfylt for at rettighetene i gruppe $G_i$ skal være aktive:
  $$\text{Tilgang innvilget} \iff (G_i \text{ matcher Subjekt, Objekt og Rettighet}) \land ((C_i == 0) \lor (\text{AktivKontekst} \land C_i == C_i))$$

---

## 2. ER-diagram (Entity-Relationship & Datamodell)

Diagrammet nedenfor viser de logiske entitetene, deres felt og relasjoner mellom brukere, sesjoner, ACL-strukturer og rettighetsregistre.

```mermaid
erDiagram
    PROFILE ||--o{ SESSION : "har aktive"
    PROFILE ||--|| ACL : "tildelt standard"
    ACL ||--|{ PAIR : "består av (4 par)"
    PAIR ||--|| GROUP_BYTE : "inneholder"
    PAIR ||--|| CONTEXT_GROUP : "betinges av"
    PAIR }|--|| GROUP_DEFINITION : "kartlegges mot (1..4)"
    GROUP_DEFINITION ||--|{ RIGHT_DEFINITION : "definerer (4 rettigheter)"
    CONTEXT_MANAGER ||--|| SIMULATED_CONTEXT : "vedlikeholder"
    SIMULATED_CONTEXT }o--|| EVALUATOR : "evalueres mot"
    ACL }o--|| EVALUATOR : "tolkes av"

    PROFILE {
        string ID PK "f.eks. admin, operator, engineer"
        string Name "Fullt visningsnavn"
        string Type "USER eller PROCESS"
        string Role "Rollebeskrivelse"
        uint8 SubjectID "2-bit ID (0..3)"
        string Password "SHA-256 hash"
        uint64 DefaultACL FK "Standard 64-bit ACL"
        string ACLHex "Heksadesimal streng"
        string Description "Formål og omfang"
    }

    SESSION {
        string Token PK "24-byte krypto-sikker heks"
        string ProfileID FK "Referanse til Profile.ID"
        datetime CreatedAt "Opprettelsestidspunkt"
        datetime ExpiresAt "Utløpstidspunkt (24 timer)"
    }

    ACL {
        uint64 RawValue PK "64-bit heltall (BigEndian)"
        string Hex "16-tegns 0x-heksstreng"
        string Binary "64-tegns binærstreng"
    }

    PAIR {
        int PairIndex PK "1, 2, 3 eller 4"
        uint8 GroupByte "8-bit verdi (Gi)"
        uint8 ContextByte "8-bit verdi (Ci)"
    }

    GROUP_BYTE {
        uint8 Subject "Bits 7..6 (0..3)"
        uint8 Object "Bits 5..4 (0..3)"
        uint8 RightsMask "Bits 3..0 (0..15 maske)"
    }

    CONTEXT_GROUP {
        uint8 RequiredMask "8-bit maskekrav for kontekst"
    }

    GROUP_DEFINITION {
        int ID PK "Gruppe-ID (1..4)"
        string Name "f.eks. File & Data Storage, SCADA"
        string Description "Bruksområde og domene"
    }

    RIGHT_DEFINITION {
        uint8 Bit PK "0x01, 0x02, 0x04 eller 0x08"
        string Name "f.eks. READ, CONNECT, POLL_TELEMETRY"
        string Description "Forklaring av rettigheten"
    }

    SIMULATED_CONTEXT {
        string Location "PLANT_FLOOR, HQ_OFFICE, REMOTE_VPN, UNTRUSTED"
        string Time "DAY_SHIFT, NIGHT_SHIFT, MAINTENANCE, WEEKEND"
        boolean TwoFactorAuth "2FA verifisert"
        boolean ManagedDevice "Bedriftsstyrt enhet"
        uint8 ContextByte "Kombinert 8-bit maske"
        string ContextHex "0x-representasjon"
    }

    CONTEXT_MANAGER {
        RWMutex mu "Trådsikker tilgang"
    }

    EVALUATOR {
        Registry registry "Peker til rettighetsregister"
    }
```

---

## 3. 64-bit Bitmask & Minnelayout Diagram

Diagrammet nedenfor visualiserer hvordan et 64-bits `uint64`-heltall er nøyaktig pakket i minnet som fire par av `(Gi, Ci)` (totalt 8 bytes / 64 bits), samt den interne anatomien i hver byte.

```mermaid
graph TB
    subgraph S64["64-bit ACL Heltall (Big-Endian uint64)"]
        direction LR
        B0["Byte 0 (Bit 63..56)<br/><b>G1</b> (Storage)"]
        B1["Byte 1 (Bit 55..48)<br/><b>C1</b> (Kontekst 1)"]
        B2["Byte 2 (Bit 47..40)<br/><b>G2</b> (Network)"]
        B3["Byte 3 (Bit 39..32)<br/><b>C2</b> (Kontekst 2)"]
        B4["Byte 4 (Bit 31..24)<br/><b>G3</b> (SCADA)"]
        B5["Byte 5 (Bit 23..16)<br/><b>C3</b> (Kontekst 3)"]
        B6["Byte 6 (Bit 15..8)<br/><b>G4</b> (Admin)"]
        B7["Byte 7 (Bit 7..0)<br/><b>C4</b> (Kontekst 4)"]
        
        B0 --- B1 --- B2 --- B3 --- B4 --- B5 --- B6 --- B7
    end

    subgraph G_ANATOMY["Anatomi av en Gruppe-byte Gi (8 bits)"]
        direction LR
        G_SUB["Bits 7..6 (2 bit)<br/><b>Subject ID</b><br/>0..3"]
        G_OBJ["Bits 5..4 (2 bit)<br/><b>Object ID</b><br/>0..3"]
        G_R4["Bit 3 (0x8)<br/><b>Rettighet 4</b>"]
        G_R3["Bit 2 (0x4)<br/><b>Rettighet 3</b>"]
        G_R2["Bit 1 (0x2)<br/><b>Rettighet 2</b>"]
        G_R1["Bit 0 (0x1)<br/><b>Rettighet 1</b>"]

        G_SUB --- G_OBJ --- G_R4 --- G_R3 --- G_R2 --- G_R1
    end

    subgraph C_ANATOMY["Anatomi av en Kontekst-byte Ci (8 bits)"]
        direction LR
        C7["Bit 7 (0x80)<br/>Managed Dev"]
        C6["Bit 6 (0x40)<br/>Helg/Ferie"]
        C5["Bit 5 (0x20)<br/>Driftsstans"]
        C4["Bit 4 (0x10)<br/>Nattskift"]
        C3["Bit 3 (0x08)<br/>2FA Maskinvare"]
        C2["Bit 2 (0x04)<br/>TLS VPN"]
        C1["Bit 1 (0x02)<br/>Fabrikknett"]
        C0["Bit 0 (0x01)<br/>Dagskift"]

        C7 --- C6 --- C5 --- C4 --- C3 --- C2 --- C1 --- C0
    end

    B0 -.->|Detaljvisning av Gi| G_ANATOMY
    B1 -.->|Detaljvisning av Ci| C_ANATOMY
```

### Grupperettigheter Semantikk (Tabell)

| Gruppe | Domene | Bit 0 (`0x1`) | Bit 1 (`0x2`) | Bit 2 (`0x4`) | Bit 3 (`0x8`) |
|---|---|---|---|---|---|
| **G1** | **File & Data Storage** | `READ` | `WRITE` | `EXECUTE` | `DELETE` |
| **G2** | **Network & Messaging** | `CONNECT` | `PUBLISH` | `SUBSCRIBE` | `DISCONNECT` |
| **G3** | **SCADA & Hardware** | `POLL_TELEMETRY` | `SET_ACTUATOR` | `CALIBRATE` | `EMERGENCY_STOP` |
| **G4** | **Admin & Security** | `VIEW_AUDIT` | `MANAGE_ROLES` | `CONFIG_SYSTEM` | `OVERRIDE` |

---

## 4. Use Case-diagram

Diagrammet viser de ulike aktørene (Operatør, Ingeniør, Administrator, Bakgrunnsprosesser og Eksternt API) og deres interaksjon med systemet.

```mermaid
graph TD
    %% Aktører
    subgraph Aktorer["Aktører"]
        User["👤 Sluttbruker<br/>(Operatør / Ingeniør / Gjest)"]
        Admin["👑 Administrator<br/>(System & Sikkerhet)"]
        Daemon["⚙️ Bakgrunnsprosess<br/>(SCADA Poller / Backup Worker)"]
        ExtAPI["💻 Ekstern Klient / API-konsument<br/>(Microservice / Gateway)"]
    end

    %% Use Cases
    subgraph Auth_Cases["Autentisering & Sesjon"]
        UC_Login(["UC1: Logge inn med brukernavn & passord"])
        UC_QuickFill(["UC1.1: Hurtigvalg av testbrukere"])
        UC_SessionCheck(["UC2: Verifisere aktiv sesjon (auth/me)"])
        UC_Logout(["UC3: Logge ut og invalidere token"])
    end

    subgraph Context_Cases["ABAC Kontekststyring"]
        UC_SimContext(["UC4: Simulere driftskontekst via dropdown"])
        UC_ViewContext(["UC5: Inspisere aktiv kontekstmaske (context/current)"])
    end

    subgraph Eval_Cases["ACL Tilgangsevaluering"]
        UC_EvalMatrix(["UC6: Evaluere full tilgangsmatrise for profil"])
        UC_CheckSingle(["UC7: Forespørre enkelt tilgangssjekk (/check)"])
        UC_CheckBatch(["UC8: Kjøre batch-evaluering av tall-liste (/check-batch)"])
        UC_VerifySubObj(["UC9: Validere Subjekt- og Objekt-ID"])
        UC_VerifyContext(["UC10: Evaluere kontekstkrav (C_i oppfylt)"])
    end

    subgraph Encode_Cases["ACL Verktøy & Administrasjon"]
        UC_Decode(["UC11: Dekode 64-bit ACL til lesbart format (/decode)"])
        UC_Encode(["UC12: Bygge 64-bit ACL fra regler (/encode)"])
        UC_ListGroups(["UC13: Hente gruppesemantikk (/groups)"])
    end

    %% Relasjoner for Bruker
    User --> UC_Login
    User --> UC_QuickFill
    User --> UC_Logout
    User --> UC_SimContext
    User --> UC_EvalMatrix
    User --> UC_CheckSingle

    %% Relasjoner for Admin
    Admin --> UC_Login
    Admin --> UC_Encode
    Admin --> UC_Decode
    Admin --> UC_ListGroups
    Admin --> UC_EvalMatrix

    %% Relasjoner for Daemon
    Daemon --> UC_CheckSingle
    Daemon --> UC_ViewContext

    %% Relasjoner for Ekstern API
    ExtAPI --> UC_CheckSingle
    ExtAPI --> UC_CheckBatch
    ExtAPI --> UC_Decode
    ExtAPI --> UC_Encode

    %% Inkluderings- og utvidelsesrelasjoner
    UC_QuickFill -.->|include| UC_Login
    UC_EvalMatrix -.->|include| UC_VerifySubObj
    UC_EvalMatrix -.->|include| UC_VerifyContext
    UC_CheckSingle -.->|include| UC_VerifySubObj
    UC_CheckSingle -.->|include| UC_VerifyContext
    UC_CheckBatch -.->|include| UC_CheckSingle
    UC_SimContext -.->|trigger| UC_EvalMatrix
```

---

## 5. Flytdiagrammer (Flowcharts)

### Flyt 1: Kjerneevaluering av tilgang (Evaluator Engine)

Dette flytdiagrammet viser den eksakte logikken i [`Evaluator.Check`](file:///C:/dev/ABAC-ACL-AuthSystemInGo-main/ABAC-ACL-AuthSystemInGo-main/pkg/acl/evaluator.go#L39-L113) når en tilgangssjekk utføres mot et 64-bit ACL-tall.

```mermaid
flowchart TD
    Start(["Motta: aclVal (uint64), targetGroup (0..4),<br/>subject (0..3), object (0..3), right, activeContext (uint8)"]) --> ParseTarget{"targetGroup spesifisert?<br/>(1..4 vs 0)"}
    
    ParseTarget -- "Ja (1..4)" --> SetBoundsSingle["startGroup = targetGroup<br/>endGroup = targetGroup"]
    ParseTarget -- "Nei (0 = alle)" --> SetBoundsAll["startGroup = 1<br/>endGroup = 4"]

    SetBoundsSingle --> InitLoop["i = startGroup<br/>contextFailed = false"]
    SetBoundsAll --> InitLoop

    InitLoop --> LoopCondition{"i <= endGroup?"}

    LoopCondition -- "Nei (Ingen regler ga tilgang)" --> CheckContextFail{"Var contextFailed == true?"}
    CheckContextFail -- "Ja" --> DenyContext["Returner Allowed: false<br/>Årsak: Regel matchet, men kontekst C_i feilet"]
    CheckContextFail -- "Nei" --> DenyNoMatch["Returner Allowed: false<br/>Årsak: Ingen matchende subjekt/objekt/rettighet funnet"]

    LoopCondition -- "Ja" --> ExtractPair["Hent Pair i:<br/>shiftG = (4 - i)*16 + 8<br/>shiftC = (4 - i)*16<br/>g = Group, c = ContextGroup"]
    
    ExtractPair --> CheckEmptyRights{"Har gruppen rettigheter?<br/>g.Rights() == 0"}
    CheckEmptyRights -- "Ja (tom)" --> NextGroup["i = i + 1"] --> LoopCondition
    CheckEmptyRights -- "Nei" --> CheckSubject{"Matcher Subjekt?<br/>g.Subject() == (subject & 0x3)"}

    CheckSubject -- "Nei" --> NextGroup
    CheckSubject -- "Ja" --> CheckObject{"Matcher Objekt?<br/>g.Object() == (object & 0x3)"}

    CheckObject -- "Nei" --> NextGroup
    CheckObject -- "Ja" --> ResolveRight["Slå opp rightBit i Registry for gruppe i"]
    
    ResolveRight --> HasRight{"Har gruppen rettighetsbiten?<br/>g.HasRight(rightBit)"}
    HasRight -- "Nei" --> NextGroup
    HasRight -- "Ja" --> CheckContext{"Er kontekst Ci oppfylt?<br/>(c == 0) || ((activeContext & c) == c)"}

    CheckContext -- "Nei" --> MarkContextFail["contextFailed = true<br/>Lagre feilårsak med manglende bits"] --> NextGroup
    CheckContext -- "Ja" --> GrantAccess(["Returner Allowed: true<br/>MatchedGroup: i<br/>Reason: Tilgang innvilget og kontekst verifisert"])
```

---

### Flyt 2: Webgrensesnitt: Innlogging og Kontekst-simulering

Viser hendelsesforløpet i nettleseren og serveren fra brukeren åpner siden til tilgang evalueres dynamisk.

```mermaid
flowchart TD
    OpenPage(["Bruker åpner http://localhost:8080/"]) --> InitUI["app.js initieres:<br/>onContextChange()<br/>checkCurrentSession()"]
    
    InitUI --> CheckSession{"Har aktiv sesjon?<br/>GET /api/v1/auth/me"}
    CheckSession -- "Ja" --> SetUserActive["setLoggedIn(profile)<br/>Skjul 'Logg inn', vis 'Logg ut'"]
    CheckSession -- "Nei" --> Idle["Vis innloggingsskjema"]

    Idle --> UserAction{"Brukerhandling"}
    
    %% Handling 1: Hurtigvalg
    UserAction -- "Klikk på Hurtigvalg-knapp<br/>(admin, operator, etc.)" --> FillForm["Fyller inn brukernavn & passord"] --> SubmitLogin
    
    %% Handling 2: Skrive inn legitimasjon
    UserAction -- "Manuell innlogging" --> SubmitLogin["POST /api/v1/auth/login<br/>{username, password}"]

    SubmitLogin --> AuthServer{"Server autentiserer:<br/>SHA-256(password) == profile.Password?"}
    AuthServer -- "Ugyldig" --> ShowLoginError["Vis rød feilboks:<br/>'Innlogging feilet'"]
    AuthServer -- "Gyldig" --> CreateSess["Generer krypto-token<br/>Lagre sesjon (24t)<br/>Sett HttpOnly cookie / JSON"]
    
    CreateSess --> SetUserActive --> AutoCheckAccess

    %% Handling 3: Endre dropdown
    UserAction -- "Endrer Kontekst-dropdown<br/>(f.eks. Nattskift eller VPN)" --> PostSimContext["POST /api/v1/context/simulate<br/>{location, time, 2fa, device}"]
    
    PostSimContext --> RecalcContext["ContextManager beregner ny 8-bit maske<br/>Oppdaterer currentContextByte"]
    RecalcContext --> IsUserLoggedIn{"Er bruker innlogget?"}
    IsUserLoggedIn -- "Nei" --> Wait["Venter på innlogging"]
    IsUserLoggedIn -- "Ja" --> AutoCheckAccess["Kall checkAccess()"]

    %% Handling 4: Klikk Sjekk tilgang
    UserAction -- "Klikker 'Sjekk tilgang'" --> AutoCheckAccess

    AutoCheckAccess --> FetchMatrix["GET /api/v1/profiles/eval-matrix?id=brukerId"]
    FetchMatrix --> EvalAllGroups["Server evaluerer G1..G4 mot aktiv kontekst<br/>Klassifiserer rettigheter: Allowed vs Denied"]
    
    EvalAllGroups --> UpdateUI{"Minst 1 rettighet innvilget?"}
    UpdateUI -- "Ja" --> RenderGranted["Statusboks GRØNN (Tillatt)<br/>Lister opp tillatte operasjoner"]
    UpdateUI -- "Nei" --> RenderDenied["Statusboks RØD (Avslått)<br/>Forklarer hvilke kontekstkrav som mangler"]
```

---

### Flyt 3: ACL Encode (Bygging av 64-bit heltall)

Viser hvordan høynivå JSON-spesifikasjon med par, subjekter, objekter og rettighetsnavn pakkes til et `uint64`-heltall i [`HandleEncode`](file:///C:/dev/ABAC-ACL-AuthSystemInGo-main/ABAC-ACL-AuthSystemInGo-main/internal/api/handler.go#L446-L514).

```mermaid
flowchart TD
    Start(["Motta EncodeRequest JSON med opptil 4 par"]) --> Init["val uint64 = 0<br/>MaxPairs = 4"]
    Init --> LoopPairs["For hvert par i = 1..len(pairs)"]

    LoopPairs --> ValidatePair{"pair_index mellom 1..4?"}
    ValidatePair -- "Ugyldig" --> Error["Returner HTTP 400 Bad Request"]
    
    ValidatePair -- "Gyldig" --> ParseRights["Løs ut rettigheter:<br/>Hvis []string: Slå opp bit for hvert navn via Registry<br/>Hvis tall: Bruk som maske"]
    
    ParseRights --> PackGroup["Pakk 8-bit Gruppe (Gi):<br/>val = (subject & 0x3) << 6 |<br/>      (object & 0x3) << 4 |<br/>      (rights & 0xF)"]
    
    PackGroup --> PackContext["Hent 8-bit Kontekst (Ci):<br/>c = pair.context & 0xFF"]
    
    PackContext --> BitShift["Beregn posisjon i 64-bit heltall:<br/>shiftG = (4 - pair_index) * 16 + 8<br/>shiftC = (4 - pair_index) * 16"]
    
    BitShift --> BitwiseOr["Kombiner inn i heltall:<br/>val |= (uint64(g) << shiftG) |<br/>       (uint64(c) << shiftC)"]
    
    BitwiseOr --> MorePairs{"Flere par i listen?"}
    MorePairs -- "Ja" --> LoopPairs
    MorePairs -- "Nei" --> FormatOutput["Generer representasjoner:<br/>- Uint64: tall<br/>- Hex: 0x...<br/>- Binary: 0b..."]
    
    FormatOutput --> ReturnSuccess(["Returner HTTP 200 med kodet ACL JSON"])
```

---

## 6. Sekvensdiagrammer

### Sekvens 1: Innlogging og dynamisk tilgangssjekk i Web UI

```mermaid
sequenceDiagram
    autonumber
    actor Bruker as 👤 Bruker (Nettleser)
    participant UI as 🌐 Web UI (app.js)
    participant Server as 🚪 API Server / Router
    participant Auth as 🔑 UserStore & Sessions
    participant CtxMgr as ⏱️ ContextManager
    participant Eval as ⚡ Evaluator & Registry

    Bruker->>UI: Velger hurtigknapp eller taster passord
    UI->>Server: POST /api/v1/auth/login {"username":"operator","password":"..."}
    Server->>Auth: Authenticate("operator", hash)
    Auth-->>Server: OK (Profile funnet, DefaultACL: 0x...)
    Server->>Auth: CreateSession(Profile)
    Auth-->>Server: Session Token (24-byte hex)
    Server-->>UI: HTTP 200 { authenticated: true, profile: {...} }
    UI->>UI: setLoggedIn() -> Oppdaterer knapper

    Bruker->>UI: Velger 'Fabrikk - Dagskift [0x0B]' i dropdown
    UI->>Server: POST /api/v1/context/simulate { location: "PLANT_FLOOR", time: "DAY_SHIFT", ... }
    Server->>CtxMgr: SetContext(Loc, Time, 2FA, Device)
    CtxMgr-->>Server: Ny maske 0x0B (0b00001011)
    Server-->>UI: HTTP 200 { context_byte: 11, context_hex: "0x0B", ... }

    UI->>Server: GET /api/v1/profiles/eval-matrix?id=operator
    Server->>CtxMgr: GetCurrent() -> activeContext (0x0B)
    Server->>Eval: Check(operator.DefaultACL, group, sub, obj, right, activeContext)
    loop For hver gruppe (G1..G4) og hver rettighet
        Eval->>Eval: Match Subjekt/Objekt & Rettighetsbit
        Eval->>Eval: Test (activeContext & Ci) == Ci
    end
    Eval-->>Server: ProfileMatrixResponse (Allowed/Denied detaljer)
    Server-->>UI: HTTP 200 JSON
    UI->>UI: checkAccess() tegner resultat
    UI-->>Bruker: Viser GRØNN status: "Tilgang: Tillatt (true) for Ola Nordmann"
```

---

### Sekvens 2: Ekstern Batch-sjekk over REST API

Viser hvordan en ekstern mikrotjeneste sender en liste med 64-bit ACL-tall for umiddelbar batch-evaluering.

```mermaid
sequenceDiagram
    autonumber
    actor Client as 🔌 Ekstern Mikrotjeneste / IoT Gateway
    participant Handler as 🚪 API Handler (/api/v1/check)
    participant CtxMgr as ⏱️ ContextManager
    participant Eval as ⚡ Evaluator
    participant ACL_Engine as 🔢 ACL Bit Engine

    Client->>Handler: POST /api/v1/check?group=1&subject=1&object=1&right=READ&context=33<br/>Body: [5990264028682846208, 0, "0x5321B16574710000", 12345]
    Handler->>Handler: Registrerer JSON Array ([...])
    Handler->>Handler: Parser query-parametre (group=1, subject=1, object=1, right="READ", context=0x21)
    
    loop For hvert element i arrayet
        Handler->>ACL_Engine: parseACLNumber(item) -> uint64
    end

    Handler->>Eval: CheckBatchFast(acls, targetGroup=1, sub=1, obj=1, right="READ", ctx=0x21)
    
    loop For hvert 64-bit tall i listen
        Eval->>ACL_Engine: acl.GetPair(1)
        ACL_Engine-->>Eval: Group 1 (g), Context 1 (c)
        Eval->>Eval: Sjekk subject, object, right bitmask
        Eval->>Eval: Sjekk (context & c) == c
        Eval->>Eval: Samle boolsk resultat (true / false)
    end

    Eval-->>Handler: []bool { true, false, true, false }
    Handler-->>Client: HTTP 200 OK<br/>[true, false, true, false]
```

---

## 7. Systemarkitektur & Komponentdiagram

Dette diagrammet viser modulene og avhengighetene i Go-applikasjonen, strukturert etter lag (Clean Architecture).

```mermaid
graph TB
    subgraph ClientLayer["Klientlag (Frontend & Eksterne Klienter)"]
        Browser["🌐 Web Dashboard<br/>(index.html, app.js, style.css)"]
        CurlClient["📟 cURL / REST Klienter"]
        IoTProcess["🤖 IoT / SCADA Prosesser"]
    end

    subgraph TransportLayer["Transport- & Serverlag (cmd/server, internal/api)"]
        Server["🚀 Server (server.go)<br/>HTTP Mux, Graceful Shutdown"]
        Middleware["🛡️ Middleware<br/>CORS & Request Logging"]
        Handler["🎯 API Handler (handler.go)<br/>REST Endpoints Router"]
    end

    subgraph ServiceLayer["Forretningslogikk & Tilstand (pkg/auth)"]
        UserStore["👥 UserStore (user.go)<br/>Forhåndsdefinerte profiler & Passordhashes"]
        SessionMgr["🎫 SessionManager (session.go)<br/>Kryptografiske tokens & Utløpstid"]
        ContextMgr["🌍 ContextManager (context_simulator.go)<br/>Simulert tid, lokasjon, 2FA, enhetsstatus"]
    end

    subgraph CoreLayer["ACL Bitmasking Kjerne (pkg/acl)"]
        Evaluator["⚡ Evaluator (evaluator.go)<br/>Rask bitmask-evaluering & Batch-prosessering"]
        Registry["📚 Registry (registry.go)<br/>Semantikk for 4 grupper & 16 rettigheter"]
        ACLType["🔢 ACL (acl.go)<br/>64-bit uint64, Pairs, Big-Endian konvertering"]
        GroupType["🧩 Group & ContextGroup (types.go)<br/>8-bit Gi & Ci bit-manipulasjon"]
    end

    %% Koblinger
    Browser -->|HTTP / JSON| Middleware
    CurlClient -->|HTTP / JSON| Middleware
    IoTProcess -->|HTTP / Token| Middleware

    Middleware --> Server
    Server --> Handler

    Handler -->|Autentiser & Hent profiler| UserStore
    Handler -->|Opprett & Valider sesjoner| SessionMgr
    Handler -->|Les & Simuler kontekst| ContextMgr
    Handler -->|Evaluer tilgang| Evaluator
    Handler -->|Encode / Decode| ACLType

    Evaluator -->|Slå opp rettigheter| Registry
    Evaluator -->|Hent par| ACLType
    ACLType -->|Dekomponerer til| GroupType
```

---

## 8. Tilstandsdiagram (State Diagram)

Diagrammet illustrerer tilstandsovergangene for en brukersesjon i systemet, og hvordan dynamisk kontekst fører til overgang mellom innvilget tilgang (`Access_Granted`) og avslått tilgang (`Access_Denied`).

```mermaid
stateDiagram-v2
    [*] --> Unauthenticated : Bruker åpner applikasjon

    Unauthenticated --> Authenticating : Sender legitimasjon (POST /auth/login)
    Authenticating --> Unauthenticated : Feil passord / Bruker finnes ikke
    Authenticating --> Authenticated_Idle : Gyldig legitimasjon (Sesjon opprettet)

    state Authenticated_Idle {
        [*] --> EvaluatingContext
        EvaluatingContext --> Access_Granted : Kontekstkrav Ci oppfylt ((ctx & Ci) == Ci)
        EvaluatingContext --> Access_Denied : Kontekstkrav Ci mangler (f.eks. utenfor arbeidstid)
    }

    Authenticated_Idle --> Context_Changed : Bruker endrer dropdown / Ny kontekst simulert
    Context_Changed --> Authenticated_Idle : Rekalkulerer evaluering

    Access_Granted --> Context_Changed : Miljøendring (f.eks. VPN frakoblet)
    Access_Denied --> Context_Changed : Miljøendring (f.eks. 2FA verifisert)

    Authenticated_Idle --> Unauthenticated : Logg ut (POST /auth/logout)
    Authenticated_Idle --> Unauthenticated : Sesjon utløper (24 timer)
```

---

## 9. Oppsummering og Anbefalinger

1. **Ytelse:** ACL-sjekken er optimalisert med rene bitvise operasjoner (`&`, `>>`, `|`), noe som gir sub-mikrosekund evalueringstid selv ved tusenvis av samtidige batch-kall.
2. **Kompakthet:** Hele sikkerhetspolicyn for et subjekt på tvers av 4 uavhengige grupper og kontekster lagres i ett enkelt 64-bits heltall (8 bytes).
3. **ABAC-integrasjon:** Kontekstbetingelsen $C_i$ sikrer at rettigheter aldri er statiske, men til enhver tid krever verifisert lokasjon, tid og tofaktorautentisering.
