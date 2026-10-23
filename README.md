# 64-bit ACL Bitmask Engine (Go Server)

Et komplett tilgangskontrollsystem (ACL) skrevet i Go, basert på **64-bit heltall og bitmasking**.

<img width="1820" height="947" alt="image" src="https://github.com/user-attachments/assets/30548ff2-feed-4a96-a56c-7c1c034d3b85" />


> **Merk om HTML-grensesnittet:**  
> Webgrensesnittet på **http://localhost:8080** er bevisst bygget helt minimalistisk og rent. HTML-koden viser **KUN innloggingsskjema + knapper og 1 dropdown-meny for kontekst-simulering**. Det er ingen ekstra faner, ingen symboler og ingen unødvendig kompleksitet.

---

## 📑 Innholdsfortegnelse
- [Webgrensesnitt](#-webgrensesnitt-kun-login--knapper--1-dropdown)
- [Kjøring med Docker](#-kjøring-med-docker)
- [Forhåndsdefinerte Brukere og Passord](#-forhåndsdefinerte-brukere-og-passord)
- [Falsk Kontekst-informasjon (Lokasjon & Tid)](#-falsk-kontekst-informasjon-lokasjon--tid)
- [Bit-Struktur og Bitmasking](#-bit-struktur-og-bitmasking)
- [System- og Arkitekturdiagrammer](#-system--og-arkitekturdiagrammer)
  - [1. ER-diagram (Entity-Relationship & Datamodell)](#1-er-diagram-entity-relationship--datamodell)
  - [2. 64-bit Bitmask & Minnelayout Diagram](#2-64-bit-bitmask--minnelayout-diagram)
  - [3. Use Case-diagram](#3-use-case-diagram)
  - [4. Flytdiagram 1: Kjerneevaluering av tilgang (Evaluator Engine)](#4-flytdiagram-1-kjerneevaluering-av-tilgang-evaluator-engine)
  - [5. Flytdiagram 2: Webgrensesnitt, Innlogging og Kontekst-simulering](#5-flytdiagram-2-webgrensesnitt-innlogging-og-kontekst-simulering)
  - [6. Flytdiagram 3: ACL Encode (Bygging av 64-bit heltall)](#6-flytdiagram-3-acl-encode-bygging-av-64-bit-heltall)
  - [7. Sekvensdiagram 1: Innlogging og dynamisk tilgangssjekk i Web UI](#7-sekvensdiagram-1-innlogging-og-dynamisk-tilgangssjekk-i-web-ui)
  - [8. Sekvensdiagram 2: Ekstern Batch-sjekk over REST API](#8-sekvensdiagram-2-ekstern-batch-sjekk-over-rest-api)
  - [9. Systemarkitektur & Komponentdiagram](#9-systemarkitektur--komponentdiagram)
  - [10. Tilstandsdiagram (State Diagram)](#10-tilstandsdiagram-state-diagram)
- [REST API Eksempler](#-rest-api-eksempler)

---

## 🖥️ Webgrensesnitt (Kun Login + Knapper + 1 Dropdown)

HTML-siden viser utelukkende følgende elementer:

1. **Innloggingsskjema:**
   - Tekstfelt for **Brukernavn**
   - Tekstfelt for **Passord**

2. **Knapper:**
   - **Logg inn** (endres til **Logg ut** når bruker er autentisert)
   - **Sjekk tilgang**
   - Hurtigvalg-knapper: `admin`, `operator`, `engineer`, `guest`

3. **1 Dropdown-meny (for kontekst-simulering):**
   - *Fabrikk - Dagskift (08:00 - 16:00, 192.168.1.x, 2FA) [Maske: 0x0B]*
   - *Fabrikk - Nattskift (22:00 - 06:00) [Maske: 0x12]*
   - *Hovedkontor - Dagskift (Oslo LAN) [Maske: 0x03]*
   - *Hjemmekontor / VPN - Arbeidstid (Kryptert tunnel, 2FA) [Maske: 0x0D]*
   - *Vedlikeholdsvindu (Planlagt driftsstans) [Maske: 0x20]*
   - *Helg / Helligdag (Stengt fabrikk) [Maske: 0x40]*
   - *Eksternt nettverk - Utenfor arbeidstid (Ukjent IP) [Maske: 0x00]*

4. **Resultatboks:**
   - Viser aktiv innlogget bruker, gjeldende kontekstmaske ($C$), og om tilgang evaluerer til **`Tillatt (true)`** eller **`Avslått (false)`**.

---

## 🐳 Kjøring med Docker

Serveren er klargjort for Docker med en multi-stage build (bygger med `golang:1.24-alpine` og kjører i minimal `alpine:3.21`).

### Start med Docker Compose (Anbefalt)
```bash
cd c:\dev\go-acl-bitmask
docker compose up --build -d
```

### Start direkte med Docker
```bash
docker build -t acl-bitmask-service .
docker run -d -p 8080:8080 --name acl-service acl-bitmask-service
```

### Lokal kjøring uten Docker (Go)
```bash
go test -v ./...
go build -o acl-server.exe ./cmd/server
.\acl-server.exe -port 8080 -static ./web/static
```

Dashboardet er tilgjengelig på: **http://localhost:8080**

---

## 👤 Forhåndsdefinerte Brukere og Passord

| Brukernavn | Passord | Type | Subject ID (`xx`) | Rolle & Beskrivelse |
|---|---|---|---|---|
| **`admin`** | `admin123` | USER | `3` (11) | **Systemadministrator:** Full tilgang på tvers av alle 4 grupper. |
| **`operator`** | `operator123` | USER | `1` (01) | **Ola Nordmann (Skiftoperatør):** Styrer prosess-aktuatorer i arbeidstid på fabrikkgulvet. |
| **`engineer`** | `engineer123` | USER | `2` (10) | **Kari Ingeniør (Automasjonsingeniør):** Kalibrering og scriptkjøring via VPN/LAN med 2FA. |
| **`guest`** | `guest123` | USER | `0` (00) | **Gjest / Revisor:** Kun lesetilgang til telemetri, ingen skrive- eller styringsrettigheter. |
| **`proc-scada-poller`** | *(token)* | PROCESS | `2` (10) | **daemon://scada-telemetry-poller:** Høyfrekvent polling av sensorer på internt nett. |
| **`proc-backup-worker`** | *(token)* | PROCESS | `1` (01) | **cron://database-backup-worker:** Nattlig arkiveringsjobb i vedlikeholdsvinduet. |

---

## 🌍 Falsk Kontekst-informasjon (Lokasjon & Tid)

Tilgangskontroll krever at kontekstgruppen $C_i$ er oppfylt for at gruppe $G_i$ skal gi rettigheter (`activeContext & Ci == Ci`). 
Gjennom den **enkle dropdown-menyen** i grensesnittet kan du simulere falsk kontekst for å teste om ACL-reglene godkjenner eller avviser tilgang:

```
Kontekstbyte C (8 bit):
Bit 0 (0x01): Arbeidstid / Day Shift (08:00 - 16:00)
Bit 1 (0x02): Fabrikkgulv Subnet (192.168.1.x) / HQ LAN
Bit 2 (0x04): Sikker TLS VPN-tunnel (Norge)
Bit 3 (0x08): Maskinvare 2FA Verifisert
Bit 4 (0x10): Nattskift (22:00 - 06:00)
Bit 5 (0x20): Vedlikeholdsvindu (Off-peak)
Bit 6 (0x40): Helg / Helligdag
Bit 7 (0x80): Godkjent Bedrifts-enhet
```

---

## 📐 Bit-Struktur og Bitmasking

### 1. Gruppe-representasjon (8 bits / 1 byte)
Hver gruppe $G$ består av 8 bit:
```
Bit:       7   6   5   4   3   2   1   0
Mønster: [  xx  ] [  yy  ] [   ----   ]
Betydning: Subject  Object    Rights Bitmask (4 rettigheter)
```
- **`xx` (Bits 7..6 - 2 bits):** Subject ID (`0..3`).
- **`yy` (Bits 5..4 - 2 bits):** Object ID (`0..3`).
- **`----` (Bits 3..0 - 4 bits):** 4-bit rettighetsmaske med distinkt betydning for hver gruppe.

### 2. 64-bit ACL Layout (G1 C1 G2 C2 G3 C3 G4 C4)
Et 64-bit heltall (`uint64`) inneholder 4 par (8 bytes):
```
Byte 0: G1 (Gruppe 1)      Byte 1: C1 (Kontekstgruppe 1)
Byte 2: G2 (Gruppe 2)      Byte 3: C2 (Kontekstgruppe 2)
Byte 4: G3 (Gruppe 3)      Byte 5: C3 (Kontekstgruppe 3)
Byte 6: G4 (Gruppe 4)      Byte 7: C4 (Kontekstgruppe 4)
```

> **Evalueringsregel:** Gruppe $G_i$ gir kun tilgang dersom tilhørende kontekst $C_i$ er oppfylt:  
> `(active_context & Ci) == Ci`

### 3. Gruppesemantikk (4 distinkte rettigheter per gruppe)

| Gruppe | Navn & Domene | Bit 0 (0x1) | Bit 1 (0x2) | Bit 2 (0x4) | Bit 3 (0x8) |
|---|---|---|---|---|---|
| **G1** | File & Data Storage | `READ` | `WRITE` | `EXECUTE` | `DELETE` |
| **G2** | Network & Messaging | `CONNECT` | `PUBLISH` | `SUBSCRIBE` | `DISCONNECT` |
| **G3** | SCADA & Hardware | `POLL_TELEMETRY` | `SET_ACTUATOR` | `CALIBRATE` | `EMERGENCY_STOP` |
| **G4** | Admin & Security | `VIEW_AUDIT` | `MANAGE_ROLES` | `CONFIG_SYSTEM` | `OVERRIDE` |

---

## 📊 System- og Arkitekturdiagrammer

### 1. ER-diagram (Entity-Relationship & Datamodell)

Viser de logiske entitetene, felt, nøkler og kardinalitet mellom brukere/prosesser, sesjoner, 64-bit ACL-verdier og rettighetsregistre.

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

### 2. 64-bit Bitmask & Minnelayout Diagram

Viser hvordan et 64-bits `uint64`-heltall er pakket i minnet (Big-Endian) som 4 par av $(G_i, C_i)$, samt bit-anatomien til $G_i$ og kontekstmasken $C_i$.

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

---

### 3. Use Case-diagram

Viser aktørene (*Operatør*, *Ingeniør*, *Administrator*, *Bakgrunnsprosess* og *Eksternt API*) og deres samhandling med systemet.

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

### 4. Flytdiagram 1: Kjerneevaluering av tilgang (Evaluator Engine)

Viser den eksakte logikken i `Evaluator.Check` når et 64-bits ACL-tall evalueres mot et mål.

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

### 5. Flytdiagram 2: Webgrensesnitt, Innlogging og Kontekst-simulering

Viser hendelsesforløpet i nettleseren og serveren fra åpning av siden til sanntids evaluering.

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

### 6. Flytdiagram 3: ACL Encode (Bygging av 64-bit heltall)

Viser hvordan JSON-regler for subjekter, objekter, rettighetsnavn og kontekstmasker kodes til et 64-bits `uint64`.

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

### 7. Sekvensdiagram 1: Innlogging og dynamisk tilgangssjekk i Web UI

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

### 8. Sekvensdiagram 2: Ekstern Batch-sjekk over REST API

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

### 9. Systemarkitektur & Komponentdiagram

Viser modulene og avhengighetene i Go-applikasjonen strukturert etter lag.

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

### 10. Tilstandsdiagram (State Diagram)

Viser tilstandsovergangene for brukersesjoner og dynamisk tilgangskontroll.

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

## 📡 REST API Eksempler

### 1. Enkelt Tilgangssjekk (Returnerer true eller false)
```bash
curl -X POST "http://localhost:8080/api/v1/check?raw=true&group=1&subject=1&object=1&right=READ&context=33" \
  -H "Content-Type: application/json" \
  -d '{"acl": 5990264028682846208}'
```
**Respons:**
```
true
```

### 2. Batch-sjekk: Send liste med tall &rarr; Få liste med true/false
```bash
curl -X POST "http://localhost:8080/api/v1/check?group=1&subject=1&object=1&right=READ&context=33" \
  -H "Content-Type: application/json" \
  -d '[5990264028682846208, 0, "0x5321B16574710000", 12345]'
```
**Respons:**
```json
[
  true,
  false,
  true,
  false
]
```

### 3. Dekode 64-bit ACL
```bash
curl "http://localhost:8080/api/v1/decode?acl=0x5321B16574710000"
```

### 4. Enkode / Bygge 64-bit ACL
```bash
curl -X POST http://localhost:8080/api/v1/encode \
  -H "Content-Type: application/json" \
  -d '{
    "pairs": [
      { "pair_index": 1, "subject": 1, "object": 1, "rights": ["READ", "WRITE"], "context": 33 },
      { "pair_index": 2, "subject": 2, "object": 3, "rights": ["CONNECT"], "context": 101 }
    ]
  }'
```