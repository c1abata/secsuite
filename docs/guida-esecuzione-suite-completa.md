# Guida step-by-step: esecuzione completa della suite SecSuite

> Versione pratica pensata anche per chi non sviluppa: segui i passaggi in ordine, copia i comandi, conserva gli output.

## 1) Obiettivo della guida

Questa guida ti accompagna nell'esecuzione **end-to-end** di SecSuite:
1. verifica dell'ambiente;
2. assessment passivo;
3. audit Active Directory (se applicabile);
4. threat validation (dry-run + esecuzione reale);
5. test della suite (Pester);
6. raccolta e organizzazione evidenze.

---

## 2) Prima di iniziare (5 minuti)

### 2.1 Cosa ti serve
- repository SecSuite già clonata;
- PowerShell 7 (`pwsh`);
- cartella di output dedicata;
- autorizzazione formale sul perimetro target;
- su Linux: `nmap` installato (solo per `-Execute` su ThreatValidation);
- su Windows AD: modulo ActiveDirectory/RSAT disponibile.

### 2.2 Regola d'oro operativa
Esegui sempre in questo ordine:
**EnvironmentCheck -> PassiveAssessment -> ADAudit -> ThreatValidation (dry-run) -> ThreatValidation (execute) -> Pester**.

---

## 3) Preparazione workspace (Windows e Ubuntu)

### 3.1 Vai nella root progetto

Windows:
```powershell
cd C:\SecSuite
```

Ubuntu:
```bash
cd ~/secsuite
```

### 3.2 Crea una cartella output per campagna

Windows:
```powershell
$RunId = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd_HHmmss')
$Out = ".\\output\\run_$RunId"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
$Out
```

Ubuntu:
```bash
run_id="$(date -u +%Y-%m-%d_%H%M%S)"
out="./output/run_${run_id}"
mkdir -p "$out"
echo "$out"
```

> Perché farlo: ogni run resta tracciabile e confrontabile nel tempo.

---

## 4) Step-by-step: esecuzione completa

## Step 1 - Environment Check
Verifica prerequisiti minimi e stato locale.

Windows:
```powershell
pwsh -NoProfile -File .\scripts\Invoke-EnvironmentCheck.ps1 -OutputPath $Out
```

Ubuntu:
```bash
pwsh -NoProfile -File ./scripts/Invoke-EnvironmentCheck.ps1 -OutputPath "$out"
```

**Cosa controllare nel JSON risultante:**
- versione PowerShell;
- privilegi correnti;
- disponibilità modulo AD (soprattutto su Windows domain scenario);
- path output corretto.

---

## Step 2 - Passive Assessment
Raccoglie inventario host + osservazioni rete passive, senza approccio offensivo.

Windows:
```powershell
pwsh -NoProfile -File .\scripts\Invoke-PassiveAssessment.ps1 -OutputPath $Out
```

Ubuntu:
```bash
pwsh -NoProfile -File ./scripts/Invoke-PassiveAssessment.ps1 -OutputPath "$out"
```

**Output atteso:** metadati host, software, snapshot rete, policy safety applicate.

---

## Step 3 - AD Audit (solo se ambiente AD)
Esegui questo step quando lavori in contesto Active Directory.

Windows:
```powershell
pwsh -NoProfile -File .\scripts\Invoke-ADAudit.ps1 -OutputPath $Out
```

Ubuntu/non-domain:
- in molti casi non applicabile o limitato;
- se non applicabile, documenta il motivo nel report operativo.

**Output atteso:** summary AD + finding su misconfiguration note.

---

## Step 4 - Threat Validation (prima dry-run)

### 4.1 Crea `targets.txt`
Un target per riga (hostname o IP autorizzato).

Esempio:
```text
10.10.10.12
srv-app-01.internal.local
```

### 4.2 (Opzionale) crea `exclude.txt`
Risorse da escludere.

### 4.3 Esegui dry-run (obbligatorio prima di execute)
Windows:
```powershell
pwsh -NoProfile -File .\scripts\Invoke-ThreatValidation.ps1 -OutputPath $Out -TargetsPath .\targets.txt -ExcludePath .\exclude.txt -Profile WebTlsBaseline
```

Ubuntu:
```bash
pwsh -NoProfile -File ./scripts/Invoke-ThreatValidation.ps1 -OutputPath "$out" -TargetsPath ./targets.txt -ExcludePath ./exclude.txt -Profile WebTlsBaseline
```

**Scopo:** validare piano e parametri senza avviare scansioni reali.

---

## Step 5 - Threat Validation execute (solo dopo approvazione)

Windows:
```powershell
pwsh -NoProfile -File .\scripts\Invoke-ThreatValidation.ps1 -OutputPath $Out -TargetsPath .\targets.txt -ExcludePath .\exclude.txt -Profile WebTlsBaseline -Execute
```

Ubuntu:
```bash
pwsh -NoProfile -File ./scripts/Invoke-ThreatValidation.ps1 -OutputPath "$out" -TargetsPath ./targets.txt -ExcludePath ./exclude.txt -Profile WebTlsBaseline -Execute
```

Profili disponibili:
- `ResilienceSnmp`
- `IdentityAccess`
- `WindowsProtocol`
- `UnixExposure`
- `MssqlAudit`
- `WebTlsBaseline`

> Consiglio pratico: parti da `WebTlsBaseline` o `UnixExposure`, poi estendi ai profili specifici.

---

## Step 6 - Esegui i test dell'intera suite (Pester)

Windows:
```powershell
Invoke-Pester -Path .\tests\unit
```

Ubuntu:
```bash
pwsh -NoProfile -Command "Invoke-Pester -Path ./tests/unit"
```

Se Pester non è installato:
```powershell
Install-Module Pester -Scope CurrentUser -Force
```

---

## Step 7 - Validazione finale output

Checklist minima:
- sono presenti file JSON per gli step eseguiti;
- i timestamp sono in UTC;
- i file appartengono alla stessa run (`run_yyyy-mm-dd_hhmmss`);
- eventuali errori non fatali sono tracciati ma non hanno interrotto il flusso;
- i finding sono classificabili per priorità (Alta/Media/Bassa).

---

## 5) Procedura rapida "copia e incolla" (Windows)

```powershell
cd C:\SecSuite
$RunId = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd_HHmmss')
$Out = ".\\output\\run_$RunId"
New-Item -ItemType Directory -Path $Out -Force | Out-Null

pwsh -NoProfile -File .\scripts\Invoke-EnvironmentCheck.ps1 -OutputPath $Out
pwsh -NoProfile -File .\scripts\Invoke-PassiveAssessment.ps1 -OutputPath $Out
pwsh -NoProfile -File .\scripts\Invoke-ADAudit.ps1 -OutputPath $Out
pwsh -NoProfile -File .\scripts\Invoke-ThreatValidation.ps1 -OutputPath $Out -TargetsPath .\targets.txt -ExcludePath .\exclude.txt -Profile WebTlsBaseline
pwsh -NoProfile -File .\scripts\Invoke-ThreatValidation.ps1 -OutputPath $Out -TargetsPath .\targets.txt -ExcludePath .\exclude.txt -Profile WebTlsBaseline -Execute
Invoke-Pester -Path .\tests\unit
```

---

## 6) Procedura rapida "copia e incolla" (Ubuntu)

```bash
cd ~/secsuite
run_id="$(date -u +%Y-%m-%d_%H%M%S)"
out="./output/run_${run_id}"
mkdir -p "$out"

pwsh -NoProfile -File ./scripts/Invoke-EnvironmentCheck.ps1 -OutputPath "$out"
pwsh -NoProfile -File ./scripts/Invoke-PassiveAssessment.ps1 -OutputPath "$out"
pwsh -NoProfile -File ./scripts/Invoke-ThreatValidation.ps1 -OutputPath "$out" -TargetsPath ./targets.txt -ExcludePath ./exclude.txt -Profile WebTlsBaseline
pwsh -NoProfile -File ./scripts/Invoke-ThreatValidation.ps1 -OutputPath "$out" -TargetsPath ./targets.txt -ExcludePath ./exclude.txt -Profile WebTlsBaseline -Execute
pwsh -NoProfile -Command "Invoke-Pester -Path ./tests/unit"
```

---

## 7) Troubleshooting essenziale

- **Errore modulo AD mancante**: installa/abilita RSAT Active Directory su Windows e rilancia Step 1.
- **`targets.txt` vuoto o invalido**: ThreatValidation non parte in execute in modo utile.
- **`nmap` non trovato su Linux**: installa `nmap` o resta in dry-run.
- **Output confuso tra campagne**: usa sempre una nuova cartella `run_...`.

---

## 8) Chiusura operativa (consigliata)

A fine run:
1. comprimi la cartella output della campagna;
2. allega note: scope, data UTC, profili usati, eventuali esclusioni;
3. prepara un breve executive summary con top finding e remediation.

Questa è la base di un processo serio, ripetibile e difensivo, in stile engineering pulito: pochi passi, chiari, verificabili.
