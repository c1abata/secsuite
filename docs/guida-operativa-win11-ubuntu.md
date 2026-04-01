# Guida operativa avanzata SecSuite (Windows 11 + Ubuntu)

> Guida pronta all'uso, scritta per chi deve ottenere risultati professionali in modo ripetibile e senza approccio offensivo.

## 1) Cosa fa davvero SecSuite

SecSuite è una suite **difensiva**: raccoglie evidenze, misura esposizioni e crea report JSON verificabili.

In pratica ti permette di:
- fare controllo ambiente (versione PowerShell, privilegi, modulo AD);
- raccogliere inventario host e osservazioni di rete passive;
- fare audit Active Directory non distruttivo;
- orchestrare validazioni threat-led con policy sicure (no exploit, no brute-force).

## 2) Quando usare Windows 11 e quando Ubuntu

### Usa Windows 11 quando
- devi eseguire l'audit Active Directory in modo completo;
- lavori in un dominio Microsoft con RSAT/ActiveDirectory;
- vuoi la massima compatibilità con tooling amministrativo Windows.

### Usa Ubuntu quando
- vuoi orchestrare assessment passivo o threat-led da una postazione Linux;
- hai bisogno di pipeline CI/CD o automazioni shell lato Linux;
- separi la macchina di raccolta dalla rete utente Windows.

> Strategia consigliata: **Ubuntu per orchestrazione + Windows 11 per audit AD profondo**.

---

## 3) Setup professionale su Windows 11

## 3.1 Prerequisiti
1. PowerShell 7.x installato.
2. Repo SecSuite clonato in una cartella locale (es. `C:\SecSuite`).
3. Se fai AD audit: modulo ActiveDirectory disponibile (tipicamente tramite RSAT).
4. Permessi utente standard per routine normali; apri PowerShell elevata solo se un controllo locale lo richiede.

## 3.2 Verifica ambiente (sempre prima di iniziare)
Apri PowerShell nella root del repo ed esegui:

```powershell
pwsh -NoProfile -File .\scripts\Invoke-EnvironmentCheck.ps1 -OutputPath .\output
```

Cosa controllare nel risultato:
- `PowerShellVersion`
- `IsAdministrator`
- `ADModuleAvailable`
- percorso `OutputPath`

## 3.3 Flusso operativo consigliato (runbook)

### Step A - Baseline passiva host/rete
```powershell
pwsh -NoProfile -File .\scripts\Invoke-PassiveAssessment.ps1 -OutputPath .\output
```
Output atteso:
- inventario host;
- software installato;
- snapshot rete passiva;
- categorie negate dalla policy di sicurezza.

### Step B - Audit Active Directory
```powershell
pwsh -NoProfile -File .\scripts\Invoke-ADAudit.ps1 -OutputPath .\output
```
Output atteso:
- sommario AD;
- findings con misconfiguration note;
- traccia policy difensiva.

### Step C - Threat-led validation (prima dry-run, poi esecuzione)
1) Crea `targets.txt` (un target per riga) e opzionalmente `exclude.txt`.

2) Dry-run (nessuna scansione reale):
```powershell
pwsh -NoProfile -File .\scripts\Invoke-ThreatValidation.ps1 -OutputPath .\output -TargetsPath .\targets.txt -ExcludePath .\exclude.txt -Profile WebTlsBaseline
```

3) Esecuzione reale:
```powershell
pwsh -NoProfile -File .\scripts\Invoke-ThreatValidation.ps1 -OutputPath .\output -TargetsPath .\targets.txt -ExcludePath .\exclude.txt -Profile WebTlsBaseline -Execute
```

Profili disponibili:
- `ResilienceSnmp`
- `IdentityAccess`
- `WindowsProtocol`
- `UnixExposure`
- `MssqlAudit`
- `WebTlsBaseline`

---

## 4) Setup professionale su Ubuntu

## 4.1 Prerequisiti
1. PowerShell 7 installato (`pwsh`).
2. Repo SecSuite clonato (es. `~/secsuite`).
3. `nmap` installato se vuoi eseguire scansioni reali threat-led.
4. Accesso di rete autorizzato verso i target.

## 4.2 Verifica rapida toolchain
Dalla root del repo:

```bash
pwsh -NoProfile -File ./scripts/Invoke-EnvironmentCheck.ps1 -OutputPath ./output
```

Nota: su Ubuntu il campo AD potrebbe non essere disponibile come in Windows; è normale in ambienti non-domain joined.

## 4.3 Flusso operativo Ubuntu

### Step A - Assessment passivo
```bash
pwsh -NoProfile -File ./scripts/Invoke-PassiveAssessment.ps1 -OutputPath ./output
```

### Step B - Threat-led validation
1) prepara `targets.txt`/`exclude.txt`;
2) fai prima dry-run;
3) abilita `-Execute` solo dopo approvazione change.

Esempio:
```bash
pwsh -NoProfile -File ./scripts/Invoke-ThreatValidation.ps1 \
  -OutputPath ./output \
  -TargetsPath ./targets.txt \
  -ExcludePath ./exclude.txt \
  -Profile UnixExposure \
  -Execute
```

---

## 5) Procedura standard "da consulenza" (chiara e ripetibile)

1. **Definisci perimetro**: cosa è incluso/escluso.
2. **Esegui EnvironmentCheck** e salva output.
3. **Esegui PassiveAssessment** per baseline tecnica.
4. **Esegui ADAudit** (se contesto AD su Windows).
5. **Esegui ThreatValidation** (dry-run -> execute).
6. **Archivia report JSON** con timestamp UTC e hostname.
7. **Confronta run successive** per capire miglioramenti o regressioni.

---

## 6) Come leggere i report senza essere sviluppatore

Concentrati su questi blocchi:
- `Context`: dati sessione (host, orario UTC, output path);
- `Findings`: osservazioni da priorizzare;
- `Safety/Principles`: prova che l'esecuzione è rimasta difensiva.

Regola pratica di priorità:
- **Alta**: esposizioni su identità, protocolli legacy, servizi critici;
- **Media**: hardening incompleto ma compensato da controlli;
- **Bassa**: miglioramenti organizzativi/documentali.

---

## 7) Playbook di troubleshooting rapido

## Problema: "ADModuleAvailable = False"
- verifica RSAT/ActiveDirectory su Windows 11;
- riesegui `Invoke-EnvironmentCheck.ps1`.

## Problema: ThreatValidation non parte in execute
- verifica `targets.txt` non vuoto;
- verifica `nmap` disponibile nel PATH;
- esegui prima in dry-run per leggere il piano.

## Problema: output confuso o sparso
- imposta sempre `-OutputPath` dedicato a ogni campagna (es. `./output/clienteA_2026-04-01`).

---

## 8) Governance minima per uso professionale

- Crea una cartella per campagna con: scope, ticket, output, note decisionali.
- Non eseguire mai `-Execute` senza autorizzazione formale.
- Conserva i JSON originali: sono evidenza tecnica.
- Presenta al cliente 3 cose: rischio, impatto operativo, azione consigliata.

---

## 9) Checklist pronta all'uso (copiabile)

### Pre-run
- [ ] Scope approvato
- [ ] Target list validata
- [ ] Exclusion list aggiornata
- [ ] Output path definito
- [ ] EnvironmentCheck eseguito

### Run
- [ ] PassiveAssessment completato
- [ ] ADAudit completato (se applicabile)
- [ ] ThreatValidation dry-run rivisto
- [ ] ThreatValidation execute approvato/eseguito

### Post-run
- [ ] Report JSON archiviati
- [ ] Findings prioritizzati
- [ ] Piano remediation condiviso
- [ ] Follow-up schedulato

---

## 10) Comandi essenziali (quick copy)

### Windows 11
```powershell
pwsh -NoProfile -File .\scripts\Invoke-EnvironmentCheck.ps1 -OutputPath .\output
pwsh -NoProfile -File .\scripts\Invoke-PassiveAssessment.ps1 -OutputPath .\output
pwsh -NoProfile -File .\scripts\Invoke-ADAudit.ps1 -OutputPath .\output
pwsh -NoProfile -File .\scripts\Invoke-ThreatValidation.ps1 -OutputPath .\output -TargetsPath .\targets.txt -ExcludePath .\exclude.txt -Profile IdentityAccess -Execute
```

### Ubuntu
```bash
pwsh -NoProfile -File ./scripts/Invoke-EnvironmentCheck.ps1 -OutputPath ./output
pwsh -NoProfile -File ./scripts/Invoke-PassiveAssessment.ps1 -OutputPath ./output
pwsh -NoProfile -File ./scripts/Invoke-ThreatValidation.ps1 -OutputPath ./output -TargetsPath ./targets.txt -ExcludePath ./exclude.txt -Profile UnixExposure -Execute
```

Questa guida è pensata per essere usata subito: esegui i blocchi in sequenza e conserva sempre gli output per confronto storico.
