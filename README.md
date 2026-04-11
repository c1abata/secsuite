# SecSuite

Suite PowerShell difensiva per security assessment passivo, audit Active Directory e reporting tecnico su Windows 11.

## Scopo

SecSuite è progettata per:

- inventory e raccolta evidenze locali
- ricognizione passiva e non intrusiva
- review di configurazioni SMB, web, VPN e host
- audit Active Directory e verifica di misconfiguration note
- mapping di base verso controlli ISO/IEC 27001, NIST SP 800-115 e baseline Microsoft
- generazione di report JSON leggibili e verificabili

## Limiti espliciti

SecSuite **non** implementa e blocca per policy:

- exploit
- brute force
- spraying
- password attacks
- coercion
- lateral movement
- execution remota
- modifica dello stato del target

## Requisiti

- Windows 11
- PowerShell 7.x consigliato
- Pester 5 per i test
- privilegi standard per la maggior parte delle funzioni; elevazione solo per controlli locali che la richiedono

## Struttura

```text
config/                  configurazione della suite
modules/Core/            logging, config, report helpers
modules/Safety/          guardrail e policy difensive
modules/Inventory/       inventory locale host e software
modules/PassiveNetwork/  raccolta passiva di dati di rete
modules/ADAudit/         audit AD non distruttivo
modules/ThreatValidation/ orchestrazione threat-led difensiva (no exploit)
modules/Workflow/        blocchi legali, compliance gate e workflow VA/PT
scripts/                 entry point operativi
tests/unit/              test Pester sicuri e dimostrativi
docs/                    preparazione ambiente, safety model, compliance
- `docs/guida-operativa-win11-ubuntu.md` guida operativa avanzata pronta all'uso (Windows 11 + Ubuntu)
- `docs/guida-esecuzione-suite-completa.md` guida step-by-step per eseguire l'intera suite (Windows 11 + Ubuntu)
```

## Uso rapido

```powershell
pwsh -NoProfile -File .\\scripts\\Invoke-EnvironmentCheck.ps1
pwsh -NoProfile -File .\\scripts\\Invoke-PassiveAssessment.ps1 -OutputPath .\\output
pwsh -NoProfile -File .\\scripts\\Invoke-ADAudit.ps1 -OutputPath .\\output
pwsh -NoProfile -File .\\scripts\\Invoke-VaPtWorkflow.ps1 -OutputPath .\\output -AssessmentType VA -AuthorizationPath .\\evidence\\authorization.txt -RulesOfEngagementPath .\\evidence\\roe.txt -ScopePath .\\evidence\\scope.txt -TargetsPath .\\targets.txt
Invoke-Pester -Path .\\tests\\unit
```

## Principi di progetto

- moduli piccoli e leggibili
- flussi autorizzati e legal-compliant prima di ogni esecuzione attiva
- output deterministico
- nessuna dipendenza offensiva
- fail closed: ciò che non è marcato sicuro viene negato
- evidenze in JSON, con timestamp UTC e hostname

## Output

Ogni esecuzione produce file JSON con:

- metadati host
- timestamp UTC
- findings o osservazioni
- errori non fatali
- hash calcolabile a valle per catena di custodia

## Note operative

La suite è adatta a laboratori, assessment autorizzati, verifiche di hardening e audit difensivi. Non è una piattaforma di red team né una suite di exploitation.


## Audit AD anche senza domain join (stile PingCastle/BloodHound, ma difensivo)

Il modulo `ADAudit` ora supporta due modalità:

- `ConnectionMode = 'Auto'`: usa `ActiveDirectory` se il modulo è disponibile.
- `ConnectionMode = 'Ldap'`: raccoglie dati via LDAP/LDAPS anche da host **non joinati**.

Novità principali:

- raccolta delle evidenze AD via LDAP (`users`, `computers`, `trusts`, gruppi privilegiati)
- calcolo `ExposureScore` (rating Low/Medium/High/Critical)
- produzione `AttackPaths` (grafo relazioni membro→gruppo, utile per analisi tipo path review)

Esempio rapido (host non joinato):

```powershell
$cred = Get-Credential
pwsh -NoProfile -File .\scripts\Invoke-ADAudit.ps1 -OutputPath .\output -DomainController dc01.contoso.local -UseLdaps -Credential $cred
```

> Nota: la suite resta difensiva e read-only. Non include azioni offensive o modifica dello stato AD.

## Threat-led validation difensiva

Per integrare le richieste operative (NIS2/DORA, controlli infrastrutturali, focus Windows/Linux/DB) mantenendo una postura difensiva:

- i profili sono eseguibili in PowerShell
- le scansioni Nmap usano sempre `--disable-arp-ping`
- non sono presenti exploit o brute-force: solo discovery, hardening check e raccolta evidenze

Profili disponibili in `Invoke-ThreatValidation.ps1`:

- `ResilienceSnmp`
- `IdentityAccess`
- `WindowsProtocol`
- `UnixExposure`
- `MssqlAudit`
- `WebTlsBaseline`

Esecuzione reale (non dry-run):

```powershell
pwsh -NoProfile -File .\scripts\Invoke-ThreatValidation.ps1 -OutputPath .\output -TargetsPath .\targets.txt -ExcludePath .\exclude.txt -AuthorizationPath .\evidence\authorization.txt -RulesOfEngagementPath .\evidence\roe.txt -ScopePath .\evidence\scope.txt -Profile MssqlAudit -Execute
```

## Workflow VA/PT legal-compliant

Il nuovo entrypoint `Invoke-VaPtWorkflow.ps1` unifica:

- verifiche legali minime prima dell'esecuzione
- inventory e passive assessment
- threat validation con profili safe-by-default
- audit AD opzionale
- report consolidato con engagement, confini operativi e mapping compliance

Documentazione correlata:

- `docs/va-pt-legal-workflow.md`
- `docs/threat-model.md`
- `devsecops-review-secsuite.md`
