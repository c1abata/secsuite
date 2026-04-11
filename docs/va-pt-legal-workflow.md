# Workflow VA/PT Legal-Compliant

## Flusso raccomandato

1. Preparare i file di autorizzazione, Rules of Engagement e scope.
2. Validare l’ambiente con `Invoke-EnvironmentCheck.ps1`.
3. Eseguire inventory e passive assessment.
4. Lanciare `Invoke-VaPtWorkflow.ps1` in dry-run per verificare piano e compliance.
5. Passare a `-ExecuteThreatValidation` solo se il gate risulta `Approved`.
6. Riesaminare findings, log ed evidenze generate nel percorso di output.

## Artefatti minimi richiesti

- lettera di autorizzazione o approvazione formale
- Rules of Engagement
- file di scope approvato
- lista target
- procedura di data handling se sono previste evidenze sensibili

## Esempio

```powershell
pwsh -NoProfile -File .\scripts\Invoke-VaPtWorkflow.ps1 `
  -OutputPath .\output `
  -AssessmentType VA-PT `
  -AuthorizationPath .\evidence\authorization.txt `
  -RulesOfEngagementPath .\evidence\roe.txt `
  -ScopePath .\evidence\scope.txt `
  -TargetsPath .\targets.txt `
  -ExcludePath .\exclude.txt `
  -DataHandlingPath .\evidence\data-handling.txt `
  -Profile IdentityAccess `
  -ExecuteThreatValidation
```

## Comportamento del gate

- `Approved`: esecuzione consentita
- `ReviewRequired`: documentazione incompleta, consentita solo preparazione/dry-run
- `Blocked`: esecuzione richiesta ma non conforme ai prerequisiti

## Principi operativi

- semplicità e modularità prima della complessità inutile
- commenti mirati solo dove aggiungono contesto
- fail-closed: in caso di dubbio la suite blocca o degrada a dry-run
- evidenze strutturate e ripetibili per audit e revisione
