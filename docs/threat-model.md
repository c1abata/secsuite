# Threat Model

## Obiettivo

SecSuite supporta vulnerability assessment e penetration testing **solo** in forma autorizzata, defensiva e fail-closed. Il modello di minaccia del progetto si concentra su:

- uso improprio della suite al di fuori di scope approvati
- raccolta eccessiva di dati sensibili
- esecuzione di controlli invasivi o con side effect
- perdita di evidenze o reporting non tracciabile

## Assunzioni di fiducia

- l’operatore ha autorizzazione scritta e scope approvato
- i file di Rules of Engagement e scope sono preparati prima dell’esecuzione
- i target sono forniti dal committente o dal team autorizzante
- l’ambiente di esecuzione protegge gli output generati

## Confini di sicurezza

- nessun exploit
- nessun brute force o spraying
- nessuna remote execution
- nessun cambiamento di stato del target
- solo discovery, audit e raccolta evidenze read-only

## Misure implementate

- compliance gate per VA/PT prima dell’esecuzione attiva
- output deterministico con timestamp UTC, hostname e session id
- profili threat-led con `--disable-arp-ping`
- moduli separati per safety, reporting, AD audit e workflow
- logging testuale e NDJSON per audit trail

## Rischi residui

- i profili Nmap dipendono dalla disponibilità dello strumento sull’host
- la qualità del perimetro dipende dai file di autorizzazione e scope forniti
- le verifiche locali inventory/passive network restano orientate a Windows

## Strategia di riduzione

- mantenere i controlli offensivi fuori dal codice
- trattare come bloccante l’assenza della documentazione legale in fase execute
- ampliare i test unitari sui casi di errore e sulle regressioni di policy
- integrare scansioni CI per secret detection e qualità PowerShell
