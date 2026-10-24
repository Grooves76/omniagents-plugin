# OmniAgents Business

Collega ChatGPT desktop alla tua installazione **OmniAgents Business** e alle fonti autorizzate di quell’installazione.

[Sito](https://omniagents.it/) · [Assistenza](mailto:info@omniagents.it)

Nel marketplace `omniagents` del repository pubblico [Grooves76/omniagents-plugin](https://github.com/Grooves76/omniagents-plugin), scegli **OmniAgents Business**. L’identificativo completo è `omniagents-business@omniagents`; la versione è `0.1.0`.

Il launcher seleziona sempre `--instance business` e preferisce il runtime incluso nell’app Business. L’indirizzo MCP viene letto dalla configurazione Business dell’utente. Il repository non contiene indirizzi di installazioni, credenziali o ID di plugin cloud. Personal resta un plugin distinto.

Il bridge è lo stesso del plugin Personal. OAuth con PKCE usa un client dedicato; il Portachiavi macOS distingue le autorizzazioni in base a cartella dell’installazione, endpoint e client ChatGPT. Il plugin Business non riusa le credenziali Personal o Claude.

Il catalogo degli strumenti viene letto dal Core Business e dipende dalla versione e dai permessi effettivi. La sola installazione non prova l’autorizzazione, la disponibilità degli strumenti o il funzionamento dei provider. La verifica reale del primo collegamento Business va completata nell’app.

Collegare ChatGPT non cambia l’AI attiva. Se Claude è attivo, ChatGPT resta collegato in attesa e il Core può rispondere `AI_NOT_ACTIVE`; l’utente sceglie quando cambiare modello nell’app. I controlli di identità, permessi, fonti ON/OFF e conferma delle operazioni rimangono nel Core Business.

Questo plugin locale richiede macOS e ChatGPT desktop con supporto ai plugin locali. Non installa un connettore nel normale ChatGPT web o mobile.

Per avviare il collegamento esplicito dal pacchetto locale:

```sh
/bin/sh bin/launch.sh --connect
```

Il comando chiede l’autorizzazione quando necessaria e verifica inizializzazione e catalogo MCP. Non invia richieste agli strumenti e non cambia il modello attivo. I test in `tests/` usano solo fixture locali e non credenziali reali.
