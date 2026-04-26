# simple_honeypot

## Descriere

`simple_honeypot` este un honeypot web simplu pentru monitorizarea traficului web suspect și colectarea datelor despre tentativele de atac. Scopul este de a evidenția tiparele de scanare și exploatare folosite de atacatori automatizați.

## Implementare

Aplicația rulează ca un serviciu HTTP care:

- răspunde la cereri HTTP standard (GET, POST, HEAD etc.)
- analizează cererile primite
- detectează semnături de atac (de exemplu path traversal, command injection, RFI/LFI)
- loghează fiecare solicitare într-un format JSON structurat

Fiecare intrare de log conține:

- `timestamp`
- `src_ip`
- `http_method`
- `endpoint`
- `user_agent`
- `attack_type`
- `status_code`

Aplicația nu oferă funcționalități reale, ea simulează prezența unui server vulnerabil pentru a atrage atacatori.

## Structura generală a logurilor

Toate evenimentele sunt înregistrate în format JSON, fiecare obiect reprezentând o cerere HTTP individuală. Structura permite corelarea rapidă între sursă, tipul cererii și comportamentul malițios detectat.

Exemplu de log:

```json
{
  "timestamp": "2026-02-01T03:12:44Z",
  "src_ip": "185.220.101.45",
  "http_method": "GET",
  "endpoint": "/.env",
  "user_agent": "python-requests/2.28.1",
  "attack_type": "LFI",
  "status_code": 404
}
```

Acest format permite analiza manuală și procesarea automată ulterioară.

## Rulare și colectare date

Aplicația a fost lăsată să ruleze timp de 5 zile consecutive fără intervenție manuală. Toate evenimentele au fost înregistrate în directorul <a href="file:///C:/Users/Denisa/Desktop/faculta/Master/anul%201/Sem%202/SAC/honeypot/Logs">Logs</a>, iar logurile din acest director reflectă activitatea zilnică pe durata perioadei de monitorizare.

## Analiză detaliată a logurilor honeypot

### Ziua 1 — Inițierea scanărilor și recunoaștere automată

Imediat după expunerea aplicației, s-a observat un volum ridicat de cereri HTTP. Aceasta indică detectarea rapidă a serviciului de către infrastructuri automate de scanare.

Majoritatea solicitărilor au fost orientate către resursa root (`/`), urmate de fișiere și directoare cu valoare informațională ridicată:

- `/.env`
- `/.git/config`
- `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`

Tentativele au inclus:

- path traversal (de exemplu secvențe `../`)
- command injection
- RFI/LFI

User-agent-urile observate (`zgrab`, `python-requests`) sugerează utilizarea unor unelte standard de scanare, fără mascarea identității.

Predominanța codurilor de răspuns `404` și `403` sugerează o fază de recunoaștere, fără adaptare activă la feedback-ul serverului.

**Interpretare:** Ziua 1 confirmă că serviciile expuse public sunt rapid incluse în ciclurile automate de scanare globale, chiar fără o vizibilitate prealabilă semnificativă.

### Ziua 2 — Consolidarea scanărilor și repetitivitate

Activitatea malițioasă a continuat într-un ritm constant, cu reluarea acelorași tipuri de cereri ca în prima zi.

Scanările au fost extinse către:

- endpoint-uri de administrare
- fișiere de configurare
- directoare asociate framework-urilor web PHP

S-au observat:

- variații frecvente ale adreselor IP
- reutilizarea structurilor de cerere, cu modificări minime

Tipurile de atac detectate au rămas identice cu cele din ziua precedentă, fără vectori noi.

**Interpretare:** Această zi sugerează rularea unor campanii de scanare distribuite, bazate pe liste predefinite de resurse și semnături, fără inteligență adaptivă.

### Ziua 3 — Diversificarea vectorilor de atac

A crescut diversitatea endpoint-urilor vizate:

- API-uri REST
- endpoint-uri de tip health check/metrics
- fișiere sensibile în formate YAML și JSON

Traficul includea cereri provenite de la infrastructuri asociate unor servicii cunoscute de cartografiere și cercetare a internetului (de exemplu `Censys`).

Deși sursele erau diferite, structura cererilor a rămas rigidă și predictibilă, iar interacțiunile legitime erau inexistente.

**Interpretare:** Această etapă sugerează suprapunerea mai multor campanii automate, cu scopuri diferite (exploatare vs. cartografiere), care operează independent asupra aceleiași ținte.

### Ziua 4 — Atacuri focalizate pe ecosisteme web populare

S-au înregistrat constant cereri către:

- `/.env`
- `/.git`
- `/vendor/phpunit`
- `/cgi-bin`

Atacurile au fost organizate secvențial pe structuri asociate framework-urilor populare:

- Laravel
- Drupal
- Yii
- Zend

Nu s-au observat:

- tentative manuale
- ajustări ale payload-urilor în funcție de răspunsul serverului

Traficul a fost exclusiv malițios.

**Interpretare:** Modelul indică utilizarea unor șabloane predefinite, optimizate pentru exploatarea rapidă a vulnerabilităților cunoscute din ecosisteme web larg răspândite.

### Ziua 5 — Stabilizarea tiparului de atac

Activitatea din ultima zi a fost aproape identică cu cea din zilele precedente.

S-au observat:

- adrese IP și user-agent-uri noi
- aceleași endpoint-uri și tehnici de atac

Codurile de răspuns HTTP negative nu au oprit scanările.

Nu există semne de compromitere sau escaladare.

**Interpretare:** Persistența atacurilor, chiar și în lipsa succesului, evidențiază natura oportunistă și complet automatizată a scanărilor, fără feedback uman.

## Concluzie analitică

Logurile demonstrează un volum constant de trafic malițios automatizat, distribuit global. Atacurile au fost:

- repetitive
- nesofisticate din punct de vedere logic
- bazate pe liste și semnături cunoscute

Lipsa adaptării sugerează că obiectivul principal este identificarea rapidă a țintelor vulnerabile, nu compromiterea activă.

Honeypot-ul a oferit un set de date reprezentativ pentru comportamentul real al atacatorilor web contemporani.
