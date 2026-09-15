# Auralis — Secure Audio Steganography System

Auralis je C++20 aplikacija za šifriranje poruka i njihovo skrivanje u WAV audio zapisima. Projekat povezuje hibridnu RSA/AES enkripciju i LSB steganografiju, uz konzolni interfejs (CLI) i Windows grafički interfejs (GUI).

Projekat je razvijen u okviru diplomskog rada. Naziv izvršne konzolne aplikacije je `stegowav`.

## Funkcionalnosti

- Generisanje RSA para ključeva i zapis u vlastiti SWKey format.
- Šifriranje poruke pomoću AES-256-CBC i PKCS#7 dopune.
- Šifriranje nasumičnog AES sesijskog ključa pomoću RSA-OAEP sa SHA-256 i MGF1.
- Skrivanje šifriranog paketa u najmanje značajnim bitovima PCM uzoraka.
- Izdvajanje i dešifriranje poruke odgovarajućim privatnim ključem.
- Unos kratkih poruka kroz CLI argument ili učitavanje kompletnog fajla.
- Ispis izdvojene poruke u konzolu ili zapis izvornih bajtova u fajl.
- GUI za izbor WAV zapisa i ključeva, generisanje ključeva i rad s tekstualnim porukama.

## Pokretanje gotove GUI aplikacije

Gotov Windows GUI nalazi se u fajlu [Auralis.exe](Auralis.exe) u korijenu repozitorija. Preuzmi taj fajl preko GitHub opcije **Download raw file**, a zatim ga pokreni dvostrukim klikom ili iz PowerShella:

```powershell
.\Auralis.exe
```

Za ovaj izvršni fajl nisu potrebni CMake ni kompajler. MinGW runtime biblioteke uključene su statički; aplikacija i dalje koristi Windows sistemske biblioteke. WAV zapise i ključeve korisnik bira ili generiše kroz aplikaciju.

## Zahtjevi za samostalni build

- Windows: GUI koristi Win32 API, a generator slučajnih bajtova Windows `BCryptGenRandom`.
- C++ kompajler s podrškom za C++20.
- CMake 3.20 ili noviji.
- Za build prikazan ispod: MinGW-w64 i `mingw32-make`, dostupni kroz `PATH`.

Kriptografski algoritmi implementirani su unutar projekta. CMake povezuje Windows biblioteke `bcrypt`, `comdlg32` i `comctl32`.

## Samostalni build iz izvornog koda

Preuzmi repozitorij pomoću `git clone` ili GitHub opcije **Code → Download ZIP** i raspakuj ga. Instaliraj navedene build alate, otvori PowerShell u korijenu projekta (pored `CMakeLists.txt`) i pokreni:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=bin
cmake --build build -j 4
```

Ove komande postavljaju izvršne fajlove u:

```text
build/bin/stegowav.exe
build/bin/Auralis.exe
```

Ako postojeći `build` koristi drugi generator ili je napravljen na drugoj putanji, koristi novi build direktorij i prilagodi putanje u narednim primjerima.

Ako želiš buildati samo GUI, nakon CMake konfiguracije pokreni:

```powershell
cmake --build build --target stegowav_gui -j 4
.\build\bin\Auralis.exe
```

`stegowav_gui` je naziv CMake targeta, a `Auralis.exe` naziv njegovog izlaznog fajla. Samostalni build ne zamjenjuje gotovi fajl u korijenu. Za ažuriranje te kopije nakon builda koristi:

```powershell
Copy-Item .\build\bin\Auralis.exe .\Auralis.exe -Force
```

## CLI

Sve naredne komande izvršavaju se iz korijena repozitorija. Ulazni WAV zapisi, poruke i ključevi iz primjera nisu uključeni u repozitorij. Putanje koje sadrže razmake stavi pod navodnike.

### Sintaksa

```text
stegowav.exe generate-keys <modulusBits> <publicExponent> <publicKeyFile> <privateKeyFile>
stegowav.exe embed <inputWav> <outputWav> <publicKeyFile> <message>
stegowav.exe embed-file <inputWav> <outputWav> <publicKeyFile> <messageFile>
stegowav.exe extract <inputWav> <privateKeyFile>
stegowav.exe extract-file <inputWav> <privateKeyFile> <outputMessageFile>
```

### 1. Generisanje ključeva

Primjer za modul od 2048 bita i javni eksponent 65537:

```powershell
.\build\bin\stegowav.exe generate-keys 2048 65537 JavniKljuc.swkey PrivatniKljuc.swkey
```

Argumenti redom određuju broj bita modula, javni eksponent, izlazni javni ključ i izlazni privatni ključ.

### 2. Skrivanje kratke tekstualne poruke

```powershell
.\build\bin\stegowav.exe embed test.wav stego_test.wav JavniKljuc.swkey "Moja tajna poruka"
```

`embed` prima samu poruku kao jedan argument komandne linije. Ne čita sadržaj fajla niti standardni ulaz.

### 3. Skrivanje poruke iz fajla

```powershell
.\build\bin\stegowav.exe embed-file test.wav stego_test.wav JavniKljuc.swkey test_poruka_1MB.txt
```

`embed-file` čita kompletan fajl u binarnom režimu, bez promjene kodiranja, završetaka redova ili uklanjanja BOM-a. Kroz argument se prenosi samo putanja, čime se izbjegava ograničenje dužine komandne linije za velike poruke.

### 4. Izdvajanje u konzolu

```powershell
.\build\bin\stegowav.exe extract stego_test.wav PrivatniKljuc.swkey
```

`extract` ispisuje oznaku `Message:`, dešifriranu poruku i završni novi red. Za tačno očuvanje bajtova koristi `extract-file`.

### 5. Izdvajanje u fajl

```powershell
.\build\bin\stegowav.exe extract-file stego_test.wav PrivatniKljuc.swkey izdvojena_poruka.txt
```

`extract-file` zapisuje dešifrirane bajtove u binarnom režimu, bez dodatnih oznaka ili promjene sadržaja. U konzolu ispisuje samo kratku potvrdu i izlaznu putanju.

Izlazni fajlovi se prepisuju ako već postoje. Za ulazni i izlazni WAV koristi različite putanje. CLI vraća izlazni kod `0` za uspjeh i `1` za prijavljenu grešku.

## Windows GUI

```powershell
.\build\bin\Auralis.exe
```

- **Encrypt:** izaberi ulazni WAV i javni SWKey, upiši poruku u polje **Secret message**, odredi izlazni WAV i pokreni skrivanje.
- **Generate:** otvori dijalog za generisanje RSA ključeva.
- **Decrypt:** izaberi stego WAV i odgovarajući privatni SWKey, zatim pokreni izdvajanje.

GUI prikazuje veličinu unesene poruke u UTF-8 bajtovima i čuva lokalne postavke u `auralis.ini` pored izvršnog fajla. Za velike poruke iz fajlova koristi CLI komande `embed-file` i `extract-file`.

## WAV format i kapacitet

Podržani su RIFF/WAVE zapisi s PCM oznakom formata `1` i dubinama uzorka od 8, 16, 24 ili 32 bita. Kompresovani i floating-point WAV formati nisu podržani.

Implementacija koristi jedan najmanje značajan bit po pojedinačnom uzorku, uključujući uzorke svih kanala:

```text
broj_uzoraka = broj_bajtova_PCM_podataka / (bitsPerSample / 8)
kapacitet_u_bajtovima = floor(broj_uzoraka / 8)
```

Ovo je kapacitet za kompletan šifrirani paket, a ne samo izvornu poruku. Potrebno je uračunati šifrirani AES ključ, IV, dopunu i zaglavlja paketa. `EmbedService` provjerava konačnu veličinu prije upisa LSB podataka i odbija poruku koja ne može stati.

Naknadna izmjena audio uzoraka, poput normalizacije, resampliranja ili konverzije u format s gubicima, može oštetiti skrivene podatke.

## Tok obrade i arhitektura

```text
Poruka → AES-256-CBC → hibridni paket → payload → LSB → stego WAV
                         ↑
              AES ključ šifriran RSA-OAEP-om
```

Pri izdvajanju se tok obrće: čitaju se LSB podaci, dekodira paket, privatnim RSA ključem dešifrira AES ključ i zatim poruka.

| Modul | Odgovornost |
| --- | --- |
| `wav` | Čitanje i zapisivanje RIFF/WAVE strukture |
| `audio` | Pristup PCM uzorcima |
| `crypto` | Veliki brojevi, prosti brojevi, RSA, AES, OAEP, hash, hibridna enkripcija i SWKey |
| `payload` | Kodiranje i dekodiranje paketa za skrivanje |
| `steganography` | Kapacitet, LSB skrivanje i izdvajanje |
| `application` | `EmbedService` i `ExtractService` koji povezuju module |
| `gui` | Win32 interfejs i lokalne postavke |
| `src/main.cpp` | CLI komande, argumenti i ulaz/izlaz poruka |

Zaglavlja se nalaze u `include/stegowav/`, a implementacije u odgovarajućim poddirektorijima `src/`.

## Mjerenje performansi

Primjeri za PowerShell, nakon builda u istoj konfiguraciji:

```powershell
Measure-Command { .\build\bin\stegowav.exe generate-keys 2048 65537 public_2048_1.swkey private_2048_1.swkey }
Measure-Command { .\build\bin\stegowav.exe embed-file test.wav stego_test.wav public_2048_1.swkey test_poruka_1MB.txt }
Measure-Command { .\build\bin\stegowav.exe extract-file stego_test.wav private_2048_1.swkey izdvojena_poruka.txt }
```

Mjerenje obuhvata kompletan CLI postupak: pokretanje procesa, potrebna učitavanja, obradu i zapis izlaznih fajlova. Ne predstavlja izolovano vrijeme kriptografskog ili LSB algoritma. `extract-file` izbjegava ispis sadržaja velike poruke na terminal, ali uključuje zapis poruke na disk.

Za ponovljena mjerenja koristi različita izlazna imena i zabilježi konfiguraciju builda, hardver, veličinu poruke, WAV format i RSA parametre. Prije prihvatanja rezultata provjeri da je komanda završila uspješno.

## Lokalni fajlovi

`.gitignore` isključuje build artefakte, `.swkey` ključeve, `.wav` zapise, lokalne testne i izdvojene poruke prema definisanim obrascima te `auralis.ini`. Ti fajlovi se generišu ili pripremaju lokalno i nisu potrebni za preuzimanje izvornog koda.
