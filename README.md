# Keycloak (RedHat SSO) ELSTER Plugin

Plugin für Keycloak bzw. RH-SSO zur Anbindung des ELSTER Unternehmenskontos / NEZO  (https://mein-unternehmenskonto.de/).

## Über das Projekt

Keycloak in der Version vor 20.0.0 sowie die zum aktuellen Zeitpunkt (Dezember 2022) neueste Version 7.6
vom RedHat Single-Sign-On (RH-SSO) ist nicht geeignet für eine Anbindung an das [ELSTER Unternehmenskonto 
(NEZO)](https://mein-unternehmenskonto.de/public/#Startseite), da dort in der SAML-Response komplexe, 
ELSTER-eigene Datentypen verwendet werden.

Ab Keycloak 20.0.0 existiert hierzu ein [Fix](https://github.com/keycloak/keycloak/commit/21f700679f21b71ef89985b835f2d3cf7ac049a0#diff-d619b0a9c091d59cfb785229e2c2b5a4a3d1420eacb25a0ebce4bfee08598548).
Da aber die aktuelle Version der kommerziellen Variante RH-SSO 7.6 auf Keycloak 18.0.3 basiert 
(vgl. die [Komponentenliste](https://access.redhat.com/articles/2342881)), wird dort noch zusätzlicher Code
in Form eines Plugins benötigt.

Das vorliegende Plugin erfüllt diesen Zweck, indem es die komplexen Datentypen in der SAML-Response in einfache Datentypen
vom Typ String umwandelt, bevor die SAML-Response geparst und verarbeitet wird.

<p align="right">(<a href="#top">nach oben</a>)</p>

## Bauen

```
mvn clean install
```

<p align="right">(<a href="#top">nach oben</a>)</p>

## Deployen

**Entweder:**

* Keycloak muss laufen
* Folgendes ausführen

```
mvn wildfly:deploy
```

**Oder:** 

Die Datei `elster-authenticator....jar` aus dem Verzeichnis `target` (existiert nach dem Build-Prozess) in das Keycloak-Verzeichnis 
`standalone/deployments` kopieren. Erst danach den Keycloak starten.


**Immer:**

* Unter `themes\base\admin\resources\partials` die Datei `realm-identity-provider-saml.html` duplizieren und nach `realm-identity-provider-elster.html` umbenennen.
* Fall KeyCloak schon im Browser läuft, einmal refreshen (F5)

<p align="right">(<a href="#top">nach oben</a>)</p>

## Konfigurieren

- Im Keycloak einen Realm `public` anlegen.
- Darin unter `Identity Providers` im Dropdown `ELSTER` auswählen
- Ganz nach unten scrollen und Datei `elster-idp-sso-descriptor-int.xml` (vom LfST) einspielen
- Konfiguration wie in Datei gezeigt `Keycloak-Konfiguration.docx` vornehmen.

<p align="right">(<a href="#top">nach oben</a>)</p>

## Testen

Um auf einem lokalen PC einen Test gegen ELSTER zu realisieren, muss man in der  Windows-Hosts-Datei 
einen neuen Eintrag vornehmen (z.B. `elster.meine-organisation.org`). Unter diesem Eintrag muss man 
dann auch im Keycloak die Metadaten extrahieren und im SSP hinterlegen.
Am besten stellt man den Keycloak-Port noch von standardmäßig 8080 auf 80 um.

Ein Test ist am einfachsten über die in den Keycloak integrierte Account-Anwendung möglich:

Diese ist folgendermaßen zu erreichen:

http://elster.meine-organisation.org/auth/realms/public/account

Falls ELSTER als Default-Provider konfiguriert ist (unter `Authentication->Identity Provider Redirector->Actions->Config->Default` "elster" eintragen), 
kommt man sofort zur Login-Maske von ELSTER, an sonsten kommt die Login-Maske des Keycloak,
wo man dann "ELSTER" anklickt (nicht direkt einloggen).

<p align="right">(<a href="#top">nach oben</a>)</p> 

## Beitragen

Beiträge sind willkommen.

Wenn Sie einen Verbesserungsvorschlag haben, eröffnen Sie bitte ein Issue mit dem Label "enhancement", forken Sie das Repo 
und erstellen Sie einen Pull-Request. Sie können auch einfach ein Issue mit dem Stichwort "Verbesserung" eröffnen.

- Eröffnen Sie ein Issue mit dem Label "enhancement" oder dem Stichwort "Verbesserung".
- Forken Sie das Projekt
- Erstellen Sie einen Feature-Branch (`git checkout -b feature/AmazingFeature`)
- Commiten Sie Ihre Änderungen (`git commit -m 'Add some AmazingFeature'`)
- Machen Sie einen Push (`git push origin feature/AmazingFeature`)
- Erstellen Sie einen Pull-Request

Mehr dazu in der Datei [CODE_OF_CONDUCT](/CODE_OF_CONDUCT.md).

<p align="right">(<a href="#top">nach oben</a>)</p>

## Lizenz

Code steht unter der MIT Lizenz. Siehe [LICENCE](/LICENSE) für mehr Infos.

<p align="right">(<a href="#top">nach oben</a>)</p>



## Kontakt

it@m - opensource@muenchen.de

<p align="right">(<a href="#top">nach oben</a>)</p>
