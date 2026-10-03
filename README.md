# Security Testing Toolkit — Golang

Application locale écrite en Go comprenant :

- un générateur de PoC CSRF à partir d'une requête HTTP brute ;
- un moniteur OAST utilisant les callbacks HTTP, DNS et e-mail de Webhook.site ;
- aucun stockage serveur et aucune base de données.

## Démarrage

Go 1.24 ou plus récent est requis.

```powershell
go run .
```

Puis ouvrir <http://127.0.0.1:8787>.

## Tests

```powershell
go test ./...
```

Pour construire un exécutable Windows autonome :

```powershell
go build -o security-testing-toolkit.exe .
```

Les fichiers de l'interface sont intégrés dans l'exécutable avec `go:embed`. Il n'est donc pas nécessaire de copier le dossier `public` avec le fichier `.exe`.

## Utilisation OAST

1. Créer une URL sur <https://webhook.site>.
2. Copier uniquement son UUID dans l'onglet **OAST Monitor**.
3. Générer un nouvel identifiant de corrélation pour chaque essai.
4. Utiliser l'adresse HTTP ou DNS produite sur un système dont vous êtes autorisé à tester la sécurité.
5. Cliquer sur **Actualiser les événements**.

La clé API Webhook.site est facultative et reste dans la mémoire de l'onglet. Le token est gardé dans `sessionStorage` jusqu'à la fermeture de l'onglet.

## Portée du MVP

- Formulaires GET et POST `application/x-www-form-urlencoded`.
- Variante `text/plain` simple.
- Une requête JSON produit un exemple `fetch` accompagné d'un avertissement CORS : elle n'est pas considérée automatiquement comme une PoC CSRF valide.
- Les champs texte et fichiers `multipart/form-data` sont pris en charge. Un fichier peut être intégré dans la PoC sous forme de Blob encodé en Base64, ou demandé manuellement avec un champ fichier.

Cet outil est destiné exclusivement aux systèmes que vous possédez ou pour lesquels vous avez une autorisation explicite de test.
