# CyberNexus AI

Terminal Java project for scanning suspicious URLs and phishing-style messages, saving history in MySQL, and explaining risk locally when an AI API is unavailable.

Work stays on the **`harman`** branch (not `main`), matching the assignment Git commands:

```
git fetch origin
git branch -a
git switch -c harman --track origin/harman
git branch
```

## Team split from the PDF

| Person | Area |
| --- | --- |
| Harman | Authentication, JDBC, MySQL, scan history, admin statistics |
| Tanisha | URL/message detectors, risk scoring, AI explanation |
| Aarchi | Terminal menus and module integration |

## Setup

1. Install Java 21, Maven, and MySQL.
2. Run `database/schema.sql` in MySQL.
3. Copy `src/main/resources/database.properties.example` to `src/main/resources/database.properties` and set your username/password.
4. Optional admin account after you register:

```sql
UPDATE users SET role = 'admin' WHERE email = 'your.email@example.com';
```

## Run

```
mvn test
mvn compile exec:java
```

Welcome menu: Register / Login / Exit. After login, users get the dashboard (URL scan, message scan, history, tips, AI explanation). Admins get statistics and all-scan reports.

Leave `ai.api.url` empty so explanations use the built-in fallback. The app still runs if a remote API is down.
