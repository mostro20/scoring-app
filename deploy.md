# Deploying the scoring app

The production VM runs Ubuntu 24.04 and is available as `scoring-app`. These
instructions assume `ssh scoring-app` is configured locally. If it is not, use
the VM's normal SSH username and address instead.

The application checkout is `/home/azureuser/scoring-app/`. Production data is
kept outside the checkout:

- SQLite database: `/var/lib/hnc-scoring/scoring.db`
- Uploaded files: `/var/lib/hnc-scoring/uploads/`
- systemd service: `scoring-app.service`

The service definition is managed on the VM rather than in this repository.

## Prepare the release locally

From the repository root:

```bash
source venv/bin/activate
python -m pip install --requirement requirements.txt
python -m pip check
python -m unittest discover -s tests -v
```

If `pip-audit` is installed, verify the production pins too:

```bash
pip-audit --requirement requirements.txt --progress-spinner off
```

Review and commit all intended changes, then push the release branch. Deploy a
reviewed commit through the normal merge process; do not deploy an uncommitted
working tree.

## Connect and inspect the running service

```bash
ssh scoring-app
sudo systemctl status scoring-app --no-pager
sudo systemctl cat scoring-app
```

The unit definition should show its `WorkingDirectory`, `EnvironmentFile`,
service user and `ExecStart`. Confirm its `WorkingDirectory` is
`/home/azureuser/scoring-app`, then check the checkout:

```bash
cd /home/azureuser/scoring-app
git remote -v
git status --short
git branch --show-current
```

Stop if there are unexpected local changes. The configured environment must
continue to set:

```text
SQLALCHEMY_DATABASE_URI=sqlite:////var/lib/hnc-scoring/scoring.db
UPLOAD_FOLDER=/var/lib/hnc-scoring/uploads
```

Do not overwrite the database, uploaded files or configured environment during
a deployment. `SECRET_KEY` and `CAPTCHA_SECRET` must also remain stable, random
values of at least 32 bytes; rotating `SECRET_KEY` signs every user out.

## Back up the database

The production SQLite database is outside the Git checkout at
`/var/lib/hnc-scoring/scoring.db`. Stop the application before copying it so the
backup is consistent:

```bash
sudo systemctl stop scoring-app
sudo install -d -m 0750 /var/backups/hnc-scoring
SCORING_BACKUP="/var/backups/hnc-scoring/scoring-$(date -u +%Y%m%dT%H%M%SZ).db"
sudo cp -a /var/lib/hnc-scoring/scoring.db "$SCORING_BACKUP"
sudo ls -lh "$SCORING_BACKUP"
```

Record the displayed backup path for rollback and confirm the copy exists before
continuing.

## Update the application

Record the current commit from `git rev-parse HEAD`; it is the rollback commit.
Then update the checked-out production branch:

```bash
git fetch --prune origin
git pull --ff-only origin main
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --requirement requirements.txt
python -m pip check
python -m unittest discover -s tests -v
```

This session-expiry and dependency release does not require a database
migration. Do not run `flask db upgrade` unless a future release contains a
reviewed migration directory and explicitly calls for it.

Ubuntu packages required by the current PDF support can be installed once with:

```bash
sudo apt update
sudo apt install python3-venv fonts-dejavu-core
```

## Restart and verify

```bash
sudo systemctl restart scoring-app
sudo systemctl is-active scoring-app
sudo systemctl status scoring-app --no-pager
sudo journalctl -u scoring-app -n 100 --no-pager
```

Then verify through the public HTTPS address:

1. The home page loads without a server error.
2. Admin login displays and its CAPTCHA renders.
3. An assessor can log in and existing scores load.
4. Editing a score and a comment persists after a page refresh.
5. PDF report generation succeeds.
6. Folio publishing can reach its configured API, when that feature is part of
   the release test.

Keep the logs open during the smoke test if needed:

```bash
sudo journalctl -u scoring-app -f
```

## Roll back

If verification fails:

```bash
sudo systemctl stop scoring-app
git switch --detach <rollback-commit-recorded-before-deployment>
source venv/bin/activate
python -m pip install --requirement requirements.txt
sudo cp -a /var/backups/hnc-scoring/<backup-file> /var/lib/hnc-scoring/scoring.db
sudo systemctl start scoring-app
sudo systemctl status scoring-app --no-pager
```

Only restore the database when the failed release changed data or schema. This
release has no schema migration, so a code-and-dependency rollback should
normally be sufficient. After recovery, switch the checkout back to the normal
production branch before the next deployment.
