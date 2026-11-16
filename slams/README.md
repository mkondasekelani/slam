# SLAMS – School Library & Asset Management System

Flask + SQLite + HTML/CSS/JS. Runs on one school computer; anyone on the school network opens it in a browser.

## Run
```
pip install -r requirements.txt
python app.py            # then open http://localhost:5000
```
Other computers/phones on the network: http://<this-computer-ip>:5000

**First login:** `admin` / `admin123` – change it immediately (click your name, top right).

## Typical workflow
1. **People** – add or CSV-import students and staff (columns: number, name, class/department).
2. **Assets → Register asset** – books get a quantity; computers/equipment one record per unit (serial number).
3. Tick assets on the list → **Print barcode labels** (Code 128) and stick them on.
4. **Issue** – scan the label (USB scanners act as a keyboard), enter the admission/staff number, submit.
5. **Returns** – scan the label again, record the return; enter damaged units if any (auto-flagged for maintenance).
6. **Reports** – inventory, current assignments, overdue, history (print or CSV).

## Rules enforced
Can't issue more than available · every issue needs a student/staff recipient and issue date · returns restore stock ·
damaged units are removed from available stock · assets are retired, never deleted, and can't be retired while units are out ·
every action is written to the activity log.

## Roles
`admin` (also manages users, retires assets), `librarian`, `technician`. Role-based restrictions beyond admin-only
are a natural next step.

## Notes
- Data lives in `slams.db` – back this file up regularly.
- Camera scanning needs HTTPS or localhost (browser rule); USB scanners work on plain http.
- To run in production use a WSGI server, e.g. `pip install waitress` then `waitress-serve --port=5000 app:app`.
