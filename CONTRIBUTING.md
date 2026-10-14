# Working together

## Rules
1. Branches:
   - `Safi` and `Elsharawy`: personal branches, each of us works only on his own.
   - `Devlope`: integration branch where both our work comes together.
   - `main`: stable version only (milestones, demo, final submission).
2. When a task is done, open a Pull Request from your branch to `Devlope` and merge it (no review required).
3. When `Devlope` works end to end (e.g. the week 6 milestone), open a Pull Request from `Devlope` to `main`.
4. Merge into `Devlope` often (at least once a week, ideally per task), and pull `Devlope` into your branch before starting new work, so the branches never drift far apart.
5. Never commit directly to `main` or `Devlope`.
6. Folder ownership (to avoid conflicts):
   - Lab and data: `lab/`, `data/`, traffic generator and label files
   - ML and app: `ml/`, `backend/`, `frontend/`
7. Notebooks: one per person, named with your name, e.g. `notebooks/safi_baseline.ipynb`.
   Code you want to reuse moves into a `.py` file in `ml/`.
8. Never commit data, logs or saved models (`.gitignore` blocks them).

## First time
```powershell
git clone https://github.com/MOUSTAFA82005/AI-ATTACK-INVESTIGATOR.git
cd AI-ATTACK-INVESTIGATOR
git checkout Safi        # or: git checkout Elsharawy
```

## Daily flow
```powershell
git checkout Safi
git pull origin Devlope  # bring in your teammate's merged work
# ... work ...
git add .
git commit -m "Short description of the change"
git push
```
When a task is done, open a Pull Request from your branch to `Devlope` and merge it.

## Ethics
All attack scripts run only against our own lab on 127.0.0.1. Never point them at any other site.
