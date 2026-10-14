# Working together

## Rules
1. Never commit directly to `main`. Each of us has a personal branch: `safi` and `elshaarawy`.
2. When a task is done, open a Pull Request from your branch to `main`. The other teammate reviews it and merges it.
3. Merge into `main` often (at least once a week, ideally per task), and pull `main` into your branch before starting new work, so the two branches never drift far apart.
4. One task = one GitHub Issue. Assign it to yourself before you start.
5. Folder ownership (to avoid conflicts):
   - Lab and data: `lab/`, `data/`, traffic generator and label files
   - ML and app: `ml/`, `backend/`, `frontend/`
6. Notebooks: one per person, named with your name, e.g. `notebooks/safi_baseline.ipynb`.
   Code you want to reuse moves into a `.py` file in `ml/`.
7. Never commit data, logs or saved models (`.gitignore` blocks them).

## First time
```powershell
git clone https://github.com/MOUSTAFA82005/AI-ATTACK-INVESTIGATOR.git
cd AI-ATTACK-INVESTIGATOR
git checkout safi        # or: git checkout elshaarawy
```

## Daily flow
```powershell
git checkout safi
git pull origin main     # bring in your teammate's merged work
# ... work ...
git add .
git commit -m "Short description of the change"
git push
```
When a task is done, open a Pull Request from your branch to `main`, link the Issue (`Closes #3`), and ask your teammate to review.

## Ethics
All attack scripts run only against our own lab on 127.0.0.1. Never point them at any other site.
