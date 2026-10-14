# Working together

## Rules
1. Never commit directly to `main`. Every task gets its own branch and a Pull Request.
2. The other teammate reviews the PR and merges it.
3. One task = one GitHub Issue. Assign it to yourself before you start.
4. Folder ownership (to avoid conflicts):
   - Lab and data: `lab/`, `data/`, traffic generator and label files
   - ML and app: `ml/`, `backend/`, `frontend/`
5. Notebooks: one per person, named with your name, e.g. `notebooks/safi_baseline.ipynb`.
   Code you want to reuse moves into a `.py` file in `ml/`.
6. Never commit data, logs or saved models (`.gitignore` blocks them).

## Daily flow
```powershell
git checkout main
git pull
git checkout -b my-task-name
# ... work ...
git add .
git commit -m "Short description of the change"
git push -u origin my-task-name
```
Then open a Pull Request on GitHub, link the Issue (`Closes #3`), and ask your teammate to review.

## Ethics
All attack scripts run only against our own lab on 127.0.0.1. Never point them at any other site.
