git rm -r --cached venv
echo "venv/" >> .gitignore
git add .gitignore
git commit -m "Remove venv from history and update .gitignore"