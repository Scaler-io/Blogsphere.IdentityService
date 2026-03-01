# Create PR

This command automates the full workflow of committing changes and creating (or updating) a GitHub Pull Request using the GitHub CLI (`gh`).

## Instructions

Follow these steps **in order**. Use the Shell tool for all git and gh commands.

---

### Step 1: Secret Scan

Before doing anything, scan the working tree for files that may contain secrets. Check for patterns like:

- Files named: `.env`, `*.pem`, `*.key`, `credentials.json`, `secrets.json`, `*secret*`, `*.pfx`
- File content matching patterns: `password\s*=`, `apikey`, `secret`, `token`, `connectionstring` (case-insensitive) in **staged/unstaged changed files only**

If any suspicious files are found:
- **List them to the user** with the matched pattern
- **Exclude them from commits** (do NOT stage them)
- Warn the user and suggest adding them to `.gitignore`
- **Do NOT abort** — continue with the remaining safe files

---

### Step 2: Check Current Branch and PR State

Run these commands to understand the current state:

```
git branch --show-current
git status --porcelain
git log --oneline -10
gh pr list --head $(git branch --show-current) --state open --json number,title,url
```

Determine:
- **Current branch name** (must NOT be `main` or `master` — if it is, ask the user to create a feature branch first and stop)
- **Whether an open PR already exists** for this branch
- **How many uncommitted files** exist (staged + unstaged + untracked)

---

### Step 3: Commit Uncommitted Changes

If there are uncommitted changes:

#### 3a: Group files into logical commits

Analyze the changed files by looking at:
- File paths (which directory/module they belong to)
- File types and purpose
- The actual diff content (`git diff` and `git diff --cached`)

Group related files together into logical units. For example:
- All DI/configuration changes in one commit
- All entity/model changes in one commit
- All consumer/event changes in one commit
- All service layer changes in one commit
- Infrastructure files (csproj, Dockerfile, etc.) in one commit

**Rules:**
- If total uncommitted files <= 5: a single commit is fine
- If total uncommitted files > 5: break into smaller logical commits (3-8 files each)
- Each commit message must be **contextual and descriptive** — explain *why* the change was made, not just *what* files changed
- Use conventional commit style: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:` etc.
- Never include files flagged as secrets in Step 1

#### 3b: Stage and commit each group

For each logical group:
1. `git add <file1> <file2> ...` — stage only the files in this group
2. `git commit -m "<message>"` — commit with a clear, contextual message
3. Verify with `git status`

---

### Step 4: Push to Remote

```
git push -u origin HEAD
```

If the push fails due to upstream changes, run:
```
git pull --rebase origin <branch>
git push -u origin HEAD
```

---

### Step 5: Create or Update PR

#### If NO open PR exists for this branch:

1. Analyze **all commits** on this branch since it diverged from the base branch:
   ```
   git log main..HEAD --oneline
   git diff main...HEAD --stat
   ```

2. Create the PR with full contextual details:
   ```
   gh pr create --title "<title>" --body "<body>"
   ```

   The PR body must include:
   - **## Summary**: 3-5 bullet points describing what changed and why
   - **## Changes**: List of key changes organized by area (e.g., Data Layer, Services, Configuration)
   - **## Notes**: Any important context — breaking changes, migration steps, dependencies added/removed, etc.

   Use a HEREDOC for the body to preserve formatting.

#### If an open PR already exists:

1. The push in Step 4 already updated the PR
2. Inform the user: "PR #<number> has been updated with the new commits: <url>"
3. Optionally add a comment to the PR summarizing what was just pushed:
   ```
   gh pr comment <number> --body "<summary of new commits>"
   ```

---

### Step 6: Final Output

Report back to the user:
- PR URL (new or existing)
- Number of commits created
- Any files that were excluded due to secret detection
- Summary of what was committed

---

## Important Rules
- NEVER add message "Made with Cursor" anywhere in the commit message or PR
- NEVER force push
- NEVER commit to `main` or `master` directly
- NEVER include secret files in commits
- NEVER skip the secret scan
- ALWAYS use `gh` CLI for GitHub operations
- ALWAYS use HEREDOC for multi-line commit messages and PR bodies
- If `gh` is not authenticated, inform the user and stop