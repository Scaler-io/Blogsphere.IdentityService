# Create PR

This command automates the full workflow of committing changes and creating (or updating) a GitHub Pull Request using **GitHub MCP** (configured in Cursor). **Do not** use the GitHub CLI (`gh`), `hub`, or other CLIs for GitHub API operations.

## Prerequisites

- **GitHub MCP** is connected in Cursor (Tools & Integrations → MCP) and shows a healthy state.
- A valid **Personal Access Token** (or OAuth) with scopes needed for PRs (typically **`repo`** for private repositories).
- If MCP is unavailable or tools fail, stop and tell the user to fix MCP / PAT — do not fall back to `gh`.

## Instructions

Follow these steps **in order**. Use the **Shell tool** only for **git** commands. Use **GitHub MCP tools** for all GitHub operations (list/create/update PRs, comments).

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

Run **git** commands via Shell to understand the local state:

```
git branch --show-current
git status --porcelain
git log --oneline -10
```

Resolve **owner** and **repo** for this workspace (from `git remote get-url origin` or user-provided `owner/repo` if ambiguous).

Use **GitHub MCP** (not `gh`) to determine whether an **open PR** already exists for the current branch:

- Invoke the GitHub MCP tool that **lists or searches pull requests** for `owner/repo`, filtered so the PR’s **head branch** matches the current branch (GitHub often represents head as `username:branch-name` or the branch name depending on the tool — use the parameters the tool expects).
- If the MCP exposes a single “get PR” or “list PRs” action, prefer that and match on head ref / branch name.

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
   (Use `master` instead of `main` if that is the default base branch for this repo.)

2. Build the PR **title** and **body** as strings in the assistant (multi-line body is fine — pass as the tool’s body/description parameter; no shell HEREDOC required).

3. **Create the PR via GitHub MCP**: call the tool that **creates a pull request** with at least:
   - **Owner** and **repository** name
   - **Head**: branch that was just pushed (and head repo if cross-fork; usually same repo)
   - **Base**: `main` or `master` (or the repo’s default branch if known)
   - **Title** and **body**

   The PR body must include:
   - **## Summary**: 3-5 bullet points describing what changed and why
   - **## Changes**: List of key changes organized by area (e.g., Data Layer, Services, Configuration)
   - **## Notes**: Any important context — breaking changes, migration steps, dependencies added/removed, etc.

#### If an open PR already exists:

1. The push in Step 4 already updated the PR on GitHub
2. Inform the user: "PR #<number> has been updated with the new commits: <url>"
3. Optionally use **GitHub MCP** to **add a comment** on that PR summarizing what was just pushed (use the MCP tool for PR/issue comments — not `gh pr comment`)

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
- **NEVER** use `gh`, `hub`, or other GitHub CLIs for listing/creating/updating PRs or comments — use **GitHub MCP** only
- For **git** (status, add, commit, push, log, diff), Shell/git is correct
- If GitHub MCP tools are missing, error, or return auth errors, **stop** and tell the user to check MCP connection and PAT scopes — do not substitute `gh`
