# Skill scaffold

Copy `SKILL.md` to `skills/<category>/<name>/SKILL.md`, rename, fill every
`TODO`, delete this README, then sync + push:

```bash
./scripts/sync_skill.sh security my-new-skill   # copies from ~/.hermes/skills/<cat>/<name>
git add -A && git commit -m "add skill: my-new-skill" && git push
```

Conventions (enforced by review, not tooling — yet):
- `SKILL.md` ≤ ~150 lines; depth goes in `references/`, automation in `scripts/`.
- `description` first 57 chars = self-contained trigger.
- Only load references when the phase needs them.
- Secrets NEVER live in repo files — scripts read credentials from env.
