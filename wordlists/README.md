# Wordlists

This directory is reserved for local wordlists used by `ffuf` during `dir_enum`.

## Expected Usage

- Add your own wordlists here or point `ffuf_wordlist_path` at another local path.
- Keep one candidate path or token per line.
- Start with small, curated lists for safe defensive scans.
- Use only wordlists you are allowed to store and run.

## Important Notes

- The repository does not ship real wordlists.
- `dir_enum` cannot run until `ffuf_wordlist_path` points to a valid file.
- The current CLI does not expose a `--wordlist` option yet, so plan wordlist configuration
  before executing the `dir_enum` phase.
