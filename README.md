# 🧰 GhostMerge

A command-line tool for merging and deduplicating GhostWriter finding libraries with human-in-the-loop decision making and robust data hygiene features.

---

## 📦 Project Structure

### 🔧 Core Scripts

- **`ghostmerge.py`** – CLI entry point powered by Typer.
- **`models.py`** – Data models (e.g., `Finding`) and safe parsing/validation.
- **`utils.py`** – Consolidated utilities for logging, I/O, HTML stripping, and signals.
- **`matching.py`** – Fuzzy matching and scoring logic using title, type, and description.
- **`sensitivity.py`** – Sensitive term detection system, with optional replacements.

### ⚙️ Configuration

- **`ghostmerge_config.json`** – Global settings including:
  - Logging verbosity and output path
  - Interactive mode toggle
  - Sensitivity checker toggle
  - Matching weights (title, description, finding_type)

### 🧪 Test Fixtures

- **`test_data_a.json`** and **`test_data_b.json`**
  - Simulated datasets (18 entries each) covering:
    - Unique and shared entries
    - Conflicts in fields like title and type
    - Identical entries (no merge needed)
    - Duplicates, invalid types (e.g. `cvss_score` as string)
    - Fuzzy match edge cases

- **`sensitive_terms.txt`**
  - File used by the sensitivity checker.
  - Format: one term per line, optionally with `=> replacement`.

### 📝 Supporting Docs

- **`TODO.md`**
  - Development roadmap and checklist, with completed items and future tasks.

- **`README.md`**
  - You're reading it.

---

## 🚀 Usage

Basic invocation:
```bash
python ghostmerge.py merge test_data_a.json test_data_b.json
```

With automated merging and no sensitive term checks:
```bash
python ghostmerge.py merge test_data_a.json test_data_b.json --automated --no-sensitivities-check
```

---

## 🔍 Development Notes

- Code uses rich logging to both console and file.
- Type hints and structured exceptions used throughout.
- Config is loaded automatically from `ghostmerge_config.json`.

---

## 🧼 Still to Implement

See `TODO.md` for upcoming features including:
- Merge engine orchestration
- Interactive resolution prompts
- Unit test harness and validation
