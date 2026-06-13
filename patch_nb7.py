import json

NB = r'e:/Dev/Graduation Project 2026/AI-Driven Adaptive Post-Quantum Security Framework for V2X Systems/train_ids_colab.ipynb'
with open(NB, encoding='utf-8') as f:
    nb = json.load(f)

for cell in nb['cells']:
    cid = cell.get('id', '')
    src = ''.join(cell['source'])

    # Fix title markdown — remove MisbehaviorX line
    if cid == 'TqKlXaay3LXD':
        new_src = '\n'.join(
            line for line in src.splitlines()
            if 'MisbehaviorX' not in line and 'IEEE DataPort' not in line
        )
        cell['source'] = (new_src + '\n').splitlines(keepends=True)
        print(f'Fixed title markdown: removed MisbehaviorX line')

    # Fix Phase 2 markdown — update description to match fresh-weights approach
    if cid == '8aac7180':
        cell['source'] = [
            '## Phase 2 — Fine-Tuning on V2X BSM Data\n',
            '\n',
            'Models are rebuilt from scratch (fresh weights) to avoid incompatible synthetic→real\n',
            'feature statistics. Training uses the VeReMi NextGen real dataset with class-weighted loss.\n',
        ]
        print(f'Fixed Phase 2 markdown description')

    # Fix Cell 22 — use VEREMI_NG_PATH instead of hardcoded /content path
    if cid == '3a679576':
        new_src = src.replace(
            "if os.path.exists('veremi_ng_train.csv'):",
            "if os.path.exists(VEREMI_NG_PATH):"
        ).replace(
            "    df_t = pd.read_csv('/content/veremi_ng_train.csv') # Changed filename and removed compression='gzip'",
            "    df_t = pd.read_csv(VEREMI_NG_PATH)"
        ).replace(
            "    print('VeReMi NextGen not loaded. Upload veremi_ng_train.csv.gz to /content/')\n    print('The test set metrics from Cell 15 (synthetic) are your primary results.')",
            "    print('Dataset not found at', VEREMI_NG_PATH)"
        )
        # Fix comment on first line
        new_src = new_src.replace(
            '# Cell 22 — Cross-dataset check (uses same veremi_ng_train.csv.gz held-out test split)',
            '# Cell 22 — Per-attack-type breakdown (VeReMi NextGen held-out test split)'
        )
        cell['source'] = new_src.splitlines(keepends=True)
        print(f'Fixed Cell 22: use VEREMI_NG_PATH')

with open(NB, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print('Done.')
