# models/

Model files are not in git. Get the six files the app needs from the
[`v12.0-final-test` release](https://github.com/MOUSTAFA82005/AI-ATTACK-INVESTIGATOR/releases/tag/v12.0-final-test)
(`talon-models-v12.zip`). Their hashes are in `results/final_v12/model_hashes.txt`.

```
models/
├── detector.joblib        request detector (v11 detector, used by v12)
├── context.joblib         visitor behaviour (v10)
├── attack_type.joblib     attack type (v10)
├── stage.joblib           attack stage (v10)
├── block_rules.joblib     block / rate-limit / allow tree (v10)
├── next_step.json         next-step Markov chain (v10)
└── archive/               older frozen versions, only for re-running old evaluations
    ├── v8/                v8 detector, context, attack type, stage
    ├── v9/                the frozen v9 set, plus its holdout detectors
    ├── v10/               the v10 detector; rejected/ = two v10 candidates that were not used
    └── v11/               the v11 detector (same file as detector.joblib)
```

The dashboard loads only the six files at the top. Nothing in `archive/` is needed to run it.
