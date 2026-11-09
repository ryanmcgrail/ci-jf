# cm-011-diff: diff-mode find cost on cm 0.11.0

This experiment measures how `cm find --diff=<diff_ref>` token usage and wall time scale with diff size. Finding quality is secondary. Each case checks out a repo at `pinned_ref` and scans the change from `diff_ref`, which is what a customer's CI does. Cases come from [`config/repos_with_diff.tsv`](../../config/repos_with_diff.tsv): up to 4 per repo, in size bands S/M/L/XL.

Setup:

- cm `0.11.0`, model `gemini-3.8-flash`, project `codemender-sandbox-416585`, image `d061a19`.
- `run.py --mode diff` passes only `--diff=<diff_ref>`. `--diff-workers` and `--diff-max-neighbors` are not set, so cm's defaults apply (4 workers, 10 one-hop neighbors per changed file).
- cm stops a delta scan after a hard-coded 5 minutes, exits 1 and imports no findings. The runner records this as `diff_timed_out: true`. The task still succeeds and its tokens are counted.

## Cross-model comparison

All three models ran the same 216 cases under `cm-011-diff` (image `c722b7b`, cm `0.11.0`, cm's default diff workers, batches A and B run one at a time). Medians and p90s cover valid cases that finished within cm's 5-minute ceiling; "Valid" excludes zero-token and evidence-mismatch cases.

| Band | Model | Valid | Timed out | Median tok | p90 tok | Median wall s | p90 wall s | Findings | Total tok |
|---|---|---|---|---|---|---|---|---|---|
| S | `gemini-3.7-flash` | 50/50 | 1 | 196,671 | 477,638 | 78 | 194 | 20 | 15,556,970 |
| S | `gemini-3.8-flash` | 49/50 | 3 | 355,852 | 914,370 | 102 | 204 | 12 | 22,394,490 |
| S | `gemini-3.1-pro-preview` | 50/50 | 8 | 144,531 | 536,158 | 63 | 215 | 87 | 22,927,017 |
| M | `gemini-3.7-flash` | 55/57 | 7 | 359,452 | 938,195 | 116 | 270 | 48 | 32,710,831 |
| M | `gemini-3.8-flash` | 52/57 | 20 | 684,954 | 1,085,921 | 190 | 250 | 23 | 49,959,968 |
| M | `gemini-3.1-pro-preview` | 55/57 | 14 | 340,035 | 876,271 | 144 | 271 | 181 | 47,078,251 |
| L | `gemini-3.7-flash` | 51/55 | 19 | 545,448 | 1,154,490 | 194 | 317 | 57 | 57,557,319 |
| L | `gemini-3.8-flash` | 44/55 | 38 | 978,900 | 1,265,726 | 204 | 283 | 23 | 58,781,068 |
| L | `gemini-3.1-pro-preview` | 45/55 | 23 | 592,060 | 1,161,301 | 190 | 288 | 185 | 49,027,204 |
| XL | `gemini-3.7-flash` | 43/54 | 30 | 675,365 | 1,805,578 | 217 | 339 | 97 | 55,322,551 |
| XL | `gemini-3.8-flash` | 40/54 | 38 | 1,508,804 | 1,634,157 | 222 | 240 | 28 | 48,084,485 |
| XL | `gemini-3.1-pro-preview` | 48/54 | 38 | 697,879 | 1,686,058 | 250 | 306 | 331 | 60,035,536 |
| ALL | `gemini-3.7-flash` | 199/216 | 57 | 370,090 | 1,037,474 | 128 | 283 | 222 | 161,147,671 |
| ALL | `gemini-3.8-flash` | 185/216 | 99 | 547,217 | 1,217,073 | 159 | 245 | 86 | 179,220,011 |
| ALL | `gemini-3.1-pro-preview` | 198/216 | 83 | 370,220 | 1,046,532 | 139 | 280 | 784 | 179,068,008 |

| Model | Valid cases | Total tokens | Timed out | OLS tokens ≈ a + b·lines | log-log r | Cases with 429s |
|---|---|---|---|---|---|---|
| `gemini-3.7-flash` | 199 | 161,147,671 | 57 | 481,260 + 28·lines (n=142) | 0.59 | 0/216 |
| `gemini-3.8-flash` | 185 | 179,220,011 | 99 | 568,289 + 60·lines (n=86) | 0.54 | 122/216 |
| `gemini-3.1-pro-preview` | 198 | 179,068,008 | 83 | 439,093 + 22·lines (n=115) | 0.64 | 22/216 |

Observations:

- `gemini-3.1-pro-preview` reported far more findings (784) than `gemini-3.7-flash` (222) or `gemini-3.8-flash` (86), at an ALL-band median token cost close to 3.7-flash (370,220 vs 370,090).
- `gemini-3.8-flash` had the highest median tokens in every band and the most timeouts (99). Its runs also hit the most 429s, so some of that cost and those timeouts may come from quota throttling rather than the model.
- All three models fit tokens to diff size weakly in linear terms (Pearson r 0.16–0.39) but better in log-log terms (0.54–0.64). Per-case cost is dominated by a base of roughly 440k–570k tokens.

## gemini-3.8-flash

These are smoke results on VAmPI. The full benchmark (216 cases from 64 repos, run as batches of 33 and 31 repos under experiment `cm-011-diff`) has full-run results for `gemini-3.8-flash` (below), `gemini-3.7-flash` and `gemini-3.1-pro-preview`.

### B0: VAmPI smoke (`cm-011-diff-smoke`)

Run `20261004_184419_find_v0.11.0_gemini-3.8-flash`, execution `cm-find-runner-594vb`, results at `gs://codemender-sandbox-416585-cm-find-results/cm-011-diff-smoke/20261004_184419_find_v0.11.0_gemini-3.8-flash/`.

| Case | Band | Files / lines | cm jobs | Total tokens | Input | Output | Cached | Thought | Turns | Wall | cm exit | Findings |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `o04-vampi--f16052d-beca461` | S | 2 / 32 | 11/11 | 419,255 | 397,013 | 1,698 | 168,297 | 20,544 | 50 | 133 s | 0 | 0 |
| `o04-vampi--f16052d-a488a52` | M | 7 / 164 | 15/15 | 720,872 | 657,463 | 4,344 | 290,824 | 59,065 | 67 | 214 s | 1 (gate) | 4 HIGH |

Both cases print cm's `merge-base(...)` banner, neither hit the 5-minute ceiling, and `diff_workers` is `null`. cm runs more jobs than there are changed files because it also scans the changed files' neighbors. The M case's exit code 1 is cm's `--diff` CI gate (findings at or above the gate severity), not a failure.

### Chaining smoke: find → verify → fix on the M case

`--operation find-verify-fix --verify-limit 2 --fix-limit 2`, under `cm-011-diff-smoke`.

| Phase | Run id | Execution | Wall | Total tokens | Result |
|---|---|---|---|---|---|
| find | `20261004_185509_find_v0.11.0_gemini-3.8-flash` | `cm-find-runner-tzlhw` | 244 s | 921,475 | 4 findings (2 CRITICAL, 2 HIGH), 15/15 jobs |
| verify | `20261004_190523_verify_v0.11.0_gemini-3.8-flash` | `cm-verify-runner-8rvz5` | 1,184 s | 5,930,613 | 2/2 VERIFIED |
| fix | `20261004_193047_fix_v0.11.0_gemini-3.8-flash` | `cm-fix-runner-nzfn9` | 784 s | 3,231,682 | 2/2 FIXED, 2 patches, 2 exploits imported |

Verify and fix run with `MODE=shallow` and record `source_find_mode=diff` in their summaries and run manifests.

### Observations

- Tokens grew with diff size: the M case (7 files, 164 lines) used 1.7× the tokens of the S case (2 files, 32 lines).
- Runs vary. The same M case used 720,872 tokens in B0 and 921,475 in the chaining find (+28%), with the same 15 jobs. Per-band comparisons need several cases per band, not single runs.
- Verify and fix cost far more than the diff find itself: for 2 findings, verify used 6.4× and fix 3.5× the find's tokens.
- Cached input was 42–44% of input tokens in both B0 cases.

### Full run (cm-011-diff)

Both batches ran unchanged with cm's default diff workers. Both went over the 10% zero-token limit because of 429s; the run continued at the user's request (accepted deviation).

| Batch | Cases | Run id | Execution | Execution wall | Results |
|---|---|---|---|---|---|
| A (repos 1–33) | 117 | `20261005_034927_find_v0.11.0_gemini-3.8-flash` | `cm-find-runner-bwgft` | 21m38s (117/117 tasks succeeded) | `gs://codemender-sandbox-416585-cm-find-results/cm-011-diff/20261005_034927_find_v0.11.0_gemini-3.8-flash/` |
| B (repos 34–64) | 99 | `20261005_041934_find_v0.11.0_gemini-3.8-flash` | `cm-find-runner-2sbzk` | 21m00s (99/99 tasks succeeded) | `gs://codemender-sandbox-416585-cm-find-results/cm-011-diff/20261005_041934_find_v0.11.0_gemini-3.8-flash/` |

Both `run.py` invocations exited 0. Every summary has `mode=diff`, `cm_version=0.11.0`, `model=gemini-3.8-flash` and `diff_workers=null`. The only evidence mismatches are the two known Flarum cases (see the `gemini-3.7-flash` section).

**429s.** cm logged `StartSession API error: code 429` on quota `aiplatform.googleapis.com/concurrent_interaction_generations` ("Global concurrent interaction generations per project"):

| Batch | Cases with 429s | Log lines | When (UTC) |
|---|---|---|---|
| A | 85/117 | 1,627 | 03:52–03:57 |
| B | 37/99 | 472 | 04:25–04:27 |

`gemini-3.7-flash` hit none at the same concurrency (about 100 tasks at once). The 429s coincide with many more cases hitting cm's 5-minute ceiling (99 of 216, against 57 for 3.7-flash). That leaves fewer finished cases for the medians, especially in L and XL.

#### Per-band results (A + B)

Medians and p90s cover the valid cases that finished within cm's 5-minute ceiling. Timed-out cases are valid: their tokens are in the band totals and they are listed below. Excluded cases are in no aggregate.

| Band | Cases | Excluded | Timed out | Median tok | p90 tok | Median wall s | p90 wall s | Median lines | Median tok/line | Findings | Total tok |
|---|---|---|---|---|---|---|---|---|---|---|---|
| S | 50 | 1 | 3 | 355,852 | 914,370 | 102 | 204 | 37 | 7,880 | 2 CRITICAL, 6 HIGH, 4 MEDIUM | 22,394,490 |
| M | 57 | 5 | 20 | 684,954 | 1,085,921 | 190 | 250 | 220 | 3,073 | 4 CRITICAL, 18 HIGH, 1 MEDIUM | 49,959,968 |
| L | 55 | 11 | 38 | 978,900 | 1,265,726 | 204 | 283 | 1,703 | 506 | 2 CRITICAL, 19 HIGH, 2 MEDIUM | 58,781,068 |
| XL | 54 | 14 | 38 | 1,508,804 | 1,634,157 | 222 | 240 | 14,800 | 158 | 7 CRITICAL, 20 HIGH, 1 MEDIUM | 48,084,485 |
| ALL | 216 | 31 | 99 | 547,217 | 1,217,073 | 159 | 245 | 105 | 4,009 | 15 CRITICAL, 63 HIGH, 8 MEDIUM | 179,220,011 |

Tokens vs changed_lines (n=86, excl. timeouts): Pearson r=0.39, log-log r=0.54, OLS tokens ≈ 568,289 + 60·lines.

Total tokens across the 185 valid cases: **179,220,011** (A 91,361,265 · B 87,858,746).

#### VAmPI variance against the smoke run

| Case | Band | Smoke `cm-011-diff-smoke` | This run | Change |
|---|---|---|---|---|
| `o04-vampi--f16052d-beca461` | S | 419,255 | 382,449 | −8.8% |
| `o04-vampi--f16052d-a488a52` | M | 720,872 | 768,624 | +6.6% |

Both VAmPI cases ran the same jobs as in the smoke run (11/11 and 15/15), logged no 429s, and stayed within ±10% of the smoke tokens.

#### Excluded cases

31 of 216 cases (A 18, B 13) are excluded. Every token-stats failure hit cm's ceiling first; then `cm-api-token-stats` timed out after 780 s, so the summary has 0 tokens and `status=failed`.

| Case | Band | Batch | 429 lines | Cause |
|---|---|---|---|---|
| `p07-express--04bc627-c63424a` | XL | A | 22 | token stats timed out |
| `p08-axios--0e4f9fa-870e0a7` | S | A | 25 | token stats timed out |
| `p08-axios--0e4f9fa-a3ff99b` | M | A | 7 | token stats timed out |
| `p08-axios--0e4f9fa-c30252f` | XL | A | 3 | token stats timed out |
| `p10-nextjs--2e7a96a-a7107a3` | XL | A | 20 | token stats timed out |
| `p14-fzf--c4a9ccd-6ea38b4` | XL | A | 10 | token stats timed out |
| `p17-opentofu--aeaeacc-a69d19d` | L | A | 0 | token stats timed out |
| `p17-opentofu--aeaeacc-dcec46e` | XL | A | 38 | token stats timed out |
| `p19-argocd--25f7504-da6c2e9` | M | A | 26 | token stats timed out |
| `p19-argocd--25f7504-b71f0c8` | L | A | 7 | token stats timed out |
| `p20-spring-boot--a25e1eb-df578d5` | L | A | 23 | token stats timed out |
| `p25-ktor--b5d9213-f1f5a2d` | L | A | 33 | token stats timed out |
| `p28-tokio--14c17fc-e62c3e9` | L | A | 17 | token stats timed out |
| `p30-valkey--2638827-c4776ca` | L | A | 6 | token stats timed out |
| `p30-valkey--2638827-a51eb05` | XL | A | 24 | token stats timed out |
| `p31-curl--fd567d4-25cbc2f` | XL | A | 5 | token stats timed out |
| `p33-openssl--4cb3112-1a4b029` | M | A | 17 | token stats timed out |
| `p33-openssl--4cb3112-0ce7d1f` | L | A | 5 | token stats timed out |
| `p34-zephyr--468eb56-7d6ca26` | L | B | 10 | token stats timed out |
| `p36-envoy--d79f6e8-5eccc35` | L | B | 0 | token stats timed out |
| `p36-envoy--d79f6e8-f101823` | XL | B | 0 | token stats timed out |
| `p37-flarum--2a693db-2299541` | M | B | 0 | evidence mismatch (3/59 vs 15/171); tokens are valid |
| `p37-flarum--2a693db-c766881` | XL | B | 0 | token stats timed out; evidence mismatch (122/2,651 vs 143/2,848) |
| `p40-aspnet-core--b8139c5-2bf9d24` | XL | B | 21 | token stats timed out |
| `h06-caddy--7088605-cabb5d7` | L | B | 8 | token stats timed out |
| `h09-exposed--d5309ce-526b2b8` | XL | B | 0 | token stats timed out |
| `h11-nginx--0ddcae0-ea8270c` | M | B | 16 | token stats timed out |
| `h13-laravel--2fd3a25-dbcad29` | XL | B | 0 | token stats timed out |
| `h14-sidekiq--30786e0-2abed51` | L | B | 11 | token stats timed out |
| `h14-sidekiq--30786e0-2ee7e27` | XL | B | 1 | token stats timed out |
| `o06-vulnerableapp--c4dd757-c68b25b` | XL | B | 20 | token stats timed out |

#### Timed-out cases

| Band | Case | Files | Lines | Jobs done | Total tok | Wall s |
|---|---|---|---|---|---|---|
| S | `p07-express--04bc627-0e3ab6e` | 3 | 335 | 13/14 | 1,073,819 | 507 |
| S | `p14-fzf--c4a9ccd-93bbb30` | 3 | 44 | 15/17 | 745,654 | 573 |
| S | `p21-keycloak--8d1956e-bda30dd` | 3 | 77 | 72/215 | 286,327 | 337 |
| M | `p03-scikit-learn--b51d0c9-b9bdb97` | 13 | 356 | 25/26 | 729,445 | 323 |
| M | `p06-requests--0e322af-d63e94f` | 15 | 640 | 23/24 | 1,407,827 | 354 |
| M | `p13-gin--75ccf94-9c61295` | 15 | 653 | 15/25 | 342,792 | 1061 |
| M | `p14-fzf--c4a9ccd-41bcbe3` | 15 | 393 | 26/27 | 2,018,121 | 589 |
| M | `p15-prometheus--879d809-612de02` | 15 | 449 | 23/32 | 701,841 | 1067 |
| M | `p16-traefik--8ea3398-6ca4c5d` | 7 | 414 | 20/44 | 566,479 | 325 |
| M | `p21-keycloak--8d1956e-79cbad8` | 10 | 210 | 149/223 | 968,186 | 878 |
| M | `p22-retrofit--cc76c22-9ae4f95` | 10 | 355 | 72/289 | 595,642 | 334 |
| M | `p26-okhttp--4984568-8eddd1d` | 14 | 264 | 24/30 | 882,630 | 1068 |
| M | `p30-valkey--2638827-0e0f58d` | 14 | 248 | 27/28 | 2,735,184 | 588 |
| M | `p31-curl--fd567d4-3455572` | 8 | 144 | 20/27 | 2,443,818 | 843 |
| M | `p32-wireguard--abba013-7e1d6ca` | 15 | 87 | 8/25 | 1,704,322 | 1165 |
| M | `p34-zephyr--468eb56-28555ae` | 15 | 203 | 15/22 | 1,988,159 | 835 |
| M | `p36-envoy--d79f6e8-2de9c29` | 11 | 233 | 21/23 | 1,957,909 | 841 |
| M | `h06-caddy--7088605-a6a45ff` | 14 | 313 | 23/25 | 2,083,710 | 354 |
| M | `h09-exposed--d5309ce-ef62acd` | 14 | 468 | 23/24 | 1,430,299 | 586 |
| M | `h12-fmt--e69e5f9-47c8f63` | 15 | 1223 | 15/18 | 1,516,792 | 827 |
| M | `o02-webgoat--5357a65-d1e44bb` | 15 | 328 | 34/37 | 1,392,837 | 595 |
| M | `o03-nodegoat--c57d268-52e51e9` | 15 | 326 | 20/36 | 691,027 | 1071 |
| M | `o07-brokencrystals--2a64b95-94d3f9b` | 15 | 2563 | 9/25 | 847,211 | 1081 |
| L | `p01-flask--c12a5d8-a18ae3d` | 47 | 7769 | 26/39 | 592,715 | 1066 |
| L | `p02-fastapi--1c3e691-27da0d0` | 20 | 709 | 23/26 | 796,064 | 575 |
| L | `p04-pytorch-geom--f1656e3-fd28440` | 49 | 3686 | 29/54 | 428,902 | 327 |
| L | `p05-django--2719a7f-0379e75` | 46 | 1316 | 22/39 | 1,469,466 | 830 |
| L | `p06-requests--0e322af-2a6f290` | 43 | 11723 | 23/31 | 618,940 | 820 |
| L | `p07-express--04bc627-a659137` | 41 | 3662 | 14/15 | 1,347,745 | 325 |
| L | `p08-axios--0e4f9fa-a6dfa72` | 49 | 2380 | 19/73 | 5,246,578 | 881 |
| L | `p09-react-admin--f046aac-1b2b556` | 47 | 1128 | 41/61 | 297,139 | 332 |
| L | `p10-nextjs--2e7a96a-3709dd9` | 48 | 668 | 22/54 | 650,990 | 830 |
| L | `p11-vue--4619461-ea494af` | 47 | 974 | 10/55 | 741,111 | 1065 |
| L | `p12-grafana--277ef25-31b6fcb` | 49 | 1613 | 22/66 | 673,068 | 833 |
| L | `p13-gin--75ccf94-1e1f0b1` | 31 | 1252 | 25/37 | 1,165,383 | 1081 |
| L | `p14-fzf--c4a9ccd-e8405f4` | 40 | 2904 | 19/52 | 1,574,567 | 1089 |
| L | `p15-prometheus--879d809-adf9939` | 46 | 627 | 25/53 | 745,181 | 825 |
| L | `p16-traefik--8ea3398-7b649e2` | 49 | 2836 | 25/77 | 1,013,105 | 577 |
| L | `p18-kubernetes--6911225-227c2e7` | 40 | 954 | 36/56 | 2,138,739 | 860 |
| L | `p21-keycloak--8d1956e-261b689` | 46 | 1056 | 111/248 | 548,335 | 854 |
| L | `p22-retrofit--cc76c22-869f48c` | 48 | 2224 | 51/317 | 891,030 | 835 |
| L | `p24-guava--73856da-d092aed` | 48 | 581 | 60/62 | 1,323,012 | 356 |
| L | `p26-okhttp--4984568-a76c40a` | 33 | 1441 | 20/43 | 682,944 | 1073 |
| L | `p27-ripgrep--e50df40-082245d` | 33 | 1292 | 47/54 | 1,562,800 | 608 |
| L | `p29-clap--5e4facf-55b1f94` | 40 | 809 | 27/43 | 1,205,327 | 330 |
| L | `p31-curl--fd567d4-0c890d9` | 49 | 1320 | 43/79 | 1,531,045 | 1076 |
| L | `p32-wireguard--abba013-1b78070` | 29 | 247 | 5/39 | 2,214,683 | 1204 |
| L | `p35-grpc--b8a04ac-32e0317` | 31 | 107 | 34/58 | 1,279,419 | 342 |
| L | `p38-symfony--08964d6-c58c599` | 48 | 625 | 40/51 | 1,013,064 | 1086 |
| L | `p39-discourse--4732483-e9a8c05` | 46 | 1217 | 14/41 | 1,103,287 | 838 |
| L | `p40-aspnet-core--b8139c5-a244ff1` | 47 | 1458 | 26/87 | 1,686,165 | 1097 |
| L | `h01-sqlalchemy--403194a-fb26ede` | 47 | 1559 | 39/40 | 2,996,138 | 586 |
| L | `h04-svelte--a8deae9-77ba5e7` | 49 | 2226 | 28/66 | 1,751,941 | 1077 |
| L | `h09-exposed--d5309ce-42ac41b` | 32 | 1109 | 36/37 | 1,969,387 | 602 |
| L | `h11-nginx--0ddcae0-6f20591` | 49 | 2900 | 22/73 | 2,544,179 | 834 |
| L | `h12-fmt--e69e5f9-79981a2` | 44 | 10140 | 14/36 | 2,605,080 | 1074 |
| L | `h13-laravel--2fd3a25-075c69f` | 44 | 1689 | 43/50 | 1,700,377 | 853 |
| L | `h15-dapper--360367c-aecffec` | 35 | 896 | 34/37 | 989,218 | 834 |
| L | `o03-nodegoat--c57d268-2de19ff` | 25 | 2129 | 27/65 | 1,304,770 | 584 |
| L | `o06-vulnerableapp--c4dd757-443c5f4` | 49 | 4593 | 21/57 | 1,458,262 | 1073 |
| L | `o07-brokencrystals--2a64b95-6626fd9` | 48 | 5352 | 26/71 | 1,124,900 | 595 |
| XL | `p01-flask--c12a5d8-200ce9b` | 77 | 14717 | 41/42 | 1,746,063 | 588 |
| XL | `p02-fastapi--1c3e691-4782887` | 143 | 1727 | 57/83 | 748,740 | 835 |
| XL | `p03-scikit-learn--b51d0c9-8600fb4` | 143 | 8177 | 38/120 | 858,111 | 826 |
| XL | `p04-pytorch-geom--f1656e3-47b0a14` | 136 | 6261 | 31/107 | 406,685 | 1070 |
| XL | `p06-requests--0e322af-130773a` | 52 | 14865 | 41/46 | 1,675,608 | 1080 |
| XL | `p09-react-admin--f046aac-0de8d33` | 150 | 5192 | 68/116 | 591,046 | 846 |
| XL | `p11-vue--4619461-c379bc2` | 150 | 6212 | 21/143 | 677,661 | 1066 |
| XL | `p12-grafana--277ef25-25390d2` | 150 | 7081 | 42/137 | 425,825 | 348 |
| XL | `p13-gin--75ccf94-0cbf290` | 91 | 8773 | 13/62 | 507,089 | 820 |
| XL | `p15-prometheus--879d809-d2817e9` | 146 | 10433 | 23/119 | 701,754 | 330 |
| XL | `p16-traefik--8ea3398-9f145db` | 71 | 4509 | 34/95 | 1,385,385 | 1085 |
| XL | `p18-kubernetes--6911225-77ecfb7` | 146 | 5018 | 22/113 | 687,972 | 358 |
| XL | `p19-argocd--25f7504-be1f0ea` | 149 | 9546 | 23/181 | 1,945,954 | 1099 |
| XL | `p20-spring-boot--a25e1eb-e8263c8` | 147 | 3661 | 51/161 | 954,732 | 1095 |
| XL | `p21-keycloak--8d1956e-2454565` | 149 | 4801 | 95/328 | 847,704 | 863 |
| XL | `p22-retrofit--cc76c22-ac57d42` | 103 | 19141 | 59/328 | 967,961 | 594 |
| XL | `p24-guava--73856da-52a62b2` | 148 | 1822 | 110/143 | 1,433,074 | 348 |
| XL | `p25-ktor--b5d9213-89805f7` | 85 | 2716 | 15/69 | 374,402 | 818 |
| XL | `p26-okhttp--4984568-cd72237` | 149 | 12062 | 27/117 | 608,552 | 1069 |
| XL | `p27-ripgrep--e50df40-f511849` | 103 | 30699 | 45/102 | 2,047,138 | 1088 |
| XL | `p28-tokio--14c17fc-4601c84` | 150 | 5435 | 40/129 | 841,445 | 831 |
| XL | `p29-clap--5e4facf-9cc4fe8` | 148 | 10361 | 47/103 | 1,364,299 | 834 |
| XL | `p34-zephyr--468eb56-7cfc8b3` | 150 | 2539 | 22/128 | 1,082,192 | 1107 |
| XL | `p38-symfony--08964d6-96d664e` | 149 | 2309 | 34/140 | 667,323 | 844 |
| XL | `p39-discourse--4732483-bfb292d` | 76 | 1824 | 23/64 | 1,887,251 | 869 |
| XL | `h01-sqlalchemy--403194a-6dc8ca2` | 120 | 5784 | 48/84 | 3,051,274 | 1089 |
| XL | `h02-pandas--d9cdd2e-859c030` | 149 | 2465 | 46/94 | 2,886,903 | 839 |
| XL | `h04-svelte--a8deae9-b62fc8c` | 85 | 2778 | 37/97 | 1,334,424 | 1081 |
| XL | `h05-cobra--a0a6ae0-a28055b` | 55 | 18522 | 20/24 | 1,475,459 | 833 |
| XL | `h06-caddy--7088605-54823f5` | 150 | 15753 | 20/278 | 1,464,690 | 825 |
| XL | `h08-hikaricp--98bd21c-ae553ce` | 94 | 8498 | 32/56 | 1,048,592 | 1072 |
| XL | `h11-nginx--0ddcae0-14341ce` | 150 | 30688 | 35/183 | 2,224,628 | 1084 |
| XL | `h15-dapper--360367c-cdc63c7` | 117 | 10076 | 72/78 | 1,504,079 | 365 |
| XL | `o01-juice-shop--a9b1dff-4488721` | 141 | 6315 | 47/120 | 1,130,782 | 856 |
| XL | `o02-webgoat--5357a65-bd398e4` | 150 | 6464 | 26/193 | 767,135 | 834 |
| XL | `o07-brokencrystals--2a64b95-c7a46e2` | 73 | 5660 | 35/95 | 983,151 | 1089 |
| XL | `o08-benchmarkpython--f129148-4369cab` | 69 | 138 | 52/114 | 834,352 | 843 |
| XL | `o09-benchmarkjava--20cbf3d-3f0c7a4` | 635 | 1738 | 31/644 | 927,442 | 862 |

## gemini-3.7-flash

Full run under `cm-011-diff`, image `c722b7b`, cm `0.11.0`, cm's default diff workers. Batch B hit the G9 evidence-mismatch stop rule (see below). As instructed, the benchmark then continued unchanged with `gemini-3.8-flash`; the Flarum mismatch is a known, accepted deviation.

| Batch | Cases | Run id | Execution | Execution wall | Results |
|---|---|---|---|---|---|
| A (repos 1–33) | 117 | `20261005_000000_find_v0.11.0_gemini-3.7-flash` | `cm-find-runner-9pwzv` | 29m06s (117/117 tasks succeeded) | `gs://codemender-sandbox-416585-cm-find-results/cm-011-diff/20261005_000000_find_v0.11.0_gemini-3.7-flash/` |
| B (repos 34–64) | 99 | `20261005_005744_find_v0.11.0_gemini-3.7-flash` | `cm-find-runner-w7w84` | 22m19s (99/99 tasks succeeded) | `gs://codemender-sandbox-416585-cm-find-results/cm-011-diff/20261005_005744_find_v0.11.0_gemini-3.7-flash/` |

`run.py` also staged repo tarballs locally before each execution (about 29 min for A, 18 min for B). Both `run.py` invocations exited 0. Every summary has `mode=diff`, `cm_version=0.11.0`, `model=gemini-3.7-flash` and `diff_workers=null`. No case logged a 429 or `RESOURCE_EXHAUSTED`.

### Per-band results (A + B)

Medians and p90s cover the valid cases that finished within cm's 5-minute ceiling. Timed-out cases are valid: their tokens are in the band totals and they are listed below. Excluded cases (next section) are in no aggregate.

| Band | Cases | Excluded | Timed out | Median tok | p90 tok | Median wall s | p90 wall s | Median lines | Median tok/line | Findings | Total tok |
|---|---|---|---|---|---|---|---|---|---|---|---|
| S | 50 | 0 | 1 | 196,671 | 477,638 | 78 | 194 | 38 | 4,063 | 4 CRITICAL, 15 HIGH, 1 MEDIUM | 15,556,970 |
| M | 57 | 2 | 7 | 359,452 | 938,195 | 116 | 270 | 280 | 1,580 | 15 CRITICAL, 28 HIGH, 4 MEDIUM, 1 LOW | 32,710,831 |
| L | 55 | 4 | 19 | 545,448 | 1,154,490 | 194 | 317 | 1,190 | 499 | 3 CRITICAL, 47 HIGH, 6 MEDIUM, 1 LOW | 57,557,319 |
| XL | 54 | 11 | 30 | 675,365 | 1,805,578 | 217 | 339 | 6,261 | 118 | 16 CRITICAL, 77 HIGH, 3 MEDIUM, 1 LOW | 55,322,551 |
| ALL | 216 | 17 | 57 | 370,090 | 1,037,474 | 128 | 283 | 274 | 1,260 | 38 CRITICAL, 167 HIGH, 14 MEDIUM, 3 LOW | 161,147,671 |

Tokens vs changed_lines (n=142, excl. timeouts): Pearson r=0.16, log-log r=0.59, OLS tokens ≈ 481,260 + 28·lines.

Total tokens across the 199 valid cases: **161,147,671** (A 99,967,374 · B 61,180,297).

### Excluded cases

17 of 216 cases are excluded from all aggregates (A 7/117, B 10/99; failed or zero-token cases are 7 in A and 9 in B, within the 10% budget).

| Case | Band | Batch | Cause |
|---|---|---|---|
| `p08-axios--0e4f9fa-a3ff99b` | M | A | token stats timed out |
| `p08-axios--0e4f9fa-a6dfa72` | L | A | token stats timed out |
| `p08-axios--0e4f9fa-c30252f` | XL | A | token stats timed out |
| `p14-fzf--c4a9ccd-6ea38b4` | XL | A | token stats timed out |
| `p18-kubernetes--6911225-77ecfb7` | XL | A | token stats timed out |
| `p19-argocd--25f7504-b71f0c8` | L | A | token stats timed out |
| `p30-valkey--2638827-a51eb05` | XL | A | token stats timed out |
| `p36-envoy--d79f6e8-f101823` | XL | B | token stats timed out |
| `p37-flarum--2a693db-c766881` | XL | B | token stats timed out; evidence mismatch (122/2,651 vs 143/2,848) |
| `p39-discourse--4732483-e9a8c05` | L | B | token stats timed out |
| `h04-svelte--a8deae9-b62fc8c` | XL | B | token stats timed out |
| `h11-nginx--0ddcae0-14341ce` | XL | B | token stats timed out |
| `h13-laravel--2fd3a25-dbcad29` | XL | B | token stats timed out |
| `o01-juice-shop--a9b1dff-4488721` | XL | B | token stats timed out |
| `o06-vulnerableapp--c4dd757-c68b25b` | XL | B | token stats timed out |
| `o07-brokencrystals--2a64b95-6626fd9` | L | B | token stats timed out |
| `p37-flarum--2a693db-2299541` | M | B | evidence mismatch (3/59 vs 15/171); tokens are valid |

"Token stats timed out": cm hit its 5-minute ceiling, then the runner's `cm-api-token-stats` hit its own 780 s limit (`token_stats_status=timeout`), so the summary has 0 tokens and `status=failed`. These cases all ran about 1,090 s; none logged a 429.

### Stop: evidence mismatch on Flarum

Flarum's `.gitattributes` marks `**/js/dist/**/*` and `**/js/dist-typings/**/*` as `-diff`. The container's `diff_stats.py` runs `git diff --numstat` in the checked-out repo, where git applies those attributes, reports the files as binary (`-\t-`) and they are dropped. The TSV `evidence` was mined without these attributes and counts them. cm still scans the files (its log lists the `dist-typings/*.d.ts` files as `[changed]`), so only the runner's `changed_files`/`changed_lines` are low. This is a pipeline bug in the measurement, which stops the benchmark before spending on the next model.

### Timed-out cases

| Band | Case | Files | Lines | Jobs done | Total tok | Wall s |
|---|---|---|---|---|---|---|
| S | `p30-valkey--2638827-fc32035` | 2 | 6 | 13/14 | 1,025,662 | 564 |
| M | `p02-fastapi--1c3e691-09e4859` | 15 | 577 | 24/25 | 382,710 | 571 |
| M | `p21-keycloak--8d1956e-79cbad8` | 10 | 210 | 215/223 | 1,002,328 | 423 |
| M | `p22-retrofit--cc76c22-9ae4f95` | 10 | 355 | 231/289 | 1,814,421 | 422 |
| M | `p30-valkey--2638827-0e0f58d` | 14 | 248 | 27/28 | 1,817,695 | 337 |
| M | `p34-zephyr--468eb56-28555ae` | 15 | 203 | 20/22 | 500,023 | 832 |
| M | `h09-exposed--d5309ce-ef62acd` | 14 | 468 | 23/24 | 755,015 | 396 |
| M | `h11-nginx--0ddcae0-ea8270c` | 14 | 81 | 18/23 | 1,444,403 | 1078 |
| L | `p14-fzf--c4a9ccd-e8405f4` | 40 | 2904 | 51/52 | 1,437,679 | 644 |
| L | `p15-prometheus--879d809-adf9939` | 46 | 627 | 52/53 | 1,185,070 | 594 |
| L | `p18-kubernetes--6911225-227c2e7` | 40 | 954 | 54/56 | 1,854,187 | 674 |
| L | `p21-keycloak--8d1956e-261b689` | 46 | 1056 | 177/248 | 1,198,088 | 676 |
| L | `p22-retrofit--cc76c22-869f48c` | 48 | 2224 | 204/317 | 1,650,819 | 418 |
| L | `p30-valkey--2638827-c4776ca` | 47 | 37050 | 65/66 | 3,944,193 | 619 |
| L | `p31-curl--fd567d4-0c890d9` | 49 | 1320 | 75/79 | 2,515,722 | 375 |
| L | `p32-wireguard--abba013-1b78070` | 29 | 247 | 33/39 | 3,331,477 | 1237 |
| L | `p33-openssl--4cb3112-0ce7d1f` | 33 | 623 | 50/52 | 3,232,332 | 873 |
| L | `p34-zephyr--468eb56-7d6ca26` | 48 | 661 | 38/53 | 2,278,063 | 880 |
| L | `p36-envoy--d79f6e8-5eccc35` | 46 | 973 | 75/78 | 1,691,303 | 874 |
| L | `h01-sqlalchemy--403194a-fb26ede` | 47 | 1559 | 38/40 | 1,695,192 | 644 |
| L | `h04-svelte--a8deae9-77ba5e7` | 49 | 2226 | 65/66 | 1,395,582 | 495 |
| L | `h06-caddy--7088605-cabb5d7` | 49 | 1553 | 63/64 | 2,116,711 | 622 |
| L | `h11-nginx--0ddcae0-6f20591` | 49 | 2900 | 35/73 | 1,705,023 | 1084 |
| L | `h12-fmt--e69e5f9-79981a2` | 44 | 10140 | 28/36 | 1,061,699 | 583 |
| L | `h13-laravel--2fd3a25-075c69f` | 44 | 1689 | 49/50 | 810,550 | 413 |
| L | `o03-nodegoat--c57d268-2de19ff` | 25 | 2129 | 45/65 | 1,484,930 | 378 |
| L | `o06-vulnerableapp--c4dd757-443c5f4` | 49 | 4593 | 50/57 | 1,223,295 | 848 |
| XL | `p03-scikit-learn--b51d0c9-8600fb4` | 143 | 8177 | 118/120 | 2,456,448 | 665 |
| XL | `p10-nextjs--2e7a96a-a7107a3` | 135 | 3133 | 92/97 | 2,017,711 | 411 |
| XL | `p11-vue--4619461-c379bc2` | 150 | 6212 | 113/143 | 1,238,151 | 637 |
| XL | `p12-grafana--277ef25-25390d2` | 150 | 7081 | 124/137 | 1,291,849 | 483 |
| XL | `p13-gin--75ccf94-0cbf290` | 91 | 8773 | 61/62 | 1,102,267 | 364 |
| XL | `p15-prometheus--879d809-d2817e9` | 146 | 10433 | 80/119 | 1,851,607 | 677 |
| XL | `p17-opentofu--aeaeacc-dcec46e` | 148 | 6588 | 77/105 | 1,807,320 | 662 |
| XL | `p19-argocd--25f7504-be1f0ea` | 149 | 9546 | 79/181 | 1,926,056 | 880 |
| XL | `p20-spring-boot--a25e1eb-e8263c8` | 147 | 3661 | 127/161 | 1,308,531 | 702 |
| XL | `p21-keycloak--8d1956e-2454565` | 149 | 4801 | 144/328 | 1,470,810 | 913 |
| XL | `p22-retrofit--cc76c22-ac57d42` | 103 | 19141 | 172/328 | 1,375,010 | 405 |
| XL | `p25-ktor--b5d9213-89805f7` | 85 | 2716 | 68/69 | 974,914 | 654 |
| XL | `p26-okhttp--4984568-cd72237` | 149 | 12062 | 95/117 | 1,675,077 | 897 |
| XL | `p27-ripgrep--e50df40-f511849` | 103 | 30699 | 101/102 | 2,164,232 | 653 |
| XL | `p31-curl--fd567d4-25cbc2f` | 70 | 1548 | 79/95 | 2,363,570 | 873 |
| XL | `p34-zephyr--468eb56-7cfc8b3` | 150 | 2539 | 55/128 | 1,729,887 | 1121 |
| XL | `p38-symfony--08964d6-96d664e` | 149 | 2309 | 139/140 | 1,078,934 | 410 |
| XL | `p39-discourse--4732483-bfb292d` | 76 | 1824 | 48/64 | 1,328,245 | 634 |
| XL | `p40-aspnet-core--b8139c5-2bf9d24` | 137 | 3981 | 81/148 | 1,504,034 | 898 |
| XL | `h01-sqlalchemy--403194a-6dc8ca2` | 120 | 5784 | 83/84 | 2,406,688 | 678 |
| XL | `h02-pandas--d9cdd2e-859c030` | 149 | 2465 | 64/94 | 1,306,176 | 478 |
| XL | `h06-caddy--7088605-54823f5` | 150 | 15753 | 118/278 | 1,051,767 | 387 |
| XL | `h09-exposed--d5309ce-526b2b8` | 149 | 7731 | 42/122 | 979,361 | 1085 |
| XL | `h10-serde--d5bc546-c17c4ee` | 110 | 24143 | 28/48 | 795,777 | 652 |
| XL | `h14-sidekiq--30786e0-2ee7e27` | 143 | 18794 | 79/118 | 1,098,737 | 858 |
| XL | `h15-dapper--360367c-cdc63c7` | 117 | 10076 | 77/78 | 815,937 | 642 |
| XL | `o02-webgoat--5357a65-bd398e4` | 150 | 6464 | 75/193 | 915,557 | 869 |
| XL | `o07-brokencrystals--2a64b95-c7a46e2` | 73 | 5660 | 51/95 | 1,202,531 | 868 |
| XL | `o08-benchmarkpython--f129148-4369cab` | 69 | 138 | 79/114 | 920,580 | 374 |
| XL | `o09-benchmarkjava--20cbf3d-3f0c7a4` | 635 | 1738 | 62/644 | 806,323 | 627 |

## gemini-3.1-pro-preview

Full run under `cm-011-diff`, image `c722b7b`, cm `0.11.0`, cm's default diff workers. Both batches ran unchanged. Zero-token cases stayed within the 10% budget (A 8/117, B 8/99); the only accepted deviation is the known Flarum mismatch.

| Batch | Cases | Run id | Execution | Execution wall | Results |
|---|---|---|---|---|---|
| A (repos 1–33) | 117 | `20261005_044751_find_v0.11.0_gemini-3.1-pro-preview` | `cm-find-runner-8crmx` | 26m37s (117/117 tasks succeeded) | `gs://codemender-sandbox-416585-cm-find-results/cm-011-diff/20261005_044751_find_v0.11.0_gemini-3.1-pro-preview/` |
| B (repos 34–64) | 99 | `20261005_051827_find_v0.11.0_gemini-3.1-pro-preview` | `cm-find-runner-vhwz9` | 21m24s (99/99 tasks succeeded) | `gs://codemender-sandbox-416585-cm-find-results/cm-011-diff/20261005_051827_find_v0.11.0_gemini-3.1-pro-preview/` |

Both `run.py` invocations exited 0. Every summary has `mode=diff`, `cm_version=0.11.0`, `model=gemini-3.1-pro-preview` and `diff_workers=null`. The only evidence mismatches are the two known Flarum cases (see the `gemini-3.7-flash` section).

**Timing check.** The stop rule allowed each batch 3× the `gemini-3.7-flash` execution time. A took 26m37s (limit 87m18s) and B 21m24s (limit 66m57s).

**429s.** On the same quota as `gemini-3.8-flash` (`aiplatform.googleapis.com/concurrent_interaction_generations`): batch A had 22/117 cases with 429s (80 log lines, around 04:55 UTC); batch B had 0/99.

### Per-band results (A + B)

Medians and p90s cover the valid cases that finished within cm's 5-minute ceiling. Timed-out cases are valid: their tokens are in the band totals and they are listed below. Excluded cases are in no aggregate.

| Band | Cases | Excluded | Timed out | Median tok | p90 tok | Median wall s | p90 wall s | Median lines | Median tok/line | Findings | Total tok |
|---|---|---|---|---|---|---|---|---|---|---|---|
| S | 50 | 0 | 8 | 144,531 | 536,158 | 63 | 215 | 40 | 3,591 | 22 CRITICAL, 53 HIGH, 12 MEDIUM | 22,927,017 |
| M | 57 | 2 | 14 | 340,035 | 876,271 | 144 | 271 | 278 | 1,346 | 37 CRITICAL, 121 HIGH, 22 MEDIUM, 1 LOW | 47,078,251 |
| L | 55 | 10 | 23 | 592,060 | 1,161,301 | 190 | 288 | 1,279 | 384 | 31 CRITICAL, 137 HIGH, 17 MEDIUM | 49,027,204 |
| XL | 54 | 6 | 38 | 697,879 | 1,686,058 | 250 | 306 | 8,848 | 85 | 47 CRITICAL, 245 HIGH, 35 MEDIUM, 4 LOW | 60,035,536 |
| ALL | 216 | 18 | 83 | 370,220 | 1,046,532 | 139 | 280 | 228 | 1,360 | 137 CRITICAL, 556 HIGH, 86 MEDIUM, 5 LOW | 179,068,008 |

Tokens vs changed_lines (n=115, excl. timeouts): Pearson r=0.19, log-log r=0.64, OLS tokens ≈ 439,093 + 22·lines.

Total tokens across the 198 valid cases: **179,068,008** (A 103,350,565 · B 75,717,443).

### Excluded cases

18 of 216 cases (A 8, B 10) are excluded. Every token-stats failure hit cm's ceiling first; then `cm-api-token-stats` timed out after 780 s, so the summary has 0 tokens and `status=failed`.

| Case | Band | Batch | 429 lines | Cause |
|---|---|---|---|---|
| `p08-axios--0e4f9fa-a6dfa72` | L | A | 0 | token stats timed out |
| `p08-axios--0e4f9fa-c30252f` | XL | A | 0 | token stats timed out |
| `p12-grafana--277ef25-31b6fcb` | L | A | 3 | token stats timed out |
| `p18-kubernetes--6911225-77ecfb7` | XL | A | 4 | token stats timed out |
| `p19-argocd--25f7504-b71f0c8` | L | A | 2 | token stats timed out |
| `p21-keycloak--8d1956e-261b689` | L | A | 0 | token stats timed out |
| `p31-curl--fd567d4-25cbc2f` | XL | A | 14 | token stats timed out |
| `p33-openssl--4cb3112-1a4b029` | M | A | 1 | token stats timed out |
| `p35-grpc--b8a04ac-32e0317` | L | B | 0 | token stats timed out |
| `p36-envoy--d79f6e8-f101823` | XL | B | 0 | token stats timed out |
| `p37-flarum--2a693db-2299541` | M | B | 0 | evidence mismatch (3/59 vs 15/171); tokens are valid |
| `p37-flarum--2a693db-c766881` | XL | B | 0 | evidence mismatch (122/2,651 vs 143/2,848); tokens are valid |
| `p39-discourse--4732483-e9a8c05` | L | B | 0 | token stats timed out |
| `h04-svelte--a8deae9-77ba5e7` | L | B | 0 | token stats timed out |
| `h11-nginx--0ddcae0-6f20591` | L | B | 0 | token stats timed out |
| `h14-sidekiq--30786e0-2abed51` | L | B | 0 | token stats timed out |
| `o01-juice-shop--a9b1dff-4488721` | XL | B | 0 | token stats timed out |
| `o03-nodegoat--c57d268-2de19ff` | L | B | 0 | token stats timed out |

### Timed-out cases

| Band | Case | Files | Lines | Jobs done | Total tok | Wall s |
|---|---|---|---|---|---|---|
| S | `p07-express--04bc627-0e3ab6e` | 3 | 335 | 13/14 | 1,459,106 | 566 |
| S | `p08-axios--0e4f9fa-870e0a7` | 3 | 31 | 11/30 | 2,027,523 | 834 |
| S | `p12-grafana--277ef25-47f85d8` | 3 | 21 | 12/13 | 2,370,762 | 587 |
| S | `p31-curl--fd567d4-3b9ac36` | 2 | 56 | 3/4 | 447,242 | 587 |
| S | `p32-wireguard--abba013-4aa61c8` | 3 | 8 | 8/9 | 583,528 | 420 |
| S | `p34-zephyr--468eb56-686a8c9` | 2 | 4 | 11/12 | 910,330 | 628 |
| S | `p37-flarum--2a693db-5d14f96` | 3 | 59 | 11/13 | 1,197,836 | 577 |
| S | `h11-nginx--0ddcae0-cca5655` | 3 | 9 | 5/7 | 2,240,706 | 823 |
| M | `p08-axios--0e4f9fa-a3ff99b` | 6 | 186 | 7/31 | 5,172,006 | 1068 |
| M | `p17-opentofu--aeaeacc-5f9800a` | 15 | 520 | 20/21 | 1,067,046 | 571 |
| M | `p19-argocd--25f7504-da6c2e9` | 14 | 415 | 50/51 | 1,740,638 | 370 |
| M | `p21-keycloak--8d1956e-79cbad8` | 10 | 210 | 197/223 | 987,212 | 630 |
| M | `p22-retrofit--cc76c22-9ae4f95` | 10 | 355 | 128/289 | 1,004,861 | 416 |
| M | `p30-valkey--2638827-0e0f58d` | 14 | 248 | 27/28 | 3,139,230 | 584 |
| M | `p31-curl--fd567d4-3455572` | 8 | 144 | 24/27 | 2,700,073 | 859 |
| M | `p32-wireguard--abba013-7e1d6ca` | 15 | 87 | 19/25 | 2,223,754 | 1168 |
| M | `p34-zephyr--468eb56-28555ae` | 15 | 203 | 21/22 | 2,079,333 | 423 |
| M | `p36-envoy--d79f6e8-2de9c29` | 11 | 233 | 21/23 | 2,600,682 | 831 |
| M | `h11-nginx--0ddcae0-ea8270c` | 14 | 81 | 4/23 | 2,171,041 | 1062 |
| M | `h12-fmt--e69e5f9-47c8f63` | 15 | 1223 | 17/18 | 879,754 | 622 |
| M | `o03-nodegoat--c57d268-52e51e9` | 15 | 326 | 35/36 | 1,211,379 | 364 |
| M | `o07-brokencrystals--2a64b95-94d3f9b` | 15 | 2563 | 22/25 | 1,359,544 | 608 |
| L | `p07-express--04bc627-a659137` | 41 | 3662 | 14/15 | 664,573 | 324 |
| L | `p11-vue--4619461-ea494af` | 47 | 974 | 53/55 | 1,333,438 | 832 |
| L | `p13-gin--75ccf94-1e1f0b1` | 31 | 1252 | 34/37 | 833,862 | 574 |
| L | `p14-fzf--c4a9ccd-e8405f4` | 40 | 2904 | 14/52 | 978,265 | 822 |
| L | `p15-prometheus--879d809-adf9939` | 46 | 627 | 44/53 | 2,181,459 | 891 |
| L | `p16-traefik--8ea3398-7b649e2` | 49 | 2836 | 76/77 | 790,334 | 361 |
| L | `p17-opentofu--aeaeacc-a69d19d` | 41 | 938 | 35/36 | 1,507,135 | 593 |
| L | `p18-kubernetes--6911225-227c2e7` | 40 | 954 | 42/56 | 1,834,858 | 858 |
| L | `p22-retrofit--cc76c22-869f48c` | 48 | 2224 | 119/317 | 918,526 | 378 |
| L | `p25-ktor--b5d9213-f1f5a2d` | 49 | 1106 | 40/46 | 996,116 | 599 |
| L | `p27-ripgrep--e50df40-082245d` | 33 | 1292 | 53/54 | 1,158,928 | 594 |
| L | `p30-valkey--2638827-c4776ca` | 47 | 37050 | 47/66 | 2,224,564 | 713 |
| L | `p31-curl--fd567d4-0c890d9` | 49 | 1320 | 47/79 | 2,244,403 | 1085 |
| L | `p32-wireguard--abba013-1b78070` | 29 | 247 | 22/39 | 2,892,728 | 1253 |
| L | `p33-openssl--4cb3112-0ce7d1f` | 33 | 623 | 25/52 | 1,137,672 | 348 |
| L | `p34-zephyr--468eb56-7d6ca26` | 48 | 661 | 29/53 | 1,562,113 | 648 |
| L | `p36-envoy--d79f6e8-5eccc35` | 46 | 973 | 45/78 | 1,950,251 | 1094 |
| L | `p40-aspnet-core--b8139c5-a244ff1` | 47 | 1458 | 49/87 | 796,808 | 590 |
| L | `h06-caddy--7088605-cabb5d7` | 49 | 1553 | 34/64 | 1,301,317 | 1079 |
| L | `h09-exposed--d5309ce-42ac41b` | 32 | 1109 | 36/37 | 1,994,595 | 581 |
| L | `h12-fmt--e69e5f9-79981a2` | 44 | 10140 | 29/36 | 1,077,622 | 1060 |
| L | `o06-vulnerableapp--c4dd757-443c5f4` | 49 | 4593 | 48/57 | 1,468,928 | 839 |
| L | `o07-brokencrystals--2a64b95-6626fd9` | 48 | 5352 | 26/71 | 2,120,620 | 857 |
| XL | `p03-scikit-learn--b51d0c9-8600fb4` | 143 | 8177 | 108/120 | 2,258,141 | 849 |
| XL | `p04-pytorch-geom--f1656e3-47b0a14` | 136 | 6261 | 85/107 | 1,123,933 | 843 |
| XL | `p06-requests--0e322af-130773a` | 52 | 14865 | 45/46 | 959,985 | 572 |
| XL | `p10-nextjs--2e7a96a-a7107a3` | 135 | 3133 | 70/97 | 2,149,125 | 1108 |
| XL | `p11-vue--4619461-c379bc2` | 150 | 6212 | 97/143 | 1,097,790 | 842 |
| XL | `p12-grafana--277ef25-25390d2` | 150 | 7081 | 102/137 | 1,088,109 | 859 |
| XL | `p13-gin--75ccf94-0cbf290` | 91 | 8773 | 34/62 | 1,260,060 | 836 |
| XL | `p14-fzf--c4a9ccd-6ea38b4` | 63 | 9112 | 22/77 | 1,644,404 | 471 |
| XL | `p15-prometheus--879d809-d2817e9` | 146 | 10433 | 55/119 | 1,302,645 | 1083 |
| XL | `p16-traefik--8ea3398-9f145db` | 71 | 4509 | 62/95 | 1,704,704 | 698 |
| XL | `p17-opentofu--aeaeacc-dcec46e` | 148 | 6588 | 47/105 | 1,211,081 | 842 |
| XL | `p19-argocd--25f7504-be1f0ea` | 149 | 9546 | 59/181 | 1,784,401 | 1088 |
| XL | `p20-spring-boot--a25e1eb-e8263c8` | 147 | 3661 | 103/161 | 1,209,447 | 612 |
| XL | `p21-keycloak--8d1956e-2454565` | 149 | 4801 | 117/328 | 2,257,233 | 638 |
| XL | `p22-retrofit--cc76c22-ac57d42` | 103 | 19141 | 130/328 | 845,907 | 394 |
| XL | `p25-ktor--b5d9213-89805f7` | 85 | 2716 | 35/69 | 1,381,345 | 589 |
| XL | `p26-okhttp--4984568-cd72237` | 149 | 12062 | 51/117 | 1,592,529 | 835 |
| XL | `p27-ripgrep--e50df40-f511849` | 103 | 30699 | 70/102 | 1,164,762 | 365 |
| XL | `p28-tokio--14c17fc-4601c84` | 150 | 5435 | 101/129 | 1,112,137 | 495 |
| XL | `p29-clap--5e4facf-9cc4fe8` | 148 | 10361 | 65/103 | 926,584 | 458 |
| XL | `p30-valkey--2638827-a51eb05` | 112 | 42087 | 29/154 | 815,946 | 824 |
| XL | `p34-zephyr--468eb56-7cfc8b3` | 150 | 2539 | 40/128 | 1,742,107 | 530 |
| XL | `p38-symfony--08964d6-96d664e` | 149 | 2309 | 117/140 | 897,628 | 380 |
| XL | `p39-discourse--4732483-bfb292d` | 76 | 1824 | 25/64 | 1,631,399 | 850 |
| XL | `p40-aspnet-core--b8139c5-2bf9d24` | 137 | 3981 | 64/148 | 890,149 | 1105 |
| XL | `h02-pandas--d9cdd2e-859c030` | 149 | 2465 | 83/94 | 1,750,181 | 596 |
| XL | `h04-svelte--a8deae9-b62fc8c` | 85 | 2778 | 53/97 | 1,664,343 | 836 |
| XL | `h06-caddy--7088605-54823f5` | 150 | 15753 | 121/278 | 1,382,603 | 603 |
| XL | `h07-jackson--cf9e855-21776ca` | 150 | 5458 | 28/29 | 828,671 | 499 |
| XL | `h09-exposed--d5309ce-526b2b8` | 149 | 7731 | 65/122 | 1,848,820 | 842 |
| XL | `h11-nginx--0ddcae0-14341ce` | 150 | 30688 | 44/183 | 1,628,513 | 1079 |
| XL | `h13-laravel--2fd3a25-dbcad29` | 150 | 3763 | 110/128 | 1,446,340 | 369 |
| XL | `h14-sidekiq--30786e0-2ee7e27` | 143 | 18794 | 49/118 | 713,768 | 588 |
| XL | `o02-webgoat--5357a65-bd398e4` | 150 | 6464 | 67/193 | 804,876 | 350 |
| XL | `o06-vulnerableapp--c4dd757-c68b25b` | 145 | 15698 | 50/176 | 1,608,728 | 858 |
| XL | `o07-brokencrystals--2a64b95-c7a46e2` | 73 | 5660 | 28/95 | 2,324,026 | 611 |
| XL | `o08-benchmarkpython--f129148-4369cab` | 69 | 138 | 85/114 | 639,466 | 626 |
| XL | `o09-benchmarkjava--20cbf3d-3f0c7a4` | 635 | 1738 | 75/644 | 752,395 | 608 |

## Token-stats smoke (`cm-ts-smoke`)

Checks the re-vendored `cm-api-token-stats` (fde-security-aigis `61338ff`, `--token-stats-workers 8`) on 5 XL cases that timed out token stats in the full runs. Both phases ran the same `run.py --mode diff` command (cm `0.11.0`, `gemini-3.8-flash`, cm's default diff workers, 780 s stats limit). Phase 1 used image `c722b7b` (vendored `2709976`); phase 2 used image `9683bac`.

- Phase 1: run `20261005_201907_find_v0.11.0_gemini-3.8-flash`, execution `cm-find-runner-5fkds`, 19m60s.
- Phase 2: run `20261005_205113_find_v0.11.0_gemini-3.8-flash`, execution `cm-find-runner-2pz7g`, 9m28s.

| Case | Phase 1 stats | Phase 1 tokens | Phase 1 stats s | Phase 1 wall s | Phase 2 stats | Phase 2 tokens | Phase 2 stats s | Phase 2 wall s |
|---|---|---|---|---|---|---|---|---|
| `p08-axios--0e4f9fa-c30252f` | timeout | 0 | 791 | 1088 | ok | 2,130,699 | 70 | 364 |
| `p31-curl--fd567d4-25cbc2f` | timeout | 0 | 792 | 1094 | ok | 1,989,251 | 50 | 349 |
| `p36-envoy--d79f6e8-f101823` | ok | 960,723 | 559 | 877 | ok | 1,087,233 | 64 | 371 |
| `p40-aspnet-core--b8139c5-2bf9d24` | timeout | 0 | 792 | 1117 | ok | 1,387,890 | 46 | 366 |
| `h14-sidekiq--30786e0-2ee7e27` | timeout | 0 | 791 | 1088 | ok | 1,341,223 | 55 | 353 |

"Stats s" runs from cm's exit to the results upload, read from the entrypoint's Cloud Logging lines, so it includes summary and upload (a few seconds). Every case in both phases hit cm's 5-minute delta ceiling or its `--fail-on` gate first.

- Phase 1 reproduced the failure on 4/5 cases. `p36-envoy` finished token stats this time, but took 559 s of the 780 s limit.
- Phase 2 recorded tokens on 5/5 cases (7,936,296 total). Token stats took 46–70 s, and each phase-2 log has `cm-api-token-stats (limit 780s, workers 8)`.
- Task wall time fell from 877–1,117 s to 349–371 s. Phases are separate cm runs, so token totals are not comparable case for case.

