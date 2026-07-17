# CI Scoring Status

Last updated: 2026-07-17 21:49:12 IST
Loop started: 2026-07-17 21:29:29 IST
Elapsed: 0h 19m (limit 8h)

## Droplet connectivity (this cycle)

| Run | IP | Reachable | Consecutive failures | Note |
|---|---|---|---|---|
| run1 | 137.184.197.51 | no | 10 | may be unreachable |
| run2 | 157.245.87.129 | no | 10 | may be unreachable |
| run3 | 206.81.9.89 | no | 10 | may be unreachable |

## run1 (droplet 137.184.197.51)

| Model | Predictions | Scored | Passed | Status |
|---|---|---|---|---|
| codellama_34b_fp16 | 215 | 62 | 11 | IN PROGRESS |
| glm4_9b_fp16 | 215 | 0 | 0 | NOT STARTED |
| glm4_9b_q4 | 215 | 0 | 0 | NOT STARTED |
| qwen25coder14b_fp16 | 215 | 0 | 0 | NOT STARTED |
| qwen25coder7b_fp16 | not synced yet | 0 | 0 | NOT STARTED |

## run2 (droplet 157.245.87.129)

| Model | Predictions | Scored | Passed | Status |
|---|---|---|---|---|
| codellama_34b_fp16 | 215 | 69 | 8 | IN PROGRESS |
| glm4_9b_fp16 | 215 | 0 | 0 | NOT STARTED |
| glm4_9b_q4 | 215 | 0 | 0 | NOT STARTED |
| qwen25coder14b_fp16 | 215 | 0 | 0 | NOT STARTED |
| qwen25coder7b_fp16 | not synced yet | 0 | 0 | NOT STARTED |

## run3 (droplet 206.81.9.89)

| Model | Predictions | Scored | Passed | Status |
|---|---|---|---|---|
| codellama_34b_fp16 | 215 | 63 | 10 | IN PROGRESS |
| glm4_9b_fp16 | 215 | 0 | 0 | NOT STARTED |
| glm4_9b_q4 | 215 | 0 | 0 | NOT STARTED |
| qwen25coder14b_fp16 | 204 | 0 | 0 | NOT STARTED |
| qwen25coder7b_fp16 | not synced yet | 0 | 0 | NOT STARTED |

## Stop condition check

Models with complete (215) predictions in all 3 runs: codellama_34b_fp16, glm4_9b_fp16, glm4_9b_q4
Of those, fully scored (results >= predictions) in all 3 runs: (none yet)
Stop condition (a) satisfied: False

