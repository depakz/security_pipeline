# Gemini Code Assist Prompt: Resilient API Connectivity & Validation Fix

I am seeing "ConnectionRefusedError: [Errno 111]" in my pipeline logs (image_0fa984.png). 
The scanner is completing with "0 actionable findings" because it cannot reach the local target.
Refactor the current security pipeline code with the following changes:

### 1. Robust Connectivity Helper
Add a helper function `verify_target_alive(target_url)` that:
- Attempts a HEAD or GET request to the target.
- If `localhost` fails, automatically tries `127.0.0.1`.
- Returns a boolean and the "working" URL.

### 2. Validator Pre-flight Check
Update the `DAG execution loop` and the `BaseValidator` class:
- Implement a `pre_flight_check()` method.
- If the check fails, log "CRITICAL: Target [URL] is unreachable. Skipping validation." 
- Immediately terminate the DAG for that target instead of executing failed edges.

### 3. Nuclei Integration Fix
- Update the Nuclei command in `run_api_scan` to include `-retry-at-attempt 3`.
- Add a check: if Nuclei returns `exit 1` within 2 seconds, log "Error: Nuclei could not connect to target. Verify port binding."

### 4. Output Correctness
- Ensure that if the target is down, the final JSON report explicitly states "Target Unreachable" in the status field instead of just "No findings."

Provide the updated Python classes for the 'Alpha' platform.