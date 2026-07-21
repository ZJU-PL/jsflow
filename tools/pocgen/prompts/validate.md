Validate the generated PoC as a true runnable reproduction, not just a script
that exits successfully.

Report whether the PoC:

1. reaches the reported sink,
2. places the payload in the tainted source binding,
3. observes the stated oracle,
4. avoids destructive side effects,
5. prints a clear success signal such as `PASS`.

Return concise JSON with `status`, `reason`, and `fix_suggestions`.

