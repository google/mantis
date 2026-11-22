# How to contribute

We'd love to accept your patches and contributions to this project.

## Before you begin

### Sign our Contributor License Agreement

Contributions to this project must be accompanied by a
[Contributor License Agreement](https://cla.developers.google.com/about) (CLA).
You (or your employer) retain the copyright to your contribution; this simply
gives us permission to use and redistribute your contributions as part of the
project.

If you or your current employer have already signed the Google CLA (even if it
was for a different project), you probably don't need to do it again.

Visit <https://cla.developers.google.com/> to see your current agreements or to
sign a new one.

### AI-assisted contributions

All submissions to Google Open Source projects need to follow Google's
Contributor License Agreement (CLA), which covers any original work of
authorship included in the submission. This doesn't prohibit the use of coding
assistance tools, including tool-, AI-, or machine-generated code, as long as
these submissions abide by the CLA's requirements.

Please do not list non-humans or AI tools in Git `Author` or `Co-Authored-By`
trailers (doing so will cause the automated `cla/google` check to fail). If you
would like to disclose AI tooling, use `Assisted-by:` or `Generated-by:` in the
commit message or PR description instead.

### Review our community guidelines

This project follows
[Google's Open Source Community Guidelines](https://opensource.google/conduct/).

## Contribution process

### Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

### Running checks locally

Before opening a pull request, please make sure the repository's offline checks
pass:

1. Run pre-commit hooks (formats Markdown with pinned `mdformat` and verifies
   Apache-2.0 license headers on all `.py` and `.sh` files):

   ```bash
   pre-commit run --all-files
   ```

2. Verify skill integrity:

   ```bash
   python3 test_skills_integrity.py
   ```

3. Run the reference harness unit and security mutation tests (with Python 3.13
   and `reference/requirements.txt` installed):

   ```bash
   cd reference
   python3 scripts/run_unit_tests.py --jobs 4
   python3 scripts/mutation_test.py --jobs 4
   ```

New `.py` and `.sh` files must include the standard Apache-2.0 license header
(`Copyright <YYYY> Google LLC`), which `pre-commit` verifies automatically.
