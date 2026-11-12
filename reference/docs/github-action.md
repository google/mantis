# Mantis GitHub Action: scan the pull request

`action/` wraps the MCP server's scan tier and deterministic gate (see
[mcp.md](mcp.md)) as a GitHub Action. On every pull request it scans the changed
files with the full Mantis pipeline, runs `check_change` over the PR diff, and
reports the verdict as annotations on the diff plus a step summary.

The action is **advisory and fail-open by default**: the job passes whatever the
verdict, the findings appear as warnings on the changed lines, and a broken
scanner -- a model outage, a setup mistake, a crash -- never stops a merge. Two
inputs change that independently once you trust it on your code: `fail-on` makes
findings fail the job; `fail-closed` makes "Mantis could not look" fail it too.

> **Status: not yet run end-to-end.** Everything below has been tested against
> stubs and read by two security audits, but the action has not yet run against
> a live project: no workflow run, no environment, no credential. Not verified
> by execution: the custom role's permission list against real model calls; the
> hash-pinned install on GitHub's runner image; the daily meter's metric, and
> whether models other than Gemini count in it; metering of the context
> compaction path; how the step summary renders; the knowledge-refresh workflow
> in its entirety; wall time against the 90-minute job timeout on a real diff.
> Until the scan has run cleanly several times, leave `fail-on` and
> `fail-closed` unset, do not set up the refresh workflow (`--refresh`), and on
> the first runs read the scan log for permission denials, the meter line, the
> spend report and the run time. The commit that records those runs should
> remove this note.

## Setup

The scan runs Gemini on the Gemini Enterprise Agent Platform (the service
formerly named Vertex AI; the API, `aiplatform.googleapis.com`, and the
`vertex_ai/` model prefix litellm uses keep their old ids). The job
authenticates with workload identity federation, so the repository holds no
long-lived key. Four things to create: a Google Cloud project that can only run
the model, a spending stop on that project, a GitHub environment that holds the
project's names and gates the job, and the workflow.

### One command

With a project created and billing attached, `scripts/setup_github_action.sh`
does the Google Cloud part, and with `--github` the GitHub part too:

```bash
reference/scripts/setup_github_action.sh --project <project> --repo org/repo \
    --budget-usd <amount> --github --reviewer-team <security-team>
```

It enables the APIs; creates a custom role that can call the model, manage its
context caches and read the project's token meter and nothing else (pass
`--role roles/aiplatform.user` to use the predefined role instead, knowing it
can also create training jobs and endpoints the meter never sees); the service
account with that role; the workload identity pool and a provider whose
condition pins the repository by its numeric id and owner id as well as by name
(read with `gh`, or passed as `--repo-id`/`--owner-id`), from the environment
`mantis-pr-scan` only; and a binding from exactly that subject to the service
account. With `--budget-usd`, a Pub/Sub topic and a billing budget at 50%, 90%
and 100% (`--no-budget` says explicitly that you want none). With `--github`,
the environment -- created **with the required reviewers you name**, self-review
prevented -- and its three secrets. It ends by printing the three values and the
workflow to commit.

Run it again after a failure or a rename and it creates nothing twice: each step
checks first, the provider condition and the role's permissions are updated to
the current ones, and an environment that already exists is never replaced
(replacing it would remove the reviewers a person added), only its secrets set;
its protection is reported, loudly if it has no reviewers. `--dry-run` prints
every command instead. `--environment`, `--service-account`, `--pool` and
`--provider` rename the pieces.

One project can serve several repositories: run the script once per repository
with its own `--provider` and `--service-account`. The pool, the role and the
budget are shared -- the budget caps the project, not a repository, so the
second run finds it and needs neither budget flag. So is the daily token meter
(see Spend). No repository gets a grant on the project itself; each one's
identity can act only as its own service account.

For the knowledge-refresh workflow, run it a second time with `--refresh`: a
second provider admitting `refs/heads/main` from the `mantis-knowledge`
environment only, and that environment created with a deployment-branch rule of
`main`.

Two things it leaves to you, and says so: the function that detaches billing
when the budget is spent (The spending stop, below), and the reading the
reviewers do before approving a run. The sections that follow are what the
script does, for doing it by hand or for checking its work.

### Google Cloud

One project reserved for this, with billing attached. Replace `org/repo` with
your repository and keep the environment name if you keep it in the workflow.

```bash
PROJECT=<project>
gcloud config set project "$PROJECT"
NUMBER=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')

# The model API, the project's own usage meter, and what workload identity
# needs to mint and exchange tokens.
gcloud services enable aiplatform.googleapis.com monitoring.googleapis.com \
    iamcredentials.googleapis.com iam.googleapis.com sts.googleapis.com

# A role that can call the model, manage its context caches, and read the
# project's meter -- and nothing else. roles/aiplatform.user would also let
# the token create training jobs and endpoints the meter never sees.
gcloud iam roles create mantisPrScan --project="$PROJECT" --title="Mantis PR scan" \
    --permissions=aiplatform.endpoints.predict,aiplatform.cachedContents.create,aiplatform.cachedContents.get,aiplatform.cachedContents.list,aiplatform.cachedContents.update,aiplatform.cachedContents.delete,monitoring.timeSeries.list

# A service account with that role.
gcloud iam service-accounts create mantis-pr-scan --display-name="Mantis PR scan"
SA="mantis-pr-scan@$PROJECT.iam.gserviceaccount.com"
gcloud projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:$SA" --role="projects/$PROJECT/roles/mantisPrScan"

# A pool with a GitHub OIDC provider, admitting one repository -- by its
# numeric ids, which a renamed or re-created repository cannot reuse, and by
# name -- from one environment. gh api repos/org/repo --jq '.id, .owner.id'
# gives the ids.
gcloud iam workload-identity-pools create github --location=global \
    --display-name="GitHub Actions (Mantis)"
gcloud iam workload-identity-pools providers create-oidc mantis \
    --location=global --workload-identity-pool=github \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
    --attribute-condition="assertion.repository_id == '<repo-id>' && assertion.repository_owner_id == '<owner-id>' && assertion.repository == 'org/repo' && assertion.environment == 'mantis-pr-scan'"

# Let exactly that repository's jobs in that environment impersonate the
# service account: one subject, not every token the pool maps for the repo.
gcloud iam service-accounts add-iam-policy-binding "$SA" \
    --role="roles/iam.workloadIdentityUser" \
    --member="principal://iam.googleapis.com/projects/$NUMBER/locations/global/workloadIdentityPools/github/subject/repo:org/repo:environment:mantis-pr-scan"

# The three values GitHub needs.
gcloud iam workload-identity-pools providers describe mantis \
    --location=global --workload-identity-pool=github --format='value(name)'
echo "$SA"
echo "$PROJECT"
```

### The spending stop

The action bounds what one run spends (see Spend). What the project may spend in
a month is yours to decide and yours to enforce, because the platform will not
do it for you: Gemini on the Agent Platform draws on dynamic shared quota, which
has no per-project ceiling to lower, and a budget on its own only sends mail.
Wire the budget to something that cuts the project off:

```bash
BILLING=$(gcloud billing projects describe "$PROJECT" --format='value(billingAccountName)')
gcloud pubsub topics create mantis-pr-scan-budget
gcloud billing budgets create --billing-account="${BILLING#billingAccounts/}" \
    --display-name="Mantis PR scan" --budget-amount=<amount>USD \
    --filter-projects="projects/$NUMBER" \
    --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 \
    --threshold-rule=percent=1.0 \
    --notifications-rule-pubsub-topic="projects/$PROJECT/topics/mantis-pr-scan-budget"
```

Then, if you want the stop to be automatic, subscribe a function to the topic
that detaches billing from the project when the message's `costAmount` reaches
`budgetAmount`. Google publishes the function and the IAM it needs:
[Disable billing with notifications](https://docs.cloud.google.com/billing/docs/how-to/disable-billing-with-notifications);
deploy it as written.

> **Warning.** Detaching billing shuts down every billable service in the
> project, and Google's own page warns that resources in it can be stopped and
> their data lost. That is the point here, and it is safe only in a project that
> holds nothing you would miss: this service account, this pool, this budget,
> and nothing else. Never attach this stop to a project with persistent
> resources, data, or anything another system depends on. Re-attaching billing
> afterwards is a manual step, and until someone does it every scan fails with a
> setup error, which is the behaviour you want from a stop.

Pick `<amount>` as the most you are prepared to lose to a bug in a month, not as
a forecast. Budget data lags by hours; the stop is for a runaway that lasts a
day, and the action's own limits are for the one that lasts a run.

### GitHub

1. Create an environment named `mantis-pr-scan` (Settings, Environments) and
   **put required reviewers on it**. This is not optional. On a `pull_request`
   event GitHub runs the pull request's own copy of the workflow file, and a job
   that declares the environment receives its secrets and can mint the identity
   token the provider accepts. Without reviewers, anyone who can push a branch
   can edit the workflow to send the credential wherever they like, remove every
   budget, or run anything at all with it, and the run happens before anyone
   reads the pull request. Branch protection and CODEOWNERS gate the merge, not
   the run; a deployment-branch rule does not help either, because the run's ref
   is the merge ref. The reviewers are the control: a person approves each run,
   and before approving reads the diff of `.github/workflows/mantis-pr-scan.yml`
   (and, if you run the action from this repository with `uses: ./action`, of
   `action/` and `reference/`). Turn on "prevent self-review"; leave
   administrator bypass off unless the administrators are the reviewers. The
   provider condition above admits tokens from this environment only, so the job
   must declare it.

2. On that environment, add three secrets: `GCP_WORKLOAD_IDENTITY_PROVIDER` (the
   provider's full resource name,
   `projects/<number>/locations/global/workloadIdentityPools/github/providers/mantis`),
   `GCP_SERVICE_ACCOUNT`, and `GCP_PROJECT`. None of them is a credential;
   keeping them out of the workflow file keeps your project ids out of the
   public record and out of the job log.

3. If the organisation allows only selected actions, allow
   `google-github-actions/auth@*`; the others are under `actions/`.

4. Add the workflow. Pin every action to a full commit SHA. This repository's
   own `.github/workflows/mantis-pr-scan.yml` is this file with
   `uses: ./action`.

   ```yaml
   name: Mantis PR scan
   on:
     pull_request:
       types: [opened, synchronize, reopened, ready_for_review]
     workflow_dispatch:
       inputs:
         base-sha:
           description: Commit to diff the checked-out ref against.
           required: true
   permissions:
     contents: read
     id-token: write
   concurrency:
     group: mantis-pr-scan-${{ github.event.pull_request.number || github.run_id }}
     cancel-in-progress: true
   jobs:
     scan:
       if: >-
         github.event_name == 'workflow_dispatch' ||
         (github.event.pull_request.head.repo.full_name == github.repository &&
          !github.event.pull_request.draft &&
          github.event.pull_request.user.type != 'Bot')
       runs-on: ubuntu-latest
       timeout-minutes: 90
       environment: mantis-pr-scan
       steps:
         - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
           with:
             fetch-depth: 0
             persist-credentials: false
         - uses: google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093 # v3.0.0
           with:
             workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
             service_account: ${{ secrets.GCP_SERVICE_ACCOUNT }}
         - uses: google/mantis/action@<commit-sha>
           env:
             GOOGLE_CLOUD_PROJECT: ${{ secrets.GCP_PROJECT }}
           with:
             model: vertex_ai/gemini-3.8-flash
             base-sha: ${{ github.event.pull_request.base.sha || inputs.base-sha }}
   ```

   `id-token: write` lets the job mint the OIDC token the auth step exchanges
   and grants nothing else. `fetch-depth: 0` makes the base commit available for
   the diff; without it the action fetches that one commit on its own, which
   works on public repositories and on private ones as long as the checkout kept
   its credentials. The `if` skips drafts until they are marked ready and skips
   bot-authored pull requests; both are runs nobody reads (see Spend).

### Repository settings

Settings only a repository administrator can make, and the action's design
assumes them, in any repository that installs it:

- **Rulesets on `main`**: require a pull request with at least one approval,
  require status checks, block force pushes, restrict deletions, and keep the
  bypass list to break-glass actors.
- **CODEOWNERS** naming a security owner for `.github/workflows/`, `action/`
  (when dogfooding), and `.mantis/knowledge/`, with "require review from code
  owners" on. The workflow file is what a pull request can rewrite; the
  knowledge directory is what later scans believe.
- **Actions permissions**: default `GITHUB_TOKEN` permissions set to read, and
  "Allow GitHub Actions to create and approve pull requests" left **off**. The
  refresh workflow copes: it pushes its branch and prints the link to open the
  pull request by hand when it may not open one itself.
- **Allowed actions**: if the organisation restricts actions, allow
  `google/mantis/action@*` and `google-github-actions/auth@*`; everything else
  this uses is under `actions/`, `github/` or `ossf/scorecard-action` and is
  pinned to a commit.
- **Dependabot** alerts and security updates on; secret scanning on. Version
  updates (the scheduled pin bumps) are a separate choice: a
  `.github/dependabot.yml` with a cooldown, or whatever else keeps your pins
  moving.
- **Scheduled workflows stop after 60 days without repository activity**, the
  refresh included; a repository that idles needs a push, or a manual dispatch,
  to wake it.

If the project the action authenticates to is inside Google's own cloud
organisation, note that workload identity federation from GitHub is denied by
policy there and needs an exception before the provider can be created; a
project outside that organisation does not. External users of this action are
not affected.

### First run

Run the workflow by hand (Actions, Mantis PR scan, Run workflow) with `base-sha`
set to any ancestor of the branch, approve it if the environment asks, and read
the result:

- The auth step fails: the provider condition does not match (the `environment`
  claim is in the token only because the job declares `environment:`; the name
  must be the same in both places), the service account binding carries the
  wrong project number, or `iamcredentials.googleapis.com` is not enabled. The
  step's error says which.
- The action exits 3 with a setup error: the preflight found no project, the
  platform rejected the credential, or the project's token meter could not be
  read for the daily budget (the service account needs
  `roles/monitoring.viewer`). The summary names what is missing. A rejected
  credential is reported this way, once, rather than as a failed scan on every
  file.
- A verdict and a summary: done. Pull requests from branches of the repository
  now trigger it on their own; forks are skipped by the `if`.

Set `VERTEXAI_LOCATION` on the step if the model is not served from `global`.
Other pipeline knobs are plain environment variables there too: `LLM_TIMEOUT`
(seconds per model call), `REASONING_EFFORT` (`low`, `medium`, `high`), and
`LLM_MAX_TOKENS`.

The `model` input takes any id the pipeline (litellm) accepts, with that
provider's credentials in `env:` on the step; the preflight asks each provider
for its own requirements. Recall differs by model and endpoint, and the verdict
reports what the model found, only that. This document covers the Agent Platform
route alone.

## Spend

The job holds a model credential while reading attacker-influenced input, on a
platform whose quota for Gemini is dynamic and shared: there is no per-project
ceiling to lower. Whatever bounds the bill therefore has to be in the action
itself, in the unit the invoice uses, and the only thing left to the platform is
the stop of last resort. Two failure modes, two different limits: one pull
request engineered to burn money, and a day on which runs do not stop coming.

### One budget per run

`max-tokens` is the hard limit on what one run can spend. The driver, not the
model, does the arithmetic:

- Every token counts at full price, whether or not the provider served it from
  cache, so the number bounds the worst case the invoice can show rather than
  the expected one.
- The budget is shared out as the run goes: each file is launched with an equal
  share of what is still unspent, so a cheap file's unspent share passes to the
  files after it and one expensive file cannot take the whole run. Each scan is
  told its share as its own ceiling and pauses when it reaches it.
- Each scan reports what it spent; a scan that reports nothing, because it was
  killed or crashed first, is charged its whole share. The budget can
  over-count, never under-count.
- A file whose share has fallen below 100,000 tokens is not launched (the
  smallest scan costs about 250,000; see Sizing). It is reported unscanned,
  which floors the verdict at REVIEW with the file named, exactly as a timeout
  would. Nothing in the pull request can raise the budget.

The step summary prints the figure for every run: tokens per file, the run total
against the budget, and the files the budget did not reach. The JSON report
carries the same under `usage` and per file under `scan.results`.

The budget is checked after each model response, so a scan can overshoot its
share by at most one request. The next layer bounds that request.

### One ceiling per request

`max-input-tokens` caps the input of any single model request. The pipeline
refuses a larger request before dispatch, whatever the model's context window
and even for a model litellm cannot look up (an `api-base` gateway, say), where
the window-relative guard would otherwise not apply. A request the cap refuses
fails that file's scan, which is REVIEW with the file named. With the cap, the
most one run can spend is `max-tokens` plus one request of `max-input-tokens`
per file, and the most one request can cost is known before the model is chosen.

### One budget per day

The two numbers above bound a run; `daily-token-budget` bounds the day, and it
does so from the platform's own meter rather than from anything this code
remembers, because the action keeps no state between runs and should not. Before
scanning, the driver reads from Cloud Monitoring how many tokens the project was
served in the trailing 24 hours (every model, input and output, the figure the
invoice is built from) and sets this run's budget to the smaller of `max-tokens`
and what is left of the day. Nothing left: nothing is launched, every file is
reported unscanned, and the verdict is REVIEW naming the day's figure. Something
left: the run proceeds with the smaller budget and the summary says so.

The meter is per project, so every repository that authenticates to the project
shares the one budget, which is the point. The meter runs a few minutes behind,
and concurrent runs each read it at their own start, so the day's figure can be
overshot by about one run budget per run in flight plus those minutes; the
billing stop below is the backstop behind that.

A daily budget that is set but cannot be read (the role is missing, the API is
off, the route has no Google Cloud project) is a setup error, exit 3, with the
fix named: a limit that is silently skipped is not a limit. `0` turns the check
off explicitly, which is the setting for a route other than the Agent Platform.

### Fewer runs

Nothing bounds how many runs a day there are except what triggers them; the
daily budget catches the day when that goes wrong, and these make it less
likely. The workflow above trims the runs nobody reads: drafts wait until they
are marked ready, bot-authored pull requests (dependency bumps) are skipped, and
`concurrency` with `cancel-in-progress` keeps a force-push from stacking runs on
one pull request. Same-repository pull requests only means every remaining run
was started by someone with push access.

If you need a ceiling on runs in flight across the repository, add a job-level
`concurrency` group without `cancel-in-progress`; runs then queue one at a time.
GitHub keeps only one queued run per group and cancels the rest, so a burst of
pull requests leaves some with a cancelled check until their next push. Fine for
an advisory check; think twice before combining it with `fail-on`.

### The stop of last resort

Everything above is this code; if it has a bug, nothing on the platform side
stops spend on its own. The one deterministic stop the platform offers is a
billing budget wired to an action that cuts the project off, set up under The
spending stop above. It is yours to do: Mantis bounds what one run spends and
what one day spends; what the project may lose to a bug in a month is a decision
only its owner can make.

### Sizing

Measured with a Gemini model, calls uncapped in practice, every token at full
price:

| File        | Tokens | Calls | Minutes |
| ----------- | ------ | ----- | ------- |
| 20 lines    | 261k   | 44    | 7       |
| 440 lines   | 353k   | 45    | 19      |
| 1,000 lines | 658k   | 51    | 14      |
| 2,000 lines | 853k   | 60    | 13      |

Calls stay well under the cap; tokens are what grows with the file, which is why
tokens are the unit. The floor is about 250k whatever the file (prompts and
graph nodes), and size adds roughly 300k per thousand lines. The defaults follow
from the table:

- `max-tokens: 10M`: a pull request of ten ordinary files finishes whole (1M a
  file); a twenty-five-file one gets 400k a file, enough for files up to a few
  hundred lines, and its biggest pause at their share with the verdict saying
  which. Below 100k a share is not worth launching and the file is reported
  unscanned instead.
- `daily-token-budget: 100M`: forty typical runs, or ten at the worst case, in
  any 24 hours. A repository that sees more pushes than that in a day raises it
  knowingly; a trigger that fires every minute is stopped within hours.
- `max-input-tokens: 262144`: a quarter of the smallest Gemini window and
  several times the largest request an ordinary scan makes.

Read your own summaries for a week before changing any of them. A budget that is
too small shows up as REVIEW with files named, never as a silent pass. Minutes
per file set the other limit: the job's `timeout-minutes` ends a run that is
still scanning, and the files it did not reach are REVIEW too.

#### In money

The budgets are in tokens because tokens are what the action can count. What
they cost is your model's price on the day, which this document does not quote:
multiply the rows below by the per-token price of the model you configure, with
output taken as about an eighth of the tokens and no prompt caching. The
defaults were sized for the default model.

| Budget                                | Tokens |
| ------------------------------------- | ------ |
| One ordinary file                     | 500k   |
| One pull request, 4 files             | 2M     |
| `max-tokens: 10M`, worst case per run | 10M    |
| `daily-token-budget: 100M`, per day   | 100M   |
| … for a month nobody looked           | 3,000M |

The last row is the one to size for. Decide what a month of unnoticed abuse may
cost you, divide by your model's blended price per token to get the month in
tokens, divide by thirty for `daily-token-budget`, and set the billing stop
(Setup) just above that month. A model that costs several times more per token
than the default needs budgets several times smaller for the same ceiling -- on
the order of `max-tokens: 3M` and `daily-token-budget: 30M` at a tenfold price
difference. The defaults are chosen so that ordinary pull requests finish whole
and a day of abuse is bounded, not so that nothing can ever be wasted: a run
that pauses short of finishing has spent the tokens and produced less, which is
the more expensive failure.

## Inputs

| Input                | Default            | Meaning                                                                                                                                                                                                         |
| -------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `base-sha`           | the PR's base SHA  | Commit the diff is taken against.                                                                                                                                                                               |
| `model`              | `gemini-3.8-flash` | Model id; a bare `gemini-*` id routes to the Gemini API when `GEMINI_API_KEY` is set, otherwise to the Agent Platform when a project is.                                                                        |
| `api-base`           | empty              | Custom OpenAI-compatible endpoint. Skips the credential check.                                                                                                                                                  |
| `max-llm-calls`      | `400`              | LLM call ceiling **per changed file**; a loop guard, not the spend control.                                                                                                                                     |
| `max-tokens`         | `10M`              | Token budget **per run**, every token at full price, shared equally over the files left to scan; files it cannot reach are reported unscanned (REVIEW). `0` removes it.                                         |
| `daily-token-budget` | `100M`             | Tokens the project may be served in any 24 hours, read from Cloud Monitoring before the run; the run's budget is cut to what is left, and re-read before every file. Unreadable: not run. `0` disables.         |
| `max-input-tokens`   | `262144`           | Input tokens one model request may carry; larger requests are refused before dispatch, for any model. `0` leaves only the model's window.                                                                       |
| `max-files`          | `25`               | Files scanned per run; the rest are reported unscanned (REVIEW).                                                                                                                                                |
| `per-file-timeout`   | `1800`             | Seconds before one file's scan is abandoned.                                                                                                                                                                    |
| `ignore`             | `default`          | Comma-separated fnmatch patterns left out of the scan and the gate. `default` is the built-in list (prose and images; not manifests or lockfiles); an empty string ignores nothing.                             |
| `fail-on`            | `none`             | What the findings do to the job. `none`: advisory. `block`: fail on BLOCK. `review`: fail on REVIEW or BLOCK.                                                                                                   |
| `fail-closed`        | `false`            | Whether Mantis being unable to look fails the job (setup failure, model outage, a changed file not scanned, a crash). `false`: never; the summary says what was not audited. `true`: green means fully audited. |
| `python-version`     | `3.13`             | Interpreter for the pipeline (3.12 or newer).                                                                                                                                                                   |

Outputs: `verdict` (`PASS`, `REVIEW`, or `BLOCK`) and `report` (path of the JSON
report with findings, blast radius, per-file scan results, and `usage`: tokens
and calls for the run against its budget).

## What the repository already knows

A repository that has had a full scan can commit what Mantis learned as text
under `.mantis/knowledge/` (`scripts/knowledge.py export`; see the reference
README). The action reads that directory **from the base commit**, imports it
into the run's fresh database, and hands it to every scan:

- Known findings feed the gate directly. An open HIGH or CRITICAL finding that
  the full scan recorded on lines a pull request touches is a BLOCK before any
  model is called; a finding the full scan marked a false positive stays quiet.
- Coverage counts. A file the full scan covered no longer draws "has never been
  scanned by Mantis".
- The threat model and architecture are in front of the model from its first
  call, instead of being rebuilt per file.

The pull request's own copy of `.mantis/knowledge/` is never read: a pull
request must not get to edit the memory of the scan that grades it. Any change
it makes there (a finding marked false positive, a trust boundary redrawn, a
file of findings deleted) is reported as a REVIEW reason with an annotation on
the file, even when the pull request changes nothing else, because it is a
security decision for a person. The files themselves are never scanned or gated,
whatever the `ignore` input says.

No `.mantis/knowledge/` in the base commit is the ordinary state of a repository
that has never exported; the scan runs as it would without one and the summary
says so. One the action cannot read (a schema it does not know) is a REVIEW
reason, not a failed check: the scan runs without it and names the problem.

### Keeping it current without rescanning everything

A full scan is the expensive way to build knowledge and the only way to build it
all at once. The cheap way is to let it accumulate: scan what lands, and sweep
what has never been covered a little at a time. This repository's
`.github/workflows/mantis-knowledge-refresh.yml` does both and is the file to
copy:

- **Nightly, the delta.** The committed export records the commit it reflects
  (`head` in `manifest.json`). The refresh runs the same driver as the action
  from that commit to `main`, importing the latest committed knowledge via
  `--knowledge-rev HEAD`, adding one hop of callers (`--radius 1`), and pointing
  `--export-knowledge` back at `.mantis/knowledge/`. The run's database is the
  prior knowledge plus what it just found, so the export is the merged result;
  `head` advances to `main` only when every changed source file in the delta was
  audited in full.
- **Weekly, a sweep.** `auto` mode over the repository with the knowledge
  imported scans files no recorded campaign has covered, under `--max-tokens`,
  and exports with `--preserve-head` so un-diffed weekday commits stay queued
  for the nightly delta; files it does not reach wait for next week. Each mode
  pushes its own `mantis/knowledge-<mode>-YYYYMMDD` branch so a Sunday sweep
  never overwrites that morning's delta branch.
- **If anything changed, a pull request.** The export is committed on a branch
  and a pull request opened, by the one step in the job that holds a token. The
  scanning steps get none: GitHub's tokens are stripped from the pipeline's
  environment in both the delta and the sweep, and the auth step's credential
  file is moved out of the tree before either runs.
- **Main only, enforced twice.** The job declares its own environment,
  `mantis-knowledge`, and GitHub runs a dispatched workflow from whichever
  branch was chosen, with that branch's copy of the file. So that environment
  must carry a deployment-branch rule of `main` only, and its provider condition
  must pin the ref:
  `setup_github_action.sh --project <project> --repo org/repo --environment mantis-knowledge --provider mantis-refresh --refresh --github`
  creates both (a second provider in the same pool, admitting `refs/heads/main`
  from that environment only, and the environment with the branch rule and its
  three secrets). The workflow's first step also refuses any ref but `main`. Put
  a CODEOWNERS entry on `.mantis/knowledge/` naming a security owner: the pull
  request the refresh opens is not itself scanned, and a merged export decides
  what later scans suppress. Read its markdown in source view; the export
  encodes HTML and strips invisible characters, but the reviewer is the control.

What a refresh does to a known finding whose lines the change rewrote, when the
rescan of that file finishes without reporting the lineage again: it marks it
**archived**. Not fixed, not dismissed, not open. It no longer gates; it appears
as a notice whenever its file is touched ("found here before, the code changed
since"); recall shows it to the model first, as the strongest reason to look at
a place again; and any later report of the same lineage reopens it. The export
records why, with the commits. A pull-request scan never archives: there, an
imported finding on rewritten lines stays open and blocks, so the change has to
fix it or a person has to dismiss it.

Cost per nightly refresh is one pull-request scan's worth for the day's changes;
the weekly sweep is whatever `--max-tokens` allows.

### Knowledge from more than one model

Models differ in what they find, and knowledge worth keeping is the union. Every
record Mantis writes names its run, and every run names its model (`runs.jsonl`
in the export), so a knowledge base can be built by several models and still say
who found what and who covered what:

- **Coverage is per model.** A file one model swept is still uncovered for
  another; `auto` mode with `--model X` sweeps what X has not seen. The gate's
  "never scanned" question stays model-agnostic: scanned by anyone counts.
- **Only the finder shelves.** A refresh archives a known finding when the
  rescan of its rewritten lines, by the model that found it, does not report it
  again. A different model's miss leaves it open and is reported as such; a
  weaker model cannot quietly retire a stronger one's finding.
- **Findings are not merged across models.** Two models describing one bug
  differently produce two lineages; both gate, both export, and the duplicate is
  a person's to dismiss. Conservative, and the safe side.
- **The threat model and architecture are the latest run's.** They seed the
  model's view of the repository; it rebuilds them per campaign.

To build with several, set `MANTIS_MODELS` in
`.github/workflows/mantis-knowledge-refresh.yml` to a space-separated list. The
delta scan runs every file under every model (`pr_scan.py --models`), the sweep
runs the models one after another over the same database, and the export carries
all of it. Spend is additive: each model gets the per-run budget, at its own
price per token. A pull-request check stays single-model: the gate reads the
knowledge whatever produced it, and a second model per pull request doubles the
cost of every pull request for a smaller gain than a second model in the sweep.

## What the verdict means

The gate is the MCP server's `check_change`. Two things come out of a run, and
two inputs decide what each does to the job.

**The verdict** is what the findings say:

- **BLOCK**: an open HIGH or CRITICAL finding sits in the changed lines or in a
  function the change modified. A known finding follows its file through a
  rename; a known finding in a file the change deletes is a REVIEW until someone
  confirms the code is gone rather than moved.
- **REVIEW**: something needs a human: lower-severity findings in the change,
  findings elsewhere in a changed file or in a caller of changed code.
- **PASS**: nothing known intersects the change.

`fail-on` decides whether a BLOCK (or, with `review`, a REVIEW) fails the job.

**Coverage** is whether Mantis could look: `complete`, `partial`, or `none`. A
changed file over `max-files`, over the token budget, timed out, failed, or
unparseable, or a missing index or database, makes coverage partial. The verdict
shown is floored to REVIEW when coverage is incomplete, so a person sees it, and
the summary names every file and why. `fail-closed` decides whether that fails
the job; by default it does not, so a scanner that cannot look is never the
reason a merge stops. With `fail-closed: true` a green check means every changed
file was audited in full -- and means a model outage or a budget exhausted by a
sibling repository on the same project turns the check red until it is fixed.
That is a trade you make knowingly.

A setup failure (no base commit, credentials missing or rejected, the daily
meter unreadable, nothing launched) is reported as **not run**: an annotation, a
summary saying what to fix, a `verdict` output of `NOT_RUN`, and exit 3 under
`fail-closed`, exit 0 otherwise. Never a verdict on the pull request, never a
silent pass.

Annotations: direct findings are warnings (errors when `fail-on` would fail the
job on them); same-file and caller-radius findings are notices; unscanned files
are warnings. GitHub shows ten per level per step; the summary lists all of
them.

Exit codes of the underlying driver (`reference/scripts/pr_scan.py`): `0` the
job passes under the two policies, `1` it fails under them, `3` a setup failure
under `fail-closed`. What the model found, or did not find, is reported as-is.

## Threat model

The job processes attacker-influenced input (the pull request) while holding a
model credential. The design keeps those two facts apart:

- **The checkout is data.** Nothing from the pull request is imported,
  installed, or executed. Both of the action's steps run from the action's own
  directory with `PYTHONSAFEPATH` set, so a `pip/` package or a module planted
  at the root of the pull request is not what `python -m pip` or the driver
  imports. The pipeline reads the checkout; the sandbox is pinned to
  `static-only`, so dynamic exploit reproduction is off and no PR-supplied code
  runs on the runner regardless of what the repository's own Mantis
  configuration says. The workflow file is the exception, and is why the
  environment's reviewers exist (Setup, GitHub).
- **Nothing is written into the checkout.** The run's database, structural
  index, and scan log live in a fresh directory under `$RUNNER_TEMP` (or
  `--state-dir`), never under the repository, and the log is opened without
  following symlinks. A pull request can therefore neither plant a symlink where
  the run would write (which would turn the log into an append on any file the
  runner can write) nor pre-seed a database or index cache the run would trust
  as its own memory.
- **The change set does not depend on how git rendered a file.** Which files
  changed comes from `git diff --name-status -z`; the unified diff only adds
  changed lines where it has them. A `.gitattributes` line marking a source file
  `-diff` cannot remove the file from the scan or the gate: it is scanned and
  gated without line information, which the gate treats as `direct`. Benign
  protected metadata (such as `.gitattributes` or `.pre-commit-config.yaml`) and
  non-source binary assets are noted as `not_scannable` while still checked
  against known findings; source files carrying NUL bytes, symlinks, or
  hardlinks are refused (`refused_by_jail`) and surface as `REVIEW` coverage
  gaps (failing `fail-closed: true`). Inside a hunk, a content line that reads
  `+++ b/other.py` is content; headers are recognized only between hunks.
- **Credential rejection is an exit status, not a log string.** The pipeline
  exits with a reserved status when the provider refuses the credentials, and
  decides that from the error's class or the provider's status code, never from
  an error message, which a model can write. The action keys on the exit status
  alone. The log echoes file names and contents the pull request author wrote,
  so no marker string in it is trusted.
- **No GitHub token.** The action never reads `github.token`. Annotations and
  the summary go through workflow commands and `GITHUB_STEP_SUMMARY`. With
  `permissions: contents: read` and `persist-credentials: false`, a compromised
  job cannot push, comment, approve, or reach other repositories. The pipeline
  subprocess does not inherit GitHub's own runtime tokens (`GITHUB_TOKEN`,
  `ACTIONS_RUNTIME_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_*`); every other variable
  on the step passes through, since which provider credentials a run needs is
  the consumer's choice of model. The credential configuration the auth step
  writes into the checkout -- which holds the URL and token for minting the
  job's identity tokens -- is moved out of the tree before the scan, and the
  pipeline never lists a `gha-creds-*.json` as a scan target. What the pipeline
  holds is the provider credential itself, for the life of the job; it holds
  nothing that reaches GitHub.
- **Output is escaped at every sink.** Annotation properties and data follow
  GitHub's workflow-command escaping, so a finding title cannot start a second
  command. Every value in the step summary that originates from the pull request
  (file names) or from the model after reading it (titles, reasons, function
  names) passes through the repository's markdown sanitizer and then has every
  angle bracket and ampersand encoded: no HTML of any kind, no headings, no
  escaping out of a code span. The JSON report is passed through the same
  credential scrubber before it is written.
- **Pinned code only, given the reviewers.** The action's own code comes from
  the commit you pin, and its Python dependencies install with
  `--require-hashes` from the pipeline's lock file; nothing is upgraded from the
  index first. The only third-party action it uses is `actions/setup-python`,
  pinned to a commit; the workflow above pins `checkout` and `auth` the same
  way. None of that binds the workflow file, which a pull request can rewrite
  and which GitHub runs as rewritten; the environment's required reviewers are
  what keep a rewritten workflow from receiving the credential.
- **No template injection.** Every input crosses into the shell through
  environment variables, never `${{ }}` interpolation inside `run:`. Revision
  arguments are validated as commit SHAs before they reach git, and every git
  call terminates option parsing explicitly.
- **Bounded spend, in tokens, by the driver.** One token budget per run, shared
  out by the driver and charged from each scan's own account (or in full when
  there is none), with an input cap on every request and the day's meter read
  again before every file; a pull request can make a run hit its budget, which
  is a coverage gap with files named, and nothing more. See Spend.

What it does **not** defend against:

- **Prompt injection into the verdict.** The pipeline reads the code it audits;
  hostile comments or strings in a pull request can try to talk the model out of
  reporting a planted defect. The deterministic layers (citation verification,
  evidence gates) raise the bar but do not remove it. This is why the default is
  advisory and why a human review stays in the loop.
- **Fork pull requests.** The scan needs the provider credential, which GitHub
  withholds from fork-triggered `pull_request` jobs by design. Keep the
  `head.repo.full_name == github.repository` condition; do not switch to
  `pull_request_target` to get credentials onto fork code.
- **Credential blast radius.** A fully compromised job holds the project's model
  credential for up to an hour. What limits it: a dedicated project that holds
  nothing else, the narrowest role that can call the model and read the meter
  (the setup script creates one; `roles/aiplatform.user` can also create
  training jobs and endpoints the token meter never sees, so prefer the custom
  role), a token that lives about an hour (workload identity; the repository
  secrets hold only names), the budget, and the platform-side stop. Treat it as
  a cost control, not an access control.

If you run the action from the same repository with `uses: ./action`, the pull
request also controls `action/` and `reference/`, so the reviewer has more to
read before approving a run (Setup, GitHub). This repository's own workflow does
exactly that. Pin to a commit anywhere else you dogfood.

## Local use

The driver runs anywhere with a checkout, the reference environment, and
application default credentials for a project with the API enabled:

```bash
cd reference && ./install.sh
gcloud auth application-default login
GOOGLE_CLOUD_PROJECT=<project> .venv/bin/python scripts/pr_scan.py \
  --repo /path/to/checkout --base <base-sha> --model vertex_ai/gemini-3.8-flash \
  --output-json /tmp/report.json
```

Without `GITHUB_STEP_SUMMARY` and `GITHUB_OUTPUT` in the environment it only
prints annotations and the one-line verdict; `--no-annotations` silences the
former.
