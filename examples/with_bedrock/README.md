# Real Bedrock + CG-ATC examples

These examples instantiate **real** `strands.Agent`s backed by AWS
Bedrock and route every chat turn through the CG-ATC layer.

They are deliberately **not** part of the default test suite or the
plain `examples/` flow because they:

* require valid AWS credentials,
* require Bedrock model access in your AWS account,
* incur Bedrock token costs,
* and produce non-deterministic LLM output.

For CI / reproducible runs, use [`examples/two_agent_chat.py`](../two_agent_chat.py)
which uses a deterministic stub LLM and exercises the same CG-ATC layer.

## Prerequisites

```sh
# AWS credentials available to boto3 (one of the standard mechanisms)
aws sso login                              # or
export AWS_PROFILE=your-profile            # or
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...

# Region with Bedrock model access.  The default model below uses the
# `global.` cross-region inference profile, so any Bedrock-enabled
# region works (e.g. us-east-1, us-west-2, ap-northeast-1).
export AWS_REGION=us-east-1

# (optional) override the model id used by the example
export CGATC_BEDROCK_MODEL=global.amazon.nova-2-lite-v1:0
```

The default model is **Amazon Nova 2 Lite** (`global.amazon.nova-2-lite-v1:0`),
chosen for low cost and low latency.  You also need the model enabled for
your AWS account in the Bedrock console (Model access → Manage model
access → enable the chosen model).

## Run

```sh
PYTHONPATH=. python examples/with_bedrock/two_agent_bedrock_chat.py
```

The script:

1. Creates two real `strands.Agent`s (`alice`, `bob`) backed by Bedrock.
2. Wraps each with the CG-ATC layer (Card, capability, middleware).
3. Has Alice generate a question via Bedrock; Alice signs the question
   into a CG-ATC envelope and sends it to Bob.
4. Bob's middleware verifies (signature, payload hash, capability,
   chain head, freshness, fanout); on success, Bob's Bedrock-backed
   agent answers.
5. Bob signs the response back to Alice; Alice verifies.
6. Both sides commit a tamper-evident audit root.

The total CG-ATC overhead per hop on the hot path is roughly 150–300 µs
(see `experiments/bench_crypto_overhead.py`).  Bedrock latency is
~1–10 s per turn, so the relative overhead is < 0.1 %.

## Cost / safety

This example sends short prompts (a few tens of tokens) and prints the
raw responses to stdout.  Each run costs only a few cents on small
Claude variants, but **anything you type into a prompt or system prompt
is sent to AWS** — do not paste real secrets.
