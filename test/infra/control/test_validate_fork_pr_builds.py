#!/usr/bin/env python3
"""Tests for validate_fork_pr_builds.py.

The trusted-gate check is a security check, and it rejects on a pattern
rather than on a real parse of GitHub expression semantics. These cases pin
both directions: the gate shapes that must be rejected, and the one nested
shape that must be accepted. validate() takes parsed documents, so no git
ref or fixture on disk is needed.
"""
import copy
import sys
import unittest

import validate_fork_pr_builds as subject

SAFE_NESTED_GATE = (
    "${{ inputs.trusted && failure() && !cancelled() "
    "&& (steps.build.outcome == 'failure' || steps.check_build.outcome == 'failure') }}"
)


def minimal_documents():
    """A contract-satisfying triple, used as the mutation baseline."""
    base = {
        "jobs": {
            "run": {
                "if": "${{ !github.event.workflow_run || github.event.workflow_run.head_repository.full_name == github.repository }}",
                "permissions": "write-all",
                "secrets": "inherit",
                "uses": "sysown/proxysql/.github/workflows/ci-builds.yml@GH-Actions",
            }
        }
    }
    fork = {
        "on": {"pull_request": {"paths-ignore": [".github/**"]}},
        "permissions": {"contents": "read"},
        "jobs": {
            "run": {
                "if": "${{ github.event.pull_request.head.repo.fork }}",
                "uses": "sysown/proxysql/.github/workflows/ci-builds.yml@" + "a" * 40,
                "with": {"trusted": False},
            }
        },
    }
    reusable = {
        "on": {
            "workflow_call": {
                "inputs": {
                    "trusted": {"type": "boolean", "default": True},
                    # The tier input must default to v40, matching the callee.
                    "tier": {"type": "string", "default": "v40"},
                }
            }
        },
        "jobs": {
            "resolve-tap-mode": {"steps": [{"uses": "actions/checkout@abc"}]},
            # resolve-tier handles every known tier and fails on anything else.
            # It must not declare `permissions:` -- a called workflow may only
            # narrow the fork caller's token, which is exactly contents: read.
            "resolve-tier": {
                "steps": [
                    {
                        "id": "t",
                        "run": (
                            "case \"${TIER_IN}\" in\n"
                            "  v30)\n    TIER=v30 ;;\n"
                            "  v31)\n    TIER=v31 ;;\n"
                            "  v40)\n    TIER=v40 ;;\n"
                            "  *)\n    echo error; exit 1 ;;\n"
                            "esac\n"
                        ),
                    }
                ]
            },
            "builds": {
                "runs-on": "${{ inputs.trusted && (runner.environment == 'self-hosted' && false) || 'ubuntu-24.04' }}",
                "strategy": {
                    "matrix": {"include": [{"dist": "ubuntu24", "type": "-tap"}]}
                },
                "steps": [
                    {"name": "Archive artifacts", "if": SAFE_NESTED_GATE, "uses": "actions/upload-artifact@v4"},
                    {"name": "Upload handoff (src)", "if": "${{ inputs.trusted && success() }}", "uses": "actions/upload-artifact@v4"},
                ],
            },
        },
    }
    return base, fork, reusable


class TopLevelDisjunction(unittest.TestCase):
    def test_rejects(self):
        for condition in (
            "${{ inputs.trusted && failure() || cancelled() }}",
            "${{ (inputs.trusted && failure()) || cancelled() }}",
            "${{ inputs.trusted && (a) || (b) }}",
        ):
            with self.subTest(condition=condition):
                self.assertTrue(subject.top_level_disjunction(condition))

    def test_accepts(self):
        for condition in (
            SAFE_NESTED_GATE,
            "${{ inputs.trusted && (a || b) && (c || d) }}",
            "${{ inputs.trusted && always() }}",
            "",
        ):
            with self.subTest(condition=condition):
                self.assertFalse(subject.top_level_disjunction(condition))


class Baseline(unittest.TestCase):
    def test_minimal_documents_satisfy_the_contract(self):
        self.assertEqual(subject.validate(*minimal_documents()), [])


class Mutations(unittest.TestCase):
    """Each mutation must be caught, and named so the failure is legible."""

    def assertRejected(self, mutate, needle):
        base, fork, reusable = minimal_documents()
        mutate(base, fork, reusable)
        problems = subject.validate(base, fork, reusable)
        self.assertTrue(problems, "mutation was not rejected")
        self.assertTrue(
            any(needle in problem for problem in problems),
            f"expected a problem mentioning {needle!r}, got {problems!r}",
        )

    def test_fork_caller_must_pin_a_full_sha(self):
        for bad in (
            "sysown/proxysql/.github/workflows/ci-builds.yml@GH-Actions",
            "sysown/proxysql/.github/workflows/ci-builds.yml@" + "a" * 39,
            "sysown/proxysql/.github/workflows/ci-builds.yml@" + "a" * 41,
            "evil/repo/.github/workflows/ci-builds.yml@" + "a" * 40,
        ):
            with self.subTest(uses=bad):
                self.assertRejected(
                    lambda b, f, r, u=bad: f["jobs"]["run"].__setitem__("uses", u),
                    "full commit SHA",
                )

    def test_fork_caller_must_stay_read_only(self):
        self.assertRejected(
            lambda b, f, r: f.__setitem__("permissions", {"contents": "write"}),
            "not exactly contents: read",
        )
        self.assertRejected(
            lambda b, f, r: f["jobs"]["run"].__setitem__("permissions", {"contents": "read"}),
            "overrides read-only workflow permissions",
        )
        self.assertRejected(
            lambda b, f, r: f["jobs"]["run"].__setitem__("secrets", "inherit"),
            "inherits or passes secrets",
        )

    def test_fork_caller_must_be_fork_scoped_and_untrusted(self):
        self.assertRejected(
            lambda b, f, r: f["jobs"]["run"].__setitem__("if", "${{ true }}"),
            "not restricted to fork heads",
        )
        self.assertRejected(
            lambda b, f, r: f["jobs"]["run"].__setitem__("with", {"trusted": True}),
            "does not select untrusted mode",
        )
        # a quoted "false" must not satisfy the boolean check
        self.assertRejected(
            lambda b, f, r: f["jobs"]["run"].__setitem__("with", {"trusted": "false"}),
            "does not select untrusted mode",
        )

    def test_trusted_caller_contract(self):
        self.assertRejected(
            lambda b, f, r: b["jobs"]["run"].__setitem__("permissions", "read-all"),
            "trusted CI-builds permission changed",
        )
        self.assertRejected(
            lambda b, f, r: b["jobs"]["run"].pop("secrets"),
            "trusted CI-builds secret handoff changed",
        )
        self.assertRejected(
            lambda b, f, r: b["jobs"]["run"].__setitem__("if", "${{ true }}"),
            "lacks same-repository guard",
        )

    def test_matrix_is_pinned(self):
        def add_leg(b, f, r):
            r["jobs"]["builds"]["strategy"]["matrix"]["include"].append(
                {"dist": "ubuntu22", "type": "-tap-mysqlx"}
            )

        self.assertRejected(add_leg, "unexpected build matrix")

    def test_privileged_steps_must_be_trusted_gated(self):
        for bad_gate in (
            "${{ inputs.trusted && failure() || cancelled() }}",
            "${{ (inputs.trusted && failure()) || cancelled() }}",
            "${{ failure() && (a == 'x' || b == 'y') }}",
            "${{ always() }}",
        ):
            with self.subTest(gate=bad_gate):
                self.assertRejected(
                    lambda b, f, r, g=bad_gate: r["jobs"]["builds"]["steps"][0].__setitem__("if", g),
                    "not trusted-gated",
                )

    def test_privileged_step_with_no_gate_is_rejected(self):
        """A step with `if:` present but empty must not crash or pass."""
        self.assertRejected(
            lambda b, f, r: r["jobs"]["builds"]["steps"][0].__setitem__("if", None),
            "not trusted-gated",
        )

    def test_privileged_step_detection_cannot_be_evaded(self):
        """Dropping every privileged step must trip the discovery assertion."""

        def strip(b, f, r):
            r["jobs"]["builds"]["steps"] = [{"name": "Checkout", "uses": "actions/checkout@abc"}]

        self.assertRejected(strip, "no privileged steps discovered")

    def test_untrusted_must_not_run_on_self_hosted(self):
        self.assertRejected(
            lambda b, f, r: r["jobs"]["builds"].__setitem__("runs-on", "ubuntu-24.04"),
            "does not force ubuntu-24.04",
        )

    def test_unsafe_checkout_flag(self):
        for label, mutate in (
            ("base", lambda b, f, r: b["jobs"]["run"].__setitem__("allow-unsafe-pr-checkout", True)),
            ("fork", lambda b, f, r: f["jobs"]["run"].__setitem__("allow-unsafe-pr-checkout", True)),
            (
                "reusable",
                lambda b, f, r: r["jobs"]["builds"]["steps"][0].__setitem__(
                    "allow-unsafe-pr-checkout", True
                ),
            ),
        ):
            with self.subTest(document=label):
                self.assertRejected(mutate, "unsafe fork checkout enabled")

    def test_tier_input_must_stay_pinned_to_v40(self):
        # A fork PR reaches the callee only through CI-builds-fork.yml, which
        # passes just trusted: false. So the tier always resolves to the input
        # default; that default must stay v40 or a downgrade tier could be
        # smuggled onto the untrusted build path.
        for bad in ("v30", "v31", "v4.0", "40", ""):
            with self.subTest(default=bad):
                self.assertRejected(
                    lambda b, f, r, d=bad: r["on"]["workflow_call"]["inputs"]["tier"].__setitem__(
                        "default", d
                    ),
                    "tier input default",
                )
        self.assertRejected(
            lambda b, f, r: r["on"]["workflow_call"]["inputs"].pop("tier"),
            "tier input default",
        )

    def test_resolve_tier_must_cover_every_tier_and_reject_the_rest(self):
        for tier in ("v30", "v31", "v40"):
            with self.subTest(missing=tier):
                def drop(b, f, r, t=tier):
                    step = r["jobs"]["resolve-tier"]["steps"][0]
                    step["run"] = step["run"].replace(f"  {t})\n", "")

                self.assertRejected(drop, f"does not handle the {tier} tier")

        # An unknown tier must fail loudly, not fall through to some default.
        def drop_catch_all(b, f, r):
            step = r["jobs"]["resolve-tier"]["steps"][0]
            step["run"] = step["run"].replace("  *)\n    echo error; exit 1 ;;\n", "")

        self.assertRejected(drop_catch_all, "catch-all")

        self.assertRejected(
            lambda b, f, r: r["jobs"].pop("resolve-tier"),
            "does not handle the v30 tier",
        )

    def test_resolve_tier_must_not_widen_the_fork_token(self):
        # Per 5e8468db4 a called workflow may only narrow the caller's token,
        # and the fork caller grants exactly contents: read. Declaring any
        # permissions: here makes every fork PR fail at startup.
        self.assertRejected(
            lambda b, f, r: r["jobs"]["resolve-tier"].__setitem__(
                "permissions", {"contents": "read"}
            ),
            "breaks the contents:read-only fork caller",
        )

    def test_all_problems_are_reported_not_just_the_first(self):
        base, fork, reusable = minimal_documents()
        fork["jobs"]["run"]["uses"] = "sysown/proxysql/.github/workflows/ci-builds.yml@GH-Actions"
        base["jobs"]["run"].pop("secrets")
        problems = subject.validate(base, fork, reusable)
        self.assertGreaterEqual(len(problems), 2, problems)

    def test_validator_does_not_mutate_its_input(self):
        base, fork, reusable = minimal_documents()
        before = copy.deepcopy((base, fork, reusable))
        subject.validate(base, fork, reusable)
        self.assertEqual((base, fork, reusable), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
