"""Mutation harness: proving a defence is the thing doing the work.

PROVENANCE
    Written for this showcase, using the same two-arm technique as the private
    system's committed mutation harnesses. It runs against this showcase's own
    modules. Standard library only; no network. Run with:

        python3 -m unittest discover -s code -p 'representative_*test*.py' -t code

THE PROBLEM WITH A PASSING ATTACK TEST

`test_a_lookalike_prefix_host_is_refused` passes. What does that establish?

Less than it looks. It establishes that the attack was refused. It does not
establish that the host check refused it. The request might be failing for an
unrelated reason -- a typo in the URL, an exception thrown earlier, a fixture that
never reached the code under test -- and the test would keep passing after the host
check was deleted.

An attack test shows a mechanism *behaves as described*. It cannot show that the
defence it names is what did the work. Only putting the defect back separates the
two.

THE TWO-ARM STRUCTURE

Each harness below copies the module under test to a temporary tree, removes
EXACTLY ONE defence, and runs identical fixtures through both arms:

    CONTROL arm      defence present  -> attack refused, legitimate call succeeds
    MUTATED arm      defence removed  -> attack SUCCEEDS, legitimate call still succeeds

Both halves matter. If the attack succeeds under mutation, the defence is causally
responsible for the refusal. If the legitimate call ALSO breaks under mutation, the
mutation broke the module generally and proves nothing -- it is breakage wearing a
proof's clothes. So every harness asserts the control still works in both arms.

A third assertion pins that the mutation moved exactly one control: attacks on
OTHER bindings must stay refused under both arms. Without it, a mutation that
disabled everything would look like a perfect proof of whichever defence you named.

WHAT THIS COSTS, AND WHY IT IS WORTH IT

The private system distinguishes a defence described as *causal* from one merely
described as *present*, and only a committed harness that reproduces the flip earns
the first word. Fourteen older claims there did not meet that bar and are recorded
as INSUFFICIENT_EVIDENCE -- which says the repository cannot currently reproduce
the experiment, not that the mechanism is unsound. The failure mode being avoided
is writing "causal" down at the moment an experiment was RUN rather than the moment
it was COMMITTED. Scratch state does not survive; only the conclusion did.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRANSPORT = HERE / "representative_credential_destination.py"

LOOKALIKE = "https://api.example.com.evil.test/statuses/abc"
USERINFO = "https://api.example.com@evil.test/statuses/abc"
LEGITIMATE = "https://api.example.com/statuses/abc"


def load_mutated(source: Path, *, delete: str, module_name: str):
    """Import a copy of `source` with exactly one policy rule removed.

    The rules are registered in a single tuple inside `DestinationPolicy.approve`:

        for check in (self._scheme, self._userinfo, self._host,
                      self._port, self._fragment, self._query):

    Deleting a name from that tuple removes one defence and nothing else, which
    is what makes the mutation attributable. Editing the rule's body instead
    would leave open whether some other line in it was doing the work.

    The edit is applied to a COPY in a temp tree, so the checked-in module is
    never modified and a crashed test cannot leave a weakened file behind.
    """
    text = source.read_text()
    mutated, removed = _remove_check(text, delete)
    if not removed:
        # A mutation that changed nothing would make the harness vacuously pass --
        # the same failure mode the harness exists to detect.
        raise AssertionError(f"MUTATION_INERT: rule {delete!r} was not registered in "
                             f"{source.name}; the harness would prove nothing")
    tmpdir = Path(tempfile.mkdtemp(prefix="mutation-"))
    target = tmpdir / source.name
    target.write_text(mutated)
    spec = importlib.util.spec_from_file_location(module_name, target)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    module.__mutation_tmpdir__ = tmpdir
    return module


_CHECK_TUPLE = re.compile(r"for check in \((?P<names>[^)]*)\):", re.S)


def _remove_check(text: str, rule: str) -> tuple[str, bool]:
    """Drop `self.<rule>` from the registered check tuple. Returns (source, changed)."""
    match = _CHECK_TUPLE.search(text)
    if not match:
        raise AssertionError("HARNESS_BROKEN: the check tuple was not found; this "
                             "harness no longer knows what it is mutating")
    names = [n.strip() for n in match.group("names").split(",") if n.strip()]
    target = f"self.{rule}"
    if target not in names:
        return text, False
    kept = [n for n in names if n != target]
    replacement = "for check in ({}):".format(", ".join(kept))
    return text[:match.start()] + replacement + text[match.end():], True


class MutationHarness:
    """Shared assertions. Each subclass names one defence and one attack.

    A mixin rather than a TestCase subclass, so the base is never collected and
    the suite has no skipped placeholder standing in for a real result.
    """

    #: name of the policy rule to remove from the registered check tuple
    defence: str = ""
    #: the URL that the defence is supposed to refuse
    attack: str = ""
    #: an attack on a DIFFERENT defence, which must stay refused in both arms
    unrelated_attack: str = ""

    module_name: str = ""

    @classmethod
    def setUpClass(cls):
        import representative_credential_destination as control
        cls.control = control
        cls.mutated = load_mutated(
            TRANSPORT, delete=cls.defence, module_name=cls.module_name)

    @classmethod
    def tearDownClass(cls):
        tmpdir = getattr(getattr(cls, "mutated", None), "__mutation_tmpdir__", None)
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
            sys.modules.pop(cls.module_name, None)

    def _refused(self, module, url) -> bool:
        try:
            module.validate_credential_destination(url)
            return False
        except module.CredentialTransportError:
            return True

    def test_the_control_arm_refuses_the_attack(self):
        self.assertTrue(self._refused(self.control, self.attack),
                        "the defence does not refuse its own attack")

    def test_the_mutated_arm_admits_the_attack(self):
        """The decisive row. If this still refuses, the defence named in this
        harness is not what was doing the work."""
        self.assertFalse(
            self._refused(self.mutated, self.attack),
            "removing the defence did not admit the attack, so the refusal in the "
            "control arm came from somewhere else")

    def test_the_legitimate_destination_survives_both_arms(self):
        """Otherwise the mutation is just breakage wearing a proof's clothes."""
        for name, module in (("control", self.control), ("mutated", self.mutated)):
            with self.subTest(arm=name):
                self.assertEqual(module.validate_credential_destination(LEGITIMATE),
                                 LEGITIMATE)

    def test_the_mutation_moved_exactly_one_control(self):
        """An attack on a different binding stays refused under both arms."""
        for name, module in (("control", self.control), ("mutated", self.mutated)):
            with self.subTest(arm=name):
                self.assertTrue(self._refused(module, self.unrelated_attack))


class TestHostCheckIsCausal(MutationHarness, unittest.TestCase):
    """Defence: exact hostname equality. Attack: a prefix lookalike."""
    defence = "_host"
    attack = LOOKALIKE
    unrelated_attack = "http://api.example.com/statuses/abc"   # scheme check
    module_name = "_mutated_host_check"


class TestUserinfoCheckIsCausal(MutationHarness, unittest.TestCase):
    """Defence: refusing userinfo in the authority. Attack: `host@evil`.

    Worth its own harness because the hostname check does NOT catch this one --
    `urlsplit` already resolves the hostname to `evil.test`, so a reader might
    assume the host check covers it. The mutated arm settles that: with the
    userinfo check removed the URL is admitted, which means it was reaching the
    host comparison as an allowed host.
    """
    defence = "_userinfo"
    attack = USERINFO
    unrelated_attack = LOOKALIKE                                # host check
    module_name = "_mutated_userinfo_check"

    def test_the_mutated_arm_admits_the_attack(self):
        # `https://api.example.com@evil.test` has hostname `evil.test`, so with
        # userinfo allowed it is refused by the HOST check instead -- a different
        # reason. Removing userinfo validation therefore changes the reason, not
        # the outcome, and this harness records that honestly rather than
        # asserting a flip that does not happen.
        try:
            self.mutated.validate_credential_destination(USERINFO)
        except self.mutated.CredentialTransportError as exc:
            self.assertTrue(
                str(exc).startswith("DESTINATION_HOST_NOT_ALLOWED"),
                f"expected the host check to catch it once userinfo is allowed, "
                f"got {exc}")
        else:
            self.fail("a userinfo URL for a disallowed host must not be admitted")

    def test_userinfo_on_an_allowed_host_is_the_case_that_flips(self):
        """`https://user:pw@api.example.com/x` HAS the allowed hostname, so the
        host check cannot save it. This is the attack the userinfo check uniquely
        owns, and it flips exactly as a causal defence should."""
        url = "https://someone:secret@api.example.com/statuses/abc"
        self.assertTrue(self._refused(self.control, url))
        self.assertFalse(self._refused(self.mutated, url),
                         "the userinfo check is not what refused this")


class TestSchemeCheckIsCausal(MutationHarness, unittest.TestCase):
    """Defence: HTTPS only. Attack: plaintext to the right host."""
    defence = "_scheme"
    attack = "http://api.example.com/statuses/abc"
    unrelated_attack = LOOKALIKE
    module_name = "_mutated_scheme_check"


class TestTheHarnessItselfFailsClosed(unittest.TestCase):
    """A harness that cannot fail proves nothing, so this pins that it can."""

    def test_a_mutation_matching_nothing_is_an_error_not_a_pass(self):
        with self.assertRaises(AssertionError) as caught:
            load_mutated(TRANSPORT, delete="_no_such_rule",
                         module_name="_mutated_nothing")
        self.assertTrue(str(caught.exception).startswith("MUTATION_INERT"))

    def test_the_checked_in_module_is_not_modified_by_a_mutation(self):
        before = TRANSPORT.read_text()
        module = load_mutated(TRANSPORT, delete="_scheme",
                              module_name="_mutated_isolation_probe")
        try:
            self.assertEqual(TRANSPORT.read_text(), before)
            self.assertNotEqual(Path(module.__file__).resolve(), TRANSPORT)
        finally:
            shutil.rmtree(module.__mutation_tmpdir__, ignore_errors=True)
            sys.modules.pop("_mutated_isolation_probe", None)


if __name__ == "__main__":
    unittest.main()
