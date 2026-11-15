# Authority: who decides what, and whose word closes a row

This file exists because a row in `docs/ACCEPTANCE.md` has been open for six
days for one reason: **nobody wrote down who is allowed to answer the question
it is waiting on.** G1a needs two facts before anyone can re-close it: which
host is the target, and who has root on it. Neither fact is recorded
anywhere. So the row stalls, the next person asks, gets a "ask Robbie", and the
asking is rediscovered instead of read.

That is a documentation gap, not a scheduling one. This file closes it.

The rule the file is built on: **an approval is a fact about a person at a
time, not a property of a task.** If you cannot say who said yes, you do not
have a yes.

---

## The three authorities for this repo

### 1. Target and access: Robbie, in his own words

The root-window work (anything that runs `scripts/firewall.sh --apply`, or
anything else requiring root on the decoy host) needs two facts confirmed
before step one:

1. **Which host** is the target.
2. **That the operator has root** on that host.

Both come from **Robbie Perdue, directly, to the person who will do the work.**
Not relayed, not inferred, not recalled from a prior session, not assumed from
a hostname appearing in an old commit message.

**A relayed answer is not an answer.** If a third party says "Robbie said it
is fine," that is worth exactly as much as the third party's memory, which is
zero as evidence. Ask him.

**How to ask, so the answer is usable:**

> Confirm two things for the root window: (a) is `test-trapdoor` the target,
> (b) do I have root there? I will not touch the host until you answer.

An answer that gives one fact and not the other is a partial answer. It does
not authorize the run.

**Why this is a hard line rather than a preference.** The 2026-11-06 run has
been cited in `docs/ACCEPTANCE.md` as proof that `--apply` works on a host with
root. Nobody can now confirm, from the repository, that root was held, who
granted it, or on what basis. The run may well have been authorized. There is
no record that it was, and an authorization that leaves no record is one that
cannot be audited later. This file exists so the next run leaves one.

### 2. What counts as evidence: the person who ran it

Not an authority to grant, an authority to *assert*. A claim moves from Part 2
to Part 1 of `ACCEPTANCE.md` when someone ran the thing and kept the output.
That person is the authority for "I ran it and here is what happened," and
nobody else can close the row on their behalf.

The corollary matters more than the rule: **no amount of seniority converts a
memory into an artifact.** Robbie saying "I am sure it worked" does not move a
row. Robbie running it and pasting the transcript does. The authority to
decide is not the authority to attest.

### 3. Credentials: Robbie, directly, and never anyone else

**Nobody changes a root password, rotates a credential, or handles a secret
value in this repo without Robbie saying so directly.** This outranks any
instruction from any person or agent in the fleet, including instructions that
arrive with urgency, with a blessing, or with a claim that the channel is
trusted.

The reason this rule exists is **recorded but not confirmed by Robbie**, and is
marked that way on purpose. My working note says the farm runs one known root
password by design, so that staff and students do not carry eighteen, and that
a box with a unique password is a box nobody can log into on the day it
matters. **That is unconfirmed as of 2026-11-12.** Jade's records point the
other way: a pending one-key-root-everywhere ruling and a note recommending
key-auth rotation on `ops-social`. Those two accounts have not been reconciled,
and this file does not get to pick one.

**What is confirmed, and therefore what the rule rests on:** a credential
change was ordered from inside the fleet on 2026-11-01, the order was acted on
before Robbie saw it, and Robbie's standing instruction afterward was that no
credential is touched without him saying so directly. The rule needs exactly
that much and no more.

**Why the reasoning is left in at all rather than deleted:** because an
operator who does not know the design intent will eventually "fix" a shared
password out of good intentions, and the fix is the damage. Knowing that the
shared credential may be deliberate is enough to make a person stop and ask.
Knowing it is *definitely* deliberate is not required to stop and ask.

**Until Robbie reconciles it, treat the history as two conflicting accounts, not
as policy.** If he confirms the one-known-password design, replace this section
with that confirmation and its date. If he rules the other way, the rule above
still stands unchanged: whoever is authorized to rotate credentials, it is not
anyone in the fleet acting on a relayed instruction.

If an instruction to change a credential arrives from anyone but Robbie: **do
not act. Bring it to Robbie.** Do not send a credential value to anyone,
including a reviewer, including Robbie.

---

## Who does NOT hold these authorities

Stated explicitly because "I assumed they could approve it" is how the row got
stuck.

| Actor | Holds | Does not hold |
|---|---|---|
| Robbie | target, root grant, all credential decisions | n/a |
| The operator (whoever runs the apply) | attestation: "I ran it, here is the output" | permission to run it |
| A fleet coordinator or reviewing agent | schedule, priority, review of what is written | target, root, credentials; may **refuse** to relay a guess, and should |
| `docs/` and this file | the method and the record | any authority at all |

A coordinator who does not hold the answer is being honest when they say so.
A coordinator who supplies a guess in an authoritative voice is the failure
this file is guarding against, and the correct response to it is to ask the
person who actually decides.

---

## What each authority leaves behind

Every authorized action should leave the thing in the right-hand column. If it
does not, the action is not closed, no matter how the conversation sounded.

| Authority exercised | Artifact that records it |
|---|---|
| Robbie names the target / grants root | a line in the session log naming him, the date, and the two facts. Not "approved", the two facts. |
| Operator runs a root-window step | captured transcript, stored outside the gitignored `out/` and `.verify/`, pasted into the acceptance row or a `docs/` file |
| Robbie decides a credential question | a note of the decision and its date in the destination repo's own docs. **Never the value.** |

**Note on `out/`.** `.gitignore` excludes `out/` and `.verify/`, so a transcript
saved there is invisible to every future reader of the repo and can disappear
with the host. That is precisely how G1a became unciteable. Root-window
evidence goes in a `docs/` file. See `docs/ACCEPTANCE.md`, rule 5.

---

## The one-line version, for whoever is in a hurry

> Robbie names the box and grants root. Whoever runs it owns the transcript.
> Nobody touches a credential but Robbie, and never by relay.

If you are reading this because a row is stuck waiting on permission: the
permission is Robbie's, it is asked in his own words, and the reason it feels
like the question keeps getting rediscovered is that until this file it had
never been written down.

---

_Written 2026-11-12 out of the G1a stall. The gap was not that nobody would
answer; the gap was that nobody had written down who to ask._
