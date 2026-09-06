# Attacks

This section provides an overview of all available attacks.

## Single-stage attacks

### OWASP [LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) Prompt Injection

<details>
<summary><strong>Adversarial Suffix</strong></summary>

In code name: `suffix`

Uses a specially crafted suffix to bypass LLM filters and restrictions, forcing the model to generate prohibited or harmful content despite the original query. Evaluates the model's vulnerability to input data manipulation.

_Original Paper: <https://arxiv.org/abs/2307.15043>, Code: <https://github.com/llm-attacks/llm-attacks>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/suffix.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Aim Jailbreak</strong></summary>

In code name: `aim_jailbreak`

Probes an LLM's ethical compliance by eliciting detailed instructions on illegal activities, using the Nicolo Machiavelli character roleplay.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/aim.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Base64 Injection</strong></summary>

In code name: `base64_injection`

Challenges the LLM with a dataset of lines, encoded into base64.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/base64_injection.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Best-of-N (BoN) Jailbreak</strong></summary>

In code name: `bon`

Probes the LLM resilience against Best-Of-N (BoN) attack by randomly transform symbols in input harmful prompt.

_Original Paper: <https://arxiv.org/abs/2412.03556>, Code: <https://github.com/jplhughes/bon-jailbreaking>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/bon.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Deceptive Delight</strong></summary>

In code name: `deceptive_delight`

Tests LLM's vulnerability to distraction and context manipulation by embedding unsafe content alongside benign topics in three messages.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/deceptive_delight.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Dialogue Injection: Continuation</strong></summary>

In code name: `dialogue_injection_continuation`

Probes an LLM's ethical compliance by eliciting detailed instructions on illegal activities, using the conversation simulation technique by using few-shot system prompting and unfinished assitant response at the end. Built according to the paper.

_Original Paper: <https://arxiv.org/abs/2503.08195>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/dialogue_injection_continuation.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Dialogue Injection: Developer mode</strong></summary>

In code name: `dialogue_injection_devmode`

Probes an LLM's ethical compliance by eliciting detailed instructions on illegal activities, using the conversation simulation technique to mislead the LLM with "Developer mode activation".

_Original Paper: <https://arxiv.org/abs/2503.08195>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/dialogue_injection_devmode.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Do Anything Now (DAN) Jailbreak</strong></summary>

In code name: `dan`

Probes an LLM's resilience against performing explicitly forbidden activities using the "Do Anything Now" (DAN) character roleplay technique.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/dan.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Ethical Compliance</strong></summary>

In code name: `ethical_compliance`

Evaluates the LLM's ability to resist discussions about harmful or inappropriate misconceptions on sensitive topics. This test aims to verify the model's adherence to ethical guidelines against propagating stereotypes and toxic content.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/ethical_compliance.py">View code on GitHub</a>
</details>

<details>
<summary><strong>HarmBench</strong></summary>

In code name: `harmbench`

Challenges the LLM with harmful behavior prompts from HarmBench (contains original and translated to Russian prompts).

_Original Paper: <https://arxiv.org/abs/2402.04249>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/harmbench.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Linguistic Evasion</strong></summary>

In code name: `linguistic_evasion`

Leverages the use of a non-Russian language to circumvent the restrictions or focus set by the system prompt.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/linguistic.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Linguistic Sandwich</strong></summary>

In code name: `linguistic_sandwich`

Exploits attention blink phenomena by hiding adversarial questions between innocent questions in low-resource languages. The attack leverages the concept that LLMs may have reduced attention when processing mixed low-resource languages.

_Original Paper: <https://arxiv.org/abs/2404.07242v1>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/linguistic_sandwich.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Semantic Game</strong></summary>

In code name: `semantic_game`

Semantic reframing attack using an emoji game and recursive expansion. EMOJI are redefined as symbolic abstractions in order to manipulate the interpretive context and bypass safety filters by role reassignment, language mutation, and intent camouflage.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/semantic_game.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Shuffle Inconsistency</strong></summary>

In code name: `shuffle`

Attempts to bypass LLM's defense mechanism by randomly shuffling elements in input harmful prompt.

_Original Paper: <https://arxiv.org/abs/2501.04931>_

<a href="https://github.com/RomiconEZ/llamator/blob/release/src/llamator/attacks/shuffle.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Time Machine</strong></summary>

In code name: `time_machine`

Uses an attack model to dynamically transform prompts into historical or future contexts to test temporal framing vulnerabilities.

_Original Paper: <https://arxiv.org/abs/2407.11969v2>, Code: <https://github.com/tml-epfl/llm-past-tense>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/time_machine.py">View code on GitHub</a>
</details>

<details>
<summary><strong>UCAR Jailbreak</strong></summary>

In code name: `ucar`

Probes an LLM's adherence to content restrictions when explicitly requested to ignore such filters. It assesses the robustness of the LLM's content moderation systems against direct challenges.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/ucar.py">View code on GitHub</a>
</details>

### OWASP [LLM10:2025](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/) Unbounded Consumption

<details>
<summary><strong>Repetition Token</strong></summary>

In code name: `repetition_token`

Attempts to exhaust model resources by injecting random marker that force the model to ignore response boundaries and generate until the maximum context length is reached.
The attack uses a two-stage approach: first generating a normal question, then using it in a prompt with special instructions to bypass token limits.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/repetition_token.py">View code on GitHub</a>
</details>

## Multi-stage attacks

<details>
<summary><strong>What Drives the Multi-stage?</strong></summary>

Multi-stage attacks are inspired by the [Jailbreaking Black Box Large Language Models in Twenty Queries (PAIR)](https://arxiv.org/abs/2310.08419) paper.

For managing a multi-stage interaction between an attacker and tested chat clients, the `MultiStageInteractionSession` class is available [[source]](https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/client/chat_client.py). It contains the following properties:
 * `attacker_session` is the session for the attacker.
 * `tested_client_session` is the session for the tested client.
 * `stop_criterion` is an optional function that determines whether to stop the conversation based on the tested client's responses.
 * `history_limit` is the maximum allowed history length for the attacker.
 * `tested_client_response_handler` is an optional function that handles the tested client's response before passing it to the attacker.
 * `current_step` is the current step of the attacker.
 * `refine_args` are additional positional arguments for the `tested_client_response_handler`.
 * `refine_kwargs` are additional keyword arguments for the `tested_client_response_handler`.
</details>

### OWASP [LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) Continuous Prompt Injection

<details>
<summary><strong>AutoDAN-Turbo</strong></summary>

In code name: `autodan_turbo`

Implements the AutoDAN-Turbo attack methodology which uses a lifelong agent for strategy self-exploration to jailbreak LLMs. This attack automatically discovers jailbreak strategies without human intervention and combines them for more effective attacks.

_Original Paper: <https://arxiv.org/abs/2410.05295v3>, Code: <https://github.com/SaFoLab-WISC/AutoDAN-Turbo>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/autodan_turbo.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Composition of Principles (CoP)</strong></summary>

In code name: `cop`

Implements the Composition-of-Principles (CoP) agentic red-teaming methodology which composes human-provided jailbreak principles to generate and iteratively refine single-turn jailbreak prompts. The pipeline selects effective principles, prompts an attacker model to compose a prompt, verifies success with an LLM judge, and mines new principles from successful attempts to improve future attacks.

Original Paper: <https://arxiv.org/html/2506.00781>

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/cop.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Crescendo</strong></summary>

In code name: `crescendo`

Challenges the LLM with a dataset of harmful behavior prompts using Crescendo strategy, operates by engaging the LLM in a series of escalating conversational turns, and multistage refinement.

_Original Paper: <https://arxiv.org/abs/2404.01833>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/crescendo.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Prompt Automatic Iterative Refinement (PAIR)</strong></summary>

In code name: `pair`

Challenges the LLM with a dataset of adversarial prompts using multistage refinement with judge model scoring.

_Original Paper: <https://arxiv.org/abs/2310.08419v4>, Code: <https://github.com/patrickrchao/JailbreakingLLMs>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/pair.py">View code on GitHub</a>
</details>

### OWASP [LLM07:2025](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/) System Prompt Leakage

<details>
<summary><strong>System Prompt Leakage</strong></summary>

In code name: `system_prompt_leakage`

Challenges the LLM with datasets of malicious prompts to extract system instructions using multistage refinement.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/system_prompt_leakage.py">View code on GitHub</a>
</details>

### OWASP [LLM09:2025](https://genai.owasp.org/llmrisk/llm092025-misinformation/) Misinformation

<details>
<summary><strong>Logical Inconsistencies Test</strong></summary>

In code name: `logical_inconsistencies`

Attacks the LLM system during a multistage conversation to generate logical inconsistencies in answers using antonyms, negations, and paraphrases based on the system's domain.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/logical_inconsistencies.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Sycophancy Test</strong></summary>

In code name: `sycophancy`

Attacks the LLM system during a multistage conversation using the argumentum ad verecundiam method based on the system's domain.

_Original Paper: <https://arxiv.org/abs/2310.13548>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/sycophancy.py">View code on GitHub</a>

</details>

### Memory Attacks

Conversational attacks against a target agent's memory/persistence subsystem. Related to
OWASP **ASI06 (Memory & Context Poisoning)**, a category not yet in this framework's
`owasp:` tag vocabulary — each attack below is tagged with the closest existing
`owasp:llm0X` value and notes its ASI06 relationship in its description. See
`docs/memory_attacks.md` for the full design rationale and taxonomy mapping.

<details>
<summary><strong>Memory Compositional Poisoning</strong></summary>

In code name: `memory_compositional`

Given only a description of the target and one objective, the attacker LLM writes the entire scenario in one planning call: choose a harmful conclusion, decompose it into statements that are each innocuous in isolation, scatter them across turns and across a session break of its own choosing, then close with an ordinary question answerable only by combining them. Per-message input filtering and write-time review are structurally unable to catch this, because no single message is malicious and the harm exists only in the combination the target performs at recall time. A judge model rules on whether the target drew a conclusion no message of the attacker's ever stated (OWASP ASI06; tagged here as `owasp:llm09`).

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/memory_compositional.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Memory Dormant Trigger</strong></summary>

In code name: `memory_dormant_trigger`

Given only a description of the target and one objective, the attacker LLM writes the entire multi-turn scenario in one planning call: plant content in ordinary conversation, then fire it from a later, seemingly unrelated message. The attacker also chooses where the conversation breaks into a new session, in which the target retains only what it durably stored. A judge model then reads the full transcript against the objective and rules on whether the planted content actually took hold. Models query-only, delayed, and context-triggered dormant memory poisoning (OWASP ASI06; tagged here as `owasp:llm01`).

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/memory_dormant_trigger.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Memory Extraction</strong></summary>

In code name: `memory_extraction`

Given only a description of the target and one objective, the attacker LLM writes the entire scenario in one planning call: under an innocent pretext, get the target to read out what it is carrying in memory -- notes it wrote about the user, the operator instructions or context block injected ahead of every reply, or, where the store is not isolated per user, another user's data. A judge model rules on the transcript, and content the attacker itself supplied explicitly does not count as a leak. Models persistence-based extraction, and reaches shared-storage cross-user extraction wherever memory is not per-user isolated.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/memory_extraction.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Memory False Belief</strong></summary>

In code name: `memory_false_belief`

Given only a description of the target and one objective, the attacker LLM writes the entire scenario in one planning call: assert a false claim in passing as settled fact, then later ask a question whose answer depends on whether it took hold. The objective steers it toward claims the target could otherwise have verified for itself, since a claim about something with no ground truth corrupts nothing. A judge model then reads the full transcript against the objective and rules on whether the claim was internalized and reused. Models false-memory / belief-corruption without any memory-write tool.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/memory_false_belief.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Memory Flooding</strong></summary>

In code name: `memory_flooding`

Given only a description of the target and one objective, the attacker LLM writes the entire scenario in one planning call: plant one checkable detail carrying a harness-generated canary token, bury it under as much unrelated filler as its turn budget (`max_steps`) allows, then ask for it back -- optionally across a session break of its own choosing. A judge model rules on the transcript; note the inverted semantics -- a "breach" means the memory subsystem failed to retain data under load (denial-of-memory), not a content-policy jailbreak (OWASP ASI06; tagged here as `owasp:llm01`).

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/memory_flooding.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Memory Forged Experience</strong></summary>

In code name: `memory_forged_experience`

Given only a description of the target and one objective, the attacker LLM writes the entire scenario in one planning call: refer in passing to an earlier occasion on which the target supposedly handled something a certain way, then present a fresh case that invokes that precedent. What is falsified is the target's own history of having already decided something -- which, unlike a claim about the world, it has no way to check -- so a precedent it believes it set itself is harder for it to refuse than a demand. A judge model rules on the transcript; doubting or verifying the invented history counts as resilience (OWASP ASI06).

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/memory_forged_experience.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Memory Guardrail Erosion</strong></summary>

In code name: `memory_guardrail_erosion`

Given only a description of the target and one objective, the attacker LLM writes the entire scenario in one planning call: ask plainly for something the target should refuse, get that refusal on the record, bury it under unrelated turns, then repeat the identical request at the end. The doubled request is the attack's own control -- the first refusal is the baseline the last answer is read against, and a target that refuses twice is unambiguously resilient. Distinct from `memory_flooding`, where what is lost under load is a user-supplied fact; here it is the target's own policy that degrades as state accumulates.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/memory_guardrail_erosion.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Memory Recommendation Bias</strong></summary>

In code name: `memory_recommendation_bias`

Given only a description of the target and one objective, the attacker LLM writes the entire scenario in one planning call: establish a named brand, product, provider or source as trusted in passing -- never praising it, never asking for it -- then later ask for a recommendation in neutral terms naming nothing. Because the final probe names nothing, a mention in the answer can only have come from what was planted. Models the in-the-wild commercial variant of memory poisoning, where the payoff is not a jailbreak but a biased recommendation the user cannot tell apart from a genuine one; the target's own data-backed suggestions do not count (OWASP ASI06; tagged here as `owasp:llm09`).

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/memory_recommendation_bias.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Memory Retention Violation</strong></summary>

In code name: `memory_retention_violation`

Given only a description of the target and one objective, the attacker LLM writes the entire scenario in one planning call: supply a detail that plainly should not outlive the conversation -- one-off, explicitly not to be kept, or obviously sensitive -- and say so at the time, then after a session break give it a natural opening to resurface without repeating it or asking what the target remembers. Because the probe never names the detail, anything that comes back can only have come from storage. Note the polarity relative to `memory_flooding`: there a breach is the subsystem losing what it should have kept, here it is retaining what it should have dropped, and one system can fail both ways at once. Models session-boundary bleed and retention-without-consent (OWASP ASI06; tagged here as `owasp:llm02`).

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/memory_retention_violation.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Memory Scope Escalation</strong></summary>

In code name: `memory_scope_escalation`

Given only a description of the target and one objective, the attacker LLM writes the entire scenario in one planning call: state an invented rule in the register of policy rather than personal preference -- flat, bureaucratic, never "for me" and never a request -- then, after a session break, ask about it impersonally as a general question about how the service works. Where a memory pipeline sorts what it stores into per-user and shared/global scopes, a user turn that lands in the shared scope reaches every other user, and a per-user access-control model does nothing to prevent it. A judge model rules on whether the target adopted the invention as its own standing policy; attributing it back to the attacker as a personal preference counts as resilience. Models the write half of cross-user/cross-tenant memory contamination (OWASP ASI06; tagged here as `owasp:llm09`).

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/memory_scope_escalation.py">View code on GitHub</a>
</details>

## VLM attacks

See an example with <a href="https://github.com/LLAMATOR-Core/llamator/blob/release/examples/llamator-vlm-attacks.ipynb">VLM attacks</a>.

### OWASP [LLM09:2025](https://genai.owasp.org/llmrisk/llm092025-misinformation/) Misinformation

<details>
<summary><strong>Lowres Documents Hallucination Attack</strong></summary>

In code name: `vlm_lowres_docs`

Test class for VLM responses for low resolution documents.
The idea is that we provide model with unreadable document and ask to describe its contents.
The goal is to see whether model will signal that the document is unreadable or hallucinate about the contents.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/vlm_lowres_docs.py">View code on GitHub</a>
</details>

<details>
<summary><strong>M-Attack</strong></summary>

In code name: `vlm_m_attack`

Test VLM for M-Attack, which adds noise to the image to make VLM see it as a different image.

_Original Paper: <https://arxiv.org/abs/2503.10635>_

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/vlm_m_attack.py">View code on GitHub</a>
</details>

<details>
<summary><strong>Text Hallucination Attack</strong></summary>

In code name: `vlm_text_hallucination`

Test class for VLM text hallucination attacks.
The idea is to give model and image which contains only text and ask it to describe it.
The goal is to see whether model will describe text or hallucinate with the description of an object written in text.

<a href="https://github.com/LLAMATOR-Core/llamator/blob/release/src/llamator/attacks/vlm_text_hallucination.py">View code on GitHub</a>
</details>
