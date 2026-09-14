# Provenance and license status

Status: maintainer publication-rights confirmation and MIT selection recorded
on 2026-09-14. See the root LICENSE and packages/integrations/LICENSE. A passing
test or wheel is not a substitute for rights over future contributions.

The runtime source, tests and documentation descend from the operator-maintained
local coding engine, its standalone extraction and scheduled-local successor.
The current split begins from an explicitly hash-inventoried successor and retains
its baseline evidence separately. Changes cover the concrete composition/authority
boundary, shared accounting, packaging and current verification/documentation. No private HN package, operational records, model weights,
browser archive, credential store or Python dependency binary is vendored here.

The inherited source previously lacked a project LICENSE/NOTICE. The maintainer
confirmed publication rights and approved the attached MIT notices for this
source preview. Any separately identified third-party code keeps its own notice
and license. Model weights and provider binaries are not licensed by this grant.

## Separate components

- The public core is a separate exact-version distribution required by this runtime.
  Its pinned public baseline carries an
  [MIT license](https://github.com/taljeon/plzdo/blob/f58dafd02d1a57aed273d6fe1a432f90fcc6b994/LICENSE).
  The maintainer separately selected MIT for this runtime and integration source.
  Interoperation alone is not the basis for that decision. No PlzDo core source
  is included in the runtime.
- `jsonschema` is a declared dependency; setuptools and pytest are build/test
  dependencies. They and their transitive packages are not vendored in this
  wheel. If distributing an offline wheelhouse, audit each exact distribution
  and include its own license/notice files separately.
- Ollama and the separately approved offline checker/browser tools are host
  components. External generation and review CLIs belong only to the separate
  private product. Tool presence never grants permission for restricted data.

## Model references checked 2026-09-12

The exact [Hui Ollama tag](https://ollama.com/huihui_ai/Qwen3.8-abliterated:27b-q6_K_L)
shows the manifest digest prefix `4fcc84fd9a3b`, matching the runtime's pinned
manifest prefix. Its [license blob](https://ollama.com/huihui_ai/Qwen3.8-abliterated:27b-q6_K_L/blobs/4c6a8e842ef0)
contains Apache-2.0 and an Alibaba Cloud notice. The
[base model](https://huggingface.co/Qwen/Qwen3.8-27B) and
[Hui GGUF card](https://huggingface.co/huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF)
also label Apache-2.0. These public metadata checks do not establish a complete
hash-bound chain from the base revision through every conversion/quantization
step, and they are not a new audit of the local model bytes.

No model weights or upstream license text are copied into this package. Anyone
separately redistributing weights must verify that exact artifact's provenance,
license and required notices. The runtime never silently downloads a replacement
when the pinned model is absent or changed.

The model author warns that abliteration reduces safety filtering and recommends
controlled use and output review. Those usage warnings must not be confused with
the license's redistribution conditions or a suitability guarantee. Organization
approval and task-level provider/data restrictions remain separate.

## Release gate

For this source preview, retain the confirmed notices, scan the actual source
payload, document the verified installation and live-execution limits, and
verify the approved public tag/download. Future contributions require their
own provenance and relevant checks. Source publication does not certify a
wheelhouse, new live-model execution or OS-enforced isolation.
