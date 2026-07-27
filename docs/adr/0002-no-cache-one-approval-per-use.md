# No cache — one Approval per secret use

Every secret use requires its own fresh WebAuthn Approval; approvals are never
remembered between calls. An earlier design cached approvals for 5 minutes per
secret id, but under the prompt-injection threat a cache window is an exfiltration
window: one benign gated call would let an injected agent make a second,
malicious call with no touch. The cost is friction — the human touches the sensor
on every call — accepted deliberately as the price of closing that window.
