"""Oracle privacy gate — sanitize, desanitize, and residue checking.

Every case payload MUST pass through :func:`~soc_ai.oracle.sanitize.sanitize`
before it is sent to a frontier cloud model.  The sanitizer replaces private
and internal identifiers with stable opaque tokens so the remote model can
reason about relationships without learning anything about the local network.
After the Oracle responds, :func:`~soc_ai.oracle.sanitize.desanitize` restores
the real values for local display.

The independent :func:`~soc_ai.oracle.sanitize.unsafe_residue` sweep is the
hard safety net: the caller MUST invoke it on the final outbound string and
refuse to transmit if any leaks are reported.

Typical call-site pattern::

    from soc_ai.oracle.sanitize import Mapping, sanitize, unsafe_residue, desanitize

    mapping = Mapping()
    payload = sanitize(case_dict, mapping)
    text = json.dumps(payload)
    leaks = unsafe_residue(text)
    if leaks:
        raise RuntimeError(f"Oracle gate blocked: {leaks}")
    response_text = call_oracle(text)
    display = desanitize(response_text, mapping)
"""
