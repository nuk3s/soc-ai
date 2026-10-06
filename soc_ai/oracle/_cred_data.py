"""Shared credential-detection DATA for the Oracle egress guard.

The redacter (:mod:`soc_ai.oracle.redact`) and the independent residue net
(:mod:`soc_ai.oracle.sanitize`) each compile their OWN regex from this data — the
two ENGINES stay independent so a bug in one cannot blind the other — but they
MUST agree on WHICH keys and WHICH stopwords define a credential.  When the data
was re-declared in each module, a token added to one net (a new service account
in the redacter's stopset, say) silently diverged from the other: the redacter
would pass that token verbatim while the residue net still flagged it, so every
alert carrying it refused Oracle escalation permanently — a silent feature outage
with one log line (finding oracle-cred-twin-nets).

Sharing the DATA (not the engine) keeps the invariant checkable: a parity test
asserts the residue net never fires on the redacter's own output across a corpus
of credential shapes, and both modules assert they reference the objects here.

This module intentionally has NO dependency on ``redact``/``sanitize`` so it can
be imported by both without a cycle.
"""

from __future__ import annotations

# Credential-context keys, longest-first so the alternation prefers ``username``
# over ``user``.  The winlog/EVTX compound field names (``TargetUserName`` /
# ``SubjectUserName`` / ``AccountName``; ``SamAccountName`` already covered) are
# spelled explicitly; ``user[_ .-]?name`` also covers the agent's own OQL echoed
# back as ``user.name:<val>``.  Each net embeds this in its OWN KV regex (the
# redacter with named groups; the residue net with json-escape-quote tolerance).
CRED_KEYS: str = (
    r"targetusername|subjectusername|samaccountname|accountname|"
    r"username|user[_ .-]?name|account|acct|logon|user|usr"
)

# Tokens that are NOT internal-identifying usernames — never tokenise these, and
# (mirror-side) never flag them as residue.  Booleans / status words that can
# follow ``account=`` / ``logon=`` in logs, plus the universal built-in accounts
# every host has.
CRED_VALUE_STOPSET: frozenset[str] = frozenset(
    {
        # booleans / status words that can follow ``account=`` / ``logon=`` in logs
        "true",
        "false",
        "null",
        "none",
        "nil",
        "yes",
        "no",
        "unknown",
        "na",
        "success",
        "successful",
        "failure",
        "failed",
        "fail",
        "denied",
        "allowed",
        "enabled",
        "disabled",
        "active",
        "inactive",
        "valid",
        "invalid",
        "error",
        "ok",
        "expired",
        "locked",
        "unlocked",
        # universal built-in accounts (every host has them — not identifying)
        "root",
        "system",
        "localsystem",
        "administrator",
        "admin",
        "guest",
        "nobody",
        "daemon",
        "bin",
        "sys",
        "sync",
        "lp",
        "mail",
        "news",
        "uucp",
        "proxy",
        "backup",
        "list",
        "irc",
        "gnats",
        "www-data",
        "sshd",
        "postfix",
        "anonymous",
        "ftp",
        "operator",
        "service",
        "localservice",
        "networkservice",
        "everyone",
        "self",
    }
)


# A credential value learned from FREE TEXT must look like an account name.
# Two production refusals on 2026-09-17 came from values the KV net accepted
# but no account could be: ``n`` (the ``n`` of ``user: n/a``) and
# ``r...v....W`` (a printable dump of shellcode after an ``account`` token).
# Each was learned by the redacter, then found again by the residue net in a
# field the redacter does not rewrite, and every escalation was refused. Both
# nets apply this ONE rule, so a value one net will not learn is a value the
# other will not flag.
CRED_VALUE_MIN_LEN: int = 3
CRED_VALUE_MIN_ALNUM: int = 3
CRED_VALUE_MIN_ALNUM_RATIO: float = 0.6


def plausible_credential_value(val: str) -> bool:
    """True if *val* has the shape of an account name."""
    if len(val) < CRED_VALUE_MIN_LEN:
        return False
    alnum = sum(1 for c in val if c.isalnum())
    if alnum < CRED_VALUE_MIN_ALNUM:
        return False
    return alnum / len(val) >= CRED_VALUE_MIN_ALNUM_RATIO


# A host name learned from FREE TEXT must look like a host name. Four of the
# nineteen refusals of 2026-08-29 to 2026-09-18 still refused after the
# credential shape rule: a 2-letter token learned from a UNC path or a logon
# name in an ICMP payload dump, a UNC-shaped junk string in an ICMP message,
# and an internal host name that is a common English word and also sat in a
# public search result URL. A learned name that fails this rule is labelled
# where it stands, and it never joins the learned set: it is not propagated
# to other fields and the residue net does not search for it elsewhere.
LEARNED_HOST_MIN_LEN: int = 3

# A small list of common English words, lower case. A host name that is one of
# them is a word first: in payload text it says nothing about an internal host,
# and the residue net would find it in any prose or URL.
_COMMON_ENGLISH_TEXT = """
    about above across act add after again against age ago agree air all allow almost alone
    along already also always among and animal another answer any appear apple area arm army
    around art ask attack away baby back bad bag ball bank base basic bear beat beauty because
    become bed been before begin behind being believe bell below best better between big bill
    bird black blood blue board boat body book born both bottom box boy brain branch bread break
    bridge bright bring broad brother brown build burn business busy but buy call came camp can
    capital captain car card care carry case cat catch cause cell center central century certain
    chair chance change charge check chief child children choose church circle city class clean
    clear climb clock close cloud coast cold color come common company complete condition
    contain continue control cook cool copy corn corner cost could count country course cover
    cow create crop cross crowd cry current cut dance dark data date daughter day dead deal dear
    death decide deep degree desert design develop did die different direct discover distant
    divide doctor does dog dollar done door double down draw dream dress drink drive drop dry
    during each early earth east easy eat edge effect egg eight either electric element else end
    enemy energy engine enough enter equal even evening event ever every exact example except
    expect experience eye face fact fair fall family famous far farm fast father fear feel feet
    fell few field fight figure fill final find fine finger finish fire first fish five flat
    floor flow flower fly follow food foot for force forest form forward found four free fresh
    friend from front fruit full fun game garden gas gate gave general gentle get girl give glad
    glass gold gone good got govern grass great green ground group grow guess guide had hair
    half hand happen happy hard has hat have head hear heard heart heat heavy held help her here
    high hill him his history hit hold hole home hope horse hot hour house how huge human
    hundred hunt hurry ice idea inch include indeed island its job join joy just keep kept key
    kill kind king knew know lady lake land language large last late laugh law lay lead learn
    least leave left leg length less let letter level lie life lift light like line liquid list
    listen little live long look lost lot loud love low machine made main major make man many
    map mark market mass master match matter may mean measure meat meet member men metal method
    middle might mile milk million mind mine minute miss modern moment money month moon more
    morning most mother mountain mouth move much music must name nation natural nature near need
    never new next night nine noise none noon nor north nose note nothing notice now number
    object ocean off offer office often oil old once one only open order other our out over own
    page paint pair paper park part party pass past path pay people perhaps period person pick
    picture piece place plain plan plane plant play please point poor port position possible
    pound power present press pretty problem produce product proper protect proud prove provide
    pull push put question quick quiet quite race radio rain raise ran reach read ready real
    reason record red region remember repeat reply rest result rich ride right ring rise river
    road rock roll room root rope rose round row rule run safe said sail salt same sand save saw
    say school science score sea season seat second section see seed seem self sell send sense
    sent serve set settle seven several shall shape share sharp she shine ship shoe shop shore
    short should shoulder shout show side sight sign silent silver simple since sing single
    sister sit six size skin sky sleep slow small smell smile snow soft soil soldier some son
    song soon sound south space speak special speed spell spend spot spread spring square stand
    star start state station stay steel step stick still stone stood stop store storm story
    straight strange stream street strong student study subject such sudden sugar summer sun
    supply support sure surface sweet swim system table tail take talk tall teach team tell ten
    term test than thank that the their them then there these thick thin thing think third this
    those though thought thousand three through throw tiny together told tone too took tool top
    total touch toward town track trade train travel tree trip trouble true try turn twenty two
    type under unit until upon use usual valley value very view village visit voice vowel wait
    walk wall want war warm was wash watch water wave way wear weather week weight well went
    were west what wheel when where which while white who whole why wide wife wild will win wind
    window wing winter wire wish with woman women wonder wood word work world would write wrong
    yard year yellow yes yet you young your
"""
COMMON_ENGLISH_WORDS: frozenset[str] = frozenset(_COMMON_ENGLISH_TEXT.split())


def plausible_learned_host(val: str) -> bool:
    """True if *val*, learned from free text, may join the learned host set.

    At least :data:`LEARNED_HOST_MIN_LEN` characters with as many letters and
    digits, the shape of :func:`plausible_netbios_domain`, no path separator,
    and not a word of :data:`COMMON_ENGLISH_WORDS`.
    """
    if len(val) < LEARNED_HOST_MIN_LEN:
        return False
    if "/" in val or "\\" in val:
        return False
    if sum(1 for c in val if c.isalnum()) < LEARNED_HOST_MIN_LEN:
        return False
    if not plausible_netbios_domain(val):
        return False
    return val.lower() not in COMMON_ENGLISH_WORDS


def plausible_netbios_domain(val: str) -> bool:
    """True if *val* has the shape of a NetBIOS domain or a host name.

    A printable dump of shellcode (``c.w.....w.0..TO.....vU..S.``) matched the
    domain half of the ``DOMAIN\\user`` rule on 2026-09-17 and was learned as a
    host. A name never has two dots in a row, never starts or ends with a dot,
    and is mostly letters and digits.
    """
    if ".." in val or val.startswith(".") or val.endswith("."):
        return False
    alnum = sum(1 for c in val if c.isalnum())
    return alnum >= 2 and alnum / len(val) >= CRED_VALUE_MIN_ALNUM_RATIO
