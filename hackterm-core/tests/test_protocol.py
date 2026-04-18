import pytest
from hackterm_core.protocol import (
    Field, Screen, FieldWrite, MutateOpts, NegotiateOpts,
    StructuredField, QueryLies, Protocol,
)


def test_field_dataclass():
    f = Field(row=5, col=10, length=20, protected=True,
              hidden=False, numeric=False, mdt=True, content=b"\xc1\xc2\xc3")
    assert f.row == 5
    assert f.protected is True
    assert f.content == b"\xc1\xc2\xc3"


def test_screen_dataclass():
    s = Screen(rows=24, cols=80, fields=[], raw=b"", rendered=[])
    assert s.rows == 24
    assert s.cols == 80
    assert s.fields == []


def test_screen_text_helper():
    """Screen.text joins rendered grid into a single string for grep/regex."""
    rendered = [["H", "I", " "], [" ", "O", "K"]]
    s = Screen(rows=2, cols=3, fields=[], raw=b"", rendered=rendered)
    assert s.text == "HI \n OK"


def test_screen_empty_factory():
    s = Screen.empty()
    assert s.rows == 24
    assert s.cols == 80
    assert s.raw == b""
    assert len(s.rendered) == 24
    assert len(s.rendered[0]) == 80


def test_mutate_opts_defaults_all_false():
    opts = MutateOpts()
    assert opts.unprotect is False
    assert opts.reveal_hidden is False
    assert opts.remove_numeric is False
    assert opts.high_visibility is False
    assert opts.color_reveal is False


def test_negotiate_opts_defaults():
    opts = NegotiateOpts()
    assert opts.spoof_device_name is None
    assert opts.force_cleartext is False
    assert opts.downgrade_functions is False


def test_field_write():
    fw = FieldWrite(row=1, col=1, data=b"\xf1\xf2\xf3")
    assert fw.data == b"\xf1\xf2\xf3"


def test_structured_field():
    sf = StructuredField(sf_type=0xD0, payload=b"data")
    assert sf.sf_type == 0xD0


def test_query_lies_defaults():
    lies = QueryLies()
    assert lies.alt_rows is None
    assert lies.deny_color is False
    assert lies.rpq_name is None


def test_protocol_is_abstract():
    """Cannot instantiate Protocol directly."""
    with pytest.raises(TypeError):
        Protocol()


def test_protocol_subclass_must_implement_all_abstracts():
    """Subclass missing an abstract method cannot be instantiated."""
    class Incomplete(Protocol):
        name = "test"
        aid_table = {}
        default_codepage = "cp037"
        # missing detect, negotiate_hook, parse, mutate, build_inbound, spoof_aid
    with pytest.raises(TypeError):
        Incomplete()


def test_protocol_optional_methods_have_defaults():
    """parse_structured returns None by default; build_query_reply raises."""
    class Minimal(Protocol):
        name = "test"
        aid_table = {"ENTER": 0x7D}
        default_codepage = "cp037"
        def detect(self, b): return False
        def negotiate_hook(self, d, dr, o): return d
        def parse(self, d): return Screen.empty()
        def mutate(self, d, o): return d
        def build_inbound(self, a, c, f): return b""
        def spoof_aid(self, o, a): return o

    p = Minimal()
    assert p.parse_structured(b"") is None
    with pytest.raises(NotImplementedError):
        p.build_query_reply(QueryLies())
