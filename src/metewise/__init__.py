"""metewise -- a broken-object-authorization regression fuzzer.

Not a pentester's magnifying glass; a regression test. It replays observed API
traffic across principals and uses a four-corner oracle to decide, with
evidence, whether an object leaked across an ownership boundary.
"""

__version__ = "0.8.0"
