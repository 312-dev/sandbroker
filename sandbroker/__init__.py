"""sandbroker: use secrets without seeing them.

One daemon per vault. It resolves references, runs your command with the values
in the environment, and strips those values out of the output on the way back.
That is the whole product.
"""

__version__ = "1.0.0"
