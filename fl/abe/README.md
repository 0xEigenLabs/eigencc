# ABE for DataSharing
## Test
1. Install [charm](../third_party/charm)
2. Run test: PYTHONPATH=../ python setup.py test


## Revoke

For each attribute, we allocate a date to it, converting the attr_i to attr_i:date, and check if it expires when decrypting each time.
