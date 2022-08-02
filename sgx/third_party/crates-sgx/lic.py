#!/usr/bin/python

import os
import re

for d in os.listdir("vendor"):
    try:
        p = os.path.join("vendor", d, "Cargo.toml")
        with open(p) as f:
            content = f.read()
            r = re.search('license-file.*=.*"(.*)"', content)
            if r:
                license_file = r.group(1)
                print(d + ": " + "see license file at " + d + "/" + license_file)
            else:
                pass
                r = re.search('license.*=.*"(.*)"', content)
                print(d + ": " + r.group(1))
    except:
        print(d + ": " + "License not found")
