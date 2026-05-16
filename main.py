#!/usr/bin/env python3
"""
soclab.py - Entry point for the SOC Lab environment.
Wraps soc_deploy.py for easier usage.
"""

import sys
import soc_deploy

if __name__ == "__main__":
    try:
        soc_deploy.main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
