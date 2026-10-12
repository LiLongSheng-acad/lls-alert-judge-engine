#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import uvicorn
from config.settings import API

if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host=API["host"],
        port=API["port"],
        reload=API["reload"],
        log_level="info"
    )
