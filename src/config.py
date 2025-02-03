
import json 

class Config:
    def __init__(self):
        with open('src/config.json') as f:
            self.config = json.load(f)
