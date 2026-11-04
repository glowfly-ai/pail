# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Deterministic retained-command actuator and explicit MOCK receipts."""
class MockPort:
    authority_source='MOCK'
    def __init__(self): self.retained=0.0; self.samples=[]
    def command(self,value): self.retained=value
    def tick(self,lifecycle):
        value=lifecycle.output(self.retained); self.samples.append(value); return value
    def recreate(self): self.retained=0.0
