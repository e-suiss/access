from .codec import Rejection


class Fuel:
    def __init__(self, budget):
        self.remaining = budget

    def spend(self, steps=1):
        # OP-111 m.7, OP-108 m.11
        if self.remaining < steps:
            raise Rejection("fuel", "fuel exhausted")
        self.remaining -= steps
