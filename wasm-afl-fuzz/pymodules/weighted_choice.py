import random

def weighted_choice(choices):
    total = sum(w for c, w in choices)
    r = random.uniform(0, total)
    count = 0
    for c, w in choices:
        if count + w >= r:
            return c
        count += w