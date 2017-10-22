import string
import random

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    rand = random.SystemRandom()
    return ''.join(rand.choice(chars) for x in range(length))
