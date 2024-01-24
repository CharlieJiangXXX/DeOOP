def is_signed(number, size: int):
    return number & (1 << ((8 * size) - 1))
