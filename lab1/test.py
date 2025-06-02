import random
from itertools import permutations


def get_feedback(guess):
    print(f"Enter feedback for {guess} (format: A B): ", end="")
    a, b = map(int, input().split())
    return a, b


def one_a_two_b_solver():
    possible_numbers = ["".join(p) for p in permutations("0123456789", 4)]
    attempts = 0

    while attempts < 10:
        guess = possible_numbers[0]
        a, b = get_feedback(guess)
        attempts += 1

        print(f"Attempt {attempts}: Guess {guess} -> {a}A{b}B")

        if a == 4:
            print("Correct! The secret number is:", guess)
            return guess

        possible_numbers = [
            num
            for num in possible_numbers
            if sum(g == s for g, s in zip(num, guess)) == a
            and sum(
                (num.count(d) > 0) and (num[i] != guess[i]) for i, d in enumerate(guess)
            )
            == b
        ]

    print("Failed to guess in 10 attempts.")
    return None

if __name__ == "__main__":
    one_a_two_b_solver()
