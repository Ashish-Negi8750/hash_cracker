#!/usr/bin/env python3
import argparse, hashlib, itertools, multiprocessing, time
from datetime import datetime
from tqdm import tqdm

# --- Hashing ---
def hash_word(word, algo):
    word = word.strip()
    if algo == "md5":
        return hashlib.md5(word.encode()).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(word.encode()).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(word.encode()).hexdigest()
    return None

# --- Mutation Engine ---
def mutate(word):
    return [
        word,
        word + "123",
        word + "!",
        word.capitalize(),
        word[::-1],
        word.replace("a", "@").replace("s", "$").replace("o", "0"),
    ]

# --- Mask Parser ---
def parse_mask(mask):
    mask_map = {
        "?l": "abcdefghijklmnopqrstuvwxyz",
        "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "?d": "0123456789",
        "?s": "!@#$%^&*"
    }
    charset_list = []
    i = 0
    while i < len(mask):
        if mask[i:i+2] in mask_map:
            charset_list.append(mask_map[mask[i:i+2]])
            i += 2
        else:
            charset_list.append(mask[i])
            i += 1
    return (''.join(candidate) for candidate in itertools.product(*charset_list))

# --- Brute-force Worker ---
def brute_worker(args):
    word, target_hash, algo = args
    return word if hash_word(word, algo) == target_hash else None

def brute_force_parallel(target_hash, charset, max_len, algo):
    candidates = (''.join(p) for l in range(1, max_len+1) for p in itertools.product(charset, repeat=l))
    with multiprocessing.Pool() as pool:
        for result in pool.imap_unordered(brute_worker, ((word, target_hash, algo) for word in candidates), chunksize=1000):
            if result:
                return result
    return None

# --- Logging ---
def log_result(password, hash_value, algo):
    with open("cracked_log.txt", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} | {algo.upper()} | {hash_value} → {password}\n")

# --- Main CLI ---
def main():
    parser = argparse.ArgumentParser(description="Ultimate Hash Cracker")
    parser.add_argument("--mode", required=True, choices=["dictionary", "rule", "brute", "mask", "combo"])
    parser.add_argument("--hash", required=True, help="Target hash to crack")
    parser.add_argument("--algo", required=True, choices=["md5", "sha1", "sha256"])
    parser.add_argument("--wordlist", help="Path to wordlist")
    parser.add_argument("--wordlist2", help="Second wordlist for combinator")
    parser.add_argument("--charset", help="Charset for brute-force")
    parser.add_argument("--maxlen", type=int, help="Max length for brute-force")
    parser.add_argument("--mask", help="Mask pattern")
    args = parser.parse_args()

    start = time.time()
    attempts = 0
    found = None

    if args.mode == "dictionary":
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = f.read().splitlines()
        for word in tqdm(words, desc="Dictionary", unit="word"):
            attempts += 1
            if hash_word(word, args.algo) == args.hash:
                found = word
                break

    elif args.mode == "rule":
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = f.read().splitlines()
        for word in tqdm(words, desc="Rule-based", unit="word"):
            for variant in mutate(word):
                attempts += 1
                if hash_word(variant, args.algo) == args.hash:
                    found = variant
                    break
            if found: break

    elif args.mode == "brute":
        result = brute_force_parallel(args.hash, args.charset, args.maxlen, args.algo)
        found = result
        # Brute-force attempts are hard to count precisely in parallel mode

    elif args.mode == "mask":
        for word in tqdm(parse_mask(args.mask), desc="Mask", unit="word"):
            attempts += 1
            if hash_word(word, args.algo) == args.hash:
                found = word
                break

    elif args.mode == "combo":
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f1, open(args.wordlist2, "r", encoding="utf-8", errors="ignore") as f2:
            list1 = f1.read().splitlines()
            list2 = f2.read().splitlines()
        for w1 in tqdm(list1, desc="Combinator", unit="word"):
            for w2 in list2:
                for combo in [w1 + w2, w2 + w1]:
                    attempts += 1
                    if hash_word(combo, args.algo) == args.hash:
                        found = combo
                        break
                if found: break
            if found: break

    # --- Output ---
    if found:
        print(f"\n[✓] Password found: {found}")
        print(f"[✓] Hash: {args.hash}")
        print(f"[✓] Algorithm: {args.algo.upper()}")
        log_result(found, args.hash, args.algo)
    else:
        print("\n[-] No match found.")

    print(f"[⏱] Time taken: {time.time() - start:.2f} seconds")
    print(f"[🔍] Attempts: {attempts if attempts else 'N/A (parallel mode)'}")

if __name__ == "__main__":
    main()