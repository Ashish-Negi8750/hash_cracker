import streamlit as st
import hashlib
import itertools
import multiprocessing
from datetime import datetime

# --- Hashing Function ---
def hash_word(word, algo):
    word = word.strip()
    if algo == "md5":
        return hashlib.md5(word.encode()).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(word.encode()).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(word.encode()).hexdigest()
    else:
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

# --- Brute-force Generator (Multiprocessing) ---
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

# --- Streamlit UI ---
st.set_page_config(page_title="Ultimate Hash Cracker", layout="wide")
st.title("🔐 Ultimate Hash Cracker")
target_hash = st.text_input("Enter the hash to crack")
algo = st.selectbox("Select hash algorithm", ["md5", "sha1", "sha256"])

tabs = st.tabs(["Dictionary", "Rule-based", "Brute-force", "Mask", "Combinator"])

# --- Dictionary Mode ---
with tabs[0]:
    st.subheader("📘 Dictionary Attack")
    uploaded_file = st.file_uploader("Upload a wordlist (.txt)", key="dict")
    if st.button("Run Dictionary Attack"):
        if uploaded_file and target_hash:
            wordlist = uploaded_file.read().decode(errors="ignore").splitlines()
            for word in wordlist:
                if hash_word(word, algo) == target_hash:
                    st.success(f"✅ Password found: {word}")
                    log_result(word, target_hash, algo)
                    break
            else:
                st.error("❌ No match found.")

# --- Rule-based Mode ---
with tabs[1]:
    st.subheader("🧠 Rule-based Attack")
    uploaded_file = st.file_uploader("Upload a wordlist (.txt)", key="rule")
    if st.button("Run Rule-based Attack"):
        if uploaded_file and target_hash:
            raw = uploaded_file.read().decode(errors="ignore").splitlines()
            for word in raw:
                for variant in mutate(word):
                    if hash_word(variant, algo) == target_hash:
                        st.success(f"✅ Password found: {variant}")
                        log_result(variant, target_hash, algo)
                        break
            else:
                st.error("❌ No match found.")

# --- Brute-force Mode ---
with tabs[2]:
    st.subheader("💣 Brute-force Attack")
    max_len = st.slider("Max length", 1, 6, 4)
    charset = st.text_input("Character set", value="abcdefghijklmnopqrstuvwxyz0123456789")
    if st.button("Run Brute-force Attack"):
        if target_hash:
            result = brute_force_parallel(target_hash, charset, max_len, algo)
            if result:
                st.success(f"✅ Password found: {result}")
                log_result(result, target_hash, algo)
            else:
                st.error("❌ No match found.")

# --- Mask Mode ---
with tabs[3]:
    st.subheader("🎭 Mask Attack")
    mask = st.text_input("Enter mask (e.g., ?l?l?d)")
    if st.button("Run Mask Attack"):
        if mask and target_hash:
            for word in parse_mask(mask):
                if hash_word(word, algo) == target_hash:
                    st.success(f"✅ Password found: {word}")
                    log_result(word, target_hash, algo)
                    break
            else:
                st.error("❌ No match found.")

# --- Combinator Mode ---
with tabs[4]:
    st.subheader("🔗 Combinator Attack")
    file1 = st.file_uploader("Upload first wordlist", key="combo1")
    file2 = st.file_uploader("Upload second wordlist", key="combo2")
    if st.button("Run Combinator Attack"):
        if file1 and file2 and target_hash:
            list1 = file1.read().decode(errors="ignore").splitlines()
            list2 = file2.read().decode(errors="ignore").splitlines()
            for w1 in list1:
                for w2 in list2:
                    for combo in [w1 + w2, w2 + w1]:
                        if hash_word(combo, algo) == target_hash:
                            st.success(f"✅ Password found: {combo}")
                            log_result(combo, target_hash, algo)
                            break
            else:
                st.error("❌ No match found.")