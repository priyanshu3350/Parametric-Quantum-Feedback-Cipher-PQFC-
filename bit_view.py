from secure_server import encryption

message = "I like mango."

msg_lst = list(message)

ascii_val = list(map(ord, msg_lst))
bin_val = list(map(lambda x: f"{x:08b}", ascii_val))

comb = list(zip(msg_lst, ascii_val, bin_val))

ascii_val_enc, _ = encryption(message, 85)
bin_enc = list(map(lambda x: f"{x:08b}", ascii_val_enc))

print(*comb, sep="\n")

print("\nSentence in binary (original):")
print("".join(bin_val))
print("\nSentence in binary (encrypted):")
print("".join(bin_enc))

message_enc = "".join(chr(val) for val in ascii_val_enc)
print(f"\nEncrypted message: {message_enc}")
print(list(message_enc))
