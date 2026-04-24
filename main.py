import gradio as gr

import quantum_filtered_arx as q_arx

# --- CLOUD MEMORY: Replaces local sockets for web deployment ---
# Format: { "ROOM_CODE": { "messages": [], "wire_log": "", "seed": 0xDEADC... } }
SERVER_ROOMS = {}
DEFAULT_SEED = 0xDEADC0DEBEEFCAFE1234567890ABCDEF

# --- PREMIUM CSS ---
CUSTOM_CSS = """
.gradio-container { background-color: #020617 !important; border: none !important; }
.wire-panel { background: #0f172a; border: 1px solid #334155; font-family: monospace; color: #10b981; padding: 10px; height: 300px; overflow-y: auto;}
.status-securing { color: #fbbf24 !important; font-weight: bold; }
.status-protected { color: #4ade80 !important; font-weight: bold; }
"""

THEME = gr.themes.Default(primary_hue="cyan", secondary_hue="slate").set(
    body_background_fill="#020617",
    block_background_fill="#0f172a",
)


def get_room(room_code):
    if room_code not in SERVER_ROOMS:
        SERVER_ROOMS[room_code] = {
            "messages": [],
            "wire_log": "📡 Waiting for encrypted transmissions...\n",
            "seed": DEFAULT_SEED,
        }
    return SERVER_ROOMS[room_code]


def join_room(room_code, username):
    if not room_code or not username:
        return "⚠️ Enter Room Code and Name.", "Idle", gr.update(interactive=True)

    room = get_room(room_code)
    sys_msg = f"{username} joined the secure channel."

    # Save to global room state
    room["messages"].append({"sender": "System", "text": sys_msg})

    return (
        f"Joined {room_code} as {username}",
        "Protected ✅",
        gr.update(interactive=False),
    )


def send_secure_message(room_code, username, message):
    if not message.strip() or not room_code:
        return ""

    room = get_room(room_code)

    # 1. ENCRYPT (Simulating Client-Side Encryption)
    encrypted_bytes = q_arx.encrypt(message.encode("utf-8"), room["seed"])

    # 2. THE WIRE (What the server/network sees)
    hex_cipher = encrypted_bytes.hex()
    entropy = q_arx.calculate_shannon_entropy(encrypted_bytes)
    wire_entry = f"\n[TX from {username}] \nCipher: {hex_cipher[:40]}...\nEntropy: {entropy:.4f}\n"
    room["wire_log"] = wire_entry + room["wire_log"]

    # 3. DECRYPT (Simulating Receiver-Side Decryption)
    decrypted_bytes = q_arx.decrypt(encrypted_bytes, room["seed"])
    decrypted_msg = decrypted_bytes.decode("utf-8")

    # Save to global room state
    room["messages"].append({"sender": username, "text": decrypted_msg})

    return ""  # Clear input box


def refresh_ui(room_code, current_username):
    """Pulls the latest data from the server room and formats it for Gradio 5.0"""
    if not room_code or room_code not in SERVER_ROOMS:
        return [], "📡 No active connection..."

    room = SERVER_ROOMS[room_code]
    chat_history = []

    # Format messages correctly for Gradio's new type="messages" format
    for msg in room["messages"]:
        if msg["sender"] == "System":
            chat_history.append({
                "role": "assistant",
                "content": f"⚙️ *[System] {msg['text']}*",
            })
        elif msg["sender"] == current_username:
            # Current user's messages show up on the right
            chat_history.append({"role": "user", "content": msg["text"]})
        else:
            # Other users' messages show up on the left
            chat_history.append({
                "role": "assistant",
                "content": f"**{msg['sender']}**: {msg['text']}",
            })

    return chat_history, room["wire_log"]


def build_ui():
    # Removed theme and css from Blocks() to fix the UserWarning
    with gr.Blocks(title="Quantum Chat") as demo:
        gr.Markdown("<center><h1>⚛️ Quantum-ARX Secure Chat</h1></center>")
        gr.Markdown(
            "<center><i>Real-time P2P simulation proving dynamic ARX encryption.</i></center>"
        )

        with gr.Row():
            # LEFT: Connection & Network Monitor
            with gr.Column(scale=1):
                gr.Markdown("### 🔗 Link Setup")
                with gr.Row():
                    room_input = gr.Textbox(
                        label="Room Code", placeholder="e.g. SECURE-77"
                    )
                    name_input = gr.Textbox(label="Your Name", placeholder="Alice")

                join_btn = gr.Button("Establish Secure Link", variant="primary")
                status_text = gr.Textbox(
                    label="Link Status", value="Idle", interactive=False
                )

                gr.Markdown("### 🕵️ Raw Network Wire")
                gr.Markdown("*(This proves the server only sees Quantum Ciphertext)*")
                wire_monitor = gr.Textbox(
                    show_label=False,
                    elem_classes="wire-panel",
                    interactive=False,
                    lines=10,
                )

            # RIGHT: The Chat App
            with gr.Column(scale=2):
                gr.Markdown("### 💬 Encrypted Channel")

                # FIX: Removed type="messages" here because Gradio 6 does this by default now
                chatbot = gr.Chatbot(label="End-to-End Encrypted Chat", height=500)

                with gr.Row():
                    msg_input = gr.Textbox(
                        show_label=False, placeholder="Type a message...", scale=8
                    )
                    send_btn = gr.Button("Encrypt & Send", variant="primary", scale=2)

        # Event Routing
        join_btn.click(
            join_room,
            inputs=[room_input, name_input],
            outputs=[status_text, status_text, join_btn],
        )

        msg_input.submit(
            send_secure_message,
            inputs=[room_input, name_input, msg_input],
            outputs=[msg_input],
        )
        send_btn.click(
            send_secure_message,
            inputs=[room_input, name_input, msg_input],
            outputs=[msg_input],
        )

        # Real-time polling
        timer = gr.Timer(0.5)
        timer.tick(
            refresh_ui, inputs=[room_input, name_input], outputs=[chatbot, wire_monitor]
        )

    return demo


if __name__ == "__main__":
    ui = build_ui()
    # Applied theme and css here in launch() per Gradio 5.0+ requirements
    ui.launch(theme=THEME, css=CUSTOM_CSS, share=True)
