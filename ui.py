import gradio as gr

from network import (
    connect_to_host,
    get_chat_history,
    get_telemetry,
    reset_session,
    send_msg,
    start_host,
)

# Premium "Cyber-Quantum" Themes & Animations
CUSTOM_CSS = """
@keyframes pulse-cyan {
  0% { box-shadow: 0 0 0 0 rgba(34, 211, 238, 0.4); }
  70% { box-shadow: 0 0 0 15px rgba(34, 211, 238, 0); }
  100% { box-shadow: 0 0 0 0 rgba(34, 211, 238, 0); }
}

@keyframes secret-glow {
  from { text-shadow: 0 0 5px #22d3ee; }
  to { text-shadow: 0 0 20px #22d3ee, 0 0 30px #06b6d4; }
}

.gradio-container { background-color: #020617 !important; border: none !important; }
.quantum-panel { 
    background: rgba(15, 23, 42, 0.8); 
    backdrop-filter: blur(10px); 
    border: 1px solid #1e293b; 
    border-radius: 16px; 
    padding: 20px;
    box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5);
}

#pulse-zone.firing {
    animation: pulse-cyan 1s infinite;
    border-color: #22d3ee !important;
}

.stat-card {
    background: #0f172a;
    border-left: 4px solid #334155;
    padding: 12px;
    border-radius: 8px;
}

.stat-card.active {
    border-left-color: #22d3ee;
}

.stat-label { font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.1em; }
.stat-value { font-family: 'JetBrains Mono', monospace; font-size: 1.2rem; color: #f8fafc; }

.status-protected { color: #4ade80 !important; font-weight: bold; }
.status-securing { color: #fbbf24 !important; font-weight: bold; }
"""

# Premium "Outfit" Theme
THEME = gr.themes.Default(
    primary_hue="cyan",
    secondary_hue="slate",
    font=[gr.themes.GoogleFont("Inter"), "sans-serif"],
).set(
    body_background_fill="#020617",
    block_background_fill="#0f172a",
    block_border_width="1px",
    block_label_text_size="*text_xs",
)


def build_ui() -> gr.Blocks:
    with gr.Blocks(title="Secure Quantum Link") as demo:
        # Session Reset on Load
        demo.load(reset_session)

        gr.HTML("<div style='text-align: center; margin-bottom: 2rem;'>")
        gr.Markdown("# ⚛️ Quantum-ARX Secure Link")
        gr.Markdown("#### Stateful Hybrid P2P Encryption with ECDH Handshake")
        gr.HTML("</div>")

        with gr.Row(equal_height=True):
            # --- LEFT: CHAT ---
            with gr.Column(scale=2, elem_id="pulse-zone"):
                chatbot = gr.Chatbot(
                    label="End-to-End Encrypted Channel",
                    height=550,
                    show_label=True,
                    # type="messages",
                    avatar_images=(
                        None,
                        "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
                    ),
                )

                with gr.Row():
                    msg_input = gr.Textbox(
                        show_label=False,
                        placeholder="Enter your message...",
                        scale=9,
                        container=False,
                    )
                    send_btn = gr.Button("Encrypt & Send", variant="primary", scale=1)

            # --- RIGHT: TELEMETRY & CONTROLS ---
            with gr.Column(scale=1):
                # Telemetry Center
                with gr.Column(elem_classes="quantum-panel"):
                    gr.Markdown("### 📡 Quantum Telemetry")

                    with gr.Row():
                        with gr.Column(elem_classes="stat-card", min_width=100):
                            gr.Markdown("<p class='stat-label'>Entropy</p>")
                            entropy_stat = gr.Markdown(
                                "<p class='stat-value'>0.0000</p>"
                            )

                        with gr.Column(elem_classes="stat-card", min_width=100):
                            gr.Markdown("<p class='stat-label'>Status</p>")
                            status_stat = gr.Markdown(
                                "<p class='stat-value' style='color:#fbbf24'>Idle</p>"
                            )

                    with gr.Row():
                        with gr.Column(elem_classes="stat-card", min_width=100):
                            gr.Markdown("<p class='stat-label'>TX Count</p>")
                            sent_stat = gr.Markdown("<p class='stat-value'>0</p>")

                        with gr.Column(elem_classes="stat-card", min_width=100):
                            gr.Markdown("<p class='stat-label'>RX Count</p>")
                            recv_stat = gr.Markdown("<p class='stat-value'>0</p>")

                    firing_light = gr.HTML(
                        "<div id='fire-indicator' style='height:4px; width:100%; background:#1e293b; border-radius:2px;'></div>"
                    )

                # Connection controls
                with gr.Accordion("⚙️ Connection Settings", open=True):
                    host_ip = gr.Textbox(label="Peer IP", value="127.0.0.1")
                    host_port = gr.Textbox(label="Port", value="9999")
                    with gr.Row():
                        host_btn = gr.Button("🏠 Host", variant="secondary")
                        join_btn = gr.Button("🔗 Join", variant="secondary")

                with gr.Accordion("🔑 Advanced Security", open=False):
                    seed_disp = gr.Textbox(
                        label="Derived Master Seed",
                        interactive=False,
                        placeholder="Negotiated via ECDH...",
                    )
                    gen_btn = gr.Button("⚛️ Self-Test Quantum Seed")

                sys_log = gr.Textbox(label="System Events", interactive=False, lines=2)

        # --- DYNAMIC LOGIC ---

        def update_ui():
            stats = get_telemetry()
            history = get_chat_history()

            # Animation Logic
            pulse_css = "firing" if stats["is_firing"] else ""
            fire_color = "#22d3ee" if stats["is_firing"] else "#1e293b"
            fire_html = f"<div id='fire-indicator' style='height:4px; width:100%; background:{fire_color}; border-radius:2px; box-shadow: 0 0 10px {fire_color};'></div>"

            status_color = (
                "#4ade80"
                if stats["handshake_status"] == "Protected"
                else "#fbbf24"
                if stats["handshake_status"] == "Securing"
                else "#94a3b8"
            )
            status_html = f"<p class='stat-value' style='color:{status_color}'>{stats['handshake_status']}</p>"

            return (
                history,
                f"<p class='stat-value'>{stats['last_entropy']:.4f}</p>",
                status_html,
                f"<p class='stat-value'>{stats['packets_sent']}</p>",
                f"<p class='stat-value'>{stats['packets_recv']}</p>",
                fire_html,
            )

        # Event Handlers
        host_btn.click(start_host, inputs=[host_port], outputs=[sys_log])
        join_btn.click(connect_to_host, inputs=[host_ip, host_port], outputs=[sys_log])

        msg_input.submit(send_msg, inputs=[msg_input], outputs=[msg_input])
        send_btn.click(send_msg, inputs=[msg_input], outputs=[msg_input])

        # Real-time state syncing
        timer = gr.Timer(value=0.5)
        timer.tick(
            update_ui,
            outputs=[
                chatbot,
                entropy_stat,
                status_stat,
                sent_stat,
                recv_stat,
                firing_light,
            ],
        )

    return demo


if __name__ == "__main__":
    ui = build_ui()
    ui.launch(theme=THEME, css=CUSTOM_CSS, share=True)
