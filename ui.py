import gradio as gr

from network import connect_to_host, get_chat_history, send_msg, start_host


def build_ui() -> gr.Blocks:
    with gr.Blocks(title="Secure Encrypted Chat") as demo:
        gr.Markdown("# 🔒 Secure P2P Encrypted Chat")

        with gr.Row():
            with gr.Column(scale=2):
                ip_input = gr.Textbox(label="IP Address", value="127.0.0.1")
                port_input = gr.Textbox(label="Port", value="65432")
            with gr.Column(scale=1):
                host_btn = gr.Button("🏠 Host Chat", variant="primary")
                connect_btn = gr.Button("🔗 Connect", variant="secondary")
                status_text = gr.Textbox(label="Status", interactive=False)

        chatbot = gr.Chatbot(label="Chat Window", height=450)

        with gr.Row():
            msg_input = gr.Textbox(
                label="Your Message",
                placeholder="Type your message and press Enter...",
                scale=4,
            )
            send_btn = gr.Button("Send 🚀", scale=1)

        # Event bindings
        host_btn.click(start_host, inputs=[port_input], outputs=[status_text])
        connect_btn.click(
            connect_to_host, inputs=[ip_input, port_input], outputs=[status_text]
        )
        msg_input.submit(send_msg, inputs=[msg_input], outputs=[msg_input])
        send_btn.click(send_msg, inputs=[msg_input], outputs=[msg_input])

        # Auto-refresh the chat window every second
        timer = gr.Timer(value=1)
        timer.tick(get_chat_history, inputs=None, outputs=[chatbot])

    return demo
