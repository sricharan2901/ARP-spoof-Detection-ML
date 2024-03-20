import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import threading
import scapy_arpspoof as arpspoof

class ARPspoofGUI:
    def __init__(self, root):
        self.root = root
        root.title("ARP Spoof Detector")

        self.output_text = ScrolledText(root, height=20)
        self.output_text.pack(padx=10, pady=10)

        self.start_button = tk.Button(root, text="Start Detection", command=self.start_detection)
        self.start_button.pack(side=tk.LEFT, padx=(10, 5), pady=5)

        self.stop_button = tk.Button(root, text="Stop Detection", command=self.stop_detection)
        self.stop_button.pack(side=tk.RIGHT, padx=(5, 10), pady=5)

        arpspoof.output_function = self.update_output

        self.req_thread = threading.Thread(target=arpspoof.sniff_requests, daemon=True)
        self.rep_thread = threading.Thread(target=arpspoof.sniff_replays, daemon=True)

    def update_output(self, message):
        self.output_text.insert(tk.END, message + '\n')
        self.output_text.see(tk.END)

    def start_detection(self):
        if not self.req_thread.is_alive():
            self.req_thread = threading.Thread(target=arpspoof.sniff_requests, daemon=True)
            self.req_thread.start()
        if not self.rep_thread.is_alive():
            self.rep_thread = threading.Thread(target=arpspoof.sniff_replays, daemon=True)
            self.rep_thread.start()

    def stop_detection(self):
        self.output_text.insert(tk.END, 'Try in Terminal\n')

if __name__ == "__main__":
    root = tk.Tk()
    gui = ARPspoofGUI(root)
    root.mainloop()