import tkinter as tk

from modules import osint_run
from modules.themes import *
from modules.osint_run import *

theme = dark_theme

class PyOsint:
    def __init__(self, root):
        self.root = root
        self.root.title("--- PyOsint ---")
        self.root.geometry('450x450')
        self.root.resizable(False, False)
        self.root.config(bg=theme["bg"])
        
        menubar = tk.Menu(self.root, bg=theme["bg"], fg=theme["fg"], activebackground=theme["accent"])
        
        option_menu = tk.Menu(menubar, tearoff=0, bg=theme["bg"], fg=theme["fg"], activebackground=theme["accent"],)

        option_menu.add_command(label="Help", command=self.help_menu, font=default_font, background=theme["bg"], foreground=theme["fg"], activebackground=theme["accent"])
        
        menubar.add_cascade(label="Options", menu=option_menu, font=default_font, background=theme["bg"], foreground=theme["fg"], activebackground=theme["accent"])
        self.root.config(menu=menubar)
        
        self.top_heading = tk.Label(self.root, text="PyOsint", font=heading_font, width=20, height=2, bg=theme["bg"], fg=theme["fg"])
        self.top_heading.pack()
        
        self.entries_frame = tk.Frame(self.root, width=50, height=20, bg=theme["bg"])
        self.entries_frame.pack(padx=5, pady=5)
        
        self.label1 = tk.Label(self.entries_frame, text="Username:", font=default_font, bg=theme["bg"], fg=theme["fg"])
        self.label1.pack(padx=5, pady=5)
        
        self.user_name_entry = tk.Entry(self.entries_frame, font=default_font, width=30, bg=theme["entry_bg"], fg=theme["entry_fg"], insertbackground=theme["entry_fg"])
        self.user_name_entry.pack(padx=5, pady=5)

        self.label2 = tk.Label(self.entries_frame, text="Email:", font=default_font, bg=theme["bg"], fg=theme["fg"])
        self.label2.pack(padx=5, pady=5)

        self.email_entry = tk.Entry(self.entries_frame, font=default_font, width=30, bg=theme["entry_bg"], fg=theme["entry_fg"], insertbackground=theme["entry_fg"])
        self.email_entry.pack(padx=5, pady=5)

        self.label3 = tk.Label(self.entries_frame, text="Domain:", font=default_font, bg=theme["bg"], fg=theme["fg"])
        self.label3.pack(padx=5, pady=5)

        self.domain_entry = tk.Entry(self.entries_frame, font=default_font, width=30, bg=theme["entry_bg"], fg=theme["entry_fg"], insertbackground=theme["entry_fg"])
        self.domain_entry.pack(padx=5, pady=5)

        self.label4 = tk.Label(self.entries_frame, text="IP Address:", font=default_font, bg=theme["bg"], fg=theme["fg"])
        self.label4.pack(padx=5, pady=5)

        self.ip_addr_entry = tk.Entry(self.entries_frame, font=default_font, width=30, bg=theme["entry_bg"], fg=theme["entry_fg"], insertbackground=theme["entry_fg"])
        self.ip_addr_entry.pack(padx=5, pady=5)

        self.osint_btn = tk.Button(self.root, text="OSINT", command=self.run_osint, font=default_font, width=20, height=1, bg=theme["button_bg"], fg=theme["button_fg"], activebackground=theme["accent"], activeforeground=theme["fg"])
        self.osint_btn.pack(padx=5, pady=5)

        self.exit_btn = tk.Button(self.root, text="Exit", command=self.root.quit, font=default_font, width=20, height=1, bg=theme["button_bg"], fg=theme["button_fg"], activebackground=theme["accent"], activeforeground=theme["fg"])
        self.exit_btn.pack(padx=5, pady=5)

        self.root.bind("<Return>", lambda event: self.run_osint())

    def run_osint(self):
        username = self.user_name_entry.get().strip()
        email = self.email_entry.get().strip()
        domain = self.domain_entry.get().strip()
        ip_addr = self.ip_addr_entry.get().strip()

        if not username and not email and not domain and not ip_addr:
            messagebox.showwarning("Input Error", "Fill at least one entry to continue.", parent=self.root)
            return

        self.osint_popup = tk.Toplevel(self.root)
        self.osint_popup.title("-- OSINT --")
        self.osint_popup.geometry('640x480')
        self.osint_popup.resizable(False, False)
        self.osint_popup.config(bg=theme["bg"])


        self.osint_label = tk.Label(self.osint_popup, text="Processing...", font=default_font, bg=theme["bg"], fg=theme["fg"])
        self.osint_label.pack(padx=5)
        
        self.result_frame = tk.Frame(self.osint_popup, bg=theme["bg"])
        self.result_frame.pack(padx=5, pady=5, fill="both", expand=True)

        scrollbar = tk.Scrollbar(self.result_frame, bg=theme["bg"])
        scrollbar.pack(side="right", fill="y")

        self.result_text = tk.Text(self.result_frame, wrap="word", font=default_font, width=50, height=18, yscrollcommand=scrollbar.set, bg=theme["entry_bg"], fg=theme["entry_fg"], insertbackground=theme["entry_fg"])
        self.result_text.pack(padx=5, pady=5, side="left", fill="both", expand=True)

        scrollbar.config(command=self.result_text.yview)


        self.done_btn = tk.Button(self.osint_popup, text="Done", command=self.osint_popup.destroy, font=default_font, width=10, height=1, bg=theme["button_bg"], fg=theme["button_fg"], activebackground=theme["accent"], activeforeground=theme["fg"])
        self.done_btn.pack(padx=5, pady=5)

        if username:
            def insert_result_username(text):
                self.result_text.insert(tk.END, "\n🔍 Username Lookup Results\n\n")
                self.result_text.insert(tk.END, text)
                self.osint_label.config(text="Results.")

            osint_run.username_lookup(username, insert_result_username)
        
        if email:
            def insert_result_email(text):
                self.result_text.insert(tk.END, "\n📧 Email Lookup Results\n\n")
                self.result_text.insert(tk.END, text)
                self.osint_label.config(text="Results.")

            osint_run.email_lookup(email, insert_result_email)

        if domain:
            def insert_result_domain(text):
                self.result_text.insert(tk.END, "\n🌐 Domain Lookup Results\n\n")
                self.result_text.insert(tk.END, text)
                self.osint_label.config(text="Results.")

            osint_run.domain_lookup(domain, insert_result_domain)

        if ip_addr:
            def insert_result_ip_addr(text):
                self.result_text.insert(tk.END, "\n💻 IP Lookup Results\n\n")
                self.result_text.insert(tk.END, text)
                self.osint_label.config(text="Results.")

            osint_run.shodan_lookup(ip_addr, insert_result_ip_addr)
        

        # self.result_text.config(state="disabled")
        self.user_name_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.domain_entry.delete(0, tk.END)
        self.ip_addr_entry.delete(0, tk.END)

    def help_menu(self):
        self.help_popup = tk.Toplevel(self.root)
        self.help_popup.title("-- Help --")
        self.help_popup.geometry('450x450')
        self.help_popup.resizable(False, False)
        self.help_popup.config(bg=theme["bg"])

        help_info = """=== Help — PyOSINT Tool 🕵️‍♂️ ===

Description:
    PyOSINT Tool is an Open Source Intelligence (OSINT) program that allows you to gather publicly available information on usernames, email addresses, domains, and IP addresses using a simple interface.

    It combines multiple lookup methods into one tool to make reconnaissance easier for cybersecurity research, ethical hacking, and personal investigation.

Features:
    1. Username Lookup → Search across multiple websites & platforms to see where a username exists.

    2. Email Lookup → Get domain info, Gravatar profile (if exists), and OSINT tips for deeper searches.

    3. Domain Lookup → Retrieve WHOIS info & DNS records.

    4. IP Lookup (Shodan) → Find open ports, services, banners, host details, and geolocation.

How to Use:
## Put your API key in SHODAN_API_KEY named variable in .env file to continue.

    1. Username Field:
        a) Enter a username (e.g., john_doe)
        b) Press Search or hit Enter
        c) The tool will check multiple sites for matches.

    2. Email Field:
        a) Enter a valid email (e.g., example@mail.com)
        b) Output includes:
            - Email domain
            - Gravatar profile (if found)
            - Suggested search query for breaches

    3. Domain Field:
        a) Enter a domain (e.g., example.com)
        b) Output includes:
            - WHOIS data (creation date, registrar, etc.)
            - DNS records (A, AAAA, MX, NS, TXT)

    4. IP Address Field:
        a) Enter a valid IP (e.g., 8.8.8.8)
        b) Output includes:
            - Organization, ISP, ASN
            - Country, City, GPS coordinates
            - Open ports & services (from Shodan)
            - Service banners

⚠ Note: This tool uses public APIs and search techniques. Some features (like Shodan lookups) require an API key. Results depend on available public data.
        """

        self.help_frame = tk.Frame(self.help_popup, bg=theme["bg"])
        self.help_frame.pack(padx=5, pady=5, fill="both", expand=True)

        scrollbar = tk.Scrollbar(self.help_frame, bg=theme["bg"])
        scrollbar.pack(side="right", fill="y")

        self.help_text = tk.Text(self.help_frame, wrap="word", font=default_font, width=50, height=18, yscrollcommand=scrollbar.set, bg=theme["entry_bg"], fg=theme["entry_fg"], insertbackground=theme["entry_fg"])
        self.help_text.pack(padx=5, pady=5, side="left", fill="both", expand=True)

        self.help_text.insert(tk.END, help_info)
        self.help_text.config(state="disabled")

        scrollbar.config(command=self.help_text.yview)

        self.dne_btn = tk.Button(self.help_popup, text="Done", command=self.help_popup.destroy, font=default_font, width=10, height=1, bg=theme["button_bg"], fg=theme["button_fg"], activebackground=theme["accent"], activeforeground=theme["fg"])
        self.dne_btn.pack(padx=5, pady=5)

if __name__ == '__main__':
    root = tk.Tk()
    app = PyOsint(root)
    root.mainloop()