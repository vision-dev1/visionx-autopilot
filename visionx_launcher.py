import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk
import os
import subprocess
import json

# =========================
# DATA STORAGE
# =========================

DATA_FILE = os.path.expanduser("~/.visionx_data.json")

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {"favorites": [], "recent": []}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def add_recent(tool, data):
    if tool in data["recent"]:
        data["recent"].remove(tool)
    data["recent"].insert(0, tool)
    data["recent"] = data["recent"][:15]
    save_data(data)

def toggle_favorite(tool, data):
    if tool in data["favorites"]:
        data["favorites"].remove(tool)
    else:
        data["favorites"].append(tool)
    save_data(data)

# =========================
# MODULE SYSTEM
# =========================

MODULES = {
    "daily-use": ["htop", "vim", "tmux", "curl", "wget"],
    "developer-stack": ["python3", "node", "go", "docker", "git"],
    "exploitation": ["msfconsole", "msfvenom", "searchsploit", "nc"],
    "network": ["nmap", "tcpdump", "wireshark", "tshark", "bettercap"],
    "osint": ["recon-ng", "theHarvester", "sherlock", "whois"],
    "password-cracking": ["hashcat", "john", "hydra", "medusa", "cewl"],
    "reverse-engineering": ["gdb", "strace", "binwalk", "radare2", "ghidra"],
    "websecurity": ["burpsuite", "nikto", "sqlmap", "gobuster", "ffuf"],
    "wireless": ["aircrack-ng", "reaver", "wifite", "hcxtools"]
}

CLI_TOOLS = {
    "nmap","tcpdump","msfconsole","msfvenom","searchsploit","nc",
    "gdb","strace","hashcat","john","hydra","whois",
    "vim","htop","tmux","curl","wget"
}

def get_all_tools():
    tools = set()
    for v in MODULES.values():
        tools.update(v)
    return sorted(list(tools))

# =========================
# MAIN APP
# =========================

class VisionX(Gtk.Window):
    def __init__(self):
        super().__init__(title="VisionX Launcher")

        self.set_default_size(1200, 720)
        self.set_border_width(10)

        self.data = load_data()
        self.all_tools = get_all_tools()

        self.apply_theme()

        # MAIN LAYOUT
        main = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(main)

        # SEARCH
        self.search = Gtk.Entry()
        self.search.set_placeholder_text("Search VisionX tools...")
        self.search.connect("changed", self.on_search)
        main.pack_start(self.search, False, False, 0)

        # BODY
        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        main.pack_start(body, True, True, 0)

        # LEFT PANEL
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        left.set_size_request(260, -1)
        body.pack_start(left, False, False, 0)

        self.add_button(left, "★ Favorites", self.show_favorites)
        self.add_button(left, "⏱ Recent", self.show_recent)
        self.add_button(left, "All Tools", self.show_all_tools)

        sep = Gtk.Separator()
        left.pack_start(sep, False, False, 5)

        for m in MODULES:
            self.add_button(left, m, lambda w, m=m: self.show_module(m))

        # RIGHT PANEL
        self.scroll = Gtk.ScrolledWindow()
        self.scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self.right_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        self.scroll.add(self.right_box)

        body.pack_start(self.scroll, True, True, 0)

        self.show_all_tools()

    # ================= THEME (FIXED) =================

    def apply_theme(self):
        css = b"""
        window {
            background-color: #2b2b2b;
            color: #ffffff;
        }

        button {
            background-color: #3c3f41;
            color: #ffffff;
            border: 1px solid #555555;
        }

        button:hover {
            background-color: #4c5052;
        }

        entry {
            background-color: #3c3f41;
            color: #ffffff;
            border: 1px solid #555555;
        }

        scrolledwindow {
            background-color: #2b2b2b;
        }
        """

        style = Gtk.CssProvider()
        style.load_from_data(css)

        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(),
            style,
            Gtk.STYLE_PROVIDER_PRIORITY_USER
        )

    # ================= UI =================

    def add_button(self, parent, label, callback):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)

        btn = Gtk.Button(label=label)
        btn.set_size_request(-1, 40)
        btn.connect("clicked", callback)

        fav = Gtk.Button(label="★")
        fav.set_size_request(40, 40)
        fav.connect("clicked", lambda w: toggle_favorite(label, self.data))

        row.pack_start(btn, True, True, 0)
        row.pack_start(fav, False, False, 0)

        parent.pack_start(row, False, False, 0)

    # ================= DISPLAY =================

    def clear(self):
        for c in self.right_box.get_children():
            self.right_box.remove(c)

    def display(self, items):
        self.clear()

        for i in items:
            b = Gtk.Button(label=i)
            b.set_size_request(-1, 40)
            b.connect("clicked", self.launch)
            self.right_box.pack_start(b, False, False, 0)

        self.right_box.show_all()

    # ================= MODULES =================

    def show_module(self, module):
        self.display(MODULES.get(module, []))

    def show_all_tools(self, widget=None):
        self.display(self.all_tools)

    def show_favorites(self, widget=None):
        self.display(self.data.get("favorites", []))

    def show_recent(self, widget=None):
        self.display(self.data.get("recent", []))

    # ================= SEARCH =================

    def on_search(self, widget):
        text = widget.get_text().lower()
        filtered = [t for t in self.all_tools if text in t.lower()]
        self.display(filtered)

    # ================= LAUNCH =================

    def launch(self, widget):
        tool = widget.get_label()
        add_recent(tool, self.data)

        try:
            if tool in CLI_TOOLS:
                subprocess.Popen(["xfce4-terminal", "--hold", "-e", tool])
            else:
                subprocess.Popen([tool])
        except:
            subprocess.Popen(["bash", "-c", tool])


# ================= RUN =================

win = VisionX()
win.connect("destroy", Gtk.main_quit)
win.show_all()
Gtk.main()
