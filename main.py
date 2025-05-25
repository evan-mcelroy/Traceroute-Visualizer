import tkinter as tk
from tkinter import ttk, messagebox
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
import folium
import requests
import webbrowser
import threading

MAX_HOPS = 30
TIMEOUT = 2

def get_ip_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = res.json()
        if data['status'] == 'success':
            return data['lat'], data['lon'], data.get('city', ip)
    except:
        return None
    return None

def perform_traceroute(dest, update_progress, update_log):
    hops = []
    seen_ips = set()

    for ttl in range(1, MAX_HOPS + 1):
        update_log(f"Probing TTL {ttl}...")
        pkt = IP(dst=dest, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=TIMEOUT)

        if reply is None:
            update_log(f"No response for TTL {ttl}.")
            update_progress(ttl)
            continue

        ip = reply.src
        if ip in seen_ips:
            update_log(f"Repeated hop at TTL {ttl}: {ip} — likely loop or endpoint.")
            update_progress(ttl)
            break

        seen_ips.add(ip)
        location = get_ip_location(ip)
        if location:
            lat, lon, city = location
            update_log(f"Hop {ttl}: {ip} ({city})")
            hops.append((ip, lat, lon, city))
        else:
            update_log(f"Hop {ttl}: {ip} (Location unknown)")
            hops.append((ip, 0, 0, "Unknown"))

        update_progress(ttl)

    update_log("Traceroute complete. Opening map...")
    return hops

def visualize_route(hops):
    if not hops:
        messagebox.showinfo("Traceroute", "No hops found to visualize.")
        return

    traceroute_map = folium.Map(location=[hops[0][1], hops[0][2]], zoom_start=2)

    for i, (ip, lat, lon, city) in enumerate(hops):
        folium.Marker(
            location=[lat, lon],
            popup=f"{i+1}. {ip} ({city})",
            icon=folium.Icon(color="blue")
        ).add_to(traceroute_map)

        if i > 0:
            folium.PolyLine(
                locations=[
                    [hops[i - 1][1], hops[i - 1][2]],
                    [lat, lon]
                ],
                color="red"
            ).add_to(traceroute_map)

    traceroute_map.save("traceroute_map.html")
    webbrowser.open("traceroute_map.html")

def run_traceroute(domain):
    progress_bar["maximum"] = MAX_HOPS
    progress_bar["value"] = 0
    log_console.config(state="normal")
    log_console.delete(1.0, tk.END)

    def update_progress(value):
        progress_bar["value"] = value

    def update_log(message):
        log_console.insert(tk.END, message + "\n")
        log_console.see(tk.END)

    hops = perform_traceroute(domain, update_progress, update_log)

    progress_bar["value"] = MAX_HOPS  # Ensure full progress bar

    visualize_route(hops)
    button.config(state=tk.NORMAL)
    log_console.config(state="disabled")

def on_traceroute():
    domain = entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP.")
        return

    button.config(state=tk.DISABLED)
    threading.Thread(target=run_traceroute, args=(domain,), daemon=True).start()

# GUI setup
root = tk.Tk()
root.title("Traceroute Visualizer")

tk.Label(root, text="Enter Domain or IP:").pack(pady=5)
entry = tk.Entry(root, width=50)
entry.pack(pady=5)

button = tk.Button(root, text="Traceroute", command=on_traceroute)
button.config(width=20)
button.config(bg="#00ff0d", fg="white", activebackground="#00ff0d")
button.config(activeforeground="black")
button.config(highlightbackground="#00ff0d", highlightcolor="#00ff0d")
button.config(highlightthickness=2, relief="raised")
button.config(borderwidth=4)
button.pack(pady=10)

progress_bar = ttk.Progressbar(root, length=400, mode="determinate")
progress_bar.pack(pady=5)

tk.Label(root, text="Console Log:").pack()
log_console = tk.Text(root, height=15, width=65, state="disabled", bg="#000000", fg="#0dff00")
log_console.pack(pady=5)

root.mainloop()
