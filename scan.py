import tkinter as tk
from tkinter import messagebox
import nmap

def network_scan(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-p 22,80,443')  # لیست پورت‌هایی که می‌خواهید اسکن کنید را مشخص کنید
    scan_results = ""
    for host in nm.all_hosts():
        scan_results += f'Host: {host} ({nm[host].hostname()})\n'
        scan_results += f'State: {nm[host].state()}\n'
        for proto in nm[host].all_protocols():
            scan_results += f'Protocol: {proto}\n'
            lport = nm[host][proto].keys()
            for port in lport:
                scan_results += f'Port: {port}\tState: {nm[host][proto][port]["state"]}\n'
        scan_results += "\n"
    return scan_results

def start_scan():
    network = entry.get()
    if not network:
        messagebox.showerror("Error", "Please enter a network range.")
        return
    try:
        scan_results = network_scan(network)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, scan_results)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ایجاد رابط کاربری
root = tk.Tk()
root.title("Network Scanner")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

label = tk.Label(frame, text="Enter Network Range (e.g., 192.168.1.0/24):")
label.pack(pady=5)

entry = tk.Entry(frame, width=30)
entry.pack(pady=5)

scan_button = tk.Button(frame, text="Start Scan", command=start_scan)
scan_button.pack(pady=5)

result_text = tk.Text(frame, width=60, height=20)
result_text.pack(pady=5)

root.mainloop()
