
"""
Beautiful TCP Port Scanner (Tkinter) — Python 3.7 compatible
Use responsibly: scan only hosts you own or have permission to test.
"""

import socket
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
import time
from datetime import datetime

# -------- Config --------
COMMON_PORTS = {
    20: "FTP Data Transfer", 21: "FTP Control", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
}
MAX_THREADS = 400
BANNER_MAX_LEN = 400

# ---------- App ----------
class BeautifulPortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Beautiful TCP Port Scanner")
        self.root.geometry("1100x660")
        self.root.minsize(980, 560)

        # theme + styles
        self._configure_style()

        # State vars
        self.target = tk.StringVar()
        self.domain = tk.StringVar(value="-")
        self.resolved_ip = tk.StringVar(value="-")
        self.start_port = tk.StringVar(value="1")
        self.end_port = tk.StringVar(value="1024")
        self.speed = tk.StringVar(value="Medium")
        self.grab_banners = tk.BooleanVar(value=True)
        self.retries = tk.IntVar(value=1)
        self.workers_override = tk.IntVar(value=0)

        self.stop_flag = threading.Event()
        self.port_queue = None
        self.threads = []
        self.total_jobs = 0
        self.done_jobs = 0

        # store all results internally; only OPEN shown in TreeView
        # entries: (input, domain, ip, port, service, status, info)
        self.all_results = []
        self.open_results = []

        self._build_ui()

    def _configure_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        # fonts and paddings
        style.configure('TFrame', background='#f6f8fb')
        style.configure('Header.TLabel', font=('Segoe UI', 11, 'bold'), background='#f6f8fb')
        style.configure('TLabel', background='#f6f8fb')
        style.configure('TEntry', padding=6)
        style.configure('Accent.TButton', background='#3b82f6', foreground='white', padding=8, relief='flat')
        style.map('Accent.TButton', background=[('active', '#2563eb'), ('disabled', '#9bbffb')])
        style.configure('Ghost.TButton', background='#ffffff', foreground='#333', padding=8, relief='flat')
        style.map('Ghost.TButton', background=[('active', '#f0f3ff')])

    def _build_ui(self):
        root = self.root
        frm = ttk.Frame(root, padding=12, style='TFrame')
        frm.pack(fill='both', expand=True)

        # Top: inputs
        top = ttk.Frame(frm, style='TFrame')
        top.pack(fill='x', pady=(0,8))

        ttk.Label(top, text='Target (domain or IP):', style='Header.TLabel').grid(row=0, column=0, sticky='w')
        e = ttk.Entry(top, textvariable=self.target, width=42)
        e.grid(row=0, column=1, columnspan=2, sticky='w', padx=(8,4))
        btn_resolve = ttk.Button(top, text='Resolve', style='Accent.TButton', command=self.resolve_ip)
        btn_resolve.grid(row=0, column=3, padx=(6,4))
        btn_clear = ttk.Button(top, text='Clear Results', style='Ghost.TButton', command=self._clear_results)
        btn_clear.grid(row=0, column=4, padx=(4,0))
        # hover effects
        for b in (btn_resolve, btn_clear):
            b.bind('<Enter>', lambda e, w=b: w.state(['active']))
            b.bind('<Leave>', lambda e, w=b: w.state(['!active']))

        # display
        self.target_display = ttk.Label(frm, text='Target: -   |   Domain: -   |   IP: -', style='TLabel')
        self.target_display.pack(anchor='w', pady=(4,8))

        # second row: ports and speed
        mid = ttk.Frame(frm, style='TFrame')
        mid.pack(fill='x', pady=(0,8))

        ttk.Label(mid, text='Start Port:').grid(row=0, column=0, sticky='w')
        ttk.Entry(mid, textvariable=self.start_port, width=10).grid(row=0, column=1, sticky='w', padx=(6,12))
        ttk.Label(mid, text='End Port:').grid(row=0, column=2, sticky='w')
        ttk.Entry(mid, textvariable=self.end_port, width=10).grid(row=0, column=3, sticky='w', padx=(6,12))

        ttk.Label(mid, text='Speed:').grid(row=0, column=4, sticky='e')
        ttk.Combobox(mid, textvariable=self.speed, values=['Fast','Medium','Slow'], state='readonly', width=12).grid(row=0, column=5, sticky='w', padx=(6,12))

        ttk.Checkbutton(mid, text='Grab banners', variable=self.grab_banners).grid(row=0, column=6, sticky='w', padx=(12,0))

        # controls row
        ctrl = ttk.Frame(frm, style='TFrame')
        ctrl.pack(fill='x', pady=(6,8))
        self.btn_start = ttk.Button(ctrl, text='Start Scan', style='Accent.TButton', command=self.start_scan)
        self.btn_start.pack(side='left')
        self.btn_stop = ttk.Button(ctrl, text='Stop', style='Ghost.TButton', command=self.stop_scan, state='disabled')
        self.btn_stop.pack(side='left', padx=(8,0))
        self.btn_retry = ttk.Button(ctrl, text='Retry Filtered', style='Ghost.TButton', command=self.retry_filtered)
        self.btn_retry.pack(side='left', padx=(8,0))
        self.btn_export = ttk.Button(ctrl, text='Export OPEN CSV', style='Ghost.TButton', command=self.export_csv, state='disabled')
        self.btn_export.pack(side='left', padx=(8,0))

        # progress
        self.progress = ttk.Progressbar(frm, orient='horizontal', mode='determinate', length=980)
        self.progress.pack(fill='x', pady=(6,6))
        self.status_label = ttk.Label(frm, text='Ready')
        self.status_label.pack(anchor='w')

        # results (only OPEN shown)
        cols = ('Input','Domain','IP','Port','Service','Banner/Info')
        self.tree = ttk.Treeview(frm, columns=cols, show='headings', height=18)
        widths = (120,180,120,80,140,360)
        for c,w in zip(cols,widths):
            self.tree.heading(c, text=c)
            anchor = 'w' if c in ('Input','Domain','Banner/Info') else 'center'
            self.tree.column(c, width=w, anchor=anchor)
        self.tree.pack(fill='both', expand=True, pady=(8,0))
        # scrollbar
        sb = ttk.Scrollbar(self.tree, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')

        # click effect: show details popup
        self.tree.bind('<Double-1>', self._on_row_double_click)

    # ---------- Handlers ----------
    def _clear_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.all_results.clear()
        self.open_results.clear()
        self.status_label.config(text='Cleared results')
        self.btn_export.config(state='disabled')

    def resolve_ip(self):
        tgt = self.target.get().strip()
        if not tgt:
            messagebox.showwarning('Input','Please enter a domain or IP.')
            return
        try:
            ip = socket.gethostbyname(tgt)
            self.resolved_ip.set(ip)
            # reverse
            domain = '-'
            try:
                parts = tgt.split('.')
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    domain = socket.gethostbyaddr(tgt)[0]
                else:
                    domain = tgt
            except Exception:
                domain = '-'
            self.domain.set(domain)
            self._update_target_display(tgt, domain, ip)
            self.status_label.config(text=f'Resolved: {tgt} → {ip} ({domain})')
        except socket.gaierror:
            # try reverse
            try:
                domain = socket.gethostbyaddr(tgt)[0]
                self.resolved_ip.set(tgt)
                self.domain.set(domain)
                self._update_target_display(tgt, domain, tgt)
                self.status_label.config(text=f'Reverse resolved: {tgt} → {domain}')
            except Exception:
                self.resolved_ip.set('-')
                self.domain.set('-')
                self._update_target_display(tgt, '-', '-')
                self.status_label.config(text='Could not resolve target')
                messagebox.showerror('Resolve Error','Could not resolve target. Check spelling or internet.')

    def _update_target_display(self, inp, domain, ip):
        self.target_display.config(text=f'Target: {inp}   |   Domain: {domain or "-"}   |   IP: {ip or "-"}')

    def start_scan(self):
        tgt = self.target.get().strip()
        if not tgt:
            messagebox.showwarning('Input','Please enter a domain or IP.')
            return

        # resolve best-effort
        resolved = None
        domain = '-'
        try:
            ip = socket.gethostbyname(tgt)
            resolved = ip
            self.resolved_ip.set(ip)
            try:
                parts = tgt.split('.')
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    domain = socket.gethostbyaddr(tgt)[0]
                else:
                    domain = tgt
            except Exception:
                domain = '-'
            self.domain.set(domain)
            self._update_target_display(tgt, domain, ip)
        except socket.gaierror:
            try:
                domain = socket.gethostbyaddr(tgt)[0]
                resolved = tgt
                self.resolved_ip.set(tgt)
                self.domain.set(domain)
                self._update_target_display(tgt, domain, tgt)
            except Exception:
                resolved = tgt
                self.resolved_ip.set('-')
                self.domain.set('-')
                self._update_target_display(tgt, '-', '-')

        # validate ports
        try:
            start_p = int(self.start_port.get())
            end_p = int(self.end_port.get())
            if start_p < 1 or end_p > 65535 or start_p > end_p:
                raise ValueError
        except ValueError:
            messagebox.showerror('Invalid Ports','Please enter a valid port range (1-65535) and ensure Start ≤ End.')
            return

        spd = self.speed.get()
        if spd == 'Fast':
            base_timeout = 0.2
            default_workers = 300
        elif spd == 'Slow':
            base_timeout = 1.0
            default_workers = 60
        else:
            base_timeout = 0.5
            default_workers = 150

        workers = self.workers_override.get() if self.workers_override.get() > 0 else min(MAX_THREADS, default_workers)
        retries = max(1, self.retries.get())

        # reset UI but keep all_results for retry
        self.open_results.clear()
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.stop_flag.clear()
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.btn_export.config(state='disabled')
        self.status_label.config(text=f'Scanning {tgt} ({resolved}) ports {start_p}-{end_p} ...')

        # prepare queue
        self.port_queue = queue.Queue()
        for p in range(start_p, end_p+1):
            self.port_queue.put(p)
        self.total_jobs = end_p - start_p + 1
        self.done_jobs = 0
        self.progress.config(maximum=self.total_jobs, value=0)

        # launch threads
        self.threads = []
        for _ in range(min(workers, self.total_jobs)):
            t = threading.Thread(target=self._worker, args=(tgt, resolved, domain, base_timeout, retries), daemon=True)
            self.threads.append(t)
            t.start()

        self.root.after(150, self._poll_done)

    def _worker(self, target_input, resolved, domain, timeout, retries):
        while not self.stop_flag.is_set():
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                return
            self._scan_one(target_input, domain, resolved, port, timeout, retries)
            self.port_queue.task_done()
            self._tick_progress()

    def _scan_one(self, target_input, domain, resolved, port, timeout, retries):
        service = COMMON_PORTS.get(port, 'Unknown')
        status = 'CLOSED'
        info = ''
        last_exc = None

        for attempt in range(retries):
            if self.stop_flag.is_set():
                return
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                res = s.connect_ex((resolved, port))
                if res == 0:
                    status = 'OPEN'
                    if self.grab_banners.get():
                        try:
                            info = self._grab_banner(s, target_input, port, timeout)
                        except Exception:
                            info = ''
                        # FIX: ensure no newline-in-string causing syntax error
                        info = (info or '').strip().replace('\r', ' ').replace('\n', ' ')
                        if len(info) > BANNER_MAX_LEN:
                            info = info[:BANNER_MAX_LEN] + '...'
                    # store
                    entry = (target_input, domain, resolved, port, service, status, info)
                    self.all_results.append(entry)
                    self.open_results.append(entry)
                    # INSERT in tree only for OPEN
                    self.root.after(0, lambda e=entry: self.tree.insert('', 'end', values=(e[0], e[1], e[2], e[3], e[4], e[6])))
                    try:
                        s.close()
                    except Exception:
                        pass
                    return
                else:
                    status = 'CLOSED'
                    last_exc = res
            except socket.timeout:
                status = 'FILTERED'
                last_exc = 'timeout'
            except OSError as e:
                last_exc = e
                if getattr(e,'errno',None) in (111,61,10061):
                    status = 'CLOSED'
                else:
                    status = 'FILTERED'
            except Exception as e:
                last_exc = e
                status = 'FILTERED'
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            time.sleep(0.05)

        # if not open after retries, record in all_results but DO NOT show in tree (per your request)
        entry = (target_input, domain, resolved, port, service, status, str(last_exc))
        self.all_results.append(entry)

    def _grab_banner(self, sock, target, port, timeout):
        sock.settimeout(timeout)
        try:
            if port == 22:
                try:
                    return sock.recv(256).decode(errors='ignore')
                except Exception:
                    return ''
            if port == 25:
                try:
                    greet = sock.recv(512).decode(errors='ignore')
                    try:
                        sock.sendall(b'EHLO example.com\r\n')
                        resp = sock.recv(512).decode(errors='ignore')
                        return (greet + ' ' + resp).strip()
                    except Exception:
                        return greet
                except Exception:
                    return ''
            if port in (80,8080):
                try:
                    host = target.encode() if isinstance(target,str) else b''
                    req = b'HEAD / HTTP/1.0\r\nHost: ' + host + b'\r\nUser-Agent: beautiful-scan\r\n\r\n'
                    sock.sendall(req)
                    data = sock.recv(2048).decode(errors='ignore')
                    for line in data.splitlines():
                        if line.lower().startswith('server:'):
                            return line
                    return data.splitlines()[0] if data else ''
                except Exception:
                    return ''
            if port == 443:
                return '<TLS - skipped>'
            if port == 3306:
                try:
                    data = sock.recv(512)
                    return data.decode(errors='ignore')
                except Exception:
                    return ''
            # generic
            try:
                data = sock.recv(512)
                return data.decode(errors='ignore') if data else ''
            except Exception:
                return ''
        except Exception:
            return ''

    def _tick_progress(self):
        self.done_jobs += 1
        if self.done_jobs % 5 == 0 or self.done_jobs == self.total_jobs:
            self.root.after(0, lambda: self.progress.config(value=self.done_jobs))
            self.root.after(0, lambda: self.status_label.config(text=f'Scanning... {self.done_jobs}/{self.total_jobs} checks'))

    def _poll_done(self):
        all_dead = all((not t.is_alive()) for t in self.threads)
        if not all_dead:
            self.root.after(150, self._poll_done)
            return
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.btn_export.config(state='normal' if self.open_results else 'disabled')
        self.status_label.config(text=f'Scan complete. Open ports: {len(self.open_results)}')
        messagebox.showinfo('Scan Complete', f'Finished! Open ports found: {len(self.open_results)}')

    def stop_scan(self):
        self.stop_flag.set()
        self.status_label.config(text='Stopping... please wait')

    def retry_filtered(self):
        # find filtered/timeout entries from all_results
        filtered = [r for r in self.all_results if r[5] in ('FILTERED','CLOSED')]
        if not filtered:
            messagebox.showinfo('Retry Filtered','No filtered/closed entries to retry.')
            return
        # ask user
        if not messagebox.askyesno('Retry Filtered','Retry {} ports with higher timeout?'.format(len(filtered))):
            return
        # requeue filtered ports with higher timeout
        for r in filtered:
            self.port_queue.put(r[3])
        # increase timeout & retries for aggressive retry
        new_timeout = 1.2
        new_retries = 2
        self.stop_flag.clear()
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.btn_export.config(state='disabled')
        # launch small worker pool
        workers = min(60, len(filtered))
        for _ in range(workers):
            t = threading.Thread(target=self._worker, args=(self.target.get().strip(), self.resolved_ip.get(), self.domain.get(), new_timeout, new_retries), daemon=True)
            self.threads.append(t)
            t.start()
        self.root.after(150, self._poll_done)

    def _on_row_double_click(self, ev):
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        vals = self.tree.item(item, 'values')
        # show a popup with details and small fade-in effect
        popup = tk.Toplevel(self.root)
        popup.title('Port details')
        popup.geometry('520x220')
        popup.attributes('-topmost', True)
        lbl = ttk.Label(popup, text=f'Input: {vals[0]}\nDomain: {vals[1]}\nIP: {vals[2]}\nPort: {vals[3]}\nService: {vals[4]}\nBanner/Info: {vals[5]}', wraplength=480)
        lbl.pack(padx=12, pady=12)
        # simple alpha fade-in (works on most platforms)
        try:
            for a in [i/10.0 for i in range(1,11)]:
                popup.attributes('-alpha', a)
                popup.update()
                time.sleep(0.02)
        except Exception:
            pass

    def export_csv(self):
        if not self.open_results:
            messagebox.showwarning('No Data','No open ports to export.')
            return
        tgt = self.target.get().strip() or 'target'
        default_name = f'open_tcp_scan_{tgt.replace(".", "_")}.csv'
        path = filedialog.asksaveasfilename(defaultextension='.csv', initialfile=default_name, filetypes=[('CSV files','*.csv')])
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(['Input','Domain','Resolved IP','Port','Service','Banner/Info','ScannedAt'])
                now = datetime.utcnow().isoformat() + 'Z'
                for e in sorted(self.open_results, key=lambda x: (x[0], x[3])):
                    w.writerow([e[0], e[1], e[2], e[3], e[4], e[6], now])
            messagebox.showinfo('Exported', f'Results saved to:\n{path}')
        except Exception as ex:
            messagebox.showerror('Export Error', f'Could not save file.\n{ex}')


if __name__ == '__main__':
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app = BeautifulPortScannerGUI(root)
    root.mainloop()
