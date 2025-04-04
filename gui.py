import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from header_analysis import fetch_headers, analyze_headers, calculate_security_grade
import threading
import webbrowser
import json
from datetime import datetime
import time
import psutil

def measure_performance(url: str, num_runs: int = 10) -> dict:
    """
    Measure performance metrics for scanning a URL
    """
    scan_times = []
    memory_usage = []
    
    for _ in range(num_runs):
        start_time = time.time()
        
        # Perform the scan
        headers = fetch_headers(url)
        results = analyze_headers(headers)
        calculate_security_grade(results, url.startswith('https'))
        
        # Record metrics
        end_time = time.time()
        scan_times.append(end_time - start_time)
        
        # Measure memory usage
        process = psutil.Process()
        memory_usage.append(process.memory_info().rss / 1024 / 1024)  # in MB
    
    return {
        'average_scan_time': sum(scan_times) / len(scan_times),
        'min_scan_time': min(scan_times),
        'max_scan_time': max(scan_times),
        'average_memory': sum(memory_usage) / len(memory_usage)
    }

# Fix instructions for missing headers
FIX_INSTRUCTIONS = {
    "Content-Security-Policy": (
        "To fix this, add a Content-Security-Policy header to your server configuration. "
        "For example:\n"
        "Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com;"
    ),
    "Strict-Transport-Security": (
        "This header enforces HTTPS by telling browsers to always use secure connections. "
        "Even if the website uses HTTPS, this header might be missing due to server configuration. "
        "To fix this, add the Strict-Transport-Security header. For example:\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains;"
    ),
    "X-Content-Type-Options": (
        "To fix this, add the X-Content-Type-Options header with the value 'nosniff'. "
        "For example:\n"
        "X-Content-Type-Options: nosniff;"
    ),
    "X-Frame-Options": (
        "To fix this, add the X-Frame-Options header to prevent clickjacking. "
        "For example:\n"
        "X-Frame-Options: DENY;"
    ),
    "X-XSS-Protection": (
        "To fix this, enable XSS protection in older browsers by adding the X-XSS-Protection header. "
        "For example:\n"
        "X-XSS-Protection: 1; mode=block;"
    ),
    "Referrer-Policy": (
        "To fix this, add the Referrer-Policy header to control referrer information. "
        "For example:\n"
        "Referrer-Policy: no-referrer-when-downgrade;"
    ),
    "Permissions-Policy": (
        "To fix this, add the Permissions-Policy header to restrict browser features. "
        "For example:\n"
        "Permissions-Policy: geolocation=(), microphone=();"
    ),
}

class SecurityHeadersScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Website Security Headers Scanner")
        self.root.geometry("900x700")
        self.root.configure(bg="#2c2f33")
        
        self.setup_styles()
        self.create_widgets()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton",
                       background="#7289da",
                       foreground="#ffffff",
                       font=("Arial", 10),
                       padding=5)
        style.map("TButton",
                 background=[("active", "#5b6ee1")])
        style.configure("TLabel",
                       background="#2c2f33",
                       foreground="#ffffff",
                       font=("Arial", 10))
        style.configure("TEntry",
                       fieldbackground="#40444b",
                       foreground="#ffffff",
                       font=("Arial", 10))
        
    def create_widgets(self):
        # Title
        title_label = tk.Label(self.root,
                             text="Website Security Headers Scanner",
                             font=("Arial", 16, "bold"),
                             bg="#2c2f33",
                             fg="#ffffff")
        title_label.pack(pady=10)
        
        # URL Input Frame
        url_frame = tk.Frame(self.root, bg="#2c2f33")
        url_frame.pack(pady=10)
        
        tk.Label(url_frame,
                text="Enter Website URL:",
                font=("Arial", 12),
                bg="#2c2f33",
                fg="#ffffff").pack(side=tk.LEFT)
        
        self.url_entry = ttk.Entry(url_frame, width=50)
        self.url_entry.pack(side=tk.LEFT, padx=10)
        
        self.analyze_button = ttk.Button(url_frame,
                                       text="Analyze",
                                       command=self.analyze_website)
        self.analyze_button.pack(side=tk.LEFT)
        
        # Progress Bar
        self.progress_frame = tk.Frame(self.root, bg="#2c2f33")
        self.progress_frame.pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(self.progress_frame,
                                          mode="indeterminate",
                                          length=200)
        self.progress_bar.pack()
        
        self.status_label = tk.Label(self.progress_frame,
                                   text="Ready",
                                   font=("Arial", 10),
                                   bg="#2c2f33",
                                   fg="#ffffff")
        self.status_label.pack()
        
        # Results Text
        self.result_text = scrolledtext.ScrolledText(self.root,
                                                   height=25,
                                                   width=90,
                                                   font=("Arial", 10),
                                                   bg="#36393f",
                                                   fg="#ffffff")
        self.result_text.pack(pady=10)
        
        # Configure tags for colors
        self.result_text.tag_config("green", foreground="#43b581")
        self.result_text.tag_config("red", foreground="#f04747")
        self.result_text.tag_config("yellow", foreground="#faa61a")
        self.result_text.tag_config("orange", foreground="#e67e22")
        self.result_text.tag_config("bold", font=("Arial", 10, "bold"))
        self.result_text.tag_config("italic",
                                  font=("Arial", 10, "italic"),
                                  foreground="#cccccc")
        
        # Buttons Frame
        buttons_frame = tk.Frame(self.root, bg="#2c2f33")
        buttons_frame.pack(pady=10)
        
        ttk.Button(buttons_frame,
                  text="Export Results",
                  command=self.export_results).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame,
                  text="Clear Results",
                  command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame,
                  text="Open Web Version",
                  command=self.open_web_version).pack(side=tk.LEFT, padx=5)
        
    def analyze_website(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("Error", "Please enter a valid URL.")
            return
        
        self.analyze_button.config(state=tk.DISABLED)
        self.status_label.config(text="Fetching headers...",
                               foreground="#ffffff")
        self.progress_bar.start()
        
        threading.Thread(target=self.fetch_and_analyze,
                       args=(url,),
                       daemon=True).start()
        
    def fetch_and_analyze(self, url):
        try:
            response_data = fetch_headers(url)
            if not response_data:
                raise Exception("Failed to fetch headers.")
            
            analysis_results = analyze_headers(response_data)
            
            self.root.after(0,
                          lambda: self.update_results(analysis_results))
        except Exception as e:
            self.root.after(0, lambda: self.on_error(str(e)))
        finally:
            self.root.after(0, self.on_complete)
            
    def update_results(self, analysis_results):
        self.clear_results()
        
        results = analysis_results['results']
        is_https = analysis_results['is_https']
        
        # Get grade info from calculate_security_grade
        grade_info = calculate_security_grade(results, is_https)
        
        # Display security grade
        grade = grade_info['grade']
        score = grade_info['score']
        description = grade_info['description']
        
        grade_color = {
            'A+': 'green',
            'A': 'green',
            'B': 'yellow',
            'C': 'yellow',
            'D': 'orange',
            'F': 'red'
        }.get(grade, 'red')
        
        self.result_text.insert(tk.END, f"Security Grade: ", "bold")
        self.result_text.insert(tk.END, f"{grade} (Score: {score})\n", grade_color)
        self.result_text.insert(tk.END, f"{description}\n\n", "italic")
        
        # Display HTTPS status
        https_status = "HTTPS is enabled" if is_https else "HTTPS is not enabled"
        https_tag = "green" if is_https else "red"
        self.result_text.insert(tk.END, f"{https_status}\n\n", https_tag)
        
        # Display header analysis
        self.result_text.insert(tk.END, "Header Analysis:\n", "bold")
        
        for header, info in results.items():
            status = info['status']
            importance = info['importance']
            
            # Header name and status
            self.result_text.insert(tk.END, f"\n{header}: ", "bold")
            if status == "Present":
                self.result_text.insert(tk.END, "Present\n", "green")
                self.result_text.insert(tk.END, f"Current Value: {info['current_value']}\n", "italic")
            else:
                self.result_text.insert(tk.END, "Missing\n", "red")
            
            # Header importance and description
            importance_color = {
                'Critical': 'red',
                'High': 'orange',
                'Medium': 'yellow'
            }.get(importance, 'italic')
            
            self.result_text.insert(tk.END, f"Importance: {importance}\n", importance_color)
            self.result_text.insert(tk.END, f"Description: {info['description']}\n", "italic")
            
            # Add fix instructions for missing headers
            if status == "Missing" and header in FIX_INSTRUCTIONS:
                self.result_text.insert(tk.END, "How to fix:\n", "bold")
                self.result_text.insert(tk.END, f"{FIX_INSTRUCTIONS[header]}\n", "italic")
        
        # Add summary
        self.result_text.insert(tk.END, "\nSummary:\n", "bold")
        self.result_text.insert(tk.END, f"Total Headers Checked: {grade_info['total_headers']}\n")
        self.result_text.insert(tk.END, f"Headers Present: {grade_info['present_headers']}\n")
        self.result_text.insert(tk.END, f"Critical Headers Score: {grade_info['critical_score']}%\n")
        self.result_text.insert(tk.END, f"High Importance Headers Score: {grade_info['high_score']}%\n")
        self.result_text.insert(tk.END, f"Medium Importance Headers Score: {grade_info['medium_score']}%\n")
        
        self.status_label.config(text="Analysis complete!",
                               foreground="#43b581")
    
    def export_results(self):
        content = self.result_text.get("1.0", tk.END)
        if not content.strip():
            messagebox.showwarning("Warning",
                                 "No results to export.")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_scan_{timestamp}.txt"
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Success",
                              f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error",
                               f"Failed to export results: {str(e)}")
    
    def clear_results(self):
        self.result_text.delete("1.0", tk.END)
        
    def open_web_version(self):
        import requests
        try:
            # Try to connect to the Flask server
            response = requests.get('http://127.0.0.1:5000', timeout=2)
            if response.status_code == 200:
                webbrowser.open('http://127.0.0.1:5000')
            else:
                messagebox.showerror("Error", 
                    "Web server is not responding properly. Please make sure app.py is running.")
        except requests.exceptions.ConnectionError:
            messagebox.showerror("Error", 
                "Could not connect to web version. Please start the web server by running app.py first.")
        except Exception as e:
            messagebox.showerror("Error", 
                f"An error occurred: {str(e)}\nPlease make sure app.py is running.")
        
    def on_error(self, error_message):
        self.status_label.config(text="Error occurred!",
                               foreground="#f04747")
        messagebox.showerror("Error", error_message)
        
    def on_complete(self):
        self.progress_bar.stop()
        self.analyze_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityHeadersScanner(root)
    root.mainloop()